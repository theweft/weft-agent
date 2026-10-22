// SPDX-FileCopyrightText: 2026 The weft authors
// SPDX-License-Identifier: MIT

//! Power loss at any point of a save, on turmoil's simulated filesystem.
//!
//! turmoil keeps writes, renames and file creations *pending* until `sync_all` / `sync_dir`
//! (or a random background sync) makes them durable; a crash discards what is still pending.
//! A wrapper cuts the power after a random number of filesystem operations, so the crash can
//! hit between writing the temporary file, the rename and the directory sync.
//!
//! The property: after the restart, the file holds the last acknowledged state or the one
//! that was being saved, never an older one, never a damaged one, never none.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::panic,
    missing_docs
)]

use std::cell::Cell;
use std::io::{self, Write as _};
use std::path::Path;
use std::rc::Rc;
use std::time::Duration;

use turmoil::fs::shim::std::fs as simfs;
use weft_decider::{FileStore, Fs, StateStore};

const DIR: &str = "/data";
const FILE: &str = "/data/state";

/// turmoil's filesystem, with a power cut after `budget` operations.
#[derive(Clone)]
struct SimFs {
    budget: Rc<Cell<Option<u32>>>,
    /// Skip all syncs: the broken protocol the test must catch.
    broken: bool,
}

impl SimFs {
    fn spend(&self) -> io::Result<()> {
        match self.budget.get() {
            Some(0) => Err(io::Error::other("power cut")),
            Some(n) => {
                self.budget.set(Some(n - 1));
                Ok(())
            }
            None => Ok(()),
        }
    }
}

impl Fs for SimFs {
    fn read(&self, path: &Path) -> io::Result<Option<Vec<u8>>> {
        match simfs::read(path) {
            Ok(b) => Ok(Some(b)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }
    fn write_synced(&self, path: &Path, bytes: &[u8]) -> io::Result<()> {
        self.spend()?;
        let mut file = simfs::File::create(path)?;
        file.write_all(bytes)?;
        self.spend()?;
        if self.broken { Ok(()) } else { file.sync_all() }
    }
    fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
        self.spend()?;
        simfs::rename(from, to)
    }
    fn sync_dir(&self, dir: &Path) -> io::Result<()> {
        self.spend()?;
        if self.broken {
            Ok(())
        } else {
            simfs::sync_dir(dir)
        }
    }
}

/// The saved payloads are counters: "state <n>".
fn payload(n: u64) -> Vec<u8> {
    format!("state {n}").into_bytes()
}

fn counter(bytes: &[u8]) -> u64 {
    std::str::from_utf8(bytes)
        .unwrap()
        .strip_prefix("state ")
        .unwrap()
        .parse()
        .unwrap()
}

/// What the restarted device found: `None` no file, `Some(Err)` a damaged one.
type Loaded = Option<Result<u64, String>>;

struct Outcome {
    acknowledged: u64,
    loaded: Loaded,
}

fn run(seed: u64, broken: bool) -> Outcome {
    let mut rng = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
    let mut next = move |n: u64| {
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        rng % n
    };
    let budget = Rc::new(Cell::new(Some(8 + next(60) as u32)));
    let acknowledged = Rc::new(Cell::new(0u64));
    let loaded: Rc<Cell<Option<Loaded>>> = Rc::new(Cell::new(None));
    let restarted = Rc::new(Cell::new(false));

    let mut builder = turmoil::Builder::new();
    builder
        .simulation_duration(Duration::from_secs(120))
        .tick_duration(Duration::from_millis(1))
        .rng_seed(seed);
    builder.fs().sync_probability(next(30) as f64 / 100.0);
    let mut sim = builder.build();

    {
        let (budget, acknowledged, loaded, restarted) = (
            budget.clone(),
            acknowledged.clone(),
            loaded.clone(),
            restarted.clone(),
        );
        sim.host("device", move || {
            let fs = SimFs {
                budget: budget.clone(),
                broken,
            };
            let (acknowledged, loaded, restarted) =
                (acknowledged.clone(), loaded.clone(), restarted.clone());
            async move {
                if !simfs::exists(DIR) {
                    simfs::create_dir_all(DIR)?;
                    simfs::sync_dir("/")?;
                }
                let mut store = FileStore::with_fs(fs, FILE);
                if restarted.get() {
                    let result = match store.load() {
                        Ok(None) => None,
                        Ok(Some(bytes)) => Some(Ok(counter(&bytes))),
                        Err(e) => Some(Err(e.0)),
                    };
                    loaded.set(Some(result));
                    return Ok(());
                }
                for n in 1.. {
                    // A failed save (power cut) stops the device; the test then crashes it.
                    store.save(&payload(n)).map_err(|e| io::Error::other(e.0))?;
                    acknowledged.set(n);
                    tokio::time::sleep(Duration::from_millis(3)).await;
                }
                Ok(())
            }
        });
    }
    sim.client("clock", async {
        tokio::time::sleep(Duration::from_secs(100)).await;
        Ok(())
    });

    loop {
        if !restarted.get() && budget.get() == Some(0) {
            sim.crash("device");
            budget.set(None);
            restarted.set(true);
            sim.bounce("device");
        }
        // An error is the device stopping at the power cut; keep stepping.
        if let Ok(true) = sim.step() {
            break;
        }
        if let Some(result) = loaded.take() {
            return Outcome {
                acknowledged: acknowledged.get(),
                loaded: result,
            };
        }
    }
    panic!("seed {seed}: device never restarted");
}

fn seeds() -> u64 {
    std::env::var("WEFT_POWER_SEEDS")
        .ok()
        .and_then(|n| n.parse().ok())
        .unwrap_or(300)
}

/// @relation(AGT-010, scope=function)
#[test]
fn acknowledged_state_survives_power_loss_at_any_point() {
    for seed in 1..=seeds() {
        let o = run(seed, false);
        match o.loaded {
            Some(Ok(n)) => assert!(
                n == o.acknowledged || n == o.acknowledged + 1,
                "seed {seed}: loaded state {n}, acknowledged {}",
                o.acknowledged
            ),
            Some(Err(e)) => panic!("seed {seed}: damaged after power loss: {e}"),
            None => assert_eq!(o.acknowledged, 0, "seed {seed}: state file lost"),
        }
    }
}

/// The same crashes against a protocol without fsyncs must lose acknowledged states:
/// otherwise the test above would prove nothing.
#[test]
fn the_test_catches_a_protocol_without_fsync() {
    let lost = (1..=seeds())
        .filter(|seed| {
            let o = run(*seed, true);
            !matches!(o.loaded, Some(Ok(n)) if n >= o.acknowledged)
        })
        .count();
    eprintln!(
        "without fsync: {lost} of {} power cuts lost an acknowledged state",
        seeds()
    );
    assert!(lost > 0, "no seed lost an acknowledged state without fsync");
}
