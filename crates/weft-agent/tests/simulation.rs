// SPDX-FileCopyrightText: 2026 The weft authors
// SPDX-License-Identifier: MIT

//! Deterministic simulation of document sync and decisions (weft-design docs/20 §5).
//!
//! Topology (turmoil hosts, UDP links):
//!
//! ```text
//!   cloud ── gateway ──┬── dev-a          (labels site=s1, line=l1)
//!                      ├── dev-c          (labels site=s1, line=l2; technician USB stick)
//!                      └── relay ── dev-b (labels site=s1, line=l1; behind a MALICIOUS relay)
//! ```
//!
//! Per seed: random latency, message loss and link failures, a gateway–relay partition, a
//! restart of dev-a, documents entering at random times (cloud, USB). The relay drops,
//! tampers with and replays documents. After the network heals, the checks are:
//!
//! 1. convergence: all honest nodes hold the same documents;
//! 2. agreement: dev-a and dev-b (same labels, different paths) decide the same;
//! 3. oracle: every device's final state equals a fresh evaluation of the same documents;
//! 4. safety: tampered documents are never accepted; time floor and versions never go back;
//! 5. expected outcome: tie conflict reported, revoked technician change gone.
//!
//! `WEFT_SIM_SEEDS=<n>` runs more seeds (default 16), `WEFT_SIM_SEED=<s>` replays one.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::too_many_lines,
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::assert_is_empty,
    missing_docs
)]

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;
use std::time::Duration;

use ed25519_dalek::{Signer, SigningKey};
use tokio::sync::mpsc;
use turmoil::net::UdpSocket;
use weft_agent::{Node, NodeConfig, Observer, sync_keys};
use weft_decider::{Decider, ExecError, Executor, Outcome, StateStore, StoreError};
use weft_sync::{Digest, Limits, Message, Sync};
use weft_transport::sim::{PORT, SimTransport, decode_frame, encode_frame};
use weft_verifier::cbor::{self, Value};
use weft_verifier::crypto::{Algorithm, PublicKey, sha256};
use weft_verifier::{DeviceFacts, Instruction, Slot, TrustAnchor, cose};

const TENANT: &str = "acme";
const HONEST: [&str; 5] = ["cloud", "gateway", "dev-a", "dev-b", "dev-c"];
const DEVICES: [&str; 3] = ["dev-a", "dev-b", "dev-c"];
const HEAL_AT: Duration = Duration::from_secs(150);
const END_AT: Duration = Duration::from_secs(330);
const ARTIFACT_A: [u8; 32] = [0xa1; 32];

// ---------------------------------------------------------------------------------------------
// Randomness (seeded, no dependency)

#[derive(Clone)]
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        // SplitMix64.
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
    fn secs(&mut self, from: u64, to: u64) -> Duration {
        Duration::from_millis(from * 1000 + self.below((to - from) * 1000))
    }
    fn chance(&mut self, percent: u64) -> bool {
        self.below(100) < percent
    }
}

// ---------------------------------------------------------------------------------------------
// Documents (signing happens outside the verifier: here, in the test)

struct Key {
    sk: SigningKey,
    pk: PublicKey,
}

fn key(seed: u8) -> Key {
    let sk = SigningKey::from_bytes(&[seed; 32]);
    let pk = PublicKey {
        alg: Algorithm::Ed25519,
        bytes: sk.verifying_key().to_bytes().to_vec(),
    };
    Key { sk, pk }
}

fn sign(k: &Key, payload: &Value) -> Vec<u8> {
    let payload = cbor::encode(payload).unwrap();
    let protected = cose::protected_header(k.pk.alg.cose_id(), &k.pk.key_id()).unwrap();
    let tbs = cose::sig_structure(&protected, &payload).unwrap();
    cose::encode_sign1(&protected, &payload, &k.sk.sign(&tbs).to_bytes()).unwrap()
}

fn texts(items: &[&str]) -> Value {
    Value::Array(items.iter().map(|s| Value::text(s)).collect())
}

fn labels(pairs: &[(&str, &str)]) -> Value {
    Value::Map(
        pairs
            .iter()
            .map(|(k, v)| (Value::text(k), Value::text(v)))
            .collect(),
    )
}

fn delegation(subject: &Key, actions: &[&str], priorities: (i64, i64), issued_at: i64) -> Value {
    Value::map([
        ("v", Value::Int(1)),
        ("type", Value::text("delegation")),
        ("tenant", Value::text(TENANT)),
        ("issued_at", Value::Int(issued_at)),
        (
            "subject",
            Value::map([
                ("alg", Value::Int(subject.pk.alg.cose_id())),
                ("key", Value::Bytes(subject.pk.bytes.clone())),
            ]),
        ),
        (
            "rights",
            Value::map([
                ("actions", texts(actions)),
                (
                    "priorities",
                    Value::Array(vec![Value::Int(priorities.0), Value::Int(priorities.1)]),
                ),
                ("components", texts(&["*"])),
                ("labels", labels(&[])),
                ("not_before", Value::Int(0)),
                ("not_after", Value::Int(i64::MAX)),
            ]),
        ),
    ])
}

fn config(
    priority: i64,
    selector: &[(&str, &str)],
    version: i64,
    values: Value,
    issued_at: i64,
) -> Value {
    Value::map([
        ("v", Value::Int(1)),
        ("type", Value::text("config")),
        ("tenant", Value::text(TENANT)),
        ("issued_at", Value::Int(issued_at)),
        ("priority", Value::Int(priority)),
        ("component", Value::text("app")),
        ("selector", labels(selector)),
        ("version", Value::Int(version)),
        ("values", values),
        ("locks", Value::Array(Vec::new())),
    ])
}

fn deployment(version: i64, artifact: [u8; 32], issued_at: i64) -> Value {
    Value::map([
        ("v", Value::Int(1)),
        ("type", Value::text("deployment")),
        ("tenant", Value::text(TENANT)),
        ("issued_at", Value::Int(issued_at)),
        ("priority", Value::Int(10)),
        ("component", Value::text("app")),
        ("version", Value::Int(version)),
        ("artifact", Value::Bytes(artifact.to_vec())),
    ])
}

fn revocation(target: &Key, issued_at: i64) -> Value {
    Value::map([
        ("v", Value::Int(1)),
        ("type", Value::text("revocation")),
        ("tenant", Value::text(TENANT)),
        ("issued_at", Value::Int(issued_at)),
        ("key_id", Value::Bytes(target.pk.key_id().to_vec())),
    ])
}

struct Docs {
    anchor: PublicKey,
    /// At start, from the cloud: delegations, fleet config v1, deployment, the tie.
    initial: Vec<Vec<u8>>,
    /// Later, from the cloud: fleet config v2.
    config_v2: Vec<u8>,
    /// Later, from the cloud: revocation of the technician.
    revoke_tech: Vec<u8>,
    /// On dev-c's USB stick: the technician's delegation and local change.
    usb: Vec<Vec<u8>>,
}

fn documents() -> Docs {
    let root = key(1);
    let site_a = key(2);
    let site_b = key(3);
    let tech = key(4);
    let fleet = |rate: i64| Value::map([("rate", Value::Int(rate)), ("mode", Value::text("auto"))]);
    Docs {
        anchor: root.pk.clone(),
        initial: vec![
            sign(
                &root,
                &delegation(&site_a, &["config.write", "delegate"], (30, 50), 1),
            ),
            sign(&root, &delegation(&site_b, &["config.write"], (30, 30), 1)),
            sign(&root, &config(10, &[], 1, fleet(5), 2)),
            sign(&root, &deployment(1, ARTIFACT_A, 2)),
            // Same priority, same path, different values: a tie on dev-a and dev-b.
            sign(
                &site_a,
                &config(
                    30,
                    &[("line", "l1")],
                    1,
                    Value::map([("limit", Value::Int(10))]),
                    3,
                ),
            ),
            sign(
                &site_b,
                &config(
                    30,
                    &[("line", "l1")],
                    1,
                    Value::map([("limit", Value::Int(20))]),
                    3,
                ),
            ),
        ],
        config_v2: sign(&root, &config(10, &[], 2, fleet(7), 5)),
        revoke_tech: sign(&root, &revocation(&tech, 9)),
        usb: vec![
            sign(&site_a, &delegation(&tech, &["config.write"], (50, 50), 4)),
            sign(
                &tech,
                &config(
                    50,
                    &[("line", "l2")],
                    1,
                    Value::map([("mode", Value::text("manual"))]),
                    6,
                ),
            ),
        ],
    }
}

// ---------------------------------------------------------------------------------------------
// Device "disk" (survives restarts), executor and observations

#[derive(Default)]
struct Disk {
    state: Option<Vec<u8>>,
    installed: BTreeMap<String, [u8; 32]>,
    applied: BTreeMap<String, [u8; 32]>,
    configs: BTreeMap<String, Vec<u8>>,
}

#[derive(Clone)]
struct DiskStore(Rc<RefCell<Disk>>);

impl StateStore for DiskStore {
    fn load(&self) -> Result<Option<Vec<u8>>, StoreError> {
        Ok(self.0.borrow().state.clone())
    }
    fn save(&mut self, state: &[u8]) -> Result<(), StoreError> {
        self.0.borrow_mut().state = Some(state.to_vec());
        Ok(())
    }
}

struct DiskExecutor(Rc<RefCell<Disk>>);

impl Executor for DiskExecutor {
    fn execute(&mut self, instruction: &Instruction) -> Result<(), ExecError> {
        let mut disk = self.0.borrow_mut();
        match instruction {
            Instruction::Install {
                component,
                artifact,
            } => {
                disk.installed.insert(component.clone(), *artifact);
            }
            Instruction::ApplyConfig {
                component,
                hash,
                config,
            } => {
                if sha256(config) != *hash {
                    return Err(ExecError("config hash mismatch".into()));
                }
                disk.applied.insert(component.clone(), *hash);
                disk.configs.insert(component.clone(), config.clone());
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Final {
    digests: BTreeSet<Digest>,
    installed: BTreeMap<String, [u8; 32]>,
    applied: BTreeMap<String, [u8; 32]>,
    conflicts: BTreeSet<[u8; 32]>,
    withheld: Vec<String>,
}

#[derive(Default, Debug, PartialEq, Eq)]
struct NodeLog {
    /// (time floor, version per slot) after every decision round, across restarts.
    history: Vec<(u64, BTreeMap<Slot, u64>)>,
    accepted_ever: BTreeSet<Digest>,
    pending: BTreeSet<Digest>,
    last: Final,
}

type Logs = Rc<RefCell<BTreeMap<String, NodeLog>>>;

struct LogObserver {
    name: String,
    logs: Logs,
}

impl<S, E> Observer<S, E> for LogObserver {
    fn observe(&mut self, sync: &Sync, decider: Option<&Decider<S, E>>, outcome: Option<&Outcome>) {
        let mut logs = self.logs.borrow_mut();
        let log = logs.entry(self.name.clone()).or_default();
        log.last.digests = sync.digests();
        log.pending = sync.pending();
        if let (Some(decider), Some(outcome)) = (decider, outcome) {
            let state = decider.state();
            log.history.push((
                state.time_floor,
                state
                    .marks
                    .iter()
                    .map(|(s, m)| (s.clone(), m.version))
                    .collect(),
            ));
            log.accepted_ever
                .extend(outcome.decisions.accepted.iter().copied());
            log.last.installed = decider.facts().installed.clone();
            log.last.applied = decider.facts().applied_config.clone();
            log.last.conflicts = outcome.decisions.conflicts.iter().map(|c| c.id).collect();
            log.last.withheld.clone_from(&outcome.decisions.withheld);
        }
    }
}

fn node_labels(name: &str) -> Vec<(&'static str, &'static str)> {
    match name {
        "dev-a" | "dev-b" => vec![("site", "s1"), ("line", "l1")],
        "dev-c" => vec![("site", "s1"), ("line", "l2")],
        "gateway" => vec![("role", "gateway")],
        _ => Vec::new(),
    }
}

fn neighbors(name: &str) -> Vec<String> {
    let list: &[&str] = match name {
        "cloud" | "dev-a" | "dev-c" => &["gateway"],
        "gateway" => &["cloud", "dev-a", "dev-c", "relay"],
        "relay" => &["gateway", "dev-b"],
        "dev-b" => &["relay"],
        _ => &[],
    };
    list.iter().map(ToString::to_string).collect()
}

fn facts_for(name: &str, disk: &Disk) -> DeviceFacts {
    DeviceFacts {
        tenant: TENANT.into(),
        labels: node_labels(name)
            .into_iter()
            .map(|(k, v)| (k.into(), v.into()))
            .collect(),
        trusted_time: 0,
        installed: disk.installed.clone(),
        applied_config: disk.applied.clone(),
    }
}

// ---------------------------------------------------------------------------------------------
// One simulated run

struct Run {
    logs: BTreeMap<String, NodeLog>,
    tampered: BTreeSet<Digest>,
    configs: BTreeMap<String, BTreeMap<String, Vec<u8>>>,
}

fn simulate(seed: u64) -> Run {
    let mut rng = Rng(seed);
    let docs = Rc::new(documents());
    let logs: Logs = Rc::default();
    let disks: Rc<BTreeMap<String, Rc<RefCell<Disk>>>> = Rc::new(
        HONEST
            .iter()
            .map(|n| ((*n).to_string(), Rc::default()))
            .collect(),
    );
    let tampered: Rc<RefCell<BTreeSet<Digest>>> = Rc::default();

    // When things happen (all from the seed).
    let config_v2_at = rng.secs(5, 60);
    let revoke_at = rng.secs(20, 100);
    let usb_at = rng.secs(1, 80);
    let partition_from = rng.secs(0, 40);
    let partition_to = partition_from + rng.secs(5, 60);
    let restart_at = rng.secs(10, 120);
    let max_latency = Duration::from_millis(20 + rng.below(480));
    let fail_rate = rng.below(8) as f64 / 100.0;

    let mut sim = turmoil::Builder::new()
        .simulation_duration(END_AT + Duration::from_secs(60))
        .tick_duration(Duration::from_millis(10))
        .min_message_latency(Duration::from_millis(1))
        .max_message_latency(max_latency)
        .fail_rate(fail_rate)
        .repair_rate(0.3)
        .enable_random_order()
        .rng_seed(seed)
        .build();

    for name in HONEST {
        let docs = docs.clone();
        let logs = logs.clone();
        let disk = disks[name].clone();
        sim.host(name, move || {
            let docs = docs.clone();
            let logs = logs.clone();
            let disk = disk.clone();
            async move {
                let (all, own) = sync_keys(TENANT, name)?;
                let transport = SimTransport::bind(neighbors(name), vec![all, own]).await?;
                let facts = facts_for(name, &disk.borrow());
                let decider = Decider::new(
                    vec![TrustAnchor {
                        tenant: TENANT.into(),
                        key: docs.anchor.clone(),
                    }],
                    facts,
                    DiskStore(disk.clone()),
                    DiskExecutor(disk.clone()),
                )?;
                let config = NodeConfig {
                    name: name.to_string(),
                    tenant: TENANT.to_string(),
                    summary_interval: Duration::from_secs(2),
                    limits: Limits::DEFAULT,
                };
                let node = Node::new(config, transport, Some(decider));
                // Local sources: the cloud issues documents, dev-c gets a USB stick.
                let schedule: Vec<(Duration, Vec<u8>)> = match name {
                    "cloud" => docs
                        .initial
                        .iter()
                        .map(|d| (Duration::ZERO, d.clone()))
                        .chain([
                            (config_v2_at, docs.config_v2.clone()),
                            (revoke_at, docs.revoke_tech.clone()),
                        ])
                        .collect(),
                    "dev-c" => docs.usb.iter().map(|d| (usb_at, d.clone())).collect(),
                    _ => Vec::new(),
                };
                let (tx, rx) = mpsc::channel(16);
                let feed = async move {
                    let mut schedule = schedule;
                    schedule.sort_by_key(|(t, _)| *t);
                    for (at, doc) in schedule {
                        if let Some(wait) = at.checked_sub(turmoil::elapsed()) {
                            tokio::time::sleep(wait).await;
                        }
                        if tx.send(doc).await.is_err() {
                            break;
                        }
                    }
                };
                let mut observer = LogObserver {
                    name: name.to_string(),
                    logs,
                };
                let (result, ()) = tokio::join!(node.run(rx, &mut observer), feed);
                result?;
                Ok(())
            }
        });
    }

    // The malicious relay: forwards frames between its neighbours, but drops, tampers with
    // and replays documents.
    {
        let tampered = tampered.clone();
        let relay_rng = Rc::new(RefCell::new(Rng(seed ^ 0x005e_ed0f_ba5e)));
        sim.host("relay", move || {
            let tampered = tampered.clone();
            let rng = relay_rng.clone();
            async move {
                let socket = UdpSocket::bind(("0.0.0.0", PORT)).await?;
                let mut seen: Vec<Vec<u8>> = Vec::new();
                let mut buf = vec![0u8; 70_000];
                let mut replay = tokio::time::interval(Duration::from_secs(5));
                loop {
                    tokio::select! {
                        biased;
                        received = socket.recv_from(&mut buf) => {
                            let (len, from) = received?;
                            let Some((key, payload)) = decode_frame(&buf[..len]) else { continue };
                            let sender = turmoil::reverse_lookup(from.ip()).unwrap_or_default();
                            let payload = {
                            let mut rng = rng.borrow_mut();
                            match Message::decode(&payload, &Limits::DEFAULT) {
                                Some(Message::Document { bytes }) => {
                                    seen.push(bytes.clone());
                                    if rng.chance(25) {
                                        continue; // drop
                                    }
                                    if rng.chance(33) {
                                        let mut bad = bytes.clone();
                                        let at = rng.below(bad.len() as u64) as usize;
                                        bad[at] ^= 0x01;
                                        tampered.borrow_mut().insert(sha256(&bad));
                                        Message::Document { bytes: bad }.encode()
                                    } else {
                                        payload
                                    }
                                }
                                Some(_) if rng.chance(10) => continue,
                                _ => payload,
                            }
                            };
                            let frame = encode_frame(&key, &payload)?;
                            for n in neighbors("relay").into_iter().filter(|n| *n != sender) {
                                let _ = socket.send_to(&frame, (n.as_str(), PORT)).await;
                            }
                        }
                        _ = replay.tick() => {
                            if seen.is_empty() {
                                continue;
                            }
                            let pick = rng.borrow_mut().below(seen.len() as u64) as usize;
                            let old = seen[pick].clone();
                            let (all, _) = sync_keys(TENANT, "relay")?;
                            let frame = encode_frame(&all, &Message::Document { bytes: old }.encode())?;
                            for n in neighbors("relay") {
                                let _ = socket.send_to(&frame, (n.as_str(), PORT)).await;
                            }
                        }
                    }
                }
            }
        });
    }

    // The client defines the run length.
    sim.client("clock", async {
        tokio::time::sleep(END_AT).await;
        Ok(())
    });

    let mut partitioned = false;
    let mut restarted = false;
    let mut healed = false;
    loop {
        let elapsed = sim.elapsed();
        if !partitioned && elapsed >= partition_from {
            sim.partition("gateway", "relay");
            partitioned = true;
        }
        if partitioned && elapsed >= partition_to.min(HEAL_AT) {
            sim.repair("gateway", "relay");
        }
        if !restarted && elapsed >= restart_at {
            sim.bounce("dev-a");
            restarted = true;
        }
        if !healed && elapsed >= HEAL_AT {
            sim.set_fail_rate(0.0);
            for a in HONEST.iter().chain(["relay"].iter()) {
                for b in neighbors(a) {
                    sim.repair(*a, b.as_str());
                }
            }
            healed = true;
        }
        match sim.step() {
            Ok(true) => break,
            Ok(false) => {}
            Err(e) => panic!("seed {seed}: simulation error: {e}"),
        }
    }

    let logs = std::mem::take(&mut *logs.borrow_mut());
    let configs = disks
        .iter()
        .map(|(n, d)| (n.clone(), d.borrow().configs.clone()))
        .collect();
    let tampered = tampered.borrow().clone();
    Run {
        logs,
        tampered,
        configs,
    }
}

// ---------------------------------------------------------------------------------------------
// Checks

/// Fresh evaluation of `documents` for `name`: what the device should end up with.
fn oracle(name: &str, documents: &[&[u8]], anchor: &PublicKey) -> Final {
    let disk = Rc::new(RefCell::new(Disk::default()));
    let mut decider = Decider::new(
        vec![TrustAnchor {
            tenant: TENANT.into(),
            key: anchor.clone(),
        }],
        facts_for(name, &Disk::default()),
        DiskStore(disk.clone()),
        DiskExecutor(disk),
    )
    .unwrap();
    // Twice: the second round sees the effects of the first (installed, applied).
    decider.decide(documents).unwrap();
    let outcome = decider.decide(documents).unwrap();
    assert!(
        outcome.decisions.actions.is_empty(),
        "oracle does not settle"
    );
    Final {
        digests: BTreeSet::new(),
        installed: decider.facts().installed.clone(),
        applied: decider.facts().applied_config.clone(),
        conflicts: outcome.decisions.conflicts.iter().map(|c| c.id).collect(),
        withheld: outcome.decisions.withheld,
    }
}

fn decoded(config: &[u8]) -> Value {
    cbor::decode(config, &cbor::Limits::DEFAULT).unwrap()
}

/// @relation(AGT-001, AGT-002, AGT-003, AGT-005, AGT-006, scope=function)
fn check(seed: u64, run: &Run) {
    let docs = documents();
    let ctx = |what: &str| format!("seed {seed}: {what} (replay with WEFT_SIM_SEED={seed})");

    let all_docs: Vec<Vec<u8>> = docs
        .initial
        .iter()
        .chain([&docs.config_v2, &docs.revoke_tech])
        .chain(docs.usb.iter())
        .cloned()
        .collect();
    let names = [
        "del-site-a",
        "del-site-b",
        "cfg-v1",
        "deploy",
        "tie-a",
        "tie-b",
        "cfg-v2",
        "revoke",
        "del-tech",
        "tech-cfg",
    ];
    let label = |d: &Digest| {
        all_docs
            .iter()
            .position(|x| sha256(x) == *d)
            .map_or("tampered", |i| names[i])
    };
    let labels = |set: &BTreeSet<Digest>| set.iter().map(label).collect::<Vec<_>>();

    // 1. Convergence.
    let expected: BTreeSet<Digest> = all_docs.iter().map(|d| sha256(d)).collect();
    for name in HONEST {
        let have = &run.logs[name].last.digests;
        assert!(
            have == &expected,
            "{}",
            ctx(&format!(
                "{name} did not converge: missing {:?}, extra {:?}, pending {:?}",
                labels(&expected.difference(have).copied().collect()),
                labels(&have.difference(&expected).copied().collect()),
                labels(&run.logs[name].pending),
            ))
        );
    }

    // 4. Safety.
    for name in HONEST {
        let log = &run.logs[name];
        assert!(
            log.accepted_ever.is_disjoint(&run.tampered),
            "{}",
            ctx(&format!("{name} accepted a tampered document"))
        );
        for pair in log.history.windows(2) {
            let ((t0, m0), (t1, m1)) = (&pair[0], &pair[1]);
            assert!(
                t1 >= t0,
                "{}",
                ctx(&format!("{name}: time floor went back"))
            );
            for (slot, v0) in m0 {
                assert!(
                    m1.get(slot).is_some_and(|v1| v1 >= v0),
                    "{}",
                    ctx(&format!("{name}: version mark went back or vanished"))
                );
            }
        }
    }

    // 3. Oracle, and 2. agreement between dev-a and dev-b.
    let refs: Vec<&[u8]> = all_docs.iter().map(Vec::as_slice).collect();
    for name in DEVICES {
        let mut actual = run.logs[name].last.clone();
        actual.digests = BTreeSet::new();
        assert_eq!(
            actual,
            oracle(name, &refs, &docs.anchor),
            "{}",
            ctx(&format!("{name} differs from a fresh evaluation"))
        );
        assert!(actual.withheld.is_empty(), "{}", ctx(name));
    }
    let (a, b) = (&run.logs["dev-a"].last, &run.logs["dev-b"].last);
    assert_eq!(
        (&a.installed, &a.applied, &a.conflicts),
        (&b.installed, &b.applied, &b.conflicts),
        "{}",
        ctx("dev-a and dev-b disagree")
    );

    // 5. Expected outcome.
    let fleet_v2 = Value::map([("rate", Value::Int(7)), ("mode", Value::text("auto"))]);
    for name in DEVICES {
        assert_eq!(
            run.logs[name].last.installed.get("app"),
            Some(&ARTIFACT_A),
            "{}",
            ctx(name)
        );
        assert_eq!(
            decoded(&run.configs[name]["app"]),
            fleet_v2,
            "{}",
            ctx(&format!("{name}: config"))
        );
    }
    assert_eq!(run.logs["dev-a"].last.conflicts.len(), 1, "{}", ctx("tie"));
    assert!(
        run.logs["dev-c"].last.conflicts.is_empty(),
        "{}",
        ctx("dev-c")
    );
}

fn seeds() -> Vec<u64> {
    if let Ok(seed) = std::env::var("WEFT_SIM_SEED") {
        return vec![seed.parse().expect("WEFT_SIM_SEED is a number")];
    }
    let count: u64 = std::env::var("WEFT_SIM_SEEDS")
        .ok()
        .and_then(|n| n.parse().ok())
        .unwrap_or(16);
    (1..=count).collect()
}

/// @relation(AGT-001, AGT-003, AGT-005, AGT-006, scope=function)
#[test]
fn documents_converge_and_devices_agree_under_faults() {
    for seed in seeds() {
        let run = simulate(seed);
        check(seed, &run);
    }
}

/// @relation(AGT-007, scope=function)
#[test]
fn same_seed_same_run() {
    let a = simulate(7);
    let b = simulate(7);
    assert_eq!(a.logs, b.logs);
    assert_eq!(a.tampered, b.tampered);
}
