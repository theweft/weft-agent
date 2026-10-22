// SPDX-FileCopyrightText: 2026 The weft authors
// SPDX-License-Identifier: MIT

//! The state file on the real filesystem.
#![allow(clippy::unwrap_used, clippy::indexing_slicing, missing_docs)]

use std::fs;
use std::path::{Path, PathBuf};

use weft_decider::{FileStore, StateStore};

fn dir(name: &str) -> PathBuf {
    let d = Path::new(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}

/// @relation(AGT-010, scope=function)
#[test]
fn saved_state_loads_back_and_a_missing_file_is_a_first_start() {
    let d = dir("roundtrip");
    let mut store = FileStore::new(d.join("state"));
    assert_eq!(store.load().unwrap(), None);
    store.save(b"one").unwrap();
    store.save(b"two").unwrap();
    assert_eq!(store.load().unwrap(), Some(b"two".to_vec()));
    assert!(!d.join("state.tmp").exists(), "temporary file left behind");
    // A new store on the same file, as after a restart.
    assert_eq!(
        FileStore::new(d.join("state")).load().unwrap(),
        Some(b"two".to_vec())
    );
}

/// @relation(AGT-010, scope=function)
#[test]
fn damaged_files_are_refused_not_loaded() {
    let d = dir("damaged");
    let mut store = FileStore::new(d.join("state"));
    store.save(b"important").unwrap();
    let mut bytes = fs::read(d.join("state")).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    fs::write(d.join("state"), &bytes).unwrap();
    assert!(store.load().is_err());
    fs::write(d.join("state"), b"short").unwrap();
    assert!(store.load().is_err());
}

/// @relation(AGT-010, scope=function)
#[test]
fn a_leftover_temporary_file_does_not_matter() {
    let d = dir("leftover");
    let mut store = FileStore::new(d.join("state"));
    store.save(b"good").unwrap();
    // A crash between writing the temporary file and the rename leaves it behind.
    fs::write(d.join("state.tmp"), b"half-written").unwrap();
    assert_eq!(store.load().unwrap(), Some(b"good".to_vec()));
    store.save(b"newer").unwrap();
    assert_eq!(store.load().unwrap(), Some(b"newer".to_vec()));
}
