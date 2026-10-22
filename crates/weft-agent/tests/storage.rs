// SPDX-FileCopyrightText: 2026 The weft authors
// SPDX-License-Identifier: MIT

//! Document directory, inbox, executed results and config paths.
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::assert_is_empty,
    missing_docs
)]

use std::fs;
use std::path::{Path, PathBuf};

use weft_agent::executor::config_path;
use weft_agent::hex;
use weft_agent::storage::{DocumentDir, Executed, scan_inbox};
use weft_decider::StdFs;
use weft_verifier::crypto::sha256;

fn dir(name: &str) -> PathBuf {
    let d = Path::new(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}

/// @relation(AGT-012, scope=function)
#[test]
fn documents_survive_a_reopen_and_damaged_files_are_ignored() {
    let d = dir("docdir");
    let (mut docs, loaded) = DocumentDir::open(StdFs, &d, 1024).unwrap();
    assert!(loaded.is_empty());
    docs.put(b"one").unwrap();
    docs.put(b"two").unwrap();
    docs.put(b"one").unwrap();
    // A file whose contents do not match its name, and a leftover temporary file.
    fs::write(d.join(hex(&sha256(b"three"))), b"tampered").unwrap();
    fs::write(d.join("x.tmp"), b"half").unwrap();
    let (mut docs, mut loaded) = DocumentDir::open(StdFs, &d, 1024).unwrap();
    loaded.sort();
    assert_eq!(loaded, vec![b"one".to_vec(), b"two".to_vec()]);
    docs.remove(&sha256(b"one")).unwrap();
    let (_, loaded) = DocumentDir::open(StdFs, &d, 1024).unwrap();
    assert_eq!(loaded, vec![b"two".to_vec()]);
}

/// @relation(AGT-011, scope=function)
#[test]
fn inbox_scan_takes_regular_visible_files_within_the_limit() {
    let d = dir("inbox");
    fs::write(d.join("a.cose"), b"aa").unwrap();
    fs::write(d.join(".hidden"), b"bb").unwrap();
    fs::write(d.join("partial.TMP"), b"cc").unwrap();
    fs::write(d.join("big.cose"), vec![0; 2048]).unwrap();
    fs::create_dir(d.join("sub")).unwrap();
    assert_eq!(scan_inbox(&StdFs, &d, 1024).unwrap(), vec![b"aa".to_vec()]);
    assert!(
        scan_inbox(&StdFs, &d.join("missing"), 1024)
            .unwrap()
            .is_empty()
    );
}

/// @relation(AGT-016, scope=function)
#[test]
fn executed_results_round_trip() {
    let mut e = Executed::default();
    e.installed.insert("app".into(), [1; 32]);
    e.applied.insert("app/pump".into(), [2; 32]);
    assert_eq!(Executed::decode(&e.encode()), Some(e));
    assert_eq!(Executed::decode(b"junk"), None);
}

/// @relation(AGT-014, scope=function)
#[test]
fn component_names_cannot_leave_the_config_directory() {
    let base = Path::new("/etc/weft/config");
    assert_eq!(config_path(base, "app").unwrap(), base.join("app.json"));
    assert_eq!(
        config_path(base, "app/pump").unwrap(),
        base.join("app/pump.json")
    );
    for bad in [
        "../etc/passwd",
        "app/../../x",
        ".",
        "app//x",
        "a b",
        "app/",
        "/abs",
    ] {
        assert!(config_path(base, bad).is_err(), "{bad}");
    }
}
