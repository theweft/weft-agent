// SPDX-FileCopyrightText: 2026 The weft authors
// SPDX-License-Identifier: MIT

//! The `weft-agent` binary, L1 end to end: inbox (USB stick), decisions, config files, install
//! hook, report, restart. Hooks use `sh`, so this runs on Unix.
#![cfg(unix)]
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::assert_is_empty,
    clippy::too_many_lines,
    missing_docs
)]

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use common::{TENANT, config, delegation, deployment, hex, key, public_file, sign};
use serde_json::Value as Json;
use weft_verifier::cbor::Value;
use weft_verifier::crypto::sha256;

const ARTIFACT: [u8; 32] = [0xa1; 32];

struct Device {
    dir: PathBuf,
}

impl Device {
    fn new(name: &str) -> Device {
        let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(name);
        let _ = fs::remove_dir_all(&dir);
        for sub in ["inbox", "usb2"] {
            fs::create_dir_all(dir.join(sub)).unwrap();
        }
        fs::write(dir.join("root.pub"), public_file(&key(1))).unwrap();
        Device { dir }
    }

    fn drop_in(&self, inbox: &str, name: &str, bytes: &[u8]) {
        fs::write(self.dir.join(inbox).join(name), bytes).unwrap();
    }

    fn run(&self, inbox: &str, install_hook: &str) -> Json {
        let out = Command::new(env!("CARGO_BIN_EXE_weft-agent"))
            .current_dir(&self.dir)
            .args([
                "run", "--once", "--tenant", TENANT, "--anchor", "root.pub", "--label", "line=l1",
            ])
            .args([
                "--state-dir",
                "state",
                "--inbox",
                inbox,
                "--config-dir",
                "config",
            ])
            .args(["--on-install", install_hook])
            .args([
                "--on-config",
                r#"echo "$WEFT_COMPONENT $WEFT_CONFIG_HASH" >> configs.log"#,
            ])
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        serde_json::from_str(
            &fs::read_to_string(self.dir.join("state/outbox/report.json")).unwrap(),
        )
        .unwrap()
    }

    fn config(&self) -> Json {
        serde_json::from_str(&fs::read_to_string(self.dir.join("config/app.json")).unwrap())
            .unwrap()
    }

    fn lines(&self, file: &str) -> Vec<String> {
        fs::read_to_string(self.dir.join(file))
            .unwrap_or_default()
            .lines()
            .map(String::from)
            .collect()
    }
}

const INSTALL: &str = r#"echo "$WEFT_COMPONENT $WEFT_ARTIFACT" >> installs.log"#;

fn count(report: &Json, field: &str) -> usize {
    report[field].as_array().unwrap().len()
}

/// @relation(AGT-011, AGT-012, AGT-013, AGT-014, AGT-015, AGT-016, scope=function)
#[test]
fn usb_stick_to_applied_config_and_installed_artifact() {
    let d = Device::new("offline-flow");
    let (root, site_a, site_b) = (key(1), key(2), key(3));
    d.drop_in(
        "inbox",
        "del-a.cose",
        &sign(&root, &delegation(&site_a, (30, 30))),
    );
    d.drop_in(
        "inbox",
        "fleet-v1.cose",
        &sign(
            &root,
            &config(10, &[], 1, Value::map([("rate", Value::Int(5))]), 2),
        ),
    );
    d.drop_in(
        "inbox",
        "deploy.cose",
        &sign(&root, &deployment(1, ARTIFACT)),
    );
    d.drop_in(
        "inbox",
        "site.cose",
        &sign(
            &site_a,
            &config(
                30,
                &[("line", "l1")],
                1,
                Value::map([("limit", Value::Int(10))]),
                3,
            ),
        ),
    );

    // First round: config written, install hook called, reported.
    let r = d.run("inbox", INSTALL);
    assert_eq!(count(&r, "executed"), 2, "{r}");
    assert_eq!(d.config(), serde_json::json!({"limit": 10, "rate": 5}));
    assert_eq!(
        d.lines("installs.log"),
        vec![format!("app {}", hex(&ARTIFACT))]
    );
    assert_eq!(d.lines("configs.log").len(), 1);
    assert_eq!(r["installed"]["app"], hex(&ARTIFACT));

    // Same inbox again: nothing to do.
    let r = d.run("inbox", INSTALL);
    assert_eq!(count(&r, "executed"), 0, "{r}");
    assert_eq!(d.lines("installs.log").len(), 1);

    // USB stick removed; a second stick brings only fleet config v2. The stored documents keep
    // everything else in place: no reinstall, nothing withheld, only the config changes.
    d.drop_in(
        "usb2",
        "fleet-v2.cose",
        &sign(
            &root,
            &config(10, &[], 2, Value::map([("rate", Value::Int(7))]), 5),
        ),
    );
    let r = d.run("usb2", INSTALL);
    assert_eq!(count(&r, "withheld"), 0, "{r}");
    assert_eq!(d.config(), serde_json::json!({"limit": 10, "rate": 7}));
    assert_eq!(d.lines("installs.log").len(), 1);

    // A second site key sets the same field at the same priority: a tie, neither applies.
    d.drop_in(
        "usb2",
        "del-b.cose",
        &sign(&root, &delegation(&site_b, (30, 30))),
    );
    d.drop_in(
        "usb2",
        "tie.cose",
        &sign(
            &site_b,
            &config(
                30,
                &[("line", "l1")],
                1,
                Value::map([("limit", Value::Int(20))]),
                6,
            ),
        ),
    );
    let r = d.run("usb2", INSTALL);
    assert_eq!(count(&r, "conflicts"), 1, "{r}");
    assert_eq!(r["conflicts"][0]["kind"], "Tie");
    assert_eq!(d.config(), serde_json::json!({"rate": 7}));

    // A forged document is rejected and never stored.
    let mut forged = sign(
        &root,
        &config(10, &[], 3, Value::map([("rate", Value::Int(99))]), 7),
    );
    let last = forged.len() - 1;
    forged[last] ^= 1;
    d.drop_in("usb2", "forged.cose", &forged);
    let r = d.run("usb2", INSTALL);
    assert!(
        r["rejected"]
            .as_array()
            .unwrap()
            .iter()
            .any(|x| x["reason"] == "BadSignature"),
        "{r}"
    );
    assert!(
        !d.dir
            .join("state/documents")
            .join(hex(&sha256(&forged)))
            .exists()
    );
    assert_eq!(d.config(), serde_json::json!({"rate": 7}));
}

/// @relation(AGT-015, AGT-016, scope=function)
#[test]
fn failed_installs_are_reported_and_retried_not_recorded() {
    let d = Device::new("offline-failing-install");
    let root = key(1);
    d.drop_in(
        "inbox",
        "deploy.cose",
        &sign(&root, &deployment(1, ARTIFACT)),
    );
    let r = d.run("inbox", "exit 3");
    assert_eq!(count(&r, "failed"), 1, "{r}");
    assert!(r["installed"].as_object().unwrap().is_empty());
    // The next round tries again, and this time the hook succeeds.
    let r = d.run("inbox", INSTALL);
    assert_eq!(count(&r, "executed"), 1, "{r}");
    assert_eq!(d.lines("installs.log").len(), 1);
}
