// SPDX-FileCopyrightText: 2026 The weft authors
// SPDX-License-Identifier: MIT

//! Decider and executor as separate processes over a Unix socket.
#![cfg(unix)]
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    clippy::panic,
    clippy::needless_pass_by_value,
    missing_docs
)]

mod common;

use std::fs;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

use common::{TENANT, config, deployment, hex, key, public_file, sign};
use serde_json::Value as Json;
use weft_agent::ipc::encode_request;
use weft_verifier::Instruction;
use weft_verifier::cbor::{self, Limits, Value};

const ARTIFACT: [u8; 32] = [0xb2; 32];
const BIN: &str = env!("CARGO_BIN_EXE_weft-agent");

struct Executor(Child);

impl Drop for Executor {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn start_executor(dir: &Path) -> Executor {
    let socket = dir.join("run/executor.sock");
    let _ = fs::remove_file(&socket);
    let child = Command::new(BIN)
        .current_dir(dir)
        .args([
            "executor",
            "--socket",
            "run/executor.sock",
            "--config-dir",
            "config",
        ])
        .args([
            "--on-install",
            r#"echo "$WEFT_COMPONENT $WEFT_ARTIFACT" >> installs.log"#,
        ])
        .stdout(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while UnixStream::connect(&socket).is_err() {
        assert!(Instant::now() < deadline, "executor did not start");
        std::thread::sleep(Duration::from_millis(20));
    }
    Executor(child)
}

fn setup(name: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = fs::remove_dir_all(&dir);
    for sub in ["inbox", "run"] {
        fs::create_dir_all(dir.join(sub)).unwrap();
    }
    fs::write(dir.join("root.pub"), public_file(&key(1))).unwrap();
    dir
}

fn decide(dir: &Path) -> Json {
    let out = Command::new(BIN)
        .current_dir(dir)
        .args([
            "decider", "--once", "--tenant", TENANT, "--anchor", "root.pub",
        ])
        .args(["--state-dir", "state", "--inbox", "inbox"])
        .args(["--executor-socket", "run/executor.sock"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_str(&fs::read_to_string(dir.join("state/outbox/report.json")).unwrap())
        .unwrap()
}

fn count(report: &Json, field: &str) -> usize {
    report[field].as_array().unwrap().len()
}

/// @relation(AGT-017, AGT-018, AGT-019, scope=function)
#[test]
fn decider_and_executor_in_separate_processes() {
    let dir = setup("separated-flow");
    let root = key(1);
    fs::write(
        dir.join("inbox/cfg1.cose"),
        sign(
            &root,
            &config(10, &[], 1, Value::map([("rate", Value::Int(5))]), 2),
        ),
    )
    .unwrap();
    fs::write(
        dir.join("inbox/deploy.cose"),
        sign(&root, &deployment(1, ARTIFACT)),
    )
    .unwrap();

    let executor = start_executor(&dir);
    let r = decide(&dir);
    assert_eq!(count(&r, "executed"), 2, "{r}");
    // Written by the executor: the decider was never told where the config lives.
    let applied: Json =
        serde_json::from_str(&fs::read_to_string(dir.join("config/app.json")).unwrap()).unwrap();
    assert_eq!(applied, serde_json::json!({"rate": 5}));
    assert_eq!(
        fs::read_to_string(dir.join("installs.log")).unwrap().trim(),
        format!("app {}", hex(&ARTIFACT))
    );

    // Executor down: the change is reported as failed and not recorded.
    drop(executor);
    fs::write(
        dir.join("inbox/cfg2.cose"),
        sign(
            &root,
            &config(10, &[], 2, Value::map([("rate", Value::Int(7))]), 3),
        ),
    )
    .unwrap();
    let r = decide(&dir);
    assert_eq!(count(&r, "failed"), 1, "{r}");
    assert_eq!(count(&r, "executed"), 0, "{r}");

    // Back up: retried and applied; nothing installed twice.
    let _executor = start_executor(&dir);
    let r = decide(&dir);
    assert_eq!(count(&r, "executed"), 1, "{r}");
    let applied: Json =
        serde_json::from_str(&fs::read_to_string(dir.join("config/app.json")).unwrap()).unwrap();
    assert_eq!(applied, serde_json::json!({"rate": 7}));
    assert_eq!(
        fs::read_to_string(dir.join("installs.log"))
            .unwrap()
            .lines()
            .count(),
        1
    );
}

/// @relation(AGT-018, scope=function)
#[test]
fn the_decider_cannot_name_commands_or_directories() {
    for flag in [
        &["--on-install", "rm -rf /"][..],
        &["--on-config", "x"][..],
        &["--config-dir", "/etc"][..],
    ] {
        let out = Command::new(BIN)
            .args([
                "decider", "--once", "--tenant", TENANT, "--anchor", "root.pub",
            ])
            .args(flag)
            .output()
            .unwrap();
        assert!(!out.status.success(), "{flag:?} accepted");
    }
}

fn frame(stream: &mut UnixStream, value: &Value) -> Option<Value> {
    let bytes = cbor::encode(value).unwrap();
    stream
        .write_all(&u32::try_from(bytes.len()).unwrap().to_be_bytes())
        .unwrap();
    stream.write_all(&bytes).unwrap();
    let mut len = [0u8; 4];
    stream.read_exact(&mut len).ok()?;
    let mut body = vec![0u8; u32::from_be_bytes(len) as usize];
    stream.read_exact(&mut body).ok()?;
    cbor::decode(&body, &Limits::DEFAULT).ok()
}

fn refused(response: Option<Value>, why: &str) {
    match response.as_ref().and_then(Value::as_array) {
        Some([Value::Int(1), Value::Text(e)]) => assert!(e.contains(why), "{e}"),
        other => panic!("expected refusal ({why}), got {other:?}"),
    }
}

/// @relation(AGT-017, scope=function)
#[test]
fn the_executor_refuses_anything_but_valid_typed_requests() {
    let dir = setup("separated-protocol");
    let _executor = start_executor(&dir);
    let socket = dir.join("run/executor.sock");

    // A configuration that does not match its hash.
    let mut request = encode_request(&Instruction::ApplyConfig {
        component: "app".into(),
        hash: [0; 32],
        config: cbor::encode(&Value::map([("rate", Value::Int(1))])).unwrap(),
    });
    refused(
        frame(&mut UnixStream::connect(&socket).unwrap(), &request),
        "does not match its hash",
    );
    // A component that would leave the config directory.
    let config = cbor::encode(&Value::map([])).unwrap();
    request = encode_request(&Instruction::ApplyConfig {
        component: "../../etc/passwd".into(),
        hash: weft_verifier::crypto::sha256(&config),
        config,
    });
    refused(
        frame(&mut UnixStream::connect(&socket).unwrap(), &request),
        "not a safe path",
    );
    // Unknown request types.
    refused(
        frame(
            &mut UnixStream::connect(&socket).unwrap(),
            &Value::Array(vec![Value::Int(9)]),
        ),
        "unknown request",
    );
    // Garbage and oversized frames close the connection...
    let mut s = UnixStream::connect(&socket).unwrap();
    s.write_all(&[0, 0, 0, 3, 0xff, 0xff, 0xff]).unwrap();
    let mut buf = [0u8; 1];
    assert_eq!(s.read(&mut buf).unwrap_or(0), 0);
    let mut s = UnixStream::connect(&socket).unwrap();
    s.write_all(&u32::MAX.to_be_bytes()).unwrap();
    assert_eq!(s.read(&mut buf).unwrap_or(0), 0);
    // ...and the executor keeps serving.
    assert!(
        !dir.join("config")
            .join("..")
            .join("..")
            .join("etc")
            .join("passwd.json")
            .exists()
    );
    let r = {
        fs::write(
            dir.join("inbox/deploy.cose"),
            sign(&key(1), &deployment(1, ARTIFACT)),
        )
        .unwrap();
        decide(&dir)
    };
    assert_eq!(count(&r, "executed"), 1, "{r}");
}
