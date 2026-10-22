// SPDX-FileCopyrightText: 2026 The weft authors
// SPDX-License-Identifier: MIT

//! Signed documents for the NixOS VM test (`tests/vm/`), deterministic: fixed keys, fixed issue
//! times, Ed25519. This test fails when the committed fixtures differ from what it generates;
//! `WEFT_REGENERATE_FIXTURES=1 cargo test --test vm_fixtures` rewrites them.
#![allow(clippy::unwrap_used, clippy::indexing_slicing, missing_docs)]

mod common;

use std::fs;
use std::path::Path;

use common::{config, delegation, deployment, key, public_file, sign};
use weft_verifier::cbor::Value;

/// The artifact digest the VM's install hook receives.
pub const ARTIFACT: [u8; 32] = [0xa1; 32];

fn fixtures() -> Vec<(&'static str, Vec<u8>)> {
    let (root, site) = (key(1), key(2));
    let mut forged = sign(
        &root,
        &config(10, &[], 3, Value::map([("rate", Value::Int(99))]), 7),
    );
    let last = forged.len() - 1;
    forged[last] ^= 1;
    vec![
        ("root.pub", public_file(&root).into_bytes()),
        (
            "stick1/fleet-v1.cose",
            sign(
                &root,
                &config(10, &[], 1, Value::map([("rate", Value::Int(5))]), 2),
            ),
        ),
        ("stick1/deploy.cose", sign(&root, &deployment(1, ARTIFACT))),
        (
            "stick1/del-site.cose",
            sign(&root, &delegation(&site, (30, 30))),
        ),
        (
            "stick1/site.cose",
            sign(
                &site,
                &config(
                    30,
                    &[("line", "l1")],
                    1,
                    Value::map([("limit", Value::Int(10))]),
                    3,
                ),
            ),
        ),
        (
            "stick2/fleet-v2.cose",
            sign(
                &root,
                &config(10, &[], 2, Value::map([("rate", Value::Int(7))]), 5),
            ),
        ),
        ("stick2/forged.cose", forged),
    ]
}

#[test]
fn vm_fixtures_are_current() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/vm/fixtures");
    let regenerate = std::env::var_os("WEFT_REGENERATE_FIXTURES").is_some();
    for (name, bytes) in fixtures() {
        let path = dir.join(name);
        if regenerate {
            fs::write(&path, &bytes).unwrap();
        } else {
            assert_eq!(
                fs::read(&path).ok().as_deref(),
                Some(bytes.as_slice()),
                "{name} is stale: WEFT_REGENERATE_FIXTURES=1 cargo test --test vm_fixtures"
            );
        }
    }
}
