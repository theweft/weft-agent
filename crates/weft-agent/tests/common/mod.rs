// SPDX-FileCopyrightText: 2026 The weft authors
// SPDX-License-Identifier: MIT

//! Test helpers: keys and signed documents (what weft-cli does on an operator machine).
#![allow(clippy::unwrap_used, dead_code, missing_docs)]

use ed25519_dalek::{Signer, SigningKey};
use weft_verifier::cbor::{self, Value};
use weft_verifier::cose;
use weft_verifier::crypto::{Algorithm, PublicKey};

pub const TENANT: &str = "acme";

pub struct Key {
    pub sk: SigningKey,
    pub pk: PublicKey,
}

pub fn key(seed: u8) -> Key {
    let sk = SigningKey::from_bytes(&[seed; 32]);
    let pk = PublicKey {
        alg: Algorithm::Ed25519,
        bytes: sk.verifying_key().to_bytes().to_vec(),
    };
    Key { sk, pk }
}

pub use weft_agent::hex;

/// The public key file format of `weft key new`.
pub fn public_file(k: &Key) -> String {
    format!(
        "weft-public-key-v1\nalg: ed25519\nkey: {}\nkey-id: {}\n",
        hex(&k.pk.bytes),
        hex(&k.pk.key_id())
    )
}

pub fn sign(k: &Key, payload: &Value) -> Vec<u8> {
    let payload = cbor::encode(payload).unwrap();
    let protected = cose::protected_header(k.pk.alg.cose_id(), &k.pk.key_id()).unwrap();
    let tbs = cose::sig_structure(&protected, &payload).unwrap();
    cose::encode_sign1(&protected, &payload, &k.sk.sign(&tbs).to_bytes()).unwrap()
}

fn header(kind: &str, issued_at: i64) -> Vec<(Value, Value)> {
    vec![
        (Value::text("v"), Value::Int(1)),
        (Value::text("type"), Value::text(kind)),
        (Value::text("tenant"), Value::text(TENANT)),
        (Value::text("issued_at"), Value::Int(issued_at)),
    ]
}

pub fn delegation(subject: &Key, priorities: (i64, i64)) -> Value {
    let mut f = header("delegation", 1);
    f.push((
        Value::text("subject"),
        Value::map([
            ("alg", Value::Int(-8)),
            ("key", Value::Bytes(subject.pk.bytes.clone())),
        ]),
    ));
    f.push((
        Value::text("rights"),
        Value::map([
            ("actions", Value::Array(vec![Value::text("config.write")])),
            (
                "priorities",
                Value::Array(vec![Value::Int(priorities.0), Value::Int(priorities.1)]),
            ),
            ("components", Value::Array(vec![Value::text("*")])),
            ("not_before", Value::Int(0)),
            ("not_after", Value::Int(i64::MAX)),
        ]),
    ));
    Value::Map(f)
}

pub fn config(
    priority: i64,
    selector: &[(&str, &str)],
    version: i64,
    values: Value,
    issued_at: i64,
) -> Value {
    let mut f = header("config", issued_at);
    f.push((Value::text("priority"), Value::Int(priority)));
    f.push((Value::text("component"), Value::text("app")));
    f.push((
        Value::text("selector"),
        Value::Map(
            selector
                .iter()
                .map(|(k, v)| (Value::text(k), Value::text(v)))
                .collect(),
        ),
    ));
    f.push((Value::text("version"), Value::Int(version)));
    f.push((Value::text("values"), values));
    Value::Map(f)
}

pub fn deployment(version: i64, artifact: [u8; 32]) -> Value {
    let mut f = header("deployment", 2);
    f.push((Value::text("priority"), Value::Int(10)));
    f.push((Value::text("component"), Value::text("app")));
    f.push((Value::text("version"), Value::Int(version)));
    f.push((Value::text("artifact"), Value::Bytes(artifact.to_vec())));
    Value::Map(f)
}
