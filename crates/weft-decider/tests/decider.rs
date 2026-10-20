// SPDX-FileCopyrightText: 2026 The weft authors
// SPDX-License-Identifier: MIT

//! The decider persists before it acts, and refuses corrupt state.
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::assert_is_empty,
    missing_docs
)]

use std::cell::RefCell;
use std::rc::Rc;

use ed25519_dalek::{Signer, SigningKey};
use weft_decider::{Decider, DeciderError, ExecError, Executor, StateStore, StoreError};
use weft_verifier::cbor::{self, Value};
use weft_verifier::crypto::{Algorithm, PublicKey, sha256};
use weft_verifier::{DeviceFacts, Instruction, TrustAnchor, cose};

#[derive(Default)]
struct Disk {
    state: Option<Vec<u8>>,
    fail: bool,
    /// Whether the state was already saved when the executor ran.
    saved_before_execute: Vec<bool>,
}

struct Store(Rc<RefCell<Disk>>);
impl StateStore for Store {
    fn load(&self) -> Result<Option<Vec<u8>>, StoreError> {
        Ok(self.0.borrow().state.clone())
    }
    fn save(&mut self, state: &[u8]) -> Result<(), StoreError> {
        let mut disk = self.0.borrow_mut();
        if disk.fail {
            return Err(StoreError("disk full".into()));
        }
        disk.state = Some(state.to_vec());
        Ok(())
    }
}

struct Exec(Rc<RefCell<Disk>>);
impl Executor for Exec {
    fn execute(&mut self, _: &Instruction) -> Result<(), ExecError> {
        let mut disk = self.0.borrow_mut();
        let saved = disk.state.is_some();
        disk.saved_before_execute.push(saved);
        Ok(())
    }
}

fn root() -> (SigningKey, PublicKey) {
    let sk = SigningKey::from_bytes(&[1; 32]);
    let pk = PublicKey {
        alg: Algorithm::Ed25519,
        bytes: sk.verifying_key().to_bytes().to_vec(),
    };
    (sk, pk)
}

fn signed_config() -> Vec<u8> {
    let (sk, pk) = root();
    let payload = cbor::encode(&Value::map([
        ("v", Value::Int(1)),
        ("type", Value::text("config")),
        ("tenant", Value::text("acme")),
        ("issued_at", Value::Int(1)),
        ("priority", Value::Int(10)),
        ("component", Value::text("app")),
        ("selector", Value::Map(Vec::new())),
        ("version", Value::Int(1)),
        ("values", Value::map([("rate", Value::Int(5))])),
        ("locks", Value::Array(Vec::new())),
    ]))
    .unwrap();
    let protected = cose::protected_header(pk.alg.cose_id(), &pk.key_id()).unwrap();
    let tbs = cose::sig_structure(&protected, &payload).unwrap();
    cose::encode_sign1(&protected, &payload, &sk.sign(&tbs).to_bytes()).unwrap()
}

fn decider(disk: &Rc<RefCell<Disk>>) -> Result<Decider<Store, Exec>, DeciderError> {
    Decider::new(
        vec![TrustAnchor {
            tenant: "acme".into(),
            key: root().1,
        }],
        DeviceFacts {
            tenant: "acme".into(),
            ..DeviceFacts::default()
        },
        Store(disk.clone()),
        Exec(disk.clone()),
    )
}

/// @relation(AGT-004, scope=function)
#[test]
fn state_is_saved_before_anything_is_executed() {
    let disk = Rc::new(RefCell::new(Disk::default()));
    let mut d = decider(&disk).unwrap();
    let doc = signed_config();
    let outcome = d.decide(&[&doc]).unwrap();
    assert_eq!(outcome.executed.len(), 1);
    assert_eq!(disk.borrow().saved_before_execute, vec![true]);
    // Applied: the next round does nothing.
    assert!(d.decide(&[&doc]).unwrap().executed.is_empty());
}

/// @relation(AGT-004, scope=function)
#[test]
fn nothing_is_executed_if_the_state_cannot_be_saved() {
    let disk = Rc::new(RefCell::new(Disk {
        fail: true,
        ..Disk::default()
    }));
    let mut d = decider(&disk).unwrap();
    let before = d.state().clone();
    let doc = signed_config();
    assert!(matches!(d.decide(&[&doc]), Err(DeciderError::Store(_))));
    assert!(disk.borrow().saved_before_execute.is_empty());
    assert_eq!(d.state(), &before);
}

/// @relation(AGT-006, scope=function)
#[test]
fn state_survives_a_restart_and_corrupt_state_is_refused() {
    let disk = Rc::new(RefCell::new(Disk::default()));
    let doc = signed_config();
    decider(&disk).unwrap().decide(&[&doc]).unwrap();
    let restarted = decider(&disk).unwrap();
    assert_eq!(restarted.state().marks.len(), 1);
    disk.borrow_mut().state = Some(b"not cbor".to_vec());
    assert!(matches!(decider(&disk), Err(DeciderError::CorruptState)));
}

/// @relation(AGT-003, scope=function)
#[test]
fn forged_documents_are_quarantined_and_valid_ones_shared() {
    let disk = Rc::new(RefCell::new(Disk::default()));
    let mut d = decider(&disk).unwrap();
    let doc = signed_config();
    let mut forged = doc.clone();
    let last = forged.len() - 1;
    forged[last] ^= 1;
    let junk = b"junk".to_vec();
    let outcome = d.decide(&[&doc, &forged, &junk]).unwrap();
    let mut quarantine = outcome.quarantine.clone();
    quarantine.sort_unstable();
    let mut expected = vec![sha256(&forged), sha256(&junk)];
    expected.sort_unstable();
    assert_eq!(quarantine, expected);
    assert_eq!(outcome.shareable, vec![sha256(&doc)]);
}
