// SPDX-FileCopyrightText: 2026 The weft authors
// SPDX-License-Identifier: MIT

//! Document sync without a network: two stores reconcile through messages.
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::assert_is_empty,
    missing_docs
)]

use weft_sync::{Limits, Message, Outgoing, Sync, Target};
use weft_verifier::crypto::sha256;

/// Delivers messages between two nodes until nothing is left; every document is "verified".
fn exchange(a: &mut Sync, b: &mut Sync, mut queue: Vec<(String, Outgoing)>) {
    let mut rounds = 0;
    while let Some((from, out)) = queue.pop() {
        rounds += 1;
        assert!(rounds < 1000, "no quiescence");
        let (to, other) = if from == a.node() {
            (&mut *b, &mut *a)
        } else {
            (&mut *a, &mut *b)
        };
        let _ = other;
        if let Target::Node(n) = &out.target
            && n != to.node()
        {
            continue;
        }
        // Over the wire and back: messages must survive encoding.
        let message = Message::decode(&out.message.encode(), &Limits::DEFAULT).unwrap();
        let (replies, new) = to.on_message(message);
        let forwarded = to.promote(&new);
        let name = to.node().to_string();
        queue.extend(
            replies
                .into_iter()
                .chain(forwarded)
                .map(|o| (name.clone(), o)),
        );
    }
}

fn node(name: &str, docs: &[&[u8]]) -> Sync {
    let mut s = Sync::new(name, Limits::DEFAULT);
    let new: Vec<_> = docs.iter().filter_map(|d| s.insert(d.to_vec())).collect();
    s.promote(&new);
    s
}

/// @relation(AGT-001, scope=function)
#[test]
fn summaries_reconcile_two_stores() {
    let mut a = node("a", &[b"one", b"two"]);
    let mut b = node("b", &[b"two", b"three"]);
    assert_ne!(a.set_hash(), b.set_hash());
    let start = vec![
        ("a".to_string(), a.summary()),
        ("b".to_string(), b.summary()),
    ];
    exchange(&mut a, &mut b, start);
    assert_eq!(a.digests(), b.digests());
    assert_eq!(a.digests().len(), 3);
    assert_eq!(a.set_hash(), b.set_hash());
}

/// @relation(AGT-002, scope=function)
#[test]
fn duplicates_are_dropped() {
    let mut s = Sync::new("a", Limits::DEFAULT);
    assert_eq!(s.insert(b"doc".to_vec()), Some(sha256(b"doc")));
    assert_eq!(s.insert(b"doc".to_vec()), None);
    s.promote(&[sha256(b"doc")]);
    assert_eq!(s.insert(b"doc".to_vec()), None);
}

/// @relation(AGT-003, scope=function)
#[test]
fn pending_documents_are_never_advertised_or_served() {
    let mut s = Sync::new("a", Limits::DEFAULT);
    let d = s.insert(b"unverified".to_vec()).unwrap();
    assert!(s.digests().is_empty());
    assert_eq!(s.documents(), vec![b"unverified".as_slice()]);
    let (replies, _) = s.on_message(Message::Fetch {
        from: "b".into(),
        digests: vec![d],
    });
    assert!(replies.is_empty());
    // Verified: shared and forwarded once.
    assert_eq!(s.promote(&[d]).len(), 1);
    assert!(s.promote(&[d]).is_empty());
    assert!(s.digests().contains(&d));
}

/// @relation(AGT-003, scope=function)
#[test]
fn quarantined_documents_never_come_back() {
    let mut s = Sync::new("a", Limits::DEFAULT);
    let d = s.insert(b"forged".to_vec()).unwrap();
    s.quarantine(&[d]);
    assert!(s.documents().is_empty());
    assert_eq!(s.insert(b"forged".to_vec()), None);
    assert!(s.quarantined().contains(&d));
}

/// @relation(AGT-008, scope=function)
#[test]
fn peers_cannot_exceed_the_limits() {
    let limits = Limits {
        max_document: 8,
        max_documents: 2,
        max_batch: 2,
        max_quarantined: 1,
        max_pending: 2,
    };
    let mut s = Sync::new("a", limits);
    assert_eq!(s.insert(vec![0; 9]), None, "oversized");
    let d1 = s.insert(b"1".to_vec()).unwrap();
    let d2 = s.insert(b"2".to_vec()).unwrap();
    assert_eq!(s.insert(b"3".to_vec()), None, "pending area full");
    s.promote(&[d1, d2]);
    let d3 = s.insert(b"3".to_vec()).unwrap();
    assert!(s.promote(&[d3]).is_empty(), "store full");
    // Over-long digest lists and oversized documents do not decode.
    let long = Message::Inventory {
        from: "b".into(),
        digests: vec![[0; 32]; 3],
    }
    .encode();
    assert_eq!(Message::decode(&long, &limits), None);
    let big = Message::Document { bytes: vec![0; 9] }.encode();
    assert_eq!(Message::decode(&big, &limits), None);
    for junk in [&b""[..], b"\xff", b"\x83\x00\x61a\x40"] {
        assert_eq!(Message::decode(junk, &limits), None);
    }
}
