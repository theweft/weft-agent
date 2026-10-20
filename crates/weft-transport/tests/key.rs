// SPDX-FileCopyrightText: 2026 The weft authors
// SPDX-License-Identifier: MIT

//! Topic keys valid on every transport (weft-design docs/15 §3.4).
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::assert_is_empty,
    missing_docs
)]

use weft_transport::{Key, KeyError, MAX_DEPTH, MAX_KEY_LEN, MAX_SEGMENT};

/// @relation(AGT-009, scope=function)
#[test]
fn keys_follow_the_portable_charset() {
    assert!(Key::new("weft/acme/dev-042/tel/pump_1").is_ok());
    for bad in [
        "",
        "weft//x",
        "weft/Acme",
        "weft/a+b",
        "weft/#",
        "weft/a.b",
        "weft/*",
        "weft/@x",
        "weft/a b",
    ] {
        assert_eq!(Key::new(bad), Err(KeyError::InvalidSegment), "{bad}");
    }
}

/// @relation(AGT-009, scope=function)
#[test]
fn keys_are_bounded() {
    let segment = "a".repeat(MAX_SEGMENT);
    assert!(Key::new(&segment).is_ok());
    assert_eq!(
        Key::new(&"a".repeat(MAX_SEGMENT + 1)),
        Err(KeyError::InvalidSegment)
    );
    assert_eq!(
        Key::new(&vec!["a"; MAX_DEPTH + 1].join("/")),
        Err(KeyError::TooLong)
    );
    assert_eq!(Key::new(&"a/".repeat(MAX_KEY_LEN)), Err(KeyError::TooLong));
}

/// @relation(AGT-009, scope=function)
#[test]
fn prefixes_match_whole_segments() {
    let key = Key::new("weft/acme/sync/to/dev-a").unwrap();
    assert!(key.starts_with(&Key::new("weft/acme/sync").unwrap()));
    assert!(key.starts_with(&key));
    assert!(!key.starts_with(&Key::new("weft/acme/sy").unwrap()));
    assert!(
        !Key::new("weft/acme/sync/to/dev-ab")
            .unwrap()
            .starts_with(&key)
    );
}
