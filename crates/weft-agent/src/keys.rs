// SPDX-FileCopyrightText: 2026 The weft authors
// SPDX-License-Identifier: MIT

//! Public key files as written by `weft key new` (weft-cli): trust anchors for the device.
//!
//! ```text
//! weft-public-key-v1
//! alg: ed25519
//! key: <64 hex digits>
//! key-id: <32 hex digits>
//! ```

use weft_verifier::crypto::{Algorithm, PublicKey};

fn unhex(text: &str) -> Option<Vec<u8>> {
    let text = text.trim();
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| {
            text.get(i..i + 2)
                .and_then(|p| u8::from_str_radix(p, 16).ok())
        })
        .collect()
}

/// Parses a public key file; the key id, if present, must match the key.
///
/// # Errors
///
/// A message describing what is wrong with the file.
pub fn parse_public(text: &str) -> Result<PublicKey, String> {
    let mut lines = text.lines();
    if lines.next().map(str::trim) != Some("weft-public-key-v1") {
        return Err("not a weft-public-key-v1 file".into());
    }
    let fields: Vec<(&str, &str)> = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim(), v.trim()))
        .collect();
    let field = |name: &str| fields.iter().find(|(k, _)| *k == name).map(|(_, v)| *v);
    if field("alg") != Some("ed25519") {
        return Err("only ed25519 keys are supported".into());
    }
    let bytes = field("key")
        .and_then(unhex)
        .filter(|b| b.len() == 32)
        .ok_or("`key` must be 32 bytes of hex")?;
    let key = PublicKey {
        alg: Algorithm::Ed25519,
        bytes,
    };
    if let Some(id) = field("key-id")
        && unhex(id).as_deref() != Some(key.key_id().as_slice())
    {
        return Err("key-id does not match the key".into());
    }
    Ok(key)
}
