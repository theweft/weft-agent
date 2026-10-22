// SPDX-FileCopyrightText: 2026 The weft authors
// SPDX-License-Identifier: MIT

//! Files on the device: the document directory, the inbox and what was executed.
//!
//! - **Documents** (`<state>/documents/<sha256>`): every document the device holds, written
//!   atomically and *before* the decider sees it, so a document the verifier accepted (and
//!   holds an anti-rollback mark for) is always still there after a reboot. Without it the
//!   verifier would withhold the component (fail safe) until the document came back.
//! - **Inbox**: a directory scanned read-only (it may be a read-only USB stick). Any regular,
//!   non-hidden file up to the size limit is a candidate document; everything is untrusted.
//! - **Executed** (`<state>/executed`): what is installed and applied, saved after each round,
//!   so a reboot does not repeat installs.

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::path::{Path, PathBuf};

use weft_decider::{Fs, write_atomic};
use weft_verifier::cbor::{self, Limits, Value};
use weft_verifier::crypto::sha256;

use crate::hex;

/// Content-addressed document files.
pub struct DocumentDir<F> {
    fs: F,
    dir: PathBuf,
    present: BTreeSet<[u8; 32]>,
}

impl<F: Fs> DocumentDir<F> {
    /// The documents in `dir` (which must exist). Files whose name is not the SHA-256 of their
    /// contents are ignored, as are leftovers of interrupted writes.
    ///
    /// # Errors
    ///
    /// I/O errors while listing or reading.
    ///
    /// @relation(AGT-012, scope=function)
    pub fn open(fs: F, dir: &Path, max_size: usize) -> io::Result<(Self, Vec<Vec<u8>>)> {
        let mut docs = Vec::new();
        let mut present = BTreeSet::new();
        for path in fs.list(dir)? {
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            if name.len() != 64 {
                continue;
            }
            let Some(bytes) = fs.read(&path)? else {
                continue;
            };
            let digest = sha256(&bytes);
            if bytes.len() <= max_size && hex(&digest) == name {
                present.insert(digest);
                docs.push(bytes);
            }
        }
        Ok((
            DocumentDir {
                fs,
                dir: dir.to_path_buf(),
                present,
            },
            docs,
        ))
    }

    /// Stores a document unless it is already there.
    ///
    /// # Errors
    ///
    /// I/O errors; the document is then not stored.
    ///
    /// @relation(AGT-012, scope=function)
    pub fn put(&mut self, bytes: &[u8]) -> io::Result<()> {
        let digest = sha256(bytes);
        if self.present.contains(&digest) {
            return Ok(());
        }
        write_atomic(&self.fs, &self.dir.join(hex(&digest)), bytes)?;
        self.present.insert(digest);
        Ok(())
    }

    /// Deletes a document (quarantined ones).
    ///
    /// # Errors
    ///
    /// I/O errors.
    pub fn remove(&mut self, digest: &[u8; 32]) -> io::Result<()> {
        self.present.remove(digest);
        self.fs.remove(&self.dir.join(hex(digest)))
    }
}

/// Candidate documents in `dir`: regular, non-hidden files up to `max_size`, never modified.
///
/// # Errors
///
/// I/O errors while listing or reading.
///
/// @relation(AGT-011, scope=function)
pub fn scan_inbox(fs: &impl Fs, dir: &Path, max_size: usize) -> io::Result<Vec<Vec<u8>>> {
    let mut docs = Vec::new();
    for path in fs.list(dir)? {
        let hidden = path.file_name().and_then(|n| n.to_str()).is_none_or(|n| {
            n.starts_with('.')
                || Path::new(n)
                    .extension()
                    .is_some_and(|e| e.eq_ignore_ascii_case("tmp"))
        });
        if hidden {
            continue;
        }
        if let Some(bytes) = fs.read(&path)?
            && bytes.len() <= max_size
        {
            docs.push(bytes);
        }
    }
    Ok(docs)
}

/// What is installed (artifact digest) and applied (config hash) per component.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Executed {
    /// Installed artifacts.
    pub installed: BTreeMap<String, [u8; 32]>,
    /// Applied configuration hashes.
    pub applied: BTreeMap<String, [u8; 32]>,
}

fn digest_map(map: &BTreeMap<String, [u8; 32]>) -> Value {
    Value::Map(
        map.iter()
            .map(|(k, v)| (Value::text(k), Value::Bytes(v.to_vec())))
            .collect(),
    )
}

fn parse_digest_map(value: &Value) -> Option<BTreeMap<String, [u8; 32]>> {
    let Value::Map(entries) = value else {
        return None;
    };
    entries
        .iter()
        .map(|(k, v)| {
            Some((
                k.as_text()?.to_string(),
                <[u8; 32]>::try_from(v.as_bytes()?).ok()?,
            ))
        })
        .collect()
}

impl Executed {
    /// Deterministic CBOR: `{"applied": {...}, "installed": {...}}`.
    pub fn encode(&self) -> Vec<u8> {
        cbor::encode(&Value::map([
            ("installed", digest_map(&self.installed)),
            ("applied", digest_map(&self.applied)),
        ]))
        .unwrap_or_default()
    }

    /// Decodes [`Executed::encode`]'s output; `None` if damaged.
    pub fn decode(bytes: &[u8]) -> Option<Executed> {
        let value = cbor::decode(bytes, &Limits::DEFAULT).ok()?;
        Some(Executed {
            installed: parse_digest_map(value.get("installed")?)?,
            applied: parse_digest_map(value.get("applied")?)?,
        })
    }
}
