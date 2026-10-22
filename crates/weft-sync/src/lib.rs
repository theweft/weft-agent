// SPDX-FileCopyrightText: 2026 The weft authors
// SPDX-License-Identifier: MIT

//! Document sync (weft-design docs/15 §3.2) as a state machine without I/O.
//!
//! - **Store**: documents are kept by SHA-256 of their bytes, the same digest the verifier
//!   uses, so duplicates arriving over several paths are dropped.
//! - **Pending vs. shared**: every arriving document is *pending* until the decider has
//!   verified it. Only *shared* documents are advertised, served and forwarded, so documents
//!   signed by unknown or unauthorized keys never spread (a node cannot be used to flood the
//!   fleet). Pending documents are re-checked on every round and shared once they verify.
//! - **Push**: the node forwards documents that have just become shared ([`Sync::promote`]).
//! - **Anti-entropy pull**: nodes publish a [`Message::Summary`] (hash of their digest set).
//!   A neighbour with a different hash answers with its [`Message::Inventory`]; each side then
//!   fetches what it lacks and sends what the other lacks.
//! - **Quarantine**: digests the decider found intrinsically invalid are removed and never
//!   accepted or forwarded again.
//!
//! Nothing here is trusted: a document's authority is decided by `weft-verifier` alone.

use std::collections::{BTreeMap, BTreeSet};

use weft_verifier::cbor::{self, Limits as CborLimits, Value};
use weft_verifier::crypto::sha256;

/// SHA-256 of a document's bytes.
pub type Digest = [u8; 32];

const SUMMARY_TAG: &[u8] = b"weft-sync-summary-v1";

/// Resource limits; everything a peer sends is bounded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Largest accepted document in bytes.
    pub max_document: usize,
    /// Most documents kept in the store.
    pub max_documents: usize,
    /// Most digests in one inventory or fetch, and most documents sent per request.
    pub max_batch: usize,
    /// Most quarantined digests remembered.
    pub max_quarantined: usize,
    /// Most pending (not yet verified) documents kept.
    pub max_pending: usize,
}

impl Limits {
    /// Defaults for gateways and Linux devices.
    pub const DEFAULT: Limits = Limits {
        max_document: 64 * 1024,
        max_documents: 4096,
        max_batch: 256,
        max_quarantined: 4096,
        max_pending: 256,
    };
}

/// Sync protocol messages. `from` is the sender's node name, used only to address replies.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Message {
    /// "This is the hash of my document set."
    Summary {
        /// Sender.
        from: String,
        /// [`Sync::set_hash`] of the sender.
        hash: Digest,
    },
    /// "These are all the digests I hold."
    Inventory {
        /// Sender.
        from: String,
        /// Sorted digests.
        digests: Vec<Digest>,
    },
    /// "Please send me these documents."
    Fetch {
        /// Sender.
        from: String,
        /// Requested digests.
        digests: Vec<Digest>,
    },
    /// A document.
    Document {
        /// The signed document bytes.
        bytes: Vec<u8>,
    },
}

/// Where a message goes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Target {
    /// Every neighbour.
    All,
    /// One node, by name.
    Node(String),
}

/// A message to send.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Outgoing {
    /// Destination.
    pub target: Target,
    /// The message.
    pub message: Message,
}

fn wire_limits(limits: &Limits) -> CborLimits {
    CborLimits {
        max_len: limits.max_document + 1024,
        max_depth: 3,
        max_items: limits.max_batch + 8,
    }
}

fn digest_list(digests: &[Digest]) -> Value {
    Value::Array(digests.iter().map(|d| Value::Bytes(d.to_vec())).collect())
}

fn parse_digests(value: &Value, limits: &Limits) -> Option<Vec<Digest>> {
    let items = value.as_array()?;
    if items.len() > limits.max_batch {
        return None;
    }
    items
        .iter()
        .map(|v| v.as_bytes().and_then(|b| <[u8; 32]>::try_from(b).ok()))
        .collect()
}

impl Message {
    /// Deterministic CBOR encoding.
    pub fn encode(&self) -> Vec<u8> {
        let value = match self {
            Message::Summary { from, hash } => Value::Array(vec![
                Value::Int(0),
                Value::text(from),
                Value::Bytes(hash.to_vec()),
            ]),
            Message::Inventory { from, digests } => {
                Value::Array(vec![Value::Int(1), Value::text(from), digest_list(digests)])
            }
            Message::Fetch { from, digests } => {
                Value::Array(vec![Value::Int(2), Value::text(from), digest_list(digests)])
            }
            Message::Document { bytes } => {
                Value::Array(vec![Value::Int(3), Value::Bytes(bytes.clone())])
            }
        };
        // Encoding a well-formed value cannot fail; an empty payload would be dropped as invalid.
        cbor::encode(&value).unwrap_or_default()
    }

    /// Decodes an untrusted message; `None` for anything malformed or over the limits.
    ///
    /// @relation(AGT-008, scope=function)
    pub fn decode(bytes: &[u8], limits: &Limits) -> Option<Message> {
        let Value::Array(parts) = cbor::decode(bytes, &wire_limits(limits)).ok()? else {
            return None;
        };
        match parts.as_slice() {
            [Value::Int(0), Value::Text(from), Value::Bytes(hash)] => Some(Message::Summary {
                from: from.clone(),
                hash: <[u8; 32]>::try_from(hash.as_slice()).ok()?,
            }),
            [Value::Int(1), Value::Text(from), list] => Some(Message::Inventory {
                from: from.clone(),
                digests: parse_digests(list, limits)?,
            }),
            [Value::Int(2), Value::Text(from), list] => Some(Message::Fetch {
                from: from.clone(),
                digests: parse_digests(list, limits)?,
            }),
            [Value::Int(3), Value::Bytes(doc)] if doc.len() <= limits.max_document => {
                Some(Message::Document { bytes: doc.clone() })
            }
            _ => None,
        }
    }
}

/// One node's document store and sync state.
#[derive(Clone, Debug)]
pub struct Sync {
    node: String,
    limits: Limits,
    /// Verified documents: advertised, served and forwarded.
    store: BTreeMap<Digest, Vec<u8>>,
    /// Not yet verified: used for decisions, never shared.
    pending: BTreeMap<Digest, Vec<u8>>,
    quarantined: BTreeSet<Digest>,
}

impl Sync {
    /// An empty store for node `node`.
    pub fn new(node: &str, limits: Limits) -> Sync {
        Sync {
            node: node.to_string(),
            limits,
            store: BTreeMap::new(),
            pending: BTreeMap::new(),
            quarantined: BTreeSet::new(),
        }
    }

    /// Adds an arriving document as *pending*. Returns its digest if it is new; `None` for
    /// duplicates, quarantined digests, oversized documents or a full pending area.
    ///
    /// @relation(AGT-002, AGT-008, scope=function)
    pub fn insert(&mut self, bytes: Vec<u8>) -> Option<Digest> {
        if bytes.len() > self.limits.max_document || self.pending.len() >= self.limits.max_pending {
            return None;
        }
        let digest = sha256(&bytes);
        if self.quarantined.contains(&digest)
            || self.store.contains_key(&digest)
            || self.pending.contains_key(&digest)
        {
            return None;
        }
        self.pending.insert(digest, bytes);
        Some(digest)
    }

    /// Moves verified pending documents to the shared store and returns the messages that
    /// forward them to every neighbour. Digests that are not pending are ignored.
    ///
    /// @relation(AGT-003, scope=function)
    pub fn promote(&mut self, verified: &[Digest]) -> Vec<Outgoing> {
        let mut out = Vec::new();
        for d in verified {
            if self.store.len() >= self.limits.max_documents {
                break;
            }
            if let Some(bytes) = self.pending.remove(d) {
                out.push(Outgoing {
                    target: Target::All,
                    message: Message::Document {
                        bytes: bytes.clone(),
                    },
                });
                self.store.insert(*d, bytes);
            }
        }
        out
    }

    /// Removes intrinsically invalid documents for good.
    ///
    /// @relation(AGT-003, scope=function)
    pub fn quarantine(&mut self, digests: &[Digest]) {
        for d in digests {
            self.store.remove(d);
            self.pending.remove(d);
            if self.quarantined.len() < self.limits.max_quarantined {
                self.quarantined.insert(*d);
            }
        }
    }

    /// Handles a message. Returns replies and the digests of newly pending documents. New
    /// documents are *not* forwarded here: the caller decides first, then [`Sync::promote`]s.
    ///
    /// @relation(AGT-001, scope=function)
    pub fn on_message(&mut self, message: Message) -> (Vec<Outgoing>, Vec<Digest>) {
        match message {
            Message::Summary { from, hash } => {
                let replies = if from != self.node && hash != self.set_hash() {
                    vec![Outgoing {
                        target: Target::Node(from),
                        message: self.inventory(),
                    }]
                } else {
                    Vec::new()
                };
                (replies, Vec::new())
            }
            Message::Inventory { from, digests } => {
                if from == self.node {
                    return (Vec::new(), Vec::new());
                }
                let theirs: BTreeSet<Digest> = digests.into_iter().collect();
                let missing: Vec<Digest> = theirs
                    .iter()
                    .filter(|d| {
                        !self.store.contains_key(*d)
                            && !self.pending.contains_key(*d)
                            && !self.quarantined.contains(*d)
                    })
                    .copied()
                    .take(self.limits.max_batch)
                    .collect();
                let mut replies = Vec::new();
                if !missing.is_empty() {
                    replies.push(Outgoing {
                        target: Target::Node(from.clone()),
                        message: Message::Fetch {
                            from: self.node.clone(),
                            digests: missing,
                        },
                    });
                }
                // Send what they lack, directly.
                let lacking: Vec<Digest> = self
                    .store
                    .keys()
                    .filter(|d| !theirs.contains(*d))
                    .copied()
                    .take(self.limits.max_batch)
                    .collect();
                replies.extend(self.documents_to(&from, &lacking));
                (replies, Vec::new())
            }
            Message::Fetch { from, digests } => {
                if from == self.node {
                    return (Vec::new(), Vec::new());
                }
                (self.documents_to(&from, &digests), Vec::new())
            }
            Message::Document { bytes } => match self.insert(bytes) {
                Some(d) => (Vec::new(), vec![d]),
                None => (Vec::new(), Vec::new()),
            },
        }
    }

    fn documents_to(&self, node: &str, digests: &[Digest]) -> Vec<Outgoing> {
        digests
            .iter()
            .take(self.limits.max_batch)
            .filter_map(|d| self.store.get(d))
            .map(|bytes| Outgoing {
                target: Target::Node(node.to_string()),
                message: Message::Document {
                    bytes: bytes.clone(),
                },
            })
            .collect()
    }

    fn inventory(&self) -> Message {
        Message::Inventory {
            from: self.node.clone(),
            digests: self
                .store
                .keys()
                .take(self.limits.max_batch)
                .copied()
                .collect(),
        }
    }

    /// The periodic summary of this node.
    pub fn summary(&self) -> Outgoing {
        Outgoing {
            target: Target::All,
            message: Message::Summary {
                from: self.node.clone(),
                hash: self.set_hash(),
            },
        }
    }

    /// Hash of the sorted digest set (first version of the summary, docs/15 §8).
    pub fn set_hash(&self) -> Digest {
        let mut bytes = Vec::with_capacity(SUMMARY_TAG.len() + self.store.len() * 32);
        bytes.extend_from_slice(SUMMARY_TAG);
        for d in self.store.keys() {
            bytes.extend_from_slice(d);
        }
        sha256(&bytes)
    }

    /// All documents for the decider: shared and pending.
    pub fn documents(&self) -> Vec<&[u8]> {
        self.store
            .values()
            .chain(self.pending.values())
            .map(Vec::as_slice)
            .collect()
    }

    /// Digests of shared (verified) documents, in order.
    pub fn digests(&self) -> BTreeSet<Digest> {
        self.store.keys().copied().collect()
    }

    /// The bytes of a shared or pending document.
    pub fn get(&self, digest: &Digest) -> Option<&[u8]> {
        self.store
            .get(digest)
            .or_else(|| self.pending.get(digest))
            .map(Vec::as_slice)
    }

    /// Digests of pending (not yet verified) documents, in order.
    pub fn pending(&self) -> BTreeSet<Digest> {
        self.pending.keys().copied().collect()
    }

    /// Quarantined digests.
    pub fn quarantined(&self) -> &BTreeSet<Digest> {
        &self.quarantined
    }

    /// This node's name.
    pub fn node(&self) -> &str {
        &self.node
    }
}
