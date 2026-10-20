// SPDX-FileCopyrightText: 2026 The weft authors
// SPDX-License-Identifier: MIT

//! The transport contract (weft-design docs/15), reduced to what document sync needs.
//!
//! A transport delivers opaque payloads published under hierarchical keys to the nodes that
//! subscribe to them, **best effort** (T3): messages may be lost, duplicated or reordered.
//! Everything that must hold end to end (dedupe, convergence, trust) is built above this trait.
//!
//! Not yet part of this subset: prefix subscriptions at runtime, request/response and link
//! state (docs/15 §5). Directed messages use a per-node key (`.../to/{node}`) instead.

use std::fmt;
use std::future::Future;

#[cfg(feature = "turmoil")]
pub mod sim;

/// Largest payload a transport must carry (weft-design `pubsub.payload_preferred`).
pub const MAX_PAYLOAD: usize = 64 * 1024;
/// Maximum characters per key segment (weft-design `pubsub.topic.segment_max`).
pub const MAX_SEGMENT: usize = 64;
/// Maximum number of key segments (weft-design `pubsub.topic.max_depth`).
pub const MAX_DEPTH: usize = 16;
/// Maximum key length in bytes (weft-design `pubsub.topic.max_len`).
pub const MAX_KEY_LEN: usize = 256;

/// A key in the weft topic namespace: `/`-separated segments of `[a-z0-9_-]`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Key(String);

/// Why a string is not a valid [`Key`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyError {
    /// Longer than [`MAX_KEY_LEN`] or deeper than [`MAX_DEPTH`].
    TooLong,
    /// Empty segment, segment longer than [`MAX_SEGMENT`], or a character outside `[a-z0-9_-]`.
    InvalidSegment,
}

impl Key {
    /// Parses and validates a key.
    ///
    /// # Errors
    ///
    /// [`KeyError`] if the key breaks the charset or size rules (docs/15 §3.4).
    ///
    /// @relation(AGT-009, scope=function)
    pub fn new(key: &str) -> Result<Key, KeyError> {
        if key.len() > MAX_KEY_LEN || key.split('/').count() > MAX_DEPTH {
            return Err(KeyError::TooLong);
        }
        let valid_segment = |s: &str| {
            !s.is_empty()
                && s.len() <= MAX_SEGMENT
                && s.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
        };
        if key.split('/').all(valid_segment) {
            Ok(Key(key.to_string()))
        } else {
            Err(KeyError::InvalidSegment)
        }
    }

    /// The key as text.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether `self` equals `prefix` or lies below it, segment by segment.
    pub fn starts_with(&self, prefix: &Key) -> bool {
        self.0 == prefix.0
            || self
                .0
                .strip_prefix(prefix.0.as_str())
                .is_some_and(|rest| rest.starts_with('/'))
    }
}

impl fmt::Display for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyError::TooLong => f.write_str("key too long or too deep"),
            KeyError::InvalidSegment => f.write_str("invalid key segment"),
        }
    }
}

impl std::error::Error for KeyError {}

/// Transport failures. Only [`TransportError::Closed`] is permanent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TransportError {
    /// The transport is shut down.
    Closed,
    /// Payload larger than [`MAX_PAYLOAD`].
    TooLarge,
    /// Any other (transient) I/O problem.
    Io(String),
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransportError::Closed => f.write_str("transport closed"),
            TransportError::TooLarge => f.write_str("payload too large"),
            TransportError::Io(e) => write!(f, "transport I/O: {e}"),
        }
    }
}

impl std::error::Error for TransportError {}

/// A best-effort publish/subscribe transport (docs/15 §1, T1–T4).
pub trait Transport {
    /// Publishes `payload` under `key`. Success means "handed to the network", nothing more.
    fn publish(
        &self,
        key: &Key,
        payload: &[u8],
    ) -> impl Future<Output = Result<(), TransportError>>;

    /// The next message for one of this node's subscriptions.
    fn recv(&self) -> impl Future<Output = Result<(Key, Vec<u8>), TransportError>>;
}
