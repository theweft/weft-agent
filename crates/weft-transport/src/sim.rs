// SPDX-FileCopyrightText: 2026 The weft authors
// SPDX-License-Identifier: MIT

//! Transport over turmoil's simulated UDP, for deterministic simulations.
//!
//! Each node sends every publication to its direct neighbours (the simulated links); a
//! neighbour delivers it if one of its subscriptions covers the key. Forwarding beyond one hop
//! is the job of the layer above (document sync), like peers and routers in Zenoh.

use turmoil::net::UdpSocket;
use weft_verifier::cbor::{self, Limits, Value};

use crate::{Key, MAX_PAYLOAD, Transport, TransportError};

/// UDP port used by simulated nodes.
pub const PORT: u16 = 7447;

const FRAME_LIMITS: Limits = Limits {
    max_len: MAX_PAYLOAD + 1024,
    max_depth: 2,
    max_items: 4,
};

/// Encodes a frame: `[key, payload]` as deterministic CBOR.
///
/// # Errors
///
/// [`TransportError::TooLarge`] for oversized payloads.
pub fn encode_frame(key: &Key, payload: &[u8]) -> Result<Vec<u8>, TransportError> {
    if payload.len() > MAX_PAYLOAD {
        return Err(TransportError::TooLarge);
    }
    cbor::encode(&Value::Array(vec![
        Value::text(key.as_str()),
        Value::Bytes(payload.to_vec()),
    ]))
    .map_err(|_| TransportError::TooLarge)
}

/// Decodes a frame; `None` for anything malformed (frames are untrusted).
pub fn decode_frame(bytes: &[u8]) -> Option<(Key, Vec<u8>)> {
    let Value::Array(parts) = cbor::decode(bytes, &FRAME_LIMITS).ok()? else {
        return None;
    };
    let [Value::Text(key), Value::Bytes(payload)] = parts.as_slice() else {
        return None;
    };
    Some((Key::new(key).ok()?, payload.clone()))
}

/// A node's endpoint in a turmoil simulation.
pub struct SimTransport {
    socket: UdpSocket,
    neighbors: Vec<String>,
    subscriptions: Vec<Key>,
}

impl SimTransport {
    /// Binds the node's socket. `neighbors` are host names of directly linked nodes.
    ///
    /// # Errors
    ///
    /// [`TransportError::Io`] if the socket cannot be bound.
    pub async fn bind(
        neighbors: Vec<String>,
        subscriptions: Vec<Key>,
    ) -> Result<SimTransport, TransportError> {
        let socket = UdpSocket::bind(("0.0.0.0", PORT))
            .await
            .map_err(|e| TransportError::Io(e.to_string()))?;
        Ok(SimTransport {
            socket,
            neighbors,
            subscriptions,
        })
    }
}

impl Transport for SimTransport {
    async fn publish(&self, key: &Key, payload: &[u8]) -> Result<(), TransportError> {
        let frame = encode_frame(key, payload)?;
        for neighbor in &self.neighbors {
            // Best effort: a broken link loses the message, like a real network.
            let _ = self.socket.send_to(&frame, (neighbor.as_str(), PORT)).await;
        }
        Ok(())
    }

    async fn recv(&self) -> Result<(Key, Vec<u8>), TransportError> {
        let mut buf = vec![0u8; MAX_PAYLOAD + 1024];
        loop {
            let (len, _) = self
                .socket
                .recv_from(&mut buf)
                .await
                .map_err(|e| TransportError::Io(e.to_string()))?;
            let Some(frame) = buf.get(..len) else {
                continue;
            };
            if let Some((key, payload)) = decode_frame(frame)
                && self.subscriptions.iter().any(|s| key.starts_with(s))
            {
                return Ok((key, payload));
            }
        }
    }
}
