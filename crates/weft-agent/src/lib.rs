// SPDX-FileCopyrightText: 2026 The weft authors
// SPDX-License-Identifier: MIT

//! The weft agent's node runtime (weft-design docs/20).
//!
//! A [`Node`] connects a [`Transport`], the document [`Sync`] and, on devices, a [`Decider`].
//! In this first milestone all three run in one task; the process separation of docs/20 §1
//! (transport / decider / executor) comes next, with the same interfaces.
//!
//! The loop is deterministic given the same inputs: `select!` is `biased` and all state is
//! kept in ordered maps, so simulations can replay a run from its seed.

use std::time::Duration;

use tokio::sync::mpsc;
use weft_decider::{Decider, DeciderError, Executor, Outcome, StateStore};
use weft_sync::{Limits, Message, Outgoing, Sync, Target};
use weft_transport::{Key, KeyError, Transport, TransportError};

/// Static configuration of a node.
#[derive(Clone, Debug)]
pub struct NodeConfig {
    /// Node name, unique within the tenant; a key segment.
    pub name: String,
    /// Tenant; a key segment.
    pub tenant: String,
    /// How often the node publishes its summary (anti-entropy).
    pub summary_interval: Duration,
    /// Sync limits.
    pub limits: Limits,
}

/// Node failures that stop the loop.
#[derive(Debug)]
pub enum NodeError {
    /// Name or tenant is not a valid key segment.
    Key(KeyError),
    /// The transport closed.
    Transport(TransportError),
    /// The decider could not persist its state; acting would be unsafe.
    Decider(DeciderError),
}

impl std::fmt::Display for NodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NodeError::Key(e) => write!(f, "invalid key: {e}"),
            NodeError::Transport(e) => write!(f, "{e}"),
            NodeError::Decider(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for NodeError {}

/// Receives a callback after every decision round, e.g. to publish reported state or, in
/// simulations, to check invariants.
pub trait Observer<S, E> {
    /// Called after each round; `decider` and `outcome` are `None` on nodes without a decider.
    fn observe(&mut self, sync: &Sync, decider: Option<&Decider<S, E>>, outcome: Option<&Outcome>);
}

/// An observer that does nothing.
pub struct NoObserver;

impl<S, E> Observer<S, E> for NoObserver {
    fn observe(&mut self, _: &Sync, _: Option<&Decider<S, E>>, _: Option<&Outcome>) {}
}

/// Sync keys of a tenant: `weft/{tenant}/sync/all` and `weft/{tenant}/sync/to/{node}`.
///
/// # Errors
///
/// [`KeyError`] if `tenant` or `node` is not a valid key segment.
pub fn sync_keys(tenant: &str, node: &str) -> Result<(Key, Key), KeyError> {
    Ok((
        Key::new(&format!("weft/{tenant}/sync/all"))?,
        Key::new(&format!("weft/{tenant}/sync/to/{node}"))?,
    ))
}

/// One node: transport, sync and an optional decider.
pub struct Node<T, S, E> {
    config: NodeConfig,
    transport: T,
    sync: Sync,
    decider: Option<Decider<S, E>>,
}

impl<T: Transport, S: StateStore, E: Executor> Node<T, S, E> {
    /// A node; `decider` is `None` for pure relays.
    pub fn new(config: NodeConfig, transport: T, decider: Option<Decider<S, E>>) -> Self {
        let sync = Sync::new(&config.name, config.limits);
        Node {
            config,
            transport,
            sync,
            decider,
        }
    }

    async fn send(&self, outgoing: Vec<Outgoing>) -> Result<(), NodeError> {
        for out in outgoing {
            let key = match &out.target {
                Target::All => Key::new(&format!("weft/{}/sync/all", self.config.tenant)),
                Target::Node(node) => {
                    Key::new(&format!("weft/{}/sync/to/{node}", self.config.tenant))
                }
            };
            // A peer may announce a name that is not a valid segment: drop the reply.
            let Ok(key) = key else { continue };
            match self.transport.publish(&key, &out.message.encode()).await {
                Ok(()) | Err(TransportError::Io(_) | TransportError::TooLarge) => {}
                Err(e @ TransportError::Closed) => return Err(NodeError::Transport(e)),
            }
        }
        Ok(())
    }

    /// Runs a decision round: decide over shared and pending documents, quarantine invalid
    /// ones, share and forward the newly verified. Nodes without a decider (pure relays)
    /// share everything they receive.
    async fn settle(&mut self, observer: &mut impl Observer<S, E>) -> Result<(), NodeError> {
        let mut outcome = None;
        let forward = if let Some(decider) = self.decider.as_mut() {
            let documents = self.sync.documents();
            let result = decider.decide(&documents).map_err(NodeError::Decider)?;
            self.sync.quarantine(&result.quarantine);
            let forward = self.sync.promote(&result.shareable);
            outcome = Some(result);
            forward
        } else {
            let pending: Vec<[u8; 32]> = self.sync.pending().into_iter().collect();
            self.sync.promote(&pending)
        };
        observer.observe(&self.sync, self.decider.as_ref(), outcome.as_ref());
        self.send(forward).await
    }

    /// Runs until the transport closes. `local` carries documents from local sources (USB
    /// stick, technician, local issuer); it may be closed at any time.
    ///
    /// # Errors
    ///
    /// [`NodeError`] if the transport closes, keys are invalid or state cannot be saved.
    ///
    /// @relation(AGT-001, AGT-005, AGT-007, scope=function)
    pub async fn run(
        mut self,
        mut local: mpsc::Receiver<Vec<u8>>,
        observer: &mut impl Observer<S, E>,
    ) -> Result<(), NodeError> {
        sync_keys(&self.config.tenant, &self.config.name).map_err(NodeError::Key)?;
        // Decide once on start: after a restart this re-establishes (or withholds) state.
        self.settle(observer).await?;
        let mut tick = tokio::time::interval(self.config.summary_interval);
        let mut local_open = true;
        loop {
            let new = tokio::select! {
                // Biased: the branch order is fixed, so runs are deterministic.
                biased;
                doc = local.recv(), if local_open => {
                    if let Some(bytes) = doc {
                        self.sync.insert(bytes).into_iter().collect()
                    } else {
                        local_open = false;
                        Vec::new()
                    }
                }
                received = self.transport.recv() => match received {
                    Ok((_, payload)) => match Message::decode(&payload, &self.config.limits) {
                        Some(message) => {
                            let (replies, new) = self.sync.on_message(message);
                            self.send(replies).await?;
                            new
                        }
                        None => Vec::new(),
                    },
                    Err(e @ TransportError::Closed) => return Err(NodeError::Transport(e)),
                    Err(_) => Vec::new(),
                },
                _ = tick.tick() => {
                    self.send(vec![self.sync.summary()]).await?;
                    Vec::new()
                }
            };
            if !new.is_empty() {
                self.settle(observer).await?;
            }
        }
    }
}
