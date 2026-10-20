// SPDX-FileCopyrightText: 2026 The weft authors
// SPDX-License-Identifier: MIT

//! The decider (weft-design docs/20 §1): no network, no privileges.
//!
//! 1. Feeds all stored documents to `weft_verifier::step`.
//! 2. **Persists the new verifier state before acting** (docs/11), so a crash can never act
//!    on a decision whose anti-rollback state was lost.
//! 3. Hands each instruction to the [`Executor`] and records what is now installed and applied.
//! 4. Reports which documents are intrinsically invalid, so sync can quarantine them.

use std::fmt;

use weft_verifier::cbor::Limits;
use weft_verifier::state::StateError;
use weft_verifier::{
    Decisions, DeviceFacts, Instruction, Reason, TrustAnchor, VerifierState, step,
};

/// SHA-256 of a document's bytes.
pub type Digest = [u8; 32];

/// Where the verifier state lives. `save` must replace the old state atomically (docs/11:
/// write a temporary file, fsync, rename, fsync the directory).
pub trait StateStore {
    /// The last saved state, or `None` on first start.
    ///
    /// # Errors
    ///
    /// [`StoreError`] if the store cannot be read.
    fn load(&self) -> Result<Option<Vec<u8>>, StoreError>;

    /// Atomically replaces the saved state.
    ///
    /// # Errors
    ///
    /// [`StoreError`] if the state was not durably saved.
    fn save(&mut self, state: &[u8]) -> Result<(), StoreError>;
}

/// A storage failure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoreError(pub String);

/// Performs instructions (weft-design docs/20 §4). Accepts nothing but [`Instruction`]s.
pub trait Executor {
    /// Performs one instruction.
    ///
    /// # Errors
    ///
    /// [`ExecError`] if the instruction was not (fully) performed.
    fn execute(&mut self, instruction: &Instruction) -> Result<(), ExecError>;
}

/// An execution failure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecError(pub String);

/// Decider failures. On any of these, nothing was executed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DeciderError {
    /// The state store failed.
    Store(StoreError),
    /// The saved state is corrupt. The decider refuses to start from an empty state, which
    /// would silently drop anti-rollback marks.
    CorruptState,
}

impl fmt::Display for DeciderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DeciderError::Store(e) => write!(f, "state store: {}", e.0),
            DeciderError::CorruptState => f.write_str("saved verifier state is corrupt"),
        }
    }
}

impl std::error::Error for DeciderError {}

impl From<StoreError> for DeciderError {
    fn from(e: StoreError) -> Self {
        DeciderError::Store(e)
    }
}

impl From<StateError> for DeciderError {
    fn from(_: StateError) -> Self {
        DeciderError::CorruptState
    }
}

/// The result of one decision round.
#[derive(Clone, Debug)]
pub struct Outcome {
    /// The verifier's decisions.
    pub decisions: Decisions,
    /// Digests that can never become valid (malformed, bad signature, wrong tenant).
    pub quarantine: Vec<Digest>,
    /// Digests that are verified and may be shared with other nodes: accepted, superseded,
    /// ignored, and rejected only for rollback, revocation, expiry or equivocation.
    pub shareable: Vec<Digest>,
    /// Instructions performed successfully.
    pub executed: Vec<Instruction>,
    /// Instructions that failed, with the reason.
    pub failed: Vec<(Instruction, ExecError)>,
}

/// Rejections that depend only on the document itself, not on this node's state. Others
/// (unknown signer, rollback, revoked, expired, equivocation) can change or are evidence, so
/// those documents stay and keep travelling.
///
/// @relation(AGT-003, scope=function)
fn is_intrinsic(reason: Reason) -> bool {
    matches!(
        reason,
        Reason::Malformed | Reason::BadSignature | Reason::WrongTenant
    )
}

/// Whether a rejected document may still travel: its signature chain was valid once, and the
/// reason depends on this node's state (rollback, expiry) or is evidence (equivocation,
/// revoked keys, whose documents must stay present so marks do not block, docs/07). Unknown
/// signers and unauthorized documents stay local: anyone could produce them.
///
/// @relation(AGT-003, scope=function)
fn is_shareable(reason: Reason) -> bool {
    matches!(
        reason,
        Reason::Rollback | Reason::Revoked | Reason::Expired | Reason::Equivocation
    )
}

/// The decider of one device.
pub struct Decider<S, E> {
    anchors: Vec<TrustAnchor>,
    facts: DeviceFacts,
    state: VerifierState,
    store: S,
    executor: E,
}

impl<S: StateStore, E: Executor> Decider<S, E> {
    /// Loads the saved state (or starts empty on first start).
    ///
    /// # Errors
    ///
    /// [`DeciderError`] if the store fails or the saved state is corrupt.
    ///
    /// @relation(AGT-006, scope=function)
    pub fn new(
        anchors: Vec<TrustAnchor>,
        facts: DeviceFacts,
        store: S,
        executor: E,
    ) -> Result<Self, DeciderError> {
        let state = match store.load()? {
            Some(bytes) => VerifierState::from_cbor(&bytes)?,
            None => VerifierState::default(),
        };
        Ok(Decider {
            anchors,
            facts,
            state,
            store,
            executor,
        })
    }

    /// One decision round over all `documents` the node holds.
    ///
    /// # Errors
    ///
    /// [`DeciderError::Store`] if the new state could not be saved; then nothing is executed
    /// and the in-memory state is unchanged.
    ///
    /// @relation(AGT-004, scope=function)
    pub fn decide(&mut self, documents: &[&[u8]]) -> Result<Outcome, DeciderError> {
        let (next, decisions) = step(
            &self.state,
            &self.anchors,
            &self.facts,
            documents,
            &Limits::DEFAULT,
        );
        if next != self.state {
            let bytes = next.to_cbor().map_err(|_| DeciderError::CorruptState)?;
            self.store.save(&bytes)?;
        }
        self.state = next;

        let mut executed = Vec::new();
        let mut failed = Vec::new();
        for instruction in &decisions.actions {
            match self.executor.execute(instruction) {
                Ok(()) => {
                    match instruction {
                        Instruction::Install {
                            component,
                            artifact,
                        } => {
                            self.facts.installed.insert(component.clone(), *artifact);
                        }
                        Instruction::ApplyConfig {
                            component, hash, ..
                        } => {
                            self.facts.applied_config.insert(component.clone(), *hash);
                        }
                    }
                    executed.push(instruction.clone());
                }
                Err(e) => failed.push((instruction.clone(), e)),
            }
        }
        let quarantine = decisions
            .rejected
            .iter()
            .filter(|r| is_intrinsic(r.reason))
            .map(|r| r.digest)
            .collect();
        let shareable = decisions
            .accepted
            .iter()
            .chain(&decisions.superseded)
            .chain(&decisions.ignored)
            .copied()
            .chain(
                decisions
                    .rejected
                    .iter()
                    .filter(|r| is_shareable(r.reason))
                    .map(|r| r.digest),
            )
            .collect();
        Ok(Outcome {
            decisions,
            quarantine,
            shareable,
            executed,
            failed,
        })
    }
}

impl<S, E> Decider<S, E> {
    /// The current verifier state.
    pub fn state(&self) -> &VerifierState {
        &self.state
    }

    /// The device facts, including what is installed and applied.
    pub fn facts(&self) -> &DeviceFacts {
        &self.facts
    }

    /// Updates the trusted lower bound on time (from NTS, Roughtime or the RTC, docs/11).
    pub fn set_trusted_time(&mut self, seconds: u64) {
        self.facts.trusted_time = self.facts.trusted_time.max(seconds);
    }

    /// The executor.
    pub fn executor(&self) -> &E {
        &self.executor
    }
}
