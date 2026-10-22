// SPDX-FileCopyrightText: 2026 The weft authors
// SPDX-License-Identifier: MIT

//! The L1 agent: no weft networking. Documents arrive through an inbox directory (a USB stick,
//! or files dropped by the adopter's own transport); the result goes to an outbox report.
//!
//! One [`OfflineAgent::round`]:
//!
//! 1. scan the inbox; store new documents in the document directory (before deciding);
//! 2. decide (the decider saves the verifier state before executing anything);
//! 3. delete quarantined documents; save what was executed;
//! 4. write `report.json` to the outbox, atomically.
//!
//! Directory layout under the state directory: `documents/`, `verifier-state`, `executed`.

use std::fmt;
use std::path::{Path, PathBuf};

use serde_json::{Value as Json, json};
use weft_decider::{
    Decider, DeciderError, Executor, FileStore, Outcome, StateStore, StdFs, write_atomic,
};
use weft_sync::{Limits, Sync};
use weft_verifier::{DeviceFacts, Instruction, TrustAnchor};

use crate::hex;
use crate::storage::{DocumentDir, Executed, scan_inbox};

/// Where the agent keeps its files.
#[derive(Clone, Debug)]
pub struct Paths {
    /// Documents, verifier state and executed results.
    pub state_dir: PathBuf,
    /// Scanned read-only for new documents.
    pub inbox: Option<PathBuf>,
    /// `report.json` goes here.
    pub outbox: PathBuf,
}

/// Agent failures. A round that fails executes nothing it has not durably recorded.
#[derive(Debug)]
pub enum AgentError {
    /// A file could not be read or written.
    Io(String),
    /// The decider could not save or load its state.
    Decider(DeciderError),
}

impl fmt::Display for AgentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AgentError::Io(e) => f.write_str(e),
            AgentError::Decider(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for AgentError {}

fn io(what: &str, path: &Path, e: &std::io::Error) -> AgentError {
    AgentError::Io(format!("{what} {}: {e}", path.display()))
}

/// The L1 agent of one device.
pub struct OfflineAgent<E> {
    name: String,
    sync: Sync,
    docs: DocumentDir<StdFs>,
    decider: Decider<FileStore, E>,
    executed_store: FileStore,
    inbox: Option<PathBuf>,
    outbox: PathBuf,
    limits: Limits,
}

impl<E: Executor> OfflineAgent<E> {
    /// Opens (or creates) the state directory and loads documents, state and results.
    ///
    /// # Errors
    ///
    /// [`AgentError`] if directories cannot be created or saved files are damaged.
    ///
    /// @relation(AGT-012, AGT-016, scope=function)
    pub fn open(
        name: &str,
        anchors: Vec<TrustAnchor>,
        mut facts: DeviceFacts,
        paths: &Paths,
        executor: E,
    ) -> Result<Self, AgentError> {
        let documents = paths.state_dir.join("documents");
        for dir in [&documents, &paths.outbox] {
            std::fs::create_dir_all(dir).map_err(|e| io("creating", dir, &e))?;
        }
        let limits = Limits::DEFAULT;
        let (docs, stored) = DocumentDir::open(StdFs, &documents, limits.max_document)
            .map_err(|e| io("reading", &documents, &e))?;
        let mut sync = Sync::new(name, limits);
        for doc in stored {
            sync.insert(doc);
        }
        let executed_store = FileStore::new(paths.state_dir.join("executed"));
        let executed = match executed_store.load() {
            Ok(Some(bytes)) => Executed::decode(&bytes)
                .ok_or_else(|| AgentError::Io("executed results are damaged".into()))?,
            Ok(None) => Executed::default(),
            Err(e) => return Err(AgentError::Io(e.0)),
        };
        facts.installed = executed.installed;
        facts.applied_config = executed.applied;
        let decider = Decider::new(
            anchors,
            facts,
            FileStore::new(paths.state_dir.join("verifier-state")),
            executor,
        )
        .map_err(AgentError::Decider)?;
        Ok(OfflineAgent {
            name: name.to_string(),
            sync,
            docs,
            decider,
            executed_store,
            inbox: paths.inbox.clone(),
            outbox: paths.outbox.clone(),
            limits,
        })
    }

    /// One round: inbox, decide, execute, persist, report. Returns the report.
    ///
    /// # Errors
    ///
    /// [`AgentError`] on I/O or state errors; nothing is executed after a failed save.
    ///
    /// @relation(AGT-011, AGT-012, AGT-013, AGT-016, scope=function)
    pub fn round(&mut self) -> Result<Json, AgentError> {
        if let Some(inbox) = &self.inbox {
            let candidates = scan_inbox(&StdFs, inbox, self.limits.max_document)
                .map_err(|e| io("scanning", inbox, &e))?;
            for bytes in candidates {
                if self.sync.insert(bytes.clone()).is_some() {
                    // Stored before the decider sees it (see `storage`).
                    self.docs
                        .put(&bytes)
                        .map_err(|e| AgentError::Io(format!("storing a document: {e}")))?;
                }
            }
        }
        let outcome = self
            .decider
            .decide(&self.sync.documents())
            .map_err(AgentError::Decider)?;
        self.sync.quarantine(&outcome.quarantine);
        for d in &outcome.quarantine {
            self.docs
                .remove(d)
                .map_err(|e| AgentError::Io(format!("removing a document: {e}")))?;
        }
        self.sync.promote(&outcome.shareable);
        if !outcome.executed.is_empty() {
            let facts = self.decider.facts();
            let executed = Executed {
                installed: facts.installed.clone(),
                applied: facts.applied_config.clone(),
            };
            self.executed_store
                .save(&executed.encode())
                .map_err(|e| AgentError::Io(e.0))?;
        }
        let report = self.report(&outcome);
        let path = self.outbox.join("report.json");
        let text = serde_json::to_string_pretty(&report).unwrap_or_default();
        write_atomic(&StdFs, &path, format!("{text}\n").as_bytes())
            .map_err(|e| io("writing", &path, &e))?;
        Ok(report)
    }

    /// The reported state (weft-design docs/05 §2.3b), in plain JSON for the adopter's tools.
    fn report(&self, outcome: &Outcome) -> Json {
        let d = &outcome.decisions;
        let facts = self.decider.facts();
        let hexes = |v: &[[u8; 32]]| v.iter().map(|x| hex(x)).collect::<Vec<_>>();
        let instruction = |i: &Instruction| match i {
            Instruction::Install {
                component,
                artifact,
            } => json!({"install": component, "artifact": hex(artifact)}),
            Instruction::ApplyConfig {
                component, hash, ..
            } => json!({"apply_config": component, "hash": hex(hash)}),
        };
        json!({
            "node": self.name,
            "time_floor": self.decider.state().time_floor,
            "installed": facts.installed.iter().map(|(k, v)| (k.clone(), Json::String(hex(v)))).collect::<serde_json::Map<_, _>>(),
            "applied_config": facts.applied_config.iter().map(|(k, v)| (k.clone(), Json::String(hex(v)))).collect::<serde_json::Map<_, _>>(),
            "executed": outcome.executed.iter().map(instruction).collect::<Vec<_>>(),
            "failed": outcome.failed.iter().map(|(i, e)| json!({"action": instruction(i), "error": e.0})).collect::<Vec<_>>(),
            "conflicts": d.conflicts.iter().map(|c| json!({
                "id": hex(&c.id),
                "kind": format!("{:?}", c.kind),
                "component": c.component,
                "path": c.path.join("/"),
                "priority": c.priority,
            })).collect::<Vec<_>>(),
            "withheld": d.withheld,
            "accepted": hexes(&d.accepted),
            "rejected": d.rejected.iter().map(|r| json!({"document": hex(&r.digest), "reason": format!("{:?}", r.reason)})).collect::<Vec<_>>(),
            "pending": self.sync.pending().iter().map(|x| hex(x)).collect::<Vec<_>>(),
            // Stays listed after the round that rejected them (they are not seen again).
            "quarantined": self.sync.quarantined().iter().map(|x| hex(x)).collect::<Vec<_>>(),
        })
    }

    /// The decider (state and facts).
    pub fn decider(&self) -> &Decider<FileStore, E> {
        &self.decider
    }
}
