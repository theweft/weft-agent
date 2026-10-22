// SPDX-FileCopyrightText: 2026 The weft authors
// SPDX-License-Identifier: MIT

//! The first executor backends (weft-design docs/20 §4), for L1: the adopter keeps their own
//! OTA tool and services.
//!
//! - **Config**: the effective configuration is written as JSON to
//!   `<config-dir>/<component>.json` (atomically), then the optional `on_config` hook runs.
//! - **Install**: the `on_install` hook runs; it hands the artifact digest to the adopter's own
//!   OTA tool (`SWUpdate`, Mender, a script). Without a hook, installs fail and are reported.
//!
//! Hooks are commands from the local configuration (trusted). Values from documents reach them
//! only as environment variables, never interpolated into the command: `WEFT_COMPONENT`,
//! `WEFT_CONFIG`, `WEFT_CONFIG_HASH`, `WEFT_ARTIFACT`. Delivery is at least once: after a crash
//! between running a hook and saving the result, the hook runs again, so hooks must be
//! idempotent.

use std::path::{Path, PathBuf};
use std::process::Command;

use weft_decider::{ExecError, Executor, StdFs, write_atomic};
use weft_verifier::Instruction;
use weft_verifier::cbor::{self, Limits};
use weft_verifier::crypto::sha256;

use crate::{hex, json};

/// Config files and hook commands.
#[derive(Clone, Debug)]
pub struct HookExecutor {
    /// Directory for `<component>.json` files.
    pub config_dir: PathBuf,
    /// Run after a config file was written.
    pub on_config: Option<String>,
    /// Run to install an artifact.
    pub on_install: Option<String>,
}

/// `<dir>/<segments>.json` for a component like `app/pump`; only `[A-Za-z0-9._-]` segments,
/// never `.` or `..`, so a component name cannot leave `dir`.
///
/// # Errors
///
/// [`ExecError`] for components that are not safe paths.
///
/// @relation(AGT-014, scope=function)
pub fn config_path(dir: &Path, component: &str) -> Result<PathBuf, ExecError> {
    let mut path = dir.to_path_buf();
    let segments: Vec<&str> = component.split('/').collect();
    for (i, segment) in segments.iter().enumerate() {
        let valid = !segment.is_empty()
            && *segment != "."
            && *segment != ".."
            && segment
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b));
        if !valid {
            return Err(ExecError(format!(
                "component `{component}` is not a safe path"
            )));
        }
        if i + 1 == segments.len() {
            path.push(format!("{segment}.json"));
        } else {
            path.push(segment);
        }
    }
    Ok(path)
}

fn run_hook(command: &str, env: &[(&str, String)]) -> Result<(), ExecError> {
    #[cfg(unix)]
    let mut cmd = {
        let mut c = Command::new("sh");
        c.arg("-c").arg(command);
        c
    };
    #[cfg(not(unix))]
    let mut cmd = {
        let mut c = Command::new("cmd");
        c.arg("/C").arg(command);
        c
    };
    for (k, v) in env {
        cmd.env(k, v);
    }
    let status = cmd
        .status()
        .map_err(|e| ExecError(format!("hook `{command}`: {e}")))?;
    if status.success() {
        Ok(())
    } else {
        Err(ExecError(format!("hook `{command}` failed: {status}")))
    }
}

impl Executor for HookExecutor {
    /// @relation(AGT-014, AGT-015, scope=function)
    fn execute(&mut self, instruction: &Instruction) -> Result<(), ExecError> {
        match instruction {
            Instruction::ApplyConfig {
                component,
                hash,
                config,
            } => {
                if sha256(config) != *hash {
                    return Err(ExecError(format!(
                        "config of {component} does not match its hash"
                    )));
                }
                let value = cbor::decode(config, &Limits::DEFAULT)
                    .map_err(|e| ExecError(format!("config of {component}: {e:?}")))?;
                let text = serde_json::to_string_pretty(&json::to_json(&value))
                    .map_err(|e| ExecError(e.to_string()))?;
                let path = config_path(&self.config_dir, component)?;
                if let Some(parent) = path.parent() {
                    std::fs::create_dir_all(parent)
                        .map_err(|e| ExecError(format!("{}: {e}", parent.display())))?;
                }
                write_atomic(&StdFs, &path, format!("{text}\n").as_bytes())
                    .map_err(|e| ExecError(format!("{}: {e}", path.display())))?;
                if let Some(hook) = &self.on_config {
                    run_hook(
                        hook,
                        &[
                            ("WEFT_COMPONENT", component.clone()),
                            ("WEFT_CONFIG", path.display().to_string()),
                            ("WEFT_CONFIG_HASH", hex(hash)),
                        ],
                    )?;
                }
                Ok(())
            }
            Instruction::Install {
                component,
                artifact,
            } => {
                let hook = self
                    .on_install
                    .as_ref()
                    .ok_or_else(|| ExecError("no install hook configured".into()))?;
                run_hook(
                    hook,
                    &[
                        ("WEFT_COMPONENT", component.clone()),
                        ("WEFT_ARTIFACT", hex(artifact)),
                    ],
                )
            }
        }
    }
}
