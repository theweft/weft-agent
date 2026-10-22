// SPDX-FileCopyrightText: 2026 The weft authors
// SPDX-License-Identifier: MIT

//! `weft-agent`: the L1 device agent. Reads signed documents from an inbox directory, lets
//! weft-verifier decide, writes configuration and calls the install hook, and reports.
// Doc comments here are clap help texts, shown as plain text: no Markdown backticks.
#![allow(clippy::doc_markdown)]

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use clap::Parser;
use weft_agent::executor::HookExecutor;
use weft_agent::keys::parse_public;
use weft_agent::offline::{OfflineAgent, Paths};
use weft_verifier::{DeviceFacts, TrustAnchor};

#[derive(Parser)]
#[command(
    name = "weft-agent",
    version,
    about = "weft device agent (L1: inbox, decide, execute, report)"
)]
struct Args {
    /// Device name in reports.
    #[arg(long, default_value = "device")]
    name: String,
    /// Tenant of this device.
    #[arg(long, env = "WEFT_TENANT")]
    tenant: String,
    /// Trust anchor public key file from `weft key new` (repeatable).
    #[arg(long = "anchor", required = true)]
    anchors: Vec<PathBuf>,
    /// Device label `key=value` (repeatable).
    #[arg(long = "label", value_name = "KEY=VALUE")]
    labels: Vec<String>,
    /// State directory: documents, verifier state, executed results.
    #[arg(long, default_value = "/var/lib/weft")]
    state_dir: PathBuf,
    /// Directory scanned for new documents (e.g. a USB stick); never modified.
    #[arg(long)]
    inbox: Option<PathBuf>,
    /// Directory for report.json (default: <state-dir>/outbox).
    #[arg(long)]
    outbox: Option<PathBuf>,
    /// Directory for <component>.json configuration files.
    #[arg(long, default_value = "/etc/weft/config")]
    config_dir: PathBuf,
    /// Command run after a configuration file changed (env: WEFT_COMPONENT, WEFT_CONFIG,
    /// WEFT_CONFIG_HASH).
    #[arg(long)]
    on_config: Option<String>,
    /// Command that installs an artifact (env: WEFT_COMPONENT, WEFT_ARTIFACT = SHA-256 hex).
    #[arg(long)]
    on_install: Option<String>,
    /// Use the system clock as a trusted lower bound on time (only with a trusted time source).
    #[arg(long)]
    trust_system_clock: bool,
    /// Run one round and exit.
    #[arg(long)]
    once: bool,
    /// Seconds between rounds.
    #[arg(long, default_value_t = 10)]
    interval: u64,
}

fn run(args: &Args) -> Result<(), String> {
    let anchors = args
        .anchors
        .iter()
        .map(|p| {
            let text = std::fs::read_to_string(p).map_err(|e| format!("{}: {e}", p.display()))?;
            let key = parse_public(&text).map_err(|e| format!("{}: {e}", p.display()))?;
            Ok(TrustAnchor {
                tenant: args.tenant.clone(),
                key,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let labels = args
        .labels
        .iter()
        .map(|l| {
            l.split_once('=')
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .ok_or_else(|| format!("label `{l}`: expected key=value"))
        })
        .collect::<Result<_, String>>()?;
    let clock = || {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs())
    };
    let facts = DeviceFacts {
        tenant: args.tenant.clone(),
        labels,
        trusted_time: if args.trust_system_clock { clock() } else { 0 },
        ..DeviceFacts::default()
    };
    let paths = Paths {
        outbox: args
            .outbox
            .clone()
            .unwrap_or_else(|| args.state_dir.join("outbox")),
        state_dir: args.state_dir.clone(),
        inbox: args.inbox.clone(),
    };
    let executor = HookExecutor {
        config_dir: args.config_dir.clone(),
        on_config: args.on_config.clone(),
        on_install: args.on_install.clone(),
    };
    let mut agent = OfflineAgent::open(&args.name, anchors, facts, &paths, executor)
        .map_err(|e| e.to_string())?;
    loop {
        let report = agent.round().map_err(|e| e.to_string())?;
        let count = |k: &str| report.get(k).and_then(|v| v.as_array()).map_or(0, Vec::len);
        println!(
            "round: {} executed, {} failed, {} conflicts, {} rejected, {} withheld",
            count("executed"),
            count("failed"),
            count("conflicts"),
            count("rejected"),
            count("withheld")
        );
        if args.once {
            return Ok(());
        }
        std::thread::sleep(Duration::from_secs(args.interval));
    }
}

fn main() -> ExitCode {
    match run(&Args::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("weft-agent: {e}");
            ExitCode::FAILURE
        }
    }
}
