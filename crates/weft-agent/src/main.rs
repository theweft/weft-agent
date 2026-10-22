// SPDX-FileCopyrightText: 2026 The weft authors
// SPDX-License-Identifier: MIT

//! `weft-agent`: the L1 device agent. Reads signed documents from an inbox directory, lets
//! weft-verifier decide, writes configuration and calls the install hook, and reports.
//!
//! - `weft-agent run`: everything in one process (development, simple setups).
//! - `weft-agent decider` + `weft-agent executor`: the separated form (weft-design docs/20 §1).
//!   The decider parses all untrusted input and runs without privileges; the executor runs
//!   with privileges and accepts only typed instructions over a Unix socket.
// Doc comments here are clap help texts, shown as plain text: no Markdown backticks.
#![allow(clippy::doc_markdown)]

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use clap::{Args, Parser, Subcommand};
use weft_agent::executor::HookExecutor;
use weft_agent::keys::parse_public;
use weft_agent::offline::{OfflineAgent, Paths};
use weft_decider::Executor;
use weft_verifier::{DeviceFacts, TrustAnchor};

#[derive(Parser)]
#[command(
    name = "weft-agent",
    version,
    about = "weft device agent (L1: inbox, decide, execute, report)"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Decider and executor in one process.
    Run {
        #[command(flatten)]
        decider: DeciderArgs,
        #[command(flatten)]
        executor: ExecutorArgs,
    },
    /// Unprivileged part: inbox, documents, decisions, report. Sends instructions to the executor.
    Decider {
        #[command(flatten)]
        decider: DeciderArgs,
        /// Socket of the executor.
        #[arg(long, default_value = "/run/weft/executor.sock")]
        executor_socket: PathBuf,
    },
    /// Privileged part: performs instructions from the decider, nothing else.
    Executor {
        #[command(flatten)]
        executor: ExecutorArgs,
        /// Socket to listen on (mode 0660; restrict its directory to the decider's group).
        #[arg(long, default_value = "/run/weft/executor.sock")]
        socket: PathBuf,
    },
}

#[derive(Args)]
struct DeciderArgs {
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

#[derive(Args)]
struct ExecutorArgs {
    /// Directory for <component>.json configuration files.
    #[arg(long, env = "WEFT_CONFIG_DIR", default_value = "/etc/weft/config")]
    config_dir: PathBuf,
    /// Command run after a configuration file changed (env: WEFT_COMPONENT, WEFT_CONFIG,
    /// WEFT_CONFIG_HASH).
    #[arg(long, env = "WEFT_ON_CONFIG")]
    on_config: Option<String>,
    /// Command that installs an artifact (env: WEFT_COMPONENT, WEFT_ARTIFACT = SHA-256 hex).
    #[arg(long, env = "WEFT_ON_INSTALL")]
    on_install: Option<String>,
}

impl ExecutorArgs {
    fn hooks(&self) -> HookExecutor {
        HookExecutor {
            config_dir: self.config_dir.clone(),
            on_config: self.on_config.clone(),
            on_install: self.on_install.clone(),
        }
    }
}

fn decide(args: &DeciderArgs, executor: impl Executor) -> Result<(), String> {
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

/// Dispatch. The decider is built without executor options: hooks and directories exist only on
/// the executor's side.
///
/// @relation(AGT-018, scope=function)
fn run(cli: Cli) -> Result<(), String> {
    match cli.command {
        Command::Run { decider, executor } => decide(&decider, executor.hooks()),
        #[cfg(unix)]
        Command::Decider {
            decider,
            executor_socket,
        } => decide(
            &decider,
            weft_agent::ipc::SocketExecutor {
                socket: executor_socket,
            },
        ),
        #[cfg(unix)]
        Command::Executor { executor, socket } => {
            let listener =
                weft_agent::ipc::bind(&socket).map_err(|e| format!("{}: {e}", socket.display()))?;
            println!("executor listening on {}", socket.display());
            weft_agent::ipc::serve(&listener, &mut executor.hooks()).map_err(|e| e.to_string())
        }
        #[cfg(not(unix))]
        Command::Decider { .. } | Command::Executor { .. } => {
            Err("the separated decider/executor needs Unix sockets; use `run`".into())
        }
    }
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("weft-agent: {e}");
            ExitCode::FAILURE
        }
    }
}
