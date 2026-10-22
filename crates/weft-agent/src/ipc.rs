// SPDX-FileCopyrightText: 2026 The weft authors
// SPDX-License-Identifier: MIT

//! Decider ↔ executor over a Unix socket (weft-design docs/20 §1, gap G10).
//!
//! The decider runs without privileges and parses all untrusted input; the executor runs with
//! privileges and accepts exactly two typed requests:
//!
//! ```text
//! request  = [0, component, config-hash, config]     ; apply configuration
//!          / [1, component, artifact-digest]          ; install an artifact
//! response = [0] / [1, error-text]
//! frame    = u32 big-endian length, then deterministic CBOR (at most 1 MiB)
//! ```
//!
//! The executor re-checks what it can: the configuration hash, and the component name before
//! it becomes a path. Hooks and directories are the executor's own configuration; the decider
//! cannot name a command. Access to the socket is controlled by its file permissions (the
//! systemd units in `dist/systemd/`).

use std::io::{self, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};

use weft_decider::{ExecError, Executor};
use weft_verifier::Instruction;
use weft_verifier::cbor::{self, Limits, Value};
use weft_verifier::crypto::sha256;

/// Largest frame in bytes.
pub const MAX_FRAME: usize = 1024 * 1024;

const FRAME_LIMITS: Limits = Limits {
    max_len: MAX_FRAME,
    max_depth: 2,
    max_items: 8,
};

fn write_frame(stream: &mut UnixStream, value: &Value) -> io::Result<()> {
    let bytes = cbor::encode(value).map_err(|e| io::Error::other(format!("{e:?}")))?;
    let len = u32::try_from(bytes.len())
        .ok()
        .filter(|l| *l as usize <= MAX_FRAME)
        .ok_or_else(|| io::Error::other("frame too large"))?;
    stream.write_all(&len.to_be_bytes())?;
    stream.write_all(&bytes)?;
    stream.flush()
}

/// Reads one frame; `Ok(None)` at a clean end of the stream.
fn read_frame(stream: &mut UnixStream) -> io::Result<Option<Value>> {
    let mut len = [0u8; 4];
    match stream.read_exact(&mut len) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = u32::from_be_bytes(len) as usize;
    if len > MAX_FRAME {
        return Err(io::Error::other("frame too large"));
    }
    let mut bytes = vec![0u8; len];
    stream.read_exact(&mut bytes)?;
    cbor::decode(&bytes, &FRAME_LIMITS)
        .map(Some)
        .map_err(|e| io::Error::other(format!("malformed frame: {e:?}")))
}

/// Encodes an instruction as a request.
pub fn encode_request(instruction: &Instruction) -> Value {
    match instruction {
        Instruction::ApplyConfig {
            component,
            hash,
            config,
        } => Value::Array(vec![
            Value::Int(0),
            Value::text(component),
            Value::Bytes(hash.to_vec()),
            Value::Bytes(config.clone()),
        ]),
        Instruction::Install {
            component,
            artifact,
        } => Value::Array(vec![
            Value::Int(1),
            Value::text(component),
            Value::Bytes(artifact.to_vec()),
        ]),
    }
}

/// Decodes and checks a request; anything else is refused.
///
/// # Errors
///
/// [`ExecError`] for unknown, malformed or inconsistent requests (config hash mismatch).
///
/// @relation(AGT-017, scope=function)
pub fn decode_request(value: &Value) -> Result<Instruction, ExecError> {
    let refuse = |why: &str| ExecError(format!("refused request: {why}"));
    let Value::Array(parts) = value else {
        return Err(refuse("not an array"));
    };
    let digest = |v: &Value| {
        v.as_bytes()
            .and_then(|b| <[u8; 32]>::try_from(b).ok())
            .ok_or_else(|| refuse("digest must be 32 bytes"))
    };
    match parts.as_slice() {
        [
            Value::Int(0),
            Value::Text(component),
            hash,
            Value::Bytes(config),
        ] => {
            let hash = digest(hash)?;
            if sha256(config) != hash {
                return Err(refuse("configuration does not match its hash"));
            }
            Ok(Instruction::ApplyConfig {
                component: component.clone(),
                hash,
                config: config.clone(),
            })
        }
        [Value::Int(1), Value::Text(component), artifact] => Ok(Instruction::Install {
            component: component.clone(),
            artifact: digest(artifact)?,
        }),
        _ => Err(refuse("unknown request")),
    }
}

/// The decider's side: an [`Executor`] that forwards instructions to the executor process.
#[derive(Clone, Debug)]
pub struct SocketExecutor {
    /// Path of the executor's socket.
    pub socket: PathBuf,
}

impl Executor for SocketExecutor {
    /// @relation(AGT-017, AGT-019, scope=function)
    fn execute(&mut self, instruction: &Instruction) -> Result<(), ExecError> {
        let failed = |e: io::Error| ExecError(format!("executor {}: {e}", self.socket.display()));
        let mut stream = UnixStream::connect(&self.socket).map_err(failed)?;
        write_frame(&mut stream, &encode_request(instruction)).map_err(failed)?;
        let response = read_frame(&mut stream)
            .map_err(failed)?
            .ok_or_else(|| ExecError("executor closed the connection".into()))?;
        match response.as_array() {
            Some([Value::Int(0)]) => Ok(()),
            Some([Value::Int(1), Value::Text(error)]) => Err(ExecError(error.clone())),
            _ => Err(ExecError("malformed response from the executor".into())),
        }
    }
}

/// Binds the executor socket, replacing a stale socket file, readable and writable by owner
/// and group only.
///
/// # Errors
///
/// I/O errors.
pub fn bind(path: &Path) -> io::Result<UnixListener> {
    use std::os::unix::fs::PermissionsExt;
    if path.exists() {
        std::fs::remove_file(path)?;
    }
    let listener = UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))?;
    Ok(listener)
}

/// The executor's side: serves connections one at a time, forever. Each request is decoded,
/// checked and handed to `inner`; malformed frames close the connection.
///
/// # Errors
///
/// Only if accepting connections fails.
///
/// @relation(AGT-017, scope=function)
pub fn serve(listener: &UnixListener, inner: &mut impl Executor) -> io::Result<()> {
    loop {
        let (mut stream, _) = listener.accept()?;
        // One bad client must not stop the executor.
        let _ = serve_connection(&mut stream, inner);
    }
}

/// Serves one connection until it closes.
///
/// # Errors
///
/// I/O errors and malformed frames (the connection should then be dropped).
pub fn serve_connection(stream: &mut UnixStream, inner: &mut impl Executor) -> io::Result<()> {
    while let Some(request) = read_frame(stream)? {
        let result = decode_request(&request).and_then(|i| inner.execute(&i));
        let response = match result {
            Ok(()) => Value::Array(vec![Value::Int(0)]),
            Err(e) => Value::Array(vec![Value::Int(1), Value::text(&e.0)]),
        };
        write_frame(stream, &response)?;
    }
    Ok(())
}
