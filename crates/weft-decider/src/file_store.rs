// SPDX-FileCopyrightText: 2026 The weft authors
// SPDX-License-Identifier: MIT

//! The verifier state as a file that survives power loss (weft-design docs/11).
//!
//! Saving follows the classic protocol:
//!
//! 1. write the new state to `<file>.tmp` and `fsync` it;
//! 2. `rename` it over `<file>` (atomic: readers see the old or the new file, never a mix);
//! 3. `fsync` the directory, so the rename itself is durable.
//!
//! After `save` returns, the new state survives a crash; before, the old one does. The file is
//! framed with a magic line and a SHA-256 of the payload, so bit rot is detected (and the
//! decider refuses to start) instead of being loaded as a different, older state.
//!
//! Filesystem access goes through [`Fs`], so simulations can substitute a filesystem that
//! models crashes (turmoil's simulated filesystem in this crate's tests).

use std::io;
use std::path::{Path, PathBuf};

use weft_verifier::crypto::sha256;

use crate::{StateStore, StoreError};

const MAGIC: &[u8] = b"weft-state-v1\n";

/// The filesystem operations the protocol needs.
pub trait Fs {
    /// The file's contents, or `None` if it does not exist.
    ///
    /// # Errors
    ///
    /// Any I/O error other than "not found".
    fn read(&self, path: &Path) -> io::Result<Option<Vec<u8>>>;

    /// Creates or truncates `path`, writes `bytes` and syncs the file's data to stable storage.
    ///
    /// # Errors
    ///
    /// Any I/O error; then nothing about the file's contents is guaranteed.
    fn write_synced(&self, path: &Path, bytes: &[u8]) -> io::Result<()>;

    /// Atomically replaces `to` with `from`.
    ///
    /// # Errors
    ///
    /// Any I/O error.
    fn rename(&self, from: &Path, to: &Path) -> io::Result<()>;

    /// Makes directory changes (the rename) in `dir` durable.
    ///
    /// # Errors
    ///
    /// Any I/O error.
    fn sync_dir(&self, dir: &Path) -> io::Result<()>;
}

/// The operating system's filesystem.
#[derive(Clone, Copy, Debug, Default)]
pub struct StdFs;

impl Fs for StdFs {
    fn read(&self, path: &Path) -> io::Result<Option<Vec<u8>>> {
        match std::fs::read(path) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn write_synced(&self, path: &Path, bytes: &[u8]) -> io::Result<()> {
        use std::io::Write;
        let mut file = std::fs::File::create(path)?;
        file.write_all(bytes)?;
        file.sync_all()
    }

    fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
        std::fs::rename(from, to)
    }

    #[cfg(unix)]
    fn sync_dir(&self, dir: &Path) -> io::Result<()> {
        std::fs::File::open(dir)?.sync_all()
    }

    /// Windows has no directory fsync; NTFS journals the rename itself.
    #[cfg(not(unix))]
    fn sync_dir(&self, _dir: &Path) -> io::Result<()> {
        Ok(())
    }
}

/// Verifier state in one file, saved atomically and durably.
#[derive(Clone, Debug)]
pub struct FileStore<F = StdFs> {
    fs: F,
    path: PathBuf,
}

impl FileStore<StdFs> {
    /// A store at `path` on the real filesystem. The directory must exist.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        FileStore {
            fs: StdFs,
            path: path.into(),
        }
    }
}

impl<F: Fs> FileStore<F> {
    /// A store at `path` on `fs`.
    pub fn with_fs(fs: F, path: impl Into<PathBuf>) -> Self {
        FileStore {
            fs,
            path: path.into(),
        }
    }

    fn temporary(&self) -> PathBuf {
        let mut name = self.path.clone().into_os_string();
        name.push(".tmp");
        PathBuf::from(name)
    }

    fn directory(&self) -> PathBuf {
        match self.path.parent() {
            Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
            _ => PathBuf::from("."),
        }
    }
}

/// Frames `payload`: magic, SHA-256, payload.
fn frame(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(MAGIC.len() + 32 + payload.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&sha256(payload));
    out.extend_from_slice(payload);
    out
}

/// The payload of a framed file, or `None` if it is damaged.
fn unframe(bytes: &[u8]) -> Option<&[u8]> {
    let rest = bytes.strip_prefix(MAGIC)?;
    let (digest, payload) = rest.split_at_checked(32)?;
    (sha256(payload).as_slice() == digest).then_some(payload)
}

fn io_error(what: &str, path: &Path, e: &io::Error) -> StoreError {
    StoreError(format!("{what} {}: {e}", path.display()))
}

impl<F: Fs> StateStore for FileStore<F> {
    /// @relation(AGT-010, scope=function)
    fn load(&self) -> Result<Option<Vec<u8>>, StoreError> {
        match self.fs.read(&self.path) {
            Ok(None) => Ok(None),
            Ok(Some(bytes)) => match unframe(&bytes) {
                Some(payload) => Ok(Some(payload.to_vec())),
                None => Err(StoreError(format!(
                    "{} is damaged (checksum mismatch)",
                    self.path.display()
                ))),
            },
            Err(e) => Err(io_error("reading", &self.path, &e)),
        }
    }

    /// @relation(AGT-010, scope=function)
    fn save(&mut self, state: &[u8]) -> Result<(), StoreError> {
        let tmp = self.temporary();
        self.fs
            .write_synced(&tmp, &frame(state))
            .map_err(|e| io_error("writing", &tmp, &e))?;
        self.fs
            .rename(&tmp, &self.path)
            .map_err(|e| io_error("renaming", &tmp, &e))?;
        let dir = self.directory();
        self.fs
            .sync_dir(&dir)
            .map_err(|e| io_error("syncing", &dir, &e))
    }
}
