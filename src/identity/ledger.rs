//! Immutable local storage for RFC 1 identity and repository-control events.

use std::{
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use atproto_dasl::Cid;

use super::control::{decode_preserving, ControlEvent, PreservedControlEvent};

pub const SURFACE_VALUES: &[crate::surface::SurfaceValue] = &[
    crate::surface::SurfaceValue::new("identity-ledger:events/*.cbor", "canonical-control-event"),
    crate::surface::SurfaceValue::new("identity-ledger:events/.tmp-*", "atomic-install"),
];

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone)]
pub struct IdentityLedger {
    root: PathBuf,
}

impl IdentityLedger {
    /// Point at the exact `identity/ledger` directory. Merely constructing or
    /// reading a ledger never creates it.
    pub fn at(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Append a supported typed event without changing its canonical bytes.
    pub fn append(&self, event: &ControlEvent) -> Result<Cid, Error> {
        self.append_canonical(&event.canonical_bytes()?)
    }

    /// Append canonical bytes received through the lossless control boundary.
    /// The proved-event CID names the immutable file, so proof variants for one
    /// logical event coexist instead of overwriting one another.
    pub fn append_canonical(&self, bytes: &[u8]) -> Result<Cid, Error> {
        let preserved = decode_preserving(bytes)?;
        let proved = preserved.proved_cid()?;
        let events = self.root.join("events");
        let destination = events.join(format!("{proved}.cbor"));
        if existing_file(&destination)? {
            verify_existing(&destination, bytes)?;
            return Ok(proved);
        }

        existing_directory_or_absent(&events)?;

        // surface-write: identity-ledger:events/*.cbor,identity-ledger:events/.tmp-*
        crate::persistence::create_dir_all(
            crate::persistence::SurfaceWrite::IdentityLedger,
            &events,
        )?;
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let temporary = events.join(format!(".tmp-{}-{sequence}-{}", std::process::id(), proved));
        // surface-write: identity-ledger:events/.tmp-*
        crate::persistence::write(
            crate::persistence::SurfaceWrite::IdentityLedger,
            &temporary,
            bytes,
        )?;
        // surface-write: identity-ledger:events/*.cbor,identity-ledger:events/.tmp-*
        if let Err(error) = crate::persistence::rename(
            crate::persistence::SurfaceWrite::IdentityLedger,
            &temporary,
            &destination,
        ) {
            // surface-write: identity-ledger:events/.tmp-*
            let _ = crate::persistence::remove_file(
                crate::persistence::SurfaceWrite::IdentityLedger,
                &temporary,
            );
            if existing_file(&destination)? {
                verify_existing(&destination, bytes)?;
                return Ok(proved);
            }
            return Err(error.into());
        }
        Ok(proved)
    }

    /// Read every retained proof variant in proved-CID order. Temporary files
    /// from interrupted installs are derived residue and never evidence.
    pub fn read_all(&self) -> Result<Vec<PreservedControlEvent>, Error> {
        let events = self.root.join("events");
        if !existing_directory_or_absent(&events)? {
            return Ok(Vec::new());
        }
        let mut entries = Vec::new();
        for entry in std::fs::read_dir(&events)? {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with(".tmp-") {
                continue;
            }
            if entry.file_type()?.is_symlink() || !entry.file_type()?.is_file() {
                return Err(Error::UnexpectedEntry(name.into_owned()));
            }
            let Some(cid_text) = name.strip_suffix(".cbor") else {
                return Err(Error::UnexpectedEntry(name.into_owned()));
            };
            let expected: Cid = cid_text
                .parse()
                .map_err(|_| Error::UnexpectedEntry(name.into_owned()))?;
            let bytes = std::fs::read(entry.path())?;
            let preserved = decode_preserving(&bytes)?;
            let actual = preserved.proved_cid()?;
            if actual != expected {
                return Err(Error::IdentifierMismatch {
                    expected: expected.to_string(),
                    actual: actual.to_string(),
                });
            }
            entries.push((actual, preserved));
        }
        entries.sort_by_key(|entry| entry.0.to_bytes());
        Ok(entries.into_iter().map(|(_, event)| event).collect())
    }
}

fn verify_existing(path: &Path, expected: &[u8]) -> Result<(), Error> {
    let actual = std::fs::read(path)?;
    if actual != expected {
        return Err(Error::ContentAddressCollision(path.to_path_buf()));
    }
    Ok(())
}

fn existing_file(path: &Path) -> Result<bool, Error> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            Err(Error::UnsafeEntry(path.to_path_buf()))
        }
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn existing_directory_or_absent(path: &Path) -> Result<bool, Error> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            Err(Error::UnsafeEntry(path.to_path_buf()))
        }
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("identity ledger I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("identity ledger control event is invalid: {0}")]
    Decode(#[from] super::control::DecodeError),
    #[error("identity ledger control envelope is invalid: {0}")]
    Control(#[from] super::control::Error),
    #[error("identity ledger CID calculation failed: {0}")]
    Cid(#[from] crate::cid::Error),
    #[error("unexpected identity ledger entry: {0}")]
    UnexpectedEntry(String),
    #[error("identity ledger path is a symlink or has the wrong file type: {0}")]
    UnsafeEntry(PathBuf),
    #[error("identity ledger filename names {expected}, but bytes address as {actual}")]
    IdentifierMismatch { expected: String, actual: String },
    #[error("identity ledger content-address collision at {0}")]
    ContentAddressCollision(PathBuf),
}
