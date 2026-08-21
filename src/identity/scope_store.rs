//! Immutable workspace-local persistence for RFC 1 scope inception.

use std::{
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use super::{
    control::{decode_preserving, ControlEvent},
    scope_inception::{ScopeId, ScopeInception, INCEPTION_DOMAIN, INCEPTION_EVENT_TYPE},
};

pub const SURFACE_VALUES: &[crate::surface::SurfaceValue] = &[
    crate::surface::SurfaceValue::new(
        "scope-identity:inception.cbor",
        "canonical-proved-inception",
    ),
    crate::surface::SurfaceValue::new("scope-identity:initialization-nonce", "inception-nonce"),
    crate::surface::SurfaceValue::new("scope-identity:LOCK", "initialization-coordination"),
    crate::surface::SurfaceValue::new("scope-identity:.tmp-*", "atomic-inception-install"),
];

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, PartialEq)]
pub struct InstalledScope {
    pub scope: ScopeId,
    pub inception: ScopeInception,
    pub event: ControlEvent,
}

/// A stored inception whose governance proof has been checked against the
/// exact identity state it names. Possessing an `InstalledScope` alone is not
/// enough to activate current claims: canonical bytes establish identity,
/// while this type additionally establishes authority.
#[derive(Debug, Clone, PartialEq)]
pub struct VerifiedScope(InstalledScope);

impl VerifiedScope {
    pub fn scope(&self) -> ScopeId {
        self.0.scope
    }

    pub fn installed(&self) -> &InstalledScope {
        &self.0
    }
}

#[derive(Debug, Clone)]
pub struct ScopeIdentityStore {
    directory: PathBuf,
}

impl ScopeIdentityStore {
    /// Point at the exact workspace-local scope identity directory,
    /// conventionally `.kan/scope`. Reads create nothing.
    pub fn at(directory: impl Into<PathBuf>) -> Self {
        Self {
            directory: directory.into(),
        }
    }

    pub fn directory(&self) -> &Path {
        &self.directory
    }

    pub fn read(&self) -> Result<Option<InstalledScope>, Error> {
        let path = self.directory.join("inception.cbor");
        if !existing_file(&path)? {
            return Ok(None);
        }
        decode_installed(&std::fs::read(path)?).map(Some)
    }

    /// Read and verify a `did:kan`-governed inception against the exact
    /// resolved controller state. Reads create and modify nothing.
    pub fn read_verified_did_kan(
        &self,
        state: &super::did_kan_update::ResolvedDidKanState,
    ) -> Result<Option<VerifiedScope>, Error> {
        let Some(installed) = self.read()? else {
            return Ok(None);
        };
        let verified = installed
            .inception
            .proved_event_with_did_kan_state(state, installed.event.proofs.clone())?;
        if verified != installed.event {
            return Err(Error::InceptionProofMismatch);
        }
        Ok(Some(VerifiedScope(installed)))
    }

    /// Verify an inception governed directly by a self-certifying static
    /// `did:key`. This keeps fixtures and imported scopes on the same closed
    /// activation-token boundary as `did:kan` scopes.
    pub fn read_verified_static(&self) -> Result<Option<VerifiedScope>, Error> {
        let Some(installed) = self.read()? else {
            return Ok(None);
        };
        let verified = installed
            .inception
            .proved_event(installed.event.proofs.clone())?;
        if verified != installed.event {
            return Err(Error::InceptionProofMismatch);
        }
        Ok(Some(VerifiedScope(installed)))
    }

    /// Return the once-generated scope inception nonce. Persisting it
    /// separately makes a retry derive the same scope identifier even
    /// when failure happened before the proved event was installed.
    pub fn initialization_nonce(&self) -> Result<[u8; 32], Error> {
        existing_directory_or_absent(&self.directory)?;
        // surface-write: scope-identity:initialization-nonce
        crate::persistence::create_dir_all(
            crate::persistence::SurfaceWrite::ScopeIdentity,
            &self.directory,
        )?;
        let path = self.directory.join("initialization-nonce");
        let mut candidate = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut candidate);
        // surface-write: scope-identity:initialization-nonce
        match crate::persistence::write_new_owner_only(
            crate::persistence::SurfaceWrite::ScopeIdentity,
            &path,
            &candidate,
        ) {
            Ok(()) => Ok(candidate),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                require_regular_file(&path)?;
                let bytes = std::fs::read(path)?;
                bytes
                    .try_into()
                    .map_err(|bytes: Vec<u8>| Error::NonceLength(bytes.len()))
            }
            Err(error) => Err(error.into()),
        }
    }

    /// Install one proved inception event. Identical scope inception is
    /// idempotent even if its proof bytes differ; a different scope is a
    /// refusal. The event becomes visible through one atomic rename.
    pub fn install(&self, event: &ControlEvent) -> Result<InstalledScope, Error> {
        let candidate = decode_installed(&event.canonical_bytes()?)?;
        existing_directory_or_absent(&self.directory)?;
        // surface-write: scope-identity:inception.cbor,scope-identity:LOCK,scope-identity:.tmp-*
        crate::persistence::create_dir_all(
            crate::persistence::SurfaceWrite::ScopeIdentity,
            &self.directory,
        )?;
        let lock_path = self.directory.join("LOCK");
        existing_file(&lock_path)?;
        // surface-write: scope-identity:LOCK
        let lock_file = crate::persistence::open_lock_file(
            crate::persistence::SurfaceWrite::ScopeIdentity,
            &lock_path,
        )?;
        fs4::FileExt::lock(&lock_file)?;
        let _lock = ScopeLock(lock_file);

        let destination = self.directory.join("inception.cbor");
        if existing_file(&destination)? {
            let installed = decode_installed(&std::fs::read(destination)?)?;
            if installed.inception == candidate.inception {
                return Ok(installed);
            }
            return Err(Error::Conflict {
                existing: installed.scope,
                candidate: candidate.scope,
            });
        }

        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let temporary = self
            .directory
            .join(format!(".tmp-{}-{sequence}", std::process::id()));
        // surface-write: scope-identity:.tmp-*
        crate::persistence::write(
            crate::persistence::SurfaceWrite::ScopeIdentity,
            &temporary,
            &event.canonical_bytes()?,
        )?;
        // surface-write: scope-identity:inception.cbor,scope-identity:.tmp-*
        if let Err(error) = crate::persistence::rename(
            crate::persistence::SurfaceWrite::ScopeIdentity,
            &temporary,
            &destination,
        ) {
            // surface-write: scope-identity:.tmp-*
            let _ = crate::persistence::remove_file(
                crate::persistence::SurfaceWrite::ScopeIdentity,
                &temporary,
            );
            return Err(error.into());
        }
        Ok(candidate)
    }
}

fn decode_installed(bytes: &[u8]) -> Result<InstalledScope, Error> {
    let preserved = decode_preserving(bytes)?;
    let event = preserved.typed().ok_or(Error::UnsupportedInception)?;
    if event.domain != INCEPTION_DOMAIN || event.event_type != INCEPTION_EVENT_TYPE {
        return Err(Error::WrongEvent);
    }
    let payload = atproto_dasl::to_vec(&event.payload)?;
    let inception: ScopeInception = atproto_dasl::from_reader(&payload[..])?;
    inception.validate()?;
    let scope = inception.scope_id()?;
    Ok(InstalledScope {
        scope,
        inception,
        event,
    })
}

struct ScopeLock(std::fs::File);

impl Drop for ScopeLock {
    fn drop(&mut self) {
        let _ = fs4::FileExt::unlock(&self.0);
    }
}

fn require_regular_file(path: &Path) -> Result<(), Error> {
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(Error::UnsafeEntry(path.to_path_buf()));
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
    #[error("scope identity conflicts: existing `{existing}`, candidate `{candidate}`")]
    Conflict {
        existing: ScopeId,
        candidate: ScopeId,
    },
    #[error("stored scope initialization nonce has {0} bytes, expected 32")]
    NonceLength(usize),
    #[error("scope identity entry is a symlink or has the wrong file type: {0}")]
    UnsafeEntry(PathBuf),
    #[error("stored scope identity is not an inception event")]
    WrongEvent,
    #[error("stored scope inception uses unsupported control fields")]
    UnsupportedInception,
    #[error("stored scope inception proof does not reproduce its canonical event")]
    InceptionProofMismatch,
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Control(#[from] super::control::Error),
    #[error(transparent)]
    DecodeControl(#[from] super::control::DecodeError),
    #[error(transparent)]
    Inception(#[from] super::scope_inception::Error),
    #[error(transparent)]
    Encode(#[from] atproto_dasl::EncodeError),
    #[error(transparent)]
    Decode(#[from] atproto_dasl::DecodeError),
}
