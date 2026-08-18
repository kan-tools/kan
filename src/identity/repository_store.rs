//! Immutable workspace-local persistence for RFC 1 repository inception.

use std::{
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use super::{
    control::{decode_preserving, ControlEvent},
    repository_inception::{RepositoryInception, INCEPTION_DOMAIN, INCEPTION_EVENT_TYPE},
};

pub const SURFACE_VALUES: &[crate::surface::SurfaceValue] = &[
    crate::surface::SurfaceValue::new(
        "repository-identity:inception.cbor",
        "canonical-proved-inception",
    ),
    crate::surface::SurfaceValue::new(
        "repository-identity:initialization-nonce",
        "inception-nonce",
    ),
    crate::surface::SurfaceValue::new("repository-identity:LOCK", "initialization-coordination"),
    crate::surface::SurfaceValue::new("repository-identity:.tmp-*", "atomic-inception-install"),
];

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, PartialEq)]
pub struct InstalledRepository {
    pub repository: String,
    pub inception: RepositoryInception,
    pub event: ControlEvent,
}

#[derive(Debug, Clone)]
pub struct RepositoryIdentityStore {
    directory: PathBuf,
}

impl RepositoryIdentityStore {
    /// Point at the exact workspace-local repository identity directory,
    /// conventionally `.kan/repository`. Reads create nothing.
    pub fn at(directory: impl Into<PathBuf>) -> Self {
        Self {
            directory: directory.into(),
        }
    }

    pub fn directory(&self) -> &Path {
        &self.directory
    }

    pub fn read(&self) -> Result<Option<InstalledRepository>, Error> {
        let path = self.directory.join("inception.cbor");
        if !existing_file(&path)? {
            return Ok(None);
        }
        decode_installed(&std::fs::read(path)?).map(Some)
    }

    /// Return the once-generated repository inception nonce. Persisting it
    /// separately makes a retry derive the same repository identifier even
    /// when failure happened before the proved event was installed.
    pub fn initialization_nonce(&self) -> Result<[u8; 32], Error> {
        existing_directory_or_absent(&self.directory)?;
        // surface-write: repository-identity:initialization-nonce
        crate::persistence::create_dir_all(
            crate::persistence::SurfaceWrite::RepositoryIdentity,
            &self.directory,
        )?;
        let path = self.directory.join("initialization-nonce");
        let mut candidate = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut candidate);
        // surface-write: repository-identity:initialization-nonce
        match crate::persistence::write_new_owner_only(
            crate::persistence::SurfaceWrite::RepositoryIdentity,
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

    /// Install one proved inception event. Identical repository inception is
    /// idempotent even if its proof bytes differ; a different repository is a
    /// refusal. The event becomes visible through one atomic rename.
    pub fn install(&self, event: &ControlEvent) -> Result<InstalledRepository, Error> {
        let candidate = decode_installed(&event.canonical_bytes()?)?;
        existing_directory_or_absent(&self.directory)?;
        // surface-write: repository-identity:inception.cbor,repository-identity:LOCK,repository-identity:.tmp-*
        crate::persistence::create_dir_all(
            crate::persistence::SurfaceWrite::RepositoryIdentity,
            &self.directory,
        )?;
        let lock_path = self.directory.join("LOCK");
        existing_file(&lock_path)?;
        // surface-write: repository-identity:LOCK
        let lock_file = crate::persistence::open_lock_file(
            crate::persistence::SurfaceWrite::RepositoryIdentity,
            &lock_path,
        )?;
        fs4::FileExt::lock(&lock_file)?;
        let _lock = RepositoryLock(lock_file);

        let destination = self.directory.join("inception.cbor");
        if existing_file(&destination)? {
            let installed = decode_installed(&std::fs::read(destination)?)?;
            if installed.inception == candidate.inception {
                return Ok(installed);
            }
            return Err(Error::Conflict {
                existing: installed.repository,
                candidate: candidate.repository,
            });
        }

        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let temporary = self
            .directory
            .join(format!(".tmp-{}-{sequence}", std::process::id()));
        // surface-write: repository-identity:.tmp-*
        crate::persistence::write(
            crate::persistence::SurfaceWrite::RepositoryIdentity,
            &temporary,
            &event.canonical_bytes()?,
        )?;
        // surface-write: repository-identity:inception.cbor,repository-identity:.tmp-*
        if let Err(error) = crate::persistence::rename(
            crate::persistence::SurfaceWrite::RepositoryIdentity,
            &temporary,
            &destination,
        ) {
            // surface-write: repository-identity:.tmp-*
            let _ = crate::persistence::remove_file(
                crate::persistence::SurfaceWrite::RepositoryIdentity,
                &temporary,
            );
            return Err(error.into());
        }
        Ok(candidate)
    }
}

fn decode_installed(bytes: &[u8]) -> Result<InstalledRepository, Error> {
    let preserved = decode_preserving(bytes)?;
    let event = preserved.typed().ok_or(Error::UnsupportedInception)?;
    if event.domain != INCEPTION_DOMAIN || event.event_type != INCEPTION_EVENT_TYPE {
        return Err(Error::WrongEvent);
    }
    let payload = atproto_dasl::to_vec(&event.payload)?;
    let inception: RepositoryInception = atproto_dasl::from_reader(&payload[..])?;
    inception.validate()?;
    let repository = inception.repository_id()?;
    Ok(InstalledRepository {
        repository,
        inception,
        event,
    })
}

struct RepositoryLock(std::fs::File);

impl Drop for RepositoryLock {
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
    #[error("repository identity conflicts: existing `{existing}`, candidate `{candidate}`")]
    Conflict { existing: String, candidate: String },
    #[error("stored repository initialization nonce has {0} bytes, expected 32")]
    NonceLength(usize),
    #[error("repository identity entry is a symlink or has the wrong file type: {0}")]
    UnsafeEntry(PathBuf),
    #[error("stored repository identity is not an inception event")]
    WrongEvent,
    #[error("stored repository inception uses unsupported control fields")]
    UnsupportedInception,
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Control(#[from] super::control::Error),
    #[error(transparent)]
    DecodeControl(#[from] super::control::DecodeError),
    #[error(transparent)]
    Inception(#[from] super::repository_inception::Error),
    #[error(transparent)]
    Encode(#[from] atproto_dasl::EncodeError),
    #[error(transparent)]
    Decode(#[from] atproto_dasl::DecodeError),
}
