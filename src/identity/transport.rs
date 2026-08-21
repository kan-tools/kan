//! Workspace-local ATProto repository identity, separate from kan authorship.

use std::path::PathBuf;

use crate::sign::Identity;

pub const SURFACE_VALUES: &[crate::surface::SurfaceValue] = &[crate::surface::SurfaceValue::new(
    "repository-transport:identity",
    "p256-private-key",
)];

/// A credential that may approve local ATProto repository transitions.
///
/// The inner signing identity is intentionally not public: code holding this
/// value can construct a repository transport signer, but cannot pass it to a
/// kan claim-signing API by accident.
pub struct LocalRepositoryTransportIdentity(Identity);

impl LocalRepositoryTransportIdentity {
    pub fn did(&self) -> String {
        self.0.did()
    }

    pub fn signer(&self) -> crate::store::log::RepositoryTransportSigner<'_> {
        crate::store::log::RepositoryTransportSigner::LocalDidKey(&self.0)
    }
}

#[derive(Debug, Clone)]
pub struct LocalRepositoryTransportStore {
    directory: PathBuf,
}

impl LocalRepositoryTransportStore {
    pub fn at(directory: impl Into<PathBuf>) -> Self {
        Self {
            directory: directory.into(),
        }
    }

    pub fn read(&self) -> Result<Option<LocalRepositoryTransportIdentity>, Error> {
        match std::fs::symlink_metadata(&self.directory) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
                return Err(Error::UnsafeDirectory(self.directory.clone()))
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        }

        let path = self.identity_path();
        let metadata = match std::fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(Error::UnsafeIdentity(path));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err(Error::IdentityPermissions(path));
            }
        }
        Ok(Some(LocalRepositoryTransportIdentity(
            Identity::load_existing(&path)?,
        )))
    }

    /// Resolve the stable local transport identity, creating it only when the
    /// caller has already decided that a repository write may proceed.
    /// Concurrent first writers converge on the credential that won the
    /// create-new race; no existing key is overwritten.
    pub fn load_or_create(&self) -> Result<LocalRepositoryTransportIdentity, Error> {
        if let Some(identity) = self.read()? {
            return Ok(identity);
        }
        // surface-write: repository-transport:identity
        crate::persistence::create_dir_all(
            crate::persistence::SurfaceWrite::RepositoryTransportIdentity,
            &self.directory,
        )?;
        let candidate = Identity::generate();
        let path = self.identity_path();
        match candidate.save_repository_transport_new(&path) {
            Ok(()) => Ok(LocalRepositoryTransportIdentity(candidate)),
            Err(crate::sign::Error::Io(error))
                if error.kind() == std::io::ErrorKind::AlreadyExists =>
            {
                self.read()?.ok_or(Error::ConcurrentCreationLost(path))
            }
            Err(error) => Err(error.into()),
        }
    }

    /// Install the credential that already owns a released workspace's
    /// reachable repository history as the separately typed transport
    /// credential. This copies key material at the explicit current-writer
    /// activation boundary; it does not rebind the repository DID or make
    /// the transport value usable as a kan author.
    pub fn continue_from_released_repository(
        &self,
        previous: &Identity,
    ) -> Result<LocalRepositoryTransportIdentity, Error> {
        if let Some(identity) = self.read()? {
            return ensure_continuity(identity, previous);
        }
        // surface-write: repository-transport:identity
        crate::persistence::create_dir_all(
            crate::persistence::SurfaceWrite::RepositoryTransportIdentity,
            &self.directory,
        )?;
        let path = self.identity_path();
        match previous.save_repository_transport_new(&path) {
            Ok(()) => self
                .read()?
                .ok_or_else(|| Error::ConcurrentCreationLost(path))
                .and_then(|identity| ensure_continuity(identity, previous)),
            Err(crate::sign::Error::Io(error))
                if error.kind() == std::io::ErrorKind::AlreadyExists =>
            {
                self.read()?
                    .ok_or_else(|| Error::ConcurrentCreationLost(path))
                    .and_then(|identity| ensure_continuity(identity, previous))
            }
            Err(error) => Err(error.into()),
        }
    }

    fn identity_path(&self) -> PathBuf {
        self.directory.join("identity")
    }
}

fn ensure_continuity(
    identity: LocalRepositoryTransportIdentity,
    previous: &Identity,
) -> Result<LocalRepositoryTransportIdentity, Error> {
    let expected = previous.did();
    let actual = identity.did();
    if actual != expected {
        return Err(Error::ContinuityMismatch { expected, actual });
    }
    Ok(identity)
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Sign(#[from] crate::sign::Error),
    #[error("repository transport directory is not a safe directory: {0}")]
    UnsafeDirectory(PathBuf),
    #[error("repository transport identity is not a safe regular file: {0}")]
    UnsafeIdentity(PathBuf),
    #[error("repository transport identity is not owner-only: {0}")]
    IdentityPermissions(PathBuf),
    #[error("another writer created {0}, but its identity could not be loaded")]
    ConcurrentCreationLost(PathBuf),
    #[error("repository transport continuity requires `{expected}`, but the installed credential is `{actual}`")]
    ContinuityMismatch { expected: String, actual: String },
}
