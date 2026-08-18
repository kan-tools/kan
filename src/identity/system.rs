//! Typed local profiles and deliberate RFC 1 system-identity initialization.

use std::{
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use serde::{Deserialize, Serialize};

use super::did_kan::validate_did;

pub const SURFACE_VALUES: &[crate::surface::SurfaceValue] = &[
    crate::surface::SurfaceValue::new(
        "identity-profiles:profiles/*.json",
        "typed-identity-profile",
    ),
    crate::surface::SurfaceValue::new("identity-profiles:default", "default-actor-alias"),
    crate::surface::SurfaceValue::new("identity-profiles:.tmp-*", "atomic-profile-install"),
    crate::surface::SurfaceValue::new("identity-profiles:LOCK", "initialization-coordination"),
];

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "provider",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum CredentialReference {
    OsKeychain { service: String, account: String },
    OwnerOnlyFile { path: String },
    Hardware { uri: String },
    Agent { socket: String, key_id: String },
    ExternalSigner { uri: String },
}

impl CredentialReference {
    pub fn validate(&self) -> Result<(), Error> {
        match self {
            Self::OsKeychain { service, account } => {
                require_nonempty(service, "credential service")?;
                require_nonempty(account, "credential account")
            }
            Self::OwnerOnlyFile { path } => require_nonempty(path, "credential path"),
            Self::Hardware { uri } | Self::ExternalSigner { uri } => {
                require_nonempty(uri, "credential URI")
            }
            Self::Agent { socket, key_id } => {
                require_nonempty(socket, "credential agent socket")?;
                require_nonempty(key_id, "credential agent key id")
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IdentityProfile {
    v: u64,
    alias: String,
    principal: String,
    credential: CredentialReference,
}

impl IdentityProfile {
    pub fn new(
        alias: String,
        principal: String,
        credential: CredentialReference,
    ) -> Result<Self, Error> {
        let profile = Self {
            v: 1,
            alias,
            principal,
            credential,
        };
        profile.validate()?;
        Ok(profile)
    }

    pub fn validate(&self) -> Result<(), Error> {
        if self.v != 1 {
            return Err(Error::UnsupportedVersion(self.v));
        }
        validate_alias(&self.alias)?;
        validate_did(&self.principal)?;
        self.credential.validate()
    }

    pub fn alias(&self) -> &str {
        &self.alias
    }

    pub fn principal(&self) -> &str {
        &self.principal
    }

    pub fn credential(&self) -> &CredentialReference {
        &self.credential
    }
}

#[derive(Debug, Clone)]
pub struct SystemIdentityStore {
    config_root: PathBuf,
}

impl SystemIdentityStore {
    /// Point at the platform configuration root containing `identity/`,
    /// `credentials/`, and `repositories/`. Construction and reads create
    /// nothing and never access a credential provider.
    pub fn at(config_root: impl Into<PathBuf>) -> Self {
        Self {
            config_root: config_root.into(),
        }
    }

    pub fn config_root(&self) -> &Path {
        &self.config_root
    }

    /// Deliberately install the first profile and select it as default.
    /// Repeating the identical request is idempotent; a different existing
    /// profile or default actor is a refusal, not an implicit actor switch.
    pub fn initialize(&self, profile: &IdentityProfile) -> Result<(), Error> {
        profile.validate()?;
        let profiles = self.profiles_dir();
        existing_directory_or_absent(&profiles)?;
        // surface-write: identity-profiles:profiles/*.json,identity-profiles:default,identity-profiles:.tmp-*
        crate::persistence::create_dir_all(
            crate::persistence::SurfaceWrite::IdentityProfiles,
            &profiles,
        )?;
        let lock_path = profiles.join("LOCK");
        existing_file(&lock_path)?;
        // surface-write: identity-profiles:LOCK
        let lock_file = crate::persistence::open_lock_file(
            crate::persistence::SurfaceWrite::IdentityProfiles,
            &lock_path,
        )?;
        fs4::FileExt::lock(&lock_file)?;
        let _lock = ProfileLock(lock_file);

        let mut encoded = serde_json::to_vec_pretty(profile)?;
        encoded.push(b'\n');
        let default = profiles.join("default");
        let expected = format!("{}\n", profile.alias);
        if existing_file(&default)? {
            let actual = std::fs::read_to_string(&default)?;
            if actual != expected {
                return Err(Error::AlreadyInitialized(actual.trim().to_string()));
            }
        }
        install_immutable(
            &profiles,
            &profiles.join(format!("{}.json", profile.alias)),
            &encoded,
        )?;
        if existing_file(&default)? {
            return Ok(());
        }
        install_immutable(&profiles, &default, expected.as_bytes())
    }

    pub fn profile(&self, alias: &str) -> Result<Option<IdentityProfile>, Error> {
        validate_alias(alias)?;
        let path = self.profiles_dir().join(format!("{alias}.json"));
        if !existing_file(&path)? {
            return Ok(None);
        }
        let bytes = std::fs::read(path)?;
        let profile: IdentityProfile = serde_json::from_slice(&bytes)?;
        profile.validate()?;
        if profile.alias != alias {
            return Err(Error::AliasMismatch {
                expected: alias.to_string(),
                actual: profile.alias,
            });
        }
        Ok(Some(profile))
    }

    pub fn default_profile(&self) -> Result<Option<IdentityProfile>, Error> {
        let default = self.profiles_dir().join("default");
        if !existing_file(&default)? {
            return Ok(None);
        }
        let alias = std::fs::read_to_string(default)?;
        let alias = alias.strip_suffix('\n').unwrap_or(&alias);
        validate_alias(alias)?;
        self.profile(alias)?
            .map(Some)
            .ok_or_else(|| Error::DefaultProfileMissing(alias.to_string()))
    }

    fn profiles_dir(&self) -> PathBuf {
        self.config_root.join("identity").join("profiles")
    }
}

struct ProfileLock(std::fs::File);

impl Drop for ProfileLock {
    fn drop(&mut self) {
        let _ = fs4::FileExt::unlock(&self.0);
    }
}

fn install_immutable(directory: &Path, destination: &Path, bytes: &[u8]) -> Result<(), Error> {
    if existing_file(destination)? {
        let actual = std::fs::read(destination)?;
        if actual == bytes {
            return Ok(());
        }
        return Err(Error::ProfileConflict(destination.to_path_buf()));
    }
    let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temporary = directory.join(format!(".tmp-{}-{sequence}", std::process::id()));
    // surface-write: identity-profiles:.tmp-*
    crate::persistence::write(
        crate::persistence::SurfaceWrite::IdentityProfiles,
        &temporary,
        bytes,
    )?;
    // surface-write: identity-profiles:profiles/*.json,identity-profiles:default,identity-profiles:.tmp-*
    if let Err(error) = crate::persistence::rename(
        crate::persistence::SurfaceWrite::IdentityProfiles,
        &temporary,
        destination,
    ) {
        // surface-write: identity-profiles:.tmp-*
        let _ = crate::persistence::remove_file(
            crate::persistence::SurfaceWrite::IdentityProfiles,
            &temporary,
        );
        if existing_file(destination)? && std::fs::read(destination)? == bytes {
            return Ok(());
        }
        return Err(error.into());
    }
    Ok(())
}

fn validate_alias(alias: &str) -> Result<(), Error> {
    if alias.is_empty()
        || alias.len() > 64
        || !alias.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-".contains(&byte)
        })
        || !alias
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
    {
        return Err(Error::InvalidAlias(alias.to_string()));
    }
    Ok(())
}

fn require_nonempty(value: &str, field: &'static str) -> Result<(), Error> {
    if value.is_empty() {
        Err(Error::Empty(field))
    } else {
        Ok(())
    }
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
    #[error("unsupported identity profile version {0}")]
    UnsupportedVersion(u64),
    #[error("invalid identity profile alias: {0}")]
    InvalidAlias(String),
    #[error("{0} must not be empty")]
    Empty(&'static str),
    #[error("identity profile `{expected}` contains alias `{actual}`")]
    AliasMismatch { expected: String, actual: String },
    #[error("system identity is already initialized with default actor `{0}`")]
    AlreadyInitialized(String),
    #[error("default identity profile is missing: {0}")]
    DefaultProfileMissing(String),
    #[error("identity profile conflicts with existing bytes at {0}")]
    ProfileConflict(PathBuf),
    #[error("identity profile path is a symlink or has the wrong file type: {0}")]
    UnsafeEntry(PathBuf),
    #[error("system identity I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("system identity JSON is invalid: {0}")]
    Json(#[from] serde_json::Error),
    #[error("system identity DID is invalid: {0}")]
    Did(#[from] super::did_kan::Error),
}
