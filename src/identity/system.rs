//! Typed local profiles and deliberate RFC 1 system-identity initialization.

use std::{
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use serde::{Deserialize, Serialize};

use super::{
    control::{IdentityVersion, Proof, SigningInput},
    did_kan::{validate_did, validate_did_url, validate_verification_method, VerificationMethod},
};

pub const SURFACE_VALUES: &[crate::surface::SurfaceValue] = &[
    crate::surface::SurfaceValue::new(
        "identity-profiles:profiles/*.json",
        "typed-identity-profile",
    ),
    crate::surface::SurfaceValue::new("identity-profiles:default", "default-actor-alias"),
    crate::surface::SurfaceValue::new("identity-profiles:.tmp-*", "atomic-profile-install"),
    crate::surface::SurfaceValue::new("identity-profiles:LOCK", "initialization-coordination"),
    crate::surface::SurfaceValue::new("identity-profiles:enrollment-nonce", "initialization-nonce"),
    crate::surface::SurfaceValue::new("credentials:owner-only-file", "p256-private-key"),
    crate::surface::SurfaceValue::new("system-config:KAN_CONFIG_DIR", "config-root-override"),
];

pub const CONFIG_DIR_ENV: &str = "KAN_CONFIG_DIR";

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
            Self::OwnerOnlyFile { path } => validate_credential_path(path),
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

/// The exact actor state selected by a local profile. Keeping all three
/// fields together prevents a credential key from silently standing in for
/// the stable principal it is authorized to represent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ActorReference {
    principal: String,
    verification_method: String,
    #[serde(with = "identity_version_json")]
    controller_state: IdentityVersion,
}

mod identity_version_json {
    use atproto_dasl::Cid;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    use super::IdentityVersion;

    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct WireRef<'a> {
        kind: &'static str,
        value: Option<&'a str>,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct Wire {
        kind: String,
        value: Option<String>,
    }

    pub fn serialize<S: Serializer>(
        state: &IdentityVersion,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let cid_text;
        let wire = match state {
            IdentityVersion::Static => WireRef {
                kind: "static",
                value: None,
            },
            IdentityVersion::Event(cid) => {
                cid_text = cid.to_string();
                WireRef {
                    kind: "event",
                    value: Some(&cid_text),
                }
            }
            IdentityVersion::VersionId(value) => WireRef {
                kind: "versionId",
                value: Some(value),
            },
            IdentityVersion::DocumentCid(cid) => {
                cid_text = cid.to_string();
                WireRef {
                    kind: "documentCid",
                    value: Some(&cid_text),
                }
            }
        };
        wire.serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<IdentityVersion, D::Error> {
        let wire = Wire::deserialize(deserializer)?;
        match (wire.kind.as_str(), wire.value) {
            ("static", None) => Ok(IdentityVersion::Static),
            ("event", Some(value)) => value
                .parse::<Cid>()
                .map(IdentityVersion::Event)
                .map_err(serde::de::Error::custom),
            ("versionId", Some(value)) if !value.is_empty() => {
                Ok(IdentityVersion::VersionId(value))
            }
            ("documentCid", Some(value)) => value
                .parse::<Cid>()
                .map(IdentityVersion::DocumentCid)
                .map_err(serde::de::Error::custom),
            _ => Err(serde::de::Error::custom(
                "invalid identity profile controller state",
            )),
        }
    }
}

impl ActorReference {
    pub fn new(
        principal: String,
        verification_method: String,
        controller_state: IdentityVersion,
    ) -> Result<Self, Error> {
        let actor = Self {
            principal,
            verification_method,
            controller_state,
        };
        actor.validate()?;
        Ok(actor)
    }

    pub fn validate(&self) -> Result<(), Error> {
        validate_did(&self.principal)?;
        validate_did_url(&self.verification_method)?;
        let method_did = self
            .verification_method
            .split_once('#')
            .map(|(did, _)| did)
            .ok_or_else(|| Error::MethodPrincipalMismatch {
                principal: self.principal.clone(),
                method: self.verification_method.clone(),
            })?;
        if method_did != self.principal {
            return Err(Error::MethodPrincipalMismatch {
                principal: self.principal.clone(),
                method: self.verification_method.clone(),
            });
        }
        let expected = match self.principal.split(':').nth(1) {
            Some("key") => "static",
            Some("kan") => "event",
            Some("plc") => "versionId",
            Some("web") => "documentCid",
            _ => return Err(Error::UnsupportedPrincipal(self.principal.clone())),
        };
        let actual = match &self.controller_state {
            IdentityVersion::Static => "static",
            IdentityVersion::Event(_) => "event",
            IdentityVersion::VersionId(_) => "versionId",
            IdentityVersion::DocumentCid(_) => "documentCid",
        };
        if actual != expected {
            return Err(Error::ControllerStateKind {
                principal: self.principal.clone(),
                expected,
                actual,
            });
        }
        if matches!(&self.controller_state, IdentityVersion::Static) {
            let fingerprint = self.principal.strip_prefix("did:key:").ok_or_else(|| {
                Error::ControllerStateKind {
                    principal: self.principal.clone(),
                    expected,
                    actual,
                }
            })?;
            if self.verification_method != format!("{}#{fingerprint}", self.principal) {
                return Err(Error::StaticMethod(self.verification_method.clone()));
            }
        }
        Ok(())
    }

    pub fn principal(&self) -> &str {
        &self.principal
    }

    pub fn verification_method(&self) -> &str {
        &self.verification_method
    }

    pub fn controller_state(&self) -> &IdentityVersion {
        &self.controller_state
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IdentityProfile {
    v: u64,
    alias: String,
    actor: ActorReference,
    credential: CredentialReference,
}

impl IdentityProfile {
    pub fn new(
        alias: String,
        actor: ActorReference,
        credential: CredentialReference,
    ) -> Result<Self, Error> {
        let profile = Self {
            v: 1,
            alias,
            actor,
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
        self.actor.validate()?;
        self.credential.validate()
    }

    pub fn alias(&self) -> &str {
        &self.alias
    }

    pub fn principal(&self) -> &str {
        self.actor.principal()
    }

    pub fn actor(&self) -> &ActorReference {
        &self.actor
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

    /// Resolve kan's platform configuration root. An explicit environment
    /// override is useful for isolated installations and automation; it never
    /// changes repository-local state.
    pub fn platform_config_root() -> Result<PathBuf, Error> {
        if let Some(root) = std::env::var_os(CONFIG_DIR_ENV) {
            return Ok(PathBuf::from(root));
        }
        #[cfg(target_os = "windows")]
        if let Some(root) = std::env::var_os("APPDATA") {
            return Ok(PathBuf::from(root).join("kan"));
        }
        #[cfg(target_os = "macos")]
        if let Some(home) = std::env::var_os("HOME") {
            return Ok(PathBuf::from(home)
                .join("Library")
                .join("Application Support")
                .join("kan"));
        }
        #[cfg(not(any(target_os = "windows", target_os = "macos")))]
        {
            if let Some(root) = std::env::var_os("XDG_CONFIG_HOME") {
                return Ok(PathBuf::from(root).join("kan"));
            }
            if let Some(home) = std::env::var_os("HOME") {
                return Ok(PathBuf::from(home).join(".config").join("kan"));
            }
        }
        Err(Error::ConfigRootUnavailable)
    }

    /// Create or import one explicitly named owner-only credential. Existing
    /// credentials are never overwritten; creation converges on the winner of
    /// a concurrent first write, while import additionally requires the
    /// existing key to be identical.
    pub fn ensure_owner_only_credential(
        &self,
        name: &str,
        import_from: Option<&Path>,
    ) -> Result<crate::sign::Identity, Error> {
        validate_credential_path(name)?;
        let candidate = match import_from {
            Some(source) => {
                require_owner_only_file(source)?;
                crate::sign::Identity::load_existing(source)?
            }
            None => crate::sign::Identity::generate(),
        };
        let credentials = self.config_root.join("credentials");
        existing_directory_or_absent(&credentials)?;
        // surface-write: credentials:owner-only-file
        crate::persistence::create_dir_all(
            crate::persistence::SurfaceWrite::SystemCredentials,
            &credentials,
        )?;
        let destination = credentials.join(name);
        match candidate.save_system_credential_new(&destination) {
            Ok(()) => Ok(candidate),
            Err(crate::sign::Error::Io(error))
                if error.kind() == std::io::ErrorKind::AlreadyExists =>
            {
                require_owner_only_file(&destination)?;
                let existing = crate::sign::Identity::load_existing(&destination)?;
                if import_from.is_some() && existing.did() != candidate.did() {
                    return Err(Error::CredentialConflict(destination));
                }
                Ok(existing)
            }
            Err(error) => Err(error.into()),
        }
    }

    /// Return the once-generated nonce used by retryable first enrollment.
    /// It is public identity input, not a credential, but is kept locally so a
    /// crash and retry cannot silently mint a different principal.
    pub fn enrollment_nonce(&self) -> Result<[u8; 32], Error> {
        let profiles = self.profiles_dir();
        existing_directory_or_absent(&profiles)?;
        // surface-write: identity-profiles:enrollment-nonce
        crate::persistence::create_dir_all(
            crate::persistence::SurfaceWrite::IdentityProfiles,
            &profiles,
        )?;
        let path = profiles.join("enrollment-nonce");
        let mut candidate = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut candidate);
        // surface-write: identity-profiles:enrollment-nonce
        match crate::persistence::write_new_owner_only(
            crate::persistence::SurfaceWrite::IdentityProfiles,
            &path,
            &candidate,
        ) {
            Ok(()) => Ok(candidate),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                require_owner_only_file(&path)?;
                let bytes = std::fs::read(&path)?;
                bytes
                    .try_into()
                    .map_err(|bytes: Vec<u8>| Error::EnrollmentNonceLength(bytes.len()))
            }
            Err(error) => Err(error.into()),
        }
    }

    /// Deliberately install the first profile and select it as default.
    /// Repeating the identical request is idempotent; a different existing
    /// profile or default actor is a refusal, not an implicit actor switch.
    pub fn initialize(&self, profile: &IdentityProfile) -> Result<(), Error> {
        self.initialize_with(profile, || Ok(()))
    }

    /// Run prerequisite installation under the same lock that selects the
    /// first actor. Candidate conflicts are checked before `prerequisite`, and
    /// the profile/default become visible only after it succeeds.
    pub(crate) fn initialize_with(
        &self,
        profile: &IdentityProfile,
        prerequisite: impl FnOnce() -> Result<(), Error>,
    ) -> Result<(), Error> {
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
        let profile_path = profiles.join(format!("{}.json", profile.alias));
        let expected = format!("{}\n", profile.alias);
        if existing_file(&default)? {
            let actual = std::fs::read_to_string(&default)?;
            if actual != expected {
                return Err(Error::AlreadyInitialized(actual.trim().to_string()));
            }
        }
        verify_immutable_or_absent(&profile_path, &encoded)?;
        prerequisite()?;
        install_immutable(&profiles, &profile_path, &encoded)?;
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

    /// Execute the profile's explicitly selected credential provider and
    /// produce a proof only when its key is the resolved verification method.
    /// No provider is touched until this method is called.
    pub fn sign(
        &self,
        profile: &IdentityProfile,
        method: &VerificationMethod,
        input: &SigningInput,
    ) -> Result<Proof, Error> {
        profile.validate()?;
        validate_verification_method(method)?;
        if method.id != profile.actor.verification_method
            || method.controller != profile.actor.principal
            || method.alg != "P256"
        {
            return Err(Error::CredentialMethodMismatch {
                expected: profile.actor.verification_method.clone(),
                actual: method.id.clone(),
            });
        }
        let expected_did =
            atrium_crypto::did::format_did_key(atrium_crypto::Algorithm::P256, &method.public_key)?;
        let identity = match &profile.credential {
            CredentialReference::OwnerOnlyFile { path } => {
                let path = self.config_root.join("credentials").join(path);
                require_owner_only_file(&path)?;
                crate::sign::Identity::load_existing(&path)?
            }
            CredentialReference::OsKeychain { service, account } => {
                crate::sign::Identity::load_keychain_existing(service, account)?
            }
            CredentialReference::Hardware { .. }
            | CredentialReference::Agent { .. }
            | CredentialReference::ExternalSigner { .. } => {
                return Err(Error::ProviderUnsupported(profile.credential.clone()));
            }
        };
        if identity.did() != expected_did {
            return Err(Error::CredentialKeyMismatch {
                method: method.id.clone(),
            });
        }
        Ok(Proof {
            method: method.id.clone(),
            controller_state: profile.actor.controller_state.clone(),
            alg: method.alg.clone(),
            sig: identity.sign(&input.canonical_bytes()?)?,
        })
    }

    fn profiles_dir(&self) -> PathBuf {
        self.config_root.join("identity").join("profiles")
    }
}

fn verify_immutable_or_absent(path: &Path, expected: &[u8]) -> Result<(), Error> {
    if existing_file(path)? && std::fs::read(path)? != expected {
        return Err(Error::ProfileConflict(path.to_path_buf()));
    }
    Ok(())
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

pub fn validate_alias(alias: &str) -> Result<(), Error> {
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

fn validate_credential_path(path: &str) -> Result<(), Error> {
    require_nonempty(path, "credential path")?;
    let path = Path::new(path);
    let components = path.components().collect::<Vec<_>>();
    if path.is_absolute()
        || components.len() != 1
        || !matches!(components[0], std::path::Component::Normal(_))
    {
        return Err(Error::InvalidCredentialPath(path.to_path_buf()));
    }
    Ok(())
}

fn require_owner_only_file(path: &Path) -> Result<(), Error> {
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(Error::UnsafeCredential(path.to_path_buf()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(Error::CredentialPermissions(path.to_path_buf()));
        }
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
    #[error("unsupported identity profile version {0}")]
    UnsupportedVersion(u64),
    #[error("invalid identity profile alias: {0}")]
    InvalidAlias(String),
    #[error("cannot locate the platform configuration directory; set KAN_CONFIG_DIR")]
    ConfigRootUnavailable,
    #[error("unsupported system identity principal: {0}")]
    UnsupportedPrincipal(String),
    #[error("verification method `{method}` does not belong to principal `{principal}`")]
    MethodPrincipalMismatch { principal: String, method: String },
    #[error("principal `{principal}` requires controller state `{expected}`, not `{actual}`")]
    ControllerStateKind {
        principal: String,
        expected: &'static str,
        actual: &'static str,
    },
    #[error("static did:key method must use its complete fingerprint fragment: {0}")]
    StaticMethod(String),
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
    #[error("credential path must be relative to the system credentials directory: {0}")]
    InvalidCredentialPath(PathBuf),
    #[error("credential is a symlink or has the wrong file type: {0}")]
    UnsafeCredential(PathBuf),
    #[error("credential file is not owner-only: {0}")]
    CredentialPermissions(PathBuf),
    #[error("credential conflicts with existing key at {0}")]
    CredentialConflict(PathBuf),
    #[error("stored enrollment nonce has {0} bytes, expected 32")]
    EnrollmentNonceLength(usize),
    #[error("credential provider is not executable by this build: {0:?}")]
    ProviderUnsupported(CredentialReference),
    #[error("resolved method mismatch: expected `{expected}`, got `{actual}`")]
    CredentialMethodMismatch { expected: String, actual: String },
    #[error("selected credential does not hold the key for verification method `{method}`")]
    CredentialKeyMismatch { method: String },
    #[error("identity profile path is a symlink or has the wrong file type: {0}")]
    UnsafeEntry(PathBuf),
    #[error("system identity I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("system identity JSON is invalid: {0}")]
    Json(#[from] serde_json::Error),
    #[error("system identity DID is invalid: {0}")]
    Did(#[from] super::did_kan::Error),
    #[error("system identity credential failed: {0}")]
    Sign(#[from] crate::sign::Error),
    #[error("system identity control event failed: {0}")]
    Control(#[from] super::control::Error),
    #[error("system identity credential key is invalid: {0}")]
    Crypto(#[from] atrium_crypto::Error),
    #[error("system identity ledger failed: {0}")]
    Ledger(#[from] super::ledger::Error),
}
