//! Local-only identity (ADR-4): a self-generated `did:key` keypair. `did:key`
//! is self-certifying — no PDS/network needed — and is the exact identity
//! atproto expects later, so local-only and future sync share one identity
//! model without re-signing history.
//!
//! `load_or_create` resolves the key in a fixed order:
//!
//! 1. **`KAN_IDENTITY_FILE`**, if set — a dedicated key file, used
//!    exclusively, keychain never consulted.
//! 2. The OS keychain (ADR-25, `keyring` crate, spiked before it was trusted
//!    per CLAUDE.md's crate-trust rule), filed under a stable random account
//!    id kept in `.kan/identity-id`.
//! 3. The plaintext file at `.kan/identity`, with a loud warning, when the
//!    keychain genuinely isn't available (headless CI, a Linux box with no
//!    Secret Service daemon).
//!
//! (1) exists because the keychain is not usable non-interactively. On macOS
//! the entry is ACL'd to the binary that created it, so *a different kan
//! binary* — every upgrade, and every `cargo build` during development —
//! blocks forever on an authorization prompt that never arrives in CI, a
//! container, an MCP server, or `day` shelling out (ADR-42). It is a hang,
//! not a failure, which is the worst shape: a caller cannot tell it from
//! slowness.
//!
//! (2)'s account id **was** the canonicalized `.kan/identity` path, so moving
//! a checkout missed the lookup and silently minted a new identity, taking
//! every prior claim out of every read at exit 0. The id file travels with
//! `.kan/`, so the identity now travels with the repo.

use std::path::Path;

use atrium_crypto::{
    keypair::{Did as _, Export as _, P256Keypair},
    verify::verify_signature,
};

use crate::claim::Did;

/// `keyring::Entry`'s `service` field — namespaces kan's identity keys away
/// from any other application's keychain entries.
const KEYCHAIN_SERVICE: &str = "dev.kan.identity";

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("crypto error: {0}")]
    Crypto(#[from] atrium_crypto::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// A local signing identity, backed by a P-256 keypair.
///
/// P-256 vs. secp256k1 (`atrium-crypto`'s other supported curve) is an
/// arbitrary but immaterial choice for local-only use — both are equally
/// atproto-compatible; P-256 has broader native platform support.
pub struct Identity {
    keypair: P256Keypair,
}

impl Identity {
    /// Generate a fresh identity. Does not persist it — call `save`.
    pub fn generate() -> Self {
        Self {
            keypair: P256Keypair::create(&mut rand::thread_rng()),
        }
    }

    /// Load the identity for the checkout whose `.kan/identity` would be
    /// `path`, or generate and persist a new one if none exists yet.
    ///
    /// `KAN_IDENTITY_FILE` short-circuits everything below when set (see the
    /// module doc): a dedicated key file, keychain never touched.
    ///
    /// Otherwise tries the OS keychain, filed under the stable account id in
    /// `.kan/identity-id` (so each checkout — `.kan/` is repo-local, ADR-3 —
    /// gets its own entry, and keeps it across a move). Three cases:
    /// - Already in the keychain: read it from there, done.
    /// - Not yet in the keychain, but a plaintext file exists at `path`:
    ///   migrate it in (write to the keychain) and deliberately *leave the
    ///   plaintext file in place* as a fallback copy (ADR-25's explicit
    ///   choice for REQ-16's open question) rather than deleting it.
    /// - Not yet in the keychain, no plaintext file either: generate fresh
    ///   and write only to the keychain — no plaintext file created, the
    ///   real point of encryption-at-rest (issue #6).
    ///
    /// If the keychain is genuinely unavailable at any point in this (no
    /// backend, access denied, locked, etc.), falls back entirely to the
    /// original plaintext-file-only behavior, with a warning on stderr.
    pub fn load_or_create(path: &Path) -> Result<Self, Error> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        // Explicit override, checked first and used exclusively: a dedicated
        // key file named by the environment. This is the terminal-compatible
        // path — CI, containers, agents, `day` (ADR-42), anything that has no
        // GUI to answer a keychain prompt — and it never consults the
        // keychain at all, so it cannot block.
        if let Some(override_path) = std::env::var_os(IDENTITY_FILE_ENV) {
            let override_path = std::path::PathBuf::from(override_path);
            if let Some(parent) = override_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            return Self::load_or_create_plaintext(&override_path);
        }

        let account = keychain_account(path)?;
        let entry = match keyring::Entry::new(KEYCHAIN_SERVICE, &account) {
            Ok(entry) => entry,
            Err(_) => {
                warn_keychain_unavailable(path);
                return Self::load_or_create_plaintext(path);
            }
        };

        match entry.get_secret() {
            Ok(bytes) => Ok(Self {
                keypair: P256Keypair::import(&bytes)?,
            }),
            Err(keyring::Error::NoEntry) => {
                let identity = match std::fs::read(path) {
                    Ok(bytes) => Self {
                        keypair: P256Keypair::import(&bytes)?,
                    },
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => Self::generate(),
                    Err(e) => return Err(e.into()),
                };
                match entry.set_secret(&identity.keypair.export()) {
                    // Migration/fresh-generate case: the keychain now holds
                    // the identity. A pre-existing plaintext file, if any,
                    // is deliberately left in place (see doc above) rather
                    // than deleted or (re)written.
                    Ok(()) => Ok(identity),
                    Err(_) => {
                        warn_keychain_unavailable(path);
                        identity.save(path)?;
                        Ok(identity)
                    }
                }
            }
            Err(_) => {
                warn_keychain_unavailable(path);
                Self::load_or_create_plaintext(path)
            }
        }
    }

    fn load_or_create_plaintext(path: &Path) -> Result<Self, Error> {
        match std::fs::read(path) {
            Ok(bytes) => {
                // Tighten an existing loose file on the way in, not just on
                // the way out — the file this repo shipped with was 0644.
                let _ = restrict_permissions(path);
                Ok(Self {
                    keypair: P256Keypair::import(&bytes)?,
                })
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let identity = Self::generate();
                identity.save(path)?;
                Ok(identity)
            }
            Err(e) => Err(e.into()),
        }
    }

    pub fn save(&self, path: &Path) -> Result<(), Error> {
        std::fs::write(path, self.keypair.export())?;
        restrict_permissions(path)?;
        Ok(())
    }

    /// This identity's `did:key:...` string — `AuthorId.did` for
    /// human-direct claims (ADR-4).
    pub fn did(&self) -> Did {
        self.keypair.did()
    }

    pub fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, Error> {
        Ok(self.keypair.sign(msg)?)
    }
}

/// The keychain "account" this checkout's key is filed under: a random,
/// stable id kept beside the identity in `.kan/`.
///
/// **Was the canonicalized `.kan/identity` path**, which meant moving or
/// renaming a checkout missed the lookup, silently generated a new keypair
/// and DID, and — because `TrustBase::Solo` trusts exactly one `AuthorId` —
/// made every prior claim vanish from every read at exit 0
/// (`.design/v0.7-milestone.md` REQ-5). A `did:key` is meant to be
/// self-certifying; its retrievability must not hang on a mutable
/// environment string.
///
/// The id file travels with `.kan/`, so the identity survives a move. It is
/// not secret — it names a keychain entry, it does not authorize access to
/// it.
fn keychain_account(identity_path: &Path) -> Result<String, Error> {
    let dir = identity_path.parent().unwrap_or(Path::new("."));
    let id_path = dir.join("identity-id");

    match std::fs::read_to_string(&id_path) {
        Ok(id) if !id.trim().is_empty() => return Ok(id.trim().to_string()),
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }

    // No id yet. If this checkout already has a keychain entry under the old
    // path-derived account, keep using that name rather than orphaning the
    // key — an upgrade must not cost anyone their identity.
    //
    // Probe only when there is plausibly something to preserve: an existing
    // key file, or an existing log beside it. A directory with neither is a
    // brand-new checkout, and probing there would spend a keychain round trip
    // per invocation to answer a question whose answer is always "no" —
    // including once per temp directory across the test suite, which is real
    // load on a real OS keychain.
    let has_prior_state = identity_path.exists() || dir.join("log").exists();
    let account = if has_prior_state {
        let legacy = std::fs::canonicalize(identity_path)
            .unwrap_or_else(|_| identity_path.to_path_buf())
            .display()
            .to_string();
        if keyring::Entry::new(KEYCHAIN_SERVICE, &legacy)
            .map(|e| e.get_secret().is_ok())
            .unwrap_or(false)
        {
            legacy
        } else {
            fresh_account()
        }
    } else {
        fresh_account()
    };

    std::fs::write(&id_path, &account)?;
    Ok(account)
}

/// A fresh, random keychain account name for a checkout that has none.
fn fresh_account() -> String {
    format!("kan-{:032x}", rand::random::<u128>())
}

/// Environment variable naming a dedicated identity key file, bypassing the
/// keychain entirely.
///
/// Exists because the OS keychain is not usable non-interactively: on macOS
/// the entry is ACL'd to the binary that created it, so *a different kan
/// binary* — which is to say every upgrade, and every `cargo build` during
/// development — blocks forever on an authorization prompt that never
/// arrives in CI, a container, an MCP server, or `day` shelling out (ADR-42).
/// Proven by running two builds against copies of one log: the hang follows
/// whichever binary touches the identity second.
pub const IDENTITY_FILE_ENV: &str = "KAN_IDENTITY_FILE";

fn warn_keychain_unavailable(path: &Path) {
    eprintln!(
        "warning: OS keychain unavailable -- falling back to a plaintext identity file at {} \
         (the identity key is not encrypted at rest in this mode; this is expected on \
         headless/CI environments with no keychain daemon running). Set {} to choose a \
         dedicated key file explicitly and skip the keychain entirely.",
        path.display(),
        IDENTITY_FILE_ENV
    );
}

/// Owner-only permissions for a file holding a private key.
///
/// The plaintext fallback was written with whatever the process umask gave
/// it — `0644`, world-readable, on this author's own machine. Applied on
/// every save *and* on every load, so an existing loose file is tightened
/// rather than merely not re-loosened.
#[cfg(unix)]
fn restrict_permissions(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(path)?.permissions();
    if perms.mode() & 0o077 != 0 {
        perms.set_mode(0o600);
        std::fs::set_permissions(path, perms)?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn restrict_permissions(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

/// Verify `sig` over `msg` against the public key encoded in `did` (a
/// `did:key:...` string, as produced by `Identity::did`).
pub fn verify(did: &Did, msg: &[u8], sig: &[u8]) -> bool {
    verify_signature(did, msg, sig).is_ok()
}
