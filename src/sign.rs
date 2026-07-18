//! Local-only identity (ADR-4): a self-generated `did:key` keypair. `did:key`
//! is self-certifying — no PDS/network needed — and is the exact identity
//! atproto expects later, so local-only and future sync share one identity
//! model without re-signing history.
//!
//! `load_or_create` (ADR-25) tries the OS keychain first (`keyring` crate,
//! verified via a stress-test spike — CLAUDE.md's crate-trust house rule —
//! before being trusted, same discipline ADR-11/12 used on `atrium-repo`'s
//! MST), falling back to the plaintext file at `.kan/identity` with a loud
//! warning when the keychain genuinely isn't available (headless CI, a
//! Linux box with no Secret Service daemon running) — kan must keep working
//! non-interactively in those environments, not hard-fail.

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
    /// Tries the OS keychain first, keyed by `path`'s canonicalized form (so
    /// each checkout — `.kan/` is repo-local, ADR-3 — gets its own keychain
    /// entry, the same way it already gets its own plaintext file; two
    /// clones of the same repo are two different checkouts with two
    /// different identities today, keychain or not, so this doesn't change
    /// that). Three cases:
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

        let account = keychain_account(path);
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
            Ok(bytes) => Ok(Self {
                keypair: P256Keypair::import(&bytes)?,
            }),
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

/// Canonicalized so the keychain account key is stable regardless of how
/// `path` was spelled (relative vs. absolute, symlinks) — falls back to the
/// uncanonicalized path if canonicalization fails (e.g. the parent doesn't
/// exist yet on a brand-new checkout, though `load_or_create` already
/// creates it first), which just means a fresh account entry gets created,
/// not a correctness problem.
fn keychain_account(path: &Path) -> String {
    std::fs::canonicalize(path)
        .unwrap_or_else(|_| path.to_path_buf())
        .display()
        .to_string()
}

fn warn_keychain_unavailable(path: &Path) {
    eprintln!(
        "warning: OS keychain unavailable -- falling back to a plaintext identity file at {} \
         (the identity key is not encrypted at rest in this mode; this is expected on \
         headless/CI environments with no keychain daemon running)",
        path.display()
    );
}

/// Verify `sig` over `msg` against the public key encoded in `did` (a
/// `did:key:...` string, as produced by `Identity::did`).
pub fn verify(did: &Did, msg: &[u8], sig: &[u8]) -> bool {
    verify_signature(did, msg, sig).is_ok()
}
