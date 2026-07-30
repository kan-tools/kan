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

use std::path::{Path, PathBuf};

use atrium_crypto::{
    keypair::{Did as _, Export as _, P256Keypair},
    verify::verify_signature,
};

use crate::claim::Did;

/// The file recording which keychain account this workspace's key is under.
/// Its presence is also the cheap, keychain-free signal that this workspace
/// has had an identity before.
pub const IDENTITY_ID_FILE: &str = "identity-id";

/// `keyring::Entry`'s `service` field — namespaces kan's identity keys away
/// from any other application's keychain entries.
const KEYCHAIN_SERVICE: &str = "dev.kan.identity";

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("crypto error: {0}")]
    Crypto(#[from] atrium_crypto::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("recovery phrase: {0}")]
    Recovery(String),
    #[error(
        "{override_path} does not exist, and this repo already has claims written under an \
         existing identity.\n\n\
         Creating a key there would give this repo a second identity: the claims already in \
         the log are signed by the first one, and a fold trusts a single author, so they \
         would all disappear from every read at exit 0 while still being on disk.\n\n\
         Point KAN_IDENTITY_FILE at the existing key file, or unset it and let kan use the \
         keychain. To \
         restore from a recovery phrase, write the key to that path first.\n\n\
         If you meant to add a second *role* to this workspace -- a director and a prover \
         signing separately, say -- that is a supported thing and this is not the way to ask \
         for it: run `kan identity role add <name> --key {override_path}`, which mints the \
         role key deliberately and registers it, then read with `--trust roles` so both \
         roles' claims are visible."
    )]
    WouldMintSecondIdentity { override_path: String },
    #[error(
        "a role named `{name}` is already declared in this workspace (key: {existing}). \
         Pick another name, or use the existing role."
    )]
    RoleNameTaken { name: String, existing: String },
    #[error(
        "that key already belongs to the declared role `{name}` ({did}). Registering one \
         identity under two role names would make attribution ambiguous in every read."
    )]
    RoleAlreadyRegistered { did: Did, name: String },
    #[error(
        "this repo has an identity in the OS keychain but it could not be read ({detail}).\n\
         \n\
         kan will not generate a second identity for a repo that already has one — a new \
         DID would drop every existing claim out of every read.\n\
         \n\
         If the keychain is locked, unlock it and retry. If this is a different kan binary \
         than the one that created the entry (an upgrade, or a local build), macOS will ask \
         for authorization the first time — run kan once in a terminal that can answer, or \
         set KAN_IDENTITY_FILE to a dedicated key file to bypass the keychain entirely."
    )]
    KeychainUnreachable { detail: String },
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
            // Refuse to mint a second identity for a repo that already has
            // one, exactly as the keychain branch does.
            //
            // Without this the guard existed on only one of two paths, and
            // the *other* path is the one `KeychainUnreachable`'s own message
            // recommends. Following that advice against a repo whose key had
            // already been migrated created a fresh keypair and a new DID,
            // and `TrustBase::Solo` then hid every existing claim: `kan
            // status` printed "no subjects yet" at exit 0 — verbatim REQ-5's
            // failure mode, reached through the release's recommended
            // workaround.
            if !override_path.exists() && log_has_claims(path) {
                return Err(Error::WouldMintSecondIdentity {
                    override_path: override_path.display().to_string(),
                });
            }
            return Self::load_or_create_plaintext(&override_path);
        }

        if keychain_disabled() {
            return Self::load_or_create_plaintext(path);
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
            Ok(bytes) => {
                let identity = Self {
                    keypair: P256Keypair::import(&bytes)?,
                };
                // The keychain already had it — so a plaintext copy sitting
                // beside it is redundant *and* unprotected, and must go.
                // Anyone whose key reached the keychain under a version
                // before this branch existed kept an unencrypted duplicate
                // indefinitely; "encrypted at rest" was notional for them.
                //
                // The comparison is against **the file's own bytes**, not
                // against the keychain key round-tripped through itself. An
                // adversarial review caught the earlier form —
                // `bytes == P256Keypair::import(&bytes).export()` — as a
                // tautology that never read the file, reducing the guard to
                // `path.exists()`: a plaintext file holding a *different*
                // key would have been deleted with no copy. Only a file that
                // holds exactly the key the keychain returned is redundant,
                // and only a redundant copy is safe to remove.
                if let Ok(file_bytes) = std::fs::read(path) {
                    if file_bytes == bytes {
                        if let Err(e) = std::fs::remove_file(path) {
                            eprintln!(
                                "warning: your signing key is in the keychain, but the \
                                 redundant plaintext copy at {} could not be removed ({e}) \
                                 -- delete it by hand; it is an unprotected copy of the same \
                                 key",
                                path.display()
                            );
                        }
                    } else {
                        eprintln!(
                            "warning: {} holds a different key than the keychain — leaving it \
                             in place rather than deleting a key kan cannot reproduce. If it \
                             is stale, remove it by hand; if it is the one you want, move the \
                             keychain entry aside.",
                            path.display()
                        );
                    }
                }
                Ok(identity)
            }
            Err(keyring::Error::NoEntry) => {
                let identity = match std::fs::read(path) {
                    Ok(bytes) => Self {
                        keypair: P256Keypair::import(&bytes)?,
                    },
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => Self::generate(),
                    Err(e) => return Err(e.into()),
                };
                match entry.set_secret(&identity.keypair.export()) {
                    Ok(()) => {
                        // Encrypted at rest, by default and in fact.
                        //
                        // ADR-25 wrote the key into the keychain and
                        // **deliberately left the plaintext file in place**
                        // as a fallback. The effect was that every migrated
                        // identity kept an unprotected copy of the same 32
                        // bytes beside the protected one -- world-readable
                        // at 0644 on this author's own machine -- so the
                        // keychain imposed its full cost and protected
                        // nothing. "Encryption at rest" only ever held for
                        // identities generated fresh after ADR-25.
                        //
                        // The plaintext copy is now removed once the
                        // keychain has it, but only after reading it back
                        // and confirming it matches: deleting the sole
                        // remaining copy of a signing key on the strength of
                        // a write that returned `Ok` is not a trade worth
                        // making, and `load_or_create` would then silently
                        // mint a *new* identity, taking every prior claim
                        // out of every read.
                        // Point at the recovery phrase, without printing it.
                        //
                        // Once the plaintext copy is gone the keychain is the
                        // only place the key lives, and `.kan/` is gitignored
                        // (ADR-3), so nothing else on the machine or in the
                        // remote has it. A user who never learns the phrase
                        // exists has a single point of failure they did not
                        // agree to. Printing the phrase here instead would
                        // undo the encryption in the same breath -- straight
                        // into a terminal scrollback, a CI log, or an agent
                        // transcript.
                        eprintln!(
                            "kan: this repo's signing key is now encrypted at rest in the OS \
                             keychain.\n      It is the only copy. Run `kan identity phrase` \
                             in a private terminal to write down a\n      24-word recovery \
                             phrase -- without it, losing .kan/ loses the identity, and \
                             every\n      claim you have written drops out of every read."
                        );
                        if path.exists() {
                            match entry.get_secret() {
                                Ok(stored) if stored == identity.keypair.export() => {
                                    if let Err(e) = std::fs::remove_file(path) {
                                        eprintln!(
                                            "warning: identity is in the keychain but the \
                                             plaintext copy at {} could not be removed ({e}) \
                                             -- delete it by hand; it is an unprotected copy \
                                             of your signing key",
                                            path.display()
                                        );
                                    }
                                }
                                _ => eprintln!(
                                    "warning: wrote the identity to the keychain but could \
                                     not read it back to confirm, so the plaintext copy at \
                                     {} was kept. Your key is not encrypted at rest.",
                                    path.display()
                                ),
                            }
                        }
                        Ok(identity)
                    }
                    Err(_) => {
                        warn_keychain_unavailable(path);
                        identity.save(path)?;
                        Ok(identity)
                    }
                }
            }
            // The keychain exists and answered, but not with the key and not
            // with "no such entry" — it is locked, access was denied, or the
            // entry is ACL'd to a different binary (the macOS case that
            // *hangs*, `IDENTITY_FILE_ENV`'s doc comment).
            //
            // Falling through to `load_or_create_plaintext` here would
            // generate a brand-new keypair whenever no plaintext file exists,
            // which is now the normal state — and a new DID means
            // `TrustBase::Solo` drops every prior claim from every read, at
            // exit 0. Silently minting a second identity for a repo that
            // already has one is the worst available outcome, so this refuses
            // instead, and names the way out.
            Err(e) => {
                if path.exists() {
                    warn_keychain_unavailable(path);
                    return Self::load_or_create_plaintext(path);
                }
                Err(Error::KeychainUnreachable {
                    detail: e.to_string(),
                })
            }
        }
    }

    pub(crate) fn load_or_create_plaintext(path: &Path) -> Result<Self, Error> {
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

    /// [`Self::load_or_create`], seed-rooting a workspace that has **never**
    /// had an identity (v0.9 REQ-4/REQ-6).
    ///
    /// The whole of the migration decision lives in one predicate. A
    /// workspace that already has an identity by any route is left completely
    /// alone — same key, same DID, same claims, no seed file, nothing
    /// rewritten. Only a genuinely fresh workspace gets a seed, and from then
    /// on its signing key is derived from that seed rather than generated.
    ///
    /// **Grandfathering is the whole point (REQ-6).** The alternative —
    /// migrating existing identities onto a seed — has to either preserve the
    /// signing key (in which case the seed is decorative) or replace it (in
    /// which case every existing DID moves and every claim vanishes from
    /// every read). That second outcome is #90 and #107 exactly, and it is
    /// not a risk worth taking for an internal tidiness. Two schemes coexist
    /// permanently, which ADR-55 anticipated and accepted.
    ///
    /// **Freshness is decided from files only, never by probing the
    /// keychain.** A keychain probe on this path can hang for a rebuilt
    /// binary (#96, and it hung during this milestone's own dogfooding), and
    /// hanging while deciding whether to mint an identity is the worst place
    /// to do it. `.kan/identity-id` exists iff the keychain has ever been
    /// used for this workspace, so its absence plus the absence of a key file
    /// is a sound, cheap "nothing here yet".
    pub fn load_or_create_for_workspace(kan_dir: &Path) -> Result<Self, Error> {
        let key_path = kan_dir.join("identity");

        // An explicit key file is its own answer: if it exists, that is the
        // identity; if it does not, `load_or_create`'s guard decides whether
        // creating one is allowed, and that judgement must not be bypassed
        // here.
        if std::env::var_os(IDENTITY_FILE_ENV).is_some() {
            return Self::load_or_create(&key_path);
        }

        // Already seed-rooted: derive and return. The signing key is never
        // written anywhere -- it is a pure function of the seed, so storing
        // it would be a second copy of the same secret for no gain, and
        // fewer secrets at rest is the whole point of keeping the seed in
        // the keychain.
        if let Some(seed) = Seed::load(kan_dir)? {
            return seed.signing_identity();
        }

        let fresh = !key_path.exists() && !kan_dir.join(IDENTITY_ID_FILE).exists();
        if !fresh {
            return Self::load_or_create(&key_path);
        }

        Seed::create(kan_dir)?.signing_identity()
    }

    /// Whether this workspace's identity is rooted in a seed, which is what
    /// decides how its recovery phrase should be read back.
    pub fn is_seed_rooted(kan_dir: &Path) -> bool {
        kan_dir.join(SEED_FILE).exists() || kan_dir.join(SEED_ID_FILE).exists()
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
    let id_path = dir.join(IDENTITY_ID_FILE);

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

/// Whether this repo's log already holds claims.
///
/// Deliberately a file-existence check rather than a read: `sign` must not
/// depend on `store`, and the question here is only "has anything ever been
/// written," which a non-empty CAR answers without decoding a single claim.
fn log_has_claims(identity_path: &Path) -> bool {
    identity_path
        .parent()
        .map(|dir| dir.join("log").join("repo.car"))
        .filter(|car| car.exists())
        .and_then(|car| std::fs::metadata(car).ok())
        .is_some_and(|m| m.len() > 0)
}

/// The file recording this workspace's declared role identities, one per
/// line as `<did>\t<name>\t<key path>`. Lives inside `.kan/` (gitignored,
/// repo-local per ADR-3) because a role is a local process arrangement, not
/// something to share — the *claims* roles write are the shareable part, and
/// they already carry their own author.
pub const ROLES_FILE: &str = "roles";

/// One declared role: a signing identity this workspace was deliberately
/// told to expect.
#[derive(Debug, Clone, PartialEq)]
pub struct Role {
    pub did: Did,
    pub name: String,
    pub key_path: PathBuf,
}

/// Mint a role key **deliberately**, bypassing the `WouldMintSecondIdentity`
/// guard, and register it.
///
/// This is the whole of REQ-4's opt-in, and the shape matters. The guard
/// (#90's fix) refuses a *new* key file whenever the log already has claims,
/// because it cannot tell a deliberate second role from the accidental
/// identity-mint that silently hid a whole log. What it was missing is a way
/// for the operator to say which one this is. Registration is that signal,
/// and it is deliberately a **separate, explicit act** rather than a flag on
/// the write verbs: a `--as` flag is something a script passes blanket and
/// forgets, whereas minting a role is a thing you do once, on purpose, and
/// can later read back with `kan identity role list`.
///
/// The guard is therefore not weakened — an *undeclared* second identity
/// against a non-empty log is refused exactly as before, which is
/// `.design/v0.8-milestone.md` AC-4's negative control.
pub fn add_role(kan_dir: &Path, name: &str, key_path: &Path) -> Result<Role, Error> {
    if let Some(parent) = key_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let existing = list_roles(kan_dir)?;
    if let Some(clash) = existing.iter().find(|r| r.name == name) {
        return Err(Error::RoleNameTaken {
            name: name.to_string(),
            existing: clash.key_path.display().to_string(),
        });
    }

    // Straight to the plaintext loader, which is what makes this the
    // opt-in: it is `load_or_create` minus the guard, reached only from
    // here. An existing key file is loaded rather than overwritten, so
    // registering a role twice is idempotent instead of destroying a key.
    let identity = Identity::load_or_create_plaintext(key_path)?;
    let did = identity.did();

    if let Some(clash) = existing.iter().find(|r| r.did == did) {
        return Err(Error::RoleAlreadyRegistered {
            did,
            name: clash.name.clone(),
        });
    }

    std::fs::create_dir_all(kan_dir)?;
    let line = format!("{}\t{}\t{}\n", did, name, key_path.display());
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(kan_dir.join(ROLES_FILE))?;
    file.write_all(line.as_bytes())?;

    Ok(Role {
        did,
        name: name.to_string(),
        key_path: key_path.to_path_buf(),
    })
}

/// Record the workspace's pre-existing identity as a role, if it is not
/// already recorded.
///
/// **Found by dogfooding, not by design.** Without this, a workspace that
/// wrote claims before declaring any roles has a *primary* identity that is
/// neither declared nor (once you are running as a role) active — so
/// `--trust roles`, the obvious "show me everything this workspace wrote"
/// command, silently omits every claim written before the roles existed.
/// The exclusion is disclosed, so it is not the silent-loss class; it is
/// still the wrong answer to the obvious question, and the same argument
/// that put the active identity into `--trust roles` applies here.
///
/// Called when the first role is declared, which is the one moment the
/// primary identity is guaranteed to be loaded and its DID known. Once
/// `KAN_IDENTITY_FILE` points at a role, kan never consults the keychain,
/// so the primary's DID is not discoverable at read time — recording it
/// while it is in hand is the only cheap option.
///
/// `key_path` is where the primary key is *looked up*, which for a keychain
/// identity is the account path rather than a file that exists.
pub fn register_active(kan_dir: &Path, did: &Did, key_path: &Path) -> Result<(), Error> {
    let existing = list_roles(kan_dir)?;
    if existing.iter().any(|r| &r.did == did) {
        return Ok(());
    }
    let name = if existing.iter().any(|r| r.name == "primary") {
        format!("primary-{}", &did[did.len().saturating_sub(8)..])
    } else {
        "primary".to_string()
    };

    std::fs::create_dir_all(kan_dir)?;
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(kan_dir.join(ROLES_FILE))?;
    file.write_all(format!("{}\t{}\t{}\n", did, name, key_path.display()).as_bytes())?;
    Ok(())
}

/// Every declared role, in declaration order. A missing file is no roles,
/// not an error — the overwhelmingly common case is a workspace that has
/// never declared one.
///
/// A malformed line is skipped rather than fatal: this file gates nothing
/// (it only *widens* a read), so a hand-edit typo should not take out every
/// command that opens a workspace.
pub fn list_roles(kan_dir: &Path) -> Result<Vec<Role>, Error> {
    let path = kan_dir.join(ROLES_FILE);
    let Ok(text) = std::fs::read_to_string(&path) else {
        return Ok(Vec::new());
    };
    Ok(text
        .lines()
        .filter_map(|line| {
            let mut parts = line.split('\t');
            let did = parts.next()?.trim();
            let name = parts.next()?.trim();
            let key_path = parts.next()?.trim();
            if did.is_empty() || !did.starts_with("did:") {
                return None;
            }
            Some(Role {
                did: did.to_string(),
                name: name.to_string(),
                key_path: PathBuf::from(key_path),
            })
        })
        .collect())
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
/// The identity's 24-word BIP-39 recovery phrase.
///
/// A P-256 private key is 32 bytes, which is exactly BIP-39's 256-bit
/// entropy size, so the phrase carries the key itself rather than a
/// derivation of it — write it down and the identity is recoverable even if
/// the keychain, the disk, and the machine are all gone.
///
/// **This is the private key in another encoding.** kan never prints it
/// unprompted: the release that made the key encrypted at rest would be
/// undone by a tool that spills it into a terminal, a CI log, or an agent
/// transcript on every migration. A human asks for it explicitly, once,
/// and stores it somewhere kan has nothing to do with.
pub fn recovery_phrase(identity: &Identity) -> Result<String, Error> {
    let entropy = identity.keypair.export();
    Ok(bip39::Mnemonic::from_entropy(&entropy)
        .map_err(|e| Error::Recovery(e.to_string()))?
        .to_string())
}

/// Rebuild an identity from its recovery phrase.
///
/// The BIP-39 checksum rejects a mistyped or reordered phrase rather than
/// silently producing a different key — which for a signing identity would
/// mean a different DID and every existing claim dropping out of every read.
pub fn from_recovery_phrase(phrase: &str) -> Result<Identity, Error> {
    let mnemonic = bip39::Mnemonic::parse(phrase.trim()).map_err(|e| {
        Error::Recovery(format!(
            "{e} — check the word order and spelling; the checksum rejects a phrase \
             that is close but not exact, rather than silently giving you a different key"
        ))
    })?;
    let entropy = mnemonic.to_entropy();
    // A correct checksum only proves the words are a well-formed BIP-39
    // phrase, not that their entropy is a usable P-256 scalar — it must lie
    // in [1, n-1], and all-zero entropy (the "abandon abandon … art" phrase)
    // does not. Without this the failure surfaced as "crypto error:
    // signature error", which tells an operator holding 24 words nothing
    // about which of the two things went wrong.
    let keypair = P256Keypair::import(&entropy).map_err(|_| {
        Error::Recovery(
            "those words are a valid BIP-39 phrase, but they do not encode a usable signing \
             key. That means they are not a phrase kan produced — check you have the right \
             one for this repo, rather than a phrase from another tool."
                .to_string(),
        )
    })?;
    Ok(Identity { keypair })
}

// ------------------------------------------------------ derived key material

/// HKDF context label for the encryption slot.
///
/// **Versioned, because it is a format decision and not an implementation
/// detail.** The bytes this label produces *are* the encryption key; changing
/// the string changes every identity's key, which for an encrypted backup
/// means everything previously wrapped to it becomes unreadable. A `v2` label
/// would be a migration, not an edit.
const ENCRYPT_LABEL: &str = "kan/v1/encrypt";

/// HKDF context label for the signing slot of a **seed-rooted** identity.
///
/// Only identities created from v0.9 onward derive their signing key this
/// way. An identity that existed before is grandfathered and keeps the key it
/// has (REQ-6) — see [`Seed`].
const SIGN_LABEL: &str = "kan/v1/sign";

/// The file holding a seed-rooted identity's root secret. Its absence is what
/// marks an identity as grandfathered.
pub const SEED_FILE: &str = "seed";

/// Names the keychain entry holding this workspace's seed. Its presence is
/// the file-only signal that a workspace is seed-rooted with the seed in the
/// keychain, so no keychain call is needed to find that out.
pub const SEED_ID_FILE: &str = "seed-id";

/// Keychain service for seeds -- separate from the signing-key service so a
/// workspace can hold one, the other, or neither without the entries
/// colliding.
const SEED_KEYCHAIN_SERVICE: &str = "dev.kan.seed";

/// Set to any value to make kan behave as though no OS keychain exists.
///
/// Not a test hook bolted on: it is the missing middle of the
/// `KAN_IDENTITY_FILE` story. Today the only way to avoid a keychain prompt
/// is to name a specific key file, which is fine for an agent that manages
/// its own key and wrong for anyone who simply does not want their secrets
/// in the keychain and is happy with `0600` files in `.kan/`.
///
/// It exists because this milestone's own tests could not otherwise run on
/// macOS. Exercising the fresh-workspace path means *not* setting
/// `KAN_IDENTITY_FILE`, which means touching the keychain, which for a
/// rebuilt binary is #96's hang -- a suite that hangs locally and passes on
/// CI is worse than one that fails.
pub const NO_KEYCHAIN_ENV: &str = "KAN_NO_KEYCHAIN";

fn keychain_disabled() -> bool {
    std::env::var_os(NO_KEYCHAIN_ENV).is_some()
}

/// A 32-byte root secret from which a new identity's signing and encryption
/// keys are both derived (ADR-55's Q1, v0.9 REQ-4).
///
/// **Only for identities created from v0.9 onward.** An identity that already
/// exists keeps its signing key verbatim (REQ-6) and derives only its
/// encryption key, from that key's own material (ADR-65). Two schemes
/// coexisting permanently is the deliberate shape: it is the one form in
/// which no existing DID can move, and a DID moving is the failure #90 and
/// #107 both were.
pub struct Seed([u8; 32]);

impl Seed {
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// Read a seed file, or create one. `0600`, like the key files.
    pub fn load_or_create(path: &Path) -> Result<Self, Error> {
        if let Some(seed) = Self::from_file(path)? {
            return Ok(seed);
        }
        let seed = Self::generate();
        seed.save(path)?;
        Ok(seed)
    }

    fn from_file(path: &Path) -> Result<Option<Self>, Error> {
        let Ok(bytes) = std::fs::read(path) else {
            return Ok(None);
        };
        if bytes.len() != 32 {
            return Err(Error::Recovery(format!(
                "{} is {} bytes, not 32 -- this is not a kan seed file. kan will not guess \
                 at it, because deriving a signing key from the wrong bytes would silently \
                 give this repo a different identity.",
                path.display(),
                bytes.len()
            )));
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&bytes);
        Ok(Some(Self(seed)))
    }

    fn save(&self, path: &Path) -> Result<(), Error> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, self.0)?;
        restrict_permissions(path)?;
        Ok(())
    }

    /// This workspace's seed, if it is seed-rooted at all.
    ///
    /// **Decided from files before any keychain call.** `.kan/seed-id` names
    /// a keychain entry; `.kan/seed` is the plaintext fallback; neither means
    /// this workspace is not seed-rooted and the keychain is never touched.
    /// That ordering is load-bearing: a grandfathered workspace on macOS must
    /// not probe the keychain for a seed it will never have, because that
    /// probe is exactly the prompt that hangs a rebuilt binary (#96).
    pub fn load(kan_dir: &Path) -> Result<Option<Self>, Error> {
        if let Some(seed) = Self::from_file(&kan_dir.join(SEED_FILE))? {
            return Ok(Some(seed));
        }
        if keychain_disabled() {
            return Ok(None);
        }
        let id_path = kan_dir.join(SEED_ID_FILE);
        let Ok(account) = std::fs::read_to_string(&id_path) else {
            return Ok(None);
        };
        let account = account.trim().to_string();
        let entry = keyring::Entry::new(SEED_KEYCHAIN_SERVICE, &account).map_err(|e| {
            Error::KeychainUnreachable {
                detail: e.to_string(),
            }
        })?;
        match entry.get_secret() {
            Ok(bytes) if bytes.len() == 32 => {
                let mut seed = [0u8; 32];
                seed.copy_from_slice(&bytes);
                Ok(Some(Self(seed)))
            }
            Ok(_) => Err(Error::Recovery(
                "the seed in the OS keychain is not 32 bytes -- refusing to derive an \
                 identity from it rather than silently producing a different DID."
                    .to_string(),
            )),
            Err(e) => Err(Error::KeychainUnreachable {
                detail: format!("seed entry: {e}"),
            }),
        }
    }

    /// Create this workspace's seed, preferring the OS keychain.
    ///
    /// Stored exactly the way the signing key is stored today (ADR-25): in
    /// the keychain when one is available, in a `0600` file when it is not,
    /// with the same warning. ADR-55's "at-rest protection is OS file
    /// permissions **plus the existing keychain path where present**" is read
    /// as sanctioning this rather than as requiring a plaintext root.
    ///
    /// Taking the file-always reading would have reopened issue #6 for every
    /// new workspace — the root secret in plaintext where the key it replaces
    /// was encrypted — which is a strictly worse at-rest posture than the
    /// version it upgrades from. Callers who genuinely need no-prompt (CI,
    /// agents, `day`) already set `KAN_IDENTITY_FILE`, which bypasses all of
    /// this and is unchanged.
    pub fn create(kan_dir: &Path) -> Result<Self, Error> {
        std::fs::create_dir_all(kan_dir)?;
        let seed = Self::generate();
        let account = fresh_account();

        let stored = !keychain_disabled()
            && keyring::Entry::new(SEED_KEYCHAIN_SERVICE, &account)
                .ok()
                .and_then(|entry| entry.set_secret(&seed.0).ok())
                .is_some();

        if stored {
            std::fs::write(kan_dir.join(SEED_ID_FILE), &account)?;
        } else {
            eprintln!(
                "kan: OS keychain unavailable -- this repo's root seed is stored as a \
                 plaintext file at {}, readable by anything running as you. Take its \
                 recovery phrase (`kan identity phrase`) and keep it somewhere safe.",
                kan_dir.join(SEED_FILE).display()
            );
            seed.save(&kan_dir.join(SEED_FILE))?;
        }
        Ok(seed)
    }

    /// The seed's own recovery phrase — 24 words, exactly as a signing key's
    /// phrase is, and deliberately indistinguishable from one.
    ///
    /// There is no marker byte and no different word count. Both would have
    /// worked, and both were rejected: a marker collides with a legacy key
    /// whose first byte happens to match (1 in 256, which is not rare enough
    /// for a recovery path), and a shorter phrase buys distinguishability by
    /// cutting the root's entropy. Ambiguity that can be resolved against a
    /// workspace is better than either.
    pub fn phrase(&self) -> Result<String, Error> {
        Ok(bip39::Mnemonic::from_entropy(&self.0)
            .map_err(|e| Error::Recovery(e.to_string()))?
            .to_string())
    }

    pub fn from_entropy(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The signing key this seed derives.
    ///
    /// **Retries on an unusable scalar rather than failing.** A P-256 private
    /// key must lie in `[1, n-1]`, and HKDF output is uniform bytes that can
    /// land outside it. The probability is about 2^-32 — negligible, and
    /// "negligible" is not a property a recovery path may rest on, because
    /// the user it fails is holding 24 words that will never work and no way
    /// to know why. The spike (`tests/key_derivation_spike.rs`) established
    /// that `P256Keypair::import` *rejects* such bytes rather than coercing
    /// them, which is what makes this loop correct instead of hopeful.
    pub fn signing_identity(&self) -> Result<Identity, Error> {
        for attempt in 0u8..64 {
            let label = if attempt == 0 {
                SIGN_LABEL.to_string()
            } else {
                format!("{SIGN_LABEL}/{attempt}")
            };
            if let Ok(keypair) = P256Keypair::import(&derive::<32>(&self.0, &label)) {
                return Ok(Identity { keypair });
            }
        }
        Err(Error::Recovery(
            "could not derive a usable signing key from this seed after 64 attempts, which \
             should be impossible -- please report it with the seed's phrase kept private."
                .to_string(),
        ))
    }

    /// The encryption key this seed derives, independently of the signing
    /// slot.
    pub fn encryption_key(&self) -> EncryptionKey {
        EncryptionKey {
            secret: x25519_dalek::StaticSecret::from(derive::<32>(&self.0, ENCRYPT_LABEL)),
        }
    }
}

/// Derive `N` bytes from root key material under a labelled context.
fn derive<const N: usize>(root: &[u8], label: &str) -> [u8; N] {
    let hk = hkdf::Hkdf::<sha2::Sha256>::new(None, root);
    let mut out = [0u8; N];
    hk.expand(label.as_bytes(), &mut out)
        .expect("output length is far inside HKDF-SHA256's limit");
    out
}

/// An identity's X25519 encryption key (ADR-55's Q2, v0.9 REQ-5).
///
/// Per *identity*, not per device: every device holding the same root derives
/// the same key, so any of them can decrypt a space shared with this identity.
/// Nothing in kan encrypts anything yet — this exists so ADR-54's L1 encrypted
/// backup and #7's HPKE protocol have a recipient to address.
pub struct EncryptionKey {
    secret: x25519_dalek::StaticSecret,
}

impl EncryptionKey {
    /// The public half, hex-encoded — safe to share, and the thing a remote
    /// or a peer wraps a content key to.
    pub fn public_hex(&self) -> String {
        x25519_dalek::PublicKey::from(&self.secret)
            .as_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    /// The secret half, for the HPKE pass that will actually use it.
    pub fn secret(&self) -> &x25519_dalek::StaticSecret {
        &self.secret
    }
}

impl Identity {
    /// This identity's encryption key, derived from the signing key's own
    /// material under a separate labelled context.
    ///
    /// **Derived, never converted.** The Ed25519→X25519 footgun is reusing
    /// one key's *scalar* on two curves; this instead runs the root through
    /// HKDF under a distinct label, so the encryption key is a one-way
    /// function of the root rather than a re-encoding of the signing key.
    /// Compromising the encryption key therefore yields nothing about the
    /// signing key.
    ///
    /// **What the root is, stated plainly because it is asymmetric.** Today
    /// the root *is* the signing key material, which means the existing
    /// recovery phrase already reproduces this key and nobody has to escrow a
    /// second secret — the property that makes this deployable to every
    /// existing workspace with no migration at all. It also means the signing
    /// key dominates the encryption key: whoever holds the former can derive
    /// the latter. That is the same shape as the seed-rooted scheme (a root
    /// that dominates both slots), with the signing key playing the root's
    /// part for identities that predate the seed. ADR-55's grandfathering is
    /// what makes that acceptable rather than a compromise: every existing
    /// DID stays valid, which was the constraint with teeth.
    pub fn encryption_key(&self) -> EncryptionKey {
        let root = self.keypair.export();
        EncryptionKey {
            secret: x25519_dalek::StaticSecret::from(derive::<32>(&root, ENCRYPT_LABEL)),
        }
    }
}

/// The recovery phrase for a workspace, whichever scheme roots it.
///
/// A seed-rooted identity's phrase encodes the **seed**; a grandfathered
/// one's encodes the **signing key**, exactly as it always has. Both are 24
/// words and neither says which it is — see [`Seed::phrase`] for why no
/// marker was added.
///
/// This is the one place that distinction reaches a person, so it is the one
/// place it must not be silent: the caller is told which root it holds, since
/// "write these down" means something different when the words are a root
/// that derives two keys than when they are one key.
pub fn workspace_phrase(kan_dir: &Path, identity: &Identity) -> Result<(String, Root), Error> {
    if let Some(seed) = Seed::load(kan_dir)? {
        return Ok((seed.phrase()?, Root::Seed));
    }
    Ok((recovery_phrase(identity)?, Root::SigningKey))
}

/// What a workspace's recovery phrase actually encodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Root {
    /// Created v0.9 or later: the phrase is the seed, and both the signing
    /// and encryption keys derive from it.
    Seed,
    /// Created before v0.9 and grandfathered: the phrase is the signing key
    /// itself, and the encryption key derives from that key (ADR-65).
    SigningKey,
}

impl Root {
    pub fn describe(&self) -> &'static str {
        match self {
            Root::Seed => {
                "a seed -- it derives both this repo's signing key and its \
                           encryption key"
            }
            Root::SigningKey => {
                "this repo's signing key -- its encryption key derives from \
                                 that key in turn"
            }
        }
    }
}

/// What a phrase yields under each reading, for a caller trying to work out
/// which workspace it belongs to.
///
/// Both readings always produce a valid DID, because both are 32 bytes of
/// BIP-39 entropy and nothing distinguishes them. Rather than guess, this
/// returns both and lets the caller compare against a workspace that knows
/// its own author — which is every case where the answer actually matters.
pub fn candidate_identities(phrase: &str) -> Result<Vec<(Root, Identity)>, Error> {
    let mnemonic = bip39::Mnemonic::parse(phrase.trim()).map_err(|e| {
        Error::Recovery(format!(
            "{e} — check the word order and spelling; the checksum rejects a phrase \
             that is close but not exact, rather than silently giving you a different key"
        ))
    })?;
    let entropy = mnemonic.to_entropy();

    let mut out = Vec::new();
    if entropy.len() == 32 {
        let mut seed_bytes = [0u8; 32];
        seed_bytes.copy_from_slice(&entropy);
        if let Ok(identity) = Seed::from_entropy(seed_bytes).signing_identity() {
            out.push((Root::Seed, identity));
        }
    }
    if let Ok(keypair) = P256Keypair::import(&entropy) {
        out.push((Root::SigningKey, Identity { keypair }));
    }

    if out.is_empty() {
        return Err(Error::Recovery(
            "those words are a valid BIP-39 phrase, but they do not encode a usable kan \
             identity under either scheme. That means they are not a phrase kan produced -- \
             check you have the right one for this repo, rather than a phrase from another \
             tool."
                .to_string(),
        ));
    }
    Ok(out)
}

pub fn verify(did: &Did, msg: &[u8], sig: &[u8]) -> bool {
    verify_signature(did, msg, sig).is_ok()
}
