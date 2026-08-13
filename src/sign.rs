//! Local-only identity (ADR-4): a self-generated `did:key` keypair. `did:key`
//! is self-certifying — no PDS/network needed — and is the exact identity
//! atproto expects later, so local-only and future sync share one identity
//! model without re-signing history.
//!
//! # Resolution: three questions, three functions
//!
//! `.design/identity-resolution.md` traced every defect of the v0.11 review
//! loop to one cause — kan conflated three questions into one function and
//! answered them with side effects. They are now separate:
//!
//! - [`workspace_identity`] — *which identity does this workspace have?* Pure.
//!   Never creates, writes or migrates. **One precedence order**, used by
//!   reads and writes alike: `.kan/seed`, then a seed in the keychain via
//!   `.kan/seed-id`, then a signing key in the keychain via
//!   `.kan/identity-id`, then `.kan/identity`.
//! - [`signing_identity`] — *which identity should sign this write?* A
//!   [`Selection`], parsed from `KAN_IDENTITY_FILE`. A selection naming
//!   something absent is **always** an error: never a mint, never a fallback,
//!   never a substitution of another key.
//! - [`create_workspace_identity`] — *may kan create one?* The only function
//!   that writes an identity, so the ADR-77 guard is a property of the
//!   workspace rather than of whichever code path reached it.
//!
//! `KAN_IDENTITY_FILE` selects; it does not redefine what identity a
//! workspace has. Conflating those is the substitution every v0.11 round's
//! defect turned out to be.
//!
//! # Why the keychain is in the chain
//!
//! Because the alternative is reads and writes disagreeing. Consulting it
//! only on the write side was #170: `kan identity did` resolved and
//! `--trust me` reported no identity, in the same workspace. A read with no
//! `--trust me` resolves nothing and never reaches here, so ADR-83 is intact.
//!
//! On macOS a keychain entry is ACL'd to the binary that created it, so a
//! rebuilt or upgraded kan blocks on an authorization prompt that never
//! arrives in CI, a container, an MCP server, or `day` shelling out (#96,
//! #69 — one cause, two issue numbers, and it is code signing rather than
//! keychains). `KAN_NO_KEYCHAIN` (ADR-66) opts out entirely; every identity
//! test sets it, which is why the keychain-reachable plane is unreachable
//! from the suite and documented in prose instead
//! (`.design/identity-resolution-cells.md`).
//!
//! # The pre-REQ-1 resolver is gone (#183)
//!
//! `Identity::load_or_create`, `load_or_create_for_workspace`,
//! `keychain_account`, `refuse_second_identity`, `existing_identity_evidence`
//! and `warn_keychain_unavailable` were deleted by v0.12 REQ-3.5. They had
//! stopped being called from `src/` when REQ-1 landed, and survived only
//! because ~46 test call sites reached them directly — so the suite was
//! reporting coverage for behaviour the product no longer performed, which is
//! the same shape as a test that cannot fail.
//!
//! Three behaviours went with them, all deliberately:
//!
//! - **plaintext→keychain migration**, and the deletion of the redundant
//!   plaintext copy (ADR-25/ADR-53). Retired as a *feature*, not merely moved
//!   off the resolution path: a capability that only ever fired as a side
//!   effect of `kan show` was never one an operator could ask for, see, or
//!   undo. [`super::sign`]'s replacement is `kan identity protect`, which is
//!   explicit, covers all four at-rest states, and has an inverse.
//! - **repairing a `0644` key file to `0600` on load** — a *read* changing a
//!   file's permissions, which is one of the three violations
//!   `.design/v0.12-milestone.md` AC-8 required to go. Anything kan itself
//!   writes is still owner-only ([`Identity::save`], [`Seed::save`]); a file
//!   kan did not write is the operator's.
//! - **minting from a selection**. `KAN_IDENTITY_FILE` naming a missing path
//!   is an error (REQ-2), so there is no longer a create-here branch to guard.
//!
//! `Identity::load_or_create_plaintext` is **not** in that list and is still
//! live: [`add_role`] calls it, because minting a role key is the one
//! deliberate creation that is not `create_workspace_identity`'s job.

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

/// Kan-managed identity and repository-configuration persistence. Keychain
/// rows name the service selected by a pointer; tests never access the live
/// keychain merely to enumerate them.
pub const SURFACE_VALUES: &[crate::surface::SurfaceValue] = &[
    crate::surface::SurfaceValue::new("identity:seed", "*"),
    crate::surface::SurfaceValue::new("identity:seed-id", "*"),
    crate::surface::SurfaceValue::new("identity:identity", "*"),
    crate::surface::SurfaceValue::new("identity:identity-id", "*"),
    crate::surface::SurfaceValue::new("identity:roles.d", "*"),
    crate::surface::SurfaceValue::new("identity:role-key-path", "caller-selected"),
    crate::surface::SurfaceValue::new("system-config:KAN_IDENTITY_FILE", "*"),
    crate::surface::SurfaceValue::new("system-config:KAN_NO_KEYCHAIN", "*"),
    crate::surface::SurfaceValue::new("repo-config:legacy-roles", "*"),
    crate::surface::SurfaceValue::new("keychain:dev.kan.seed", "*"),
    crate::surface::SurfaceValue::new("keychain:dev.kan.identity", "*"),
];

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
    /// A deliberate refusal. Its own variant because `Recovery`'s
    /// "recovery phrase: " prefix was being stamped onto messages with nothing
    /// to do with a phrase -- the KAN_NO_KEYCHAIN refusal reached the user as
    /// "error: recovery phrase: refusing: ...".
    #[error("{0}")]
    Refused(String),
    #[error(
        "this repo already has an identity -- {evidence} -- and {attempt} would give it a \
         second identity.\n\n\
         Two identities in one workspace means the one kan resolves is the one that signs, \
         and that is decided by environment and file layout rather than by anything you \
         said. Authorship of everything written from here on would depend on which key won \
         that race.\n\n\
         {remedy}\n\n\
         If you meant to add a second *role* to this workspace -- a director and a prover \
         signing separately, say -- that is a supported thing and this is not the way to ask \
         for it: run `kan identity role add <name> --key <path>`, which mints the role key \
         deliberately and registers it, then read with `--trust roles` so both roles' claims \
         are visible."
    )]
    WouldMintSecondIdentity {
        attempt: String,
        remedy: String,
        evidence: String,
    },
    /// **`DeclaredRoleKeyMissing` was here and is deleted** (REQ-4). It named
    /// the role whose key had gone missing, by matching the path against the
    /// registry's third column — and the registry no longer has one, because a
    /// path is machine-specific and unverifiable from a claim. A DID cannot
    /// substitute for it: computing one means loading the key that is missing.
    ///
    /// Rebuilding it by convention was specified and then rejected — it would
    /// have kept the specific message only for keys kan itself minted at
    /// `.kan/roles.d/<name>`, which is the case least likely to have gone
    /// missing, and told the operator who typed `--key /elsewhere` nothing.
    /// [`Error::SelectionMissing`] carries the facts instead, in every case.
    #[error(
        "KAN_IDENTITY_FILE names {path}, which does not exist.\n\n\
         That variable SELECTS which identity signs this write; it does not define which \
         identity this workspace has. A selection whose target is missing is an error -- \
         kan will not create a key there, and will not quietly sign as somebody else.\n\n\
         Point it at the key you meant, or unset it to use this workspace's own identity. \
         To restore from a recovery phrase, write the key to that path first.{declared}\n\n\
         If you meant to add a second *role* to this workspace -- a director and a prover \
         signing separately, say -- that is supported and this is not the way to ask for \
         it: run `kan identity role add <name>`, which mints the role key at \
         .kan/roles.d/<name> and declares it, then read with `--trust roles` so both \
         roles' claims are visible."
    )]
    SelectionMissing {
        path: String,
        /// A pre-rendered clause naming this workspace's declared roles, or
        /// empty when they are not knowable here.
        ///
        /// **Pre-rendered rather than a `Vec<String>`, and filled in by the
        /// caller, because of where this is raised.** `signing_identity` sits
        /// below the log: it resolves keys and knows nothing about claims, and
        /// the declared set is now a projection over claims. So `sign` raises
        /// this with the clause empty and
        /// `Workspace::commit_identity` refills it, which is the first layer
        /// that can see both the selection and the log. One variant either
        /// way — REQ-4 deletes a variant and adds none.
        declared: String,
    },
    #[error(
        "a role named `{name}` is already declared in this workspace, as {existing}. \
         Pick another name, or use the existing role.\n\n\
         Declaring it again would not fail -- the log is append-only and the later \
         declaration would simply win -- which is why this refuses BEFORE the write \
         rather than after."
    )]
    RoleNameTaken { name: String, existing: String },
    #[error(
        "only this workspace's own identity can declare a role, and right now kan is \
         signing as {signer}.\n\n\
         This workspace's identity is {workspace}. A declaration written by anyone else \
         is a valid claim that grants NOTHING -- it would appear in `kan show` and never \
         in `--trust roles` -- so kan refuses rather than writing one that silently does \
         nothing.\n\n\
         Unset KAN_IDENTITY_FILE to declare as this workspace. A role that needs to \
         declare roles is a second workspace identity, and the honest way to say that is \
         to be one (`.design/role-declarations.md`, depth 0)."
    )]
    NotTheWorkspaceIdentity { signer: Did, workspace: Did },
    #[error(
        "this workspace has no identity of its own, so a role declared here could never \
         be honoured.\n\n\
         Only the identity a workspace RESOLVES TO may declare a role, and this one \
         resolves to none -- kan is signing as {signer}, selected with KAN_IDENTITY_FILE. \
         Writing the declaration would succeed and grant nothing: it would appear in `kan \
         show` and never in `--trust roles`.\n\n\
         Give the workspace an identity of its own first (`kan identity adopt --key \
         <path>` names a key it already has claims from), then declare the role."
    )]
    NoWorkspaceIdentityToDeclare { signer: Did },
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

    /// Load a key that must already exist -- never creates one.
    ///
    /// `load_or_create` cannot serve `adopt`: its whole contract is to
    /// produce a key one way or another, and adopt's contract is the
    /// opposite. Pointing adopt at a path that holds nothing must fail
    /// loudly, not quietly mint the identity the operator is trying to
    /// recover from losing.
    pub fn load_existing(path: &Path) -> Result<Self, Error> {
        let bytes = std::fs::read(path)?;
        Ok(Self {
            keypair: P256Keypair::import(&bytes)?,
        })
    }

    /// Write this key to `path` at `0600`, creating its parent if needed.
    ///
    /// The `create_dir_all` matches [`Seed::save`] and is not new behaviour
    /// moving: the retired `load_or_create` did it at the top of the function,
    /// so every caller that named a path inside a not-yet-existing `.kan/`
    /// relied on it. Keeping it here is what lets `Identity::generate()` +
    /// `save` be a drop-in for `load_or_create` (#183) rather than a
    /// rewrite that quietly needs a `create_dir_all` at every call site.
    pub fn save(&self, path: &Path) -> Result<(), Error> {
        if let Some(parent) = path.parent() {
            // surface-write: identity:identity,identity:role-key-path
            std::fs::create_dir_all(parent)?;
        }
        // surface-write: identity:identity,identity:role-key-path
        std::fs::write(path, self.keypair.export())?;
        restrict_permissions(path)?;
        Ok(())
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

/// Whether this repo's log already holds claims.
///
/// Deliberately a file-existence check rather than a read: `sign` must not
/// depend on `store`, and the question here is only "has anything ever been
/// written," which a non-empty CAR answers without decoding a single claim.
fn log_has_claims(kan_dir: &Path) -> bool {
    Some(kan_dir.join("log").join("repo.car"))
        .filter(|car| car.exists())
        .and_then(|car| std::fs::metadata(car).ok())
        .is_some_and(|m| m.len() > 0)
}

/// The file recording this workspace's declared role identities, one per
/// line as `<did>\t<name>\t<key path>`.
///
/// **Read-only since v0.12, and kept only as `kan identity role import`'s
/// input.** Nothing writes it any more; the registry is
/// `ClaimBody::RoleDeclaration` claims (`.design/role-declarations.md`).
///
/// *This docstring used to argue the opposite, and the reversal is the point.*
/// It said the file lives in `.kan/` "because a role is a local process
/// arrangement, not something to share — the *claims* roles write are the
/// shareable part, and they already carry their own author." That reasoning
/// holds for a **path**, which is why REQ-4 keeps the path out of the claim.
/// It does not hold for the **binding**: that this workspace vouched for a DID
/// under a name is exactly the attributable, revocable assertion kan exists to
/// record, and keeping it in a file is what cost it provenance, an author, and
/// revocation-by-retraction.
///
/// kan neither rewrites nor deletes this file. `import` says it is safe to
/// remove and names the one reason to keep it — a kan older than v0.12 reads
/// it and cannot interpret a declaration.
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
/// **Registration is now a claim, so this only mints the key.** The clash
/// checks moved to `actions::declare_role`, where the declared set is
/// resolvable from the log; they survive as write-time *affordance* — an
/// append-only log cannot refuse a duplicate, so the warning happens before
/// the log grows a shape that needs a tiebreak (`.design/role-declarations.md`
/// REQ-6).
pub fn mint_role_key(name: &str, key_path: &Path) -> Result<Role, Error> {
    if let Some(parent) = key_path.parent() {
        // surface-write: identity:role-key-path
        std::fs::create_dir_all(parent)?;
    }

    // Straight to the plaintext loader, which is what makes this the
    // opt-in: it is `load_or_create` minus the guard, reached only from
    // here. An existing key file is loaded rather than overwritten, so
    // registering a role twice is idempotent instead of destroying a key.
    let identity = Identity::load_or_create_plaintext(key_path)?;

    Ok(Role {
        did: identity.did(),
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
/// **Now a claim, appended by `actions::declare_role`.** The reasoning above
/// is unchanged and is why the auto-declaration survived the move; only the
/// medium changed, and with it the last argument for the registry carrying a
/// key path — the primary's `key_path` was always the path it is *looked up*
/// at, which for a keychain-rooted workspace is a file that does not exist.
/// Measured in exactly that state: `sheaf-games` records its primary at
/// `.kan/identity`, which has never been there.
/// **Returns a name that is genuinely free**, which it did not until a third
/// cold review.
///
/// It used to ask only whether the literal `"primary"` was taken and, if so,
/// return `primary-<suffix>` **without checking that too**. So a workspace
/// where both were already declared got a name that collided, REQ-6's
/// latest-wins rebound it, and the previous holder's claims silently left
/// `--trust roles` — round 1's defect reached from a third direction.
///
/// The round-2 fix that extended the caller's `taken` list bought nothing
/// against that, because the branch it selects never consulted the list for
/// the fallback. The comment claiming "`primary-<suffix>` cannot collide with
/// one either" was false when written, and no test covered it: reverting that
/// hunk left all 385 tests green.
pub fn primary_role_name(did: &Did, taken: &[String]) -> String {
    let suffix = &did[did.len().saturating_sub(8)..];
    let free = |candidate: &String| !taken.iter().any(|name| name == candidate);

    let preferred = ["primary".to_string(), format!("primary-{suffix}")];
    if let Some(name) = preferred.into_iter().find(|c| free(c)) {
        return name;
    }
    // Both taken. Deterministic and unbounded rather than "give up and
    // collide": a name that silently replaces a live declaration is the one
    // outcome this function exists to avoid.
    (2..)
        .map(|n| format!("primary-{suffix}-{n}"))
        .find(|c| free(c))
        .expect("an unbounded sequence always contains a free name")
}

/// Every declared role, in declaration order. A missing file is no roles,
/// not an error — the overwhelmingly common case is a workspace that has
/// never declared one.
///
/// A malformed line is skipped rather than fatal: this file gates nothing
/// (it only *widens* a read), so a hand-edit typo should not take out every
/// command that opens a workspace.
pub fn workspace_identity(kan_dir: &Path) -> Result<Option<Identity>, Error> {
    // 1 & 2: a root seed, from `.kan/seed` or from the keychain via
    // `.kan/seed-id`. `Seed::load` decides from files before any keychain
    // call and creates nothing.
    if let Some(seed) = Seed::load(kan_dir)? {
        return Ok(Some(seed.signing_identity()?));
    }
    // 3: a keychain-held signing key, named by `.kan/identity-id`. This is
    // the branch the read side never had, and its absence *was* #170.
    if let Some(identity) = keychain_identity(kan_dir)? {
        return Ok(Some(identity));
    }
    // 4: a plaintext key file.
    let key_path = kan_dir.join("identity");
    if key_path.exists() {
        return Ok(Some(Identity::load_existing(&key_path)?));
    }
    Ok(None)
}

/// Where this workspace's secret sits **at rest**, decided from files alone.
///
/// **This must mirror [`workspace_identity`]'s precedence exactly**, and that
/// is the single most likely way REQ-3 goes wrong. Get it wrong and `protect`
/// moves a secret that is not the one signing — which is #170's disagreement
/// class (two answers to one question) wearing a new hat, in a command whose
/// whole job is to move a secret without changing the DID.
///
/// Note that **`.kan/identity-id` outranks `.kan/identity`**, which is not the
/// order anyone writes from memory. `src/sign.rs` already holds three
/// orderings over these four files — this one, [`identity_evidence`]'s (which
/// only selects a message, so its order is not a precedence claim) and
/// [`Seed::load`]'s. This is deliberately not a fourth.
///
/// Pure: file existence only, no keychain call, nothing created. That is what
/// lets `plan_protect` and `plan_unprotect` be enumerated by
/// `tests/derived_cells.rs` over the same configurations the resolvers are,
/// rather than hand-listed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AtRest {
    /// `.kan/seed` — a passphraseless root seed. The default from v0.12.
    SeedFile,
    /// `.kan/seed-id` — a root seed in the OS keychain.
    SeedKeychain,
    /// `.kan/identity-id` — a grandfathered signing key in the OS keychain.
    KeyKeychain,
    /// `.kan/identity` — a grandfathered plaintext signing key.
    KeyFile,
    /// No at-rest secret of this workspace's own.
    None_,
}

impl AtRest {
    /// Whether the secret is already in the OS keychain.
    pub fn is_protected(self) -> bool {
        matches!(self, AtRest::SeedKeychain | AtRest::KeyKeychain)
    }

    /// The file that holds or names it, relative to `.kan/`.
    pub fn file(self) -> Option<&'static str> {
        match self {
            AtRest::SeedFile => Some(SEED_FILE),
            AtRest::SeedKeychain => Some(SEED_ID_FILE),
            AtRest::KeyKeychain => Some(IDENTITY_ID_FILE),
            AtRest::KeyFile => Some("identity"),
            AtRest::None_ => None,
        }
    }
}

/// See [`AtRest`]. Mirrors [`workspace_identity`]'s order: seed, seed-id,
/// identity-id, identity.
pub fn at_rest(kan_dir: &Path) -> AtRest {
    if kan_dir.join(SEED_FILE).exists() {
        return AtRest::SeedFile;
    }
    if kan_dir.join(SEED_ID_FILE).exists() {
        return AtRest::SeedKeychain;
    }
    if kan_dir.join(IDENTITY_ID_FILE).exists() {
        return AtRest::KeyKeychain;
    }
    if kan_dir.join("identity").exists() {
        return AtRest::KeyFile;
    }
    AtRest::None_
}

/// Every at-rest artifact present, in precedence order — not just the winner.
///
/// `protect` must report what it did **not** move: protecting the signing
/// secret while `.kan/identity` still sits beside it leaves a plaintext key on
/// disk under a command whose entire promise is that none remains. Precedence
/// says the others are not signing; that is not the same as their not being
/// there.
pub fn at_rest_all(kan_dir: &Path) -> Vec<AtRest> {
    [
        AtRest::SeedFile,
        AtRest::SeedKeychain,
        AtRest::KeyKeychain,
        AtRest::KeyFile,
    ]
    .into_iter()
    .filter(|a| a.file().is_some_and(|f| kan_dir.join(f).exists()))
    .collect()
}

/// What `protect` or `unprotect` would do here — decided from files alone.
///
/// Pure, so it joins the derived cell table alongside the resolvers instead of
/// being a hand-kept list of cases.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Plan {
    /// Move the secret into the keychain. `stale_pointer` is a pointer file
    /// that already exists for this secret kind and will be retired.
    Protect {
        from: AtRest,
        stale_pointer: Option<&'static str>,
    },
    /// Move the secret out of the keychain into a `0600` file. `occupied` is a
    /// destination file that already exists — the case AC-3.9 turns on.
    Unprotect {
        from: AtRest,
        occupied: Option<&'static str>,
    },
    /// Already in the state asked for; nothing is written.
    AlreadyThere(AtRest),
    /// This workspace has no identity of its own to move.
    NoIdentity,
}

/// [`Plan`] for `kan identity protect`.
pub fn plan_protect(kan_dir: &Path) -> Plan {
    match at_rest(kan_dir) {
        AtRest::None_ => Plan::NoIdentity,
        a if a.is_protected() => Plan::AlreadyThere(a),
        from => Plan::Protect {
            from,
            // A pointer for this secret kind that already exists. Retired
            // audibly rather than silently overwritten: orphaning a keychain
            // entry is this codebase's accepted behaviour (`retire_seed` does
            // it deliberately and the entry stays reachable in Keychain
            // Access) — doing it without saying so is the part that was wrong.
            stale_pointer: match from {
                AtRest::SeedFile if kan_dir.join(SEED_ID_FILE).exists() => Some(SEED_ID_FILE),
                // UNREACHABLE: `at_rest` returns `KeyKeychain` before `KeyFile`, so
                // `from` is never `KeyFile` while identity-id exists. A cold
                // review enumerated all 16 layouts and confirmed it never
                // fires. Kept with this note rather than deleted, so the next
                // reader does not wonder whether the case was forgotten.
                AtRest::KeyFile if kan_dir.join(IDENTITY_ID_FILE).exists() => {
                    Some(IDENTITY_ID_FILE)
                }
                _ => None,
            },
        },
    }
}

/// [`Plan`] for `kan identity unprotect`.
pub fn plan_unprotect(kan_dir: &Path) -> Plan {
    match at_rest(kan_dir) {
        AtRest::None_ => Plan::NoIdentity,
        a if !a.is_protected() => Plan::AlreadyThere(a),
        from => Plan::Unprotect {
            from,
            // The destination already holding something is the ONLY case that
            // can destroy a secret in this design, and it is reachable from a
            // state kan itself creates: ADR-53 keeps a plaintext copy exactly
            // when it DIFFERS from the keychain. See `unprotect_to`.
            occupied: match from {
                // Unreachable for the mirror reason: `at_rest` returns
                // `SeedFile` before `SeedKeychain`.
                AtRest::SeedKeychain if kan_dir.join(SEED_FILE).exists() => Some(SEED_FILE),
                AtRest::KeyKeychain if kan_dir.join("identity").exists() => Some("identity"),
                _ => None,
            },
        },
    }
}

/// Which keychain service holds a given secret kind.
fn service_for(a: AtRest) -> &'static str {
    match a {
        AtRest::SeedFile | AtRest::SeedKeychain => SEED_KEYCHAIN_SERVICE,
        _ => KEYCHAIN_SERVICE,
    }
}

/// The DID a secret of this kind derives, without installing it anywhere.
fn did_of(kind: AtRest, bytes: &[u8]) -> Result<Did, Error> {
    match kind {
        AtRest::SeedFile | AtRest::SeedKeychain => {
            let mut b = [0u8; 32];
            if bytes.len() != 32 {
                return Err(Error::Recovery(format!(
                    "expected a 32-byte seed, got {} bytes",
                    bytes.len()
                )));
            }
            b.copy_from_slice(bytes);
            Ok(Seed::from_entropy(b).signing_identity()?.did())
        }
        _ => Ok(Identity {
            keypair: P256Keypair::import(bytes)?,
        }
        .did()),
    }
}

/// **AC-3.9's whole substance, extracted from the executor so it can be
/// tested.**
///
/// `unprotect` reads from the keychain, which is the plane no test can reach
/// (#96) — so a guard living inside that read is a guard no test can exercise,
/// and #112's history is precisely a guard that was never exercised because it
/// was a tautology (`bytes == import(bytes).export()`, which never read the
/// file). Taking the decision out and passing the bytes in is the same move
/// that made `at_rest` derivable: the part that can be wrong becomes the part
/// that is checked.
///
/// Refuses on a DIFFERENT secret, and refuses on an unreadable one. "I cannot
/// tell whether this file holds a different identity" and "this file holds the
/// same identity" are different answers; only the second permits a write.
pub fn refuse_to_overwrite_a_different_secret(
    dest: &Path,
    incoming: &[u8],
    kind: AtRest,
    incoming_did: &Did,
    account: &str,
) -> Result<(), Error> {
    if !dest.exists() {
        return Ok(());
    }
    let existing = std::fs::read(dest)?;
    if existing == incoming {
        return Ok(());
    }
    // Deliberately NOT "keep the newer" or "keep both". The operator is the
    // only one who knows which identity they mean, and choosing here destroys
    // the other one silently.
    let other = did_of(kind, &existing)
        .map(|d| d.to_string())
        .unwrap_or_else(|_| "an unreadable secret".to_string());
    Err(Error::Recovery(format!(
        "refusing to unprotect: {} already exists and holds a DIFFERENT secret.\n\n\
         the keychain holds {incoming_did}\n\
         that file holds  {other}\n\n\
         Writing the keychain's copy over that file would destroy the only copy of the \
         second identity, and any claims signed by it would drop out of every read. kan \
         will not choose for you.\n\n\
         Move that file aside if you want the keychain's identity, or delete the keychain \
         entry ({account}) if you want the file's.",
        dest.display()
    )))
}

/// Execute `Plan::Unprotect`: move the secret from the keychain into a `0600`
/// file, and **never write over a different one**.
///
/// **AC-3.9, and it is the only path in this design that can destroy a secret.**
/// `.kan/identity` holding key A beside `.kan/identity-id` naming key B is not
/// hypothetical — kan produces it deliberately, because ADR-53 deletes a
/// plaintext copy only when it MATCHES the keychain and keeps it when it
/// DIFFERS (which is what #112's negative control existed to protect).
/// `identity-id` outranks `identity`, so B signs and A sits there as the only
/// copy of another identity. Writing B over A and reporting success is the
/// #90/#107 shape that CLAUDE.md's invariant forbids.
///
/// So: same bytes, proceed. Different, refuse naming both DIDs. **Cannot tell,
/// refuse** — that is part of the rule rather than a fallback, because "I
/// cannot tell whether this file holds a different identity" and "this file
/// holds the same identity" are different answers and only one permits a write.
pub fn unprotect_to(
    kan_dir: &Path,
    from: AtRest,
    dest_name: &str,
    store: &dyn SecretStore,
) -> Result<Did, Error> {
    // Same rule, opposite reason: unprotect must READ the keychain to move the
    // secret out of it, so with the flag set there is nothing it can do.
    if keychain_disabled() {
        return Err(Error::Refused(
            "refusing: KAN_NO_KEYCHAIN is set, and `unprotect` must READ the keychain to move the secret out of it.\n\nUnset it and try again."
                .to_string(),
        ));
    }
    let account_file = from.file().expect("a protected state names a pointer file");
    let account = std::fs::read_to_string(kan_dir.join(account_file))?
        .trim()
        .to_string();
    let _warn =
        SlowKeychainWarning::start("reading this repo's secret to move it out of the keychain");
    let bytes = store.get(service_for(from), &account)?.ok_or_else(|| {
        Error::Recovery(format!(
            "the keychain holds nothing under {account}, which .kan/{account_file} names. \
             Nothing has been changed."
        ))
    })?;
    let did = did_of(from, &bytes)?;

    let dest = kan_dir.join(dest_name);
    refuse_to_overwrite_a_different_secret(&dest, &bytes, from, &did, &account)?;

    let restored = match from {
        AtRest::SeedKeychain => {
            let mut b = [0u8; 32];
            b.copy_from_slice(&bytes);
            Seed::from_entropy(b).save(&dest)?;
            did_of(from, &bytes)?
        }
        _ => {
            let identity = Identity {
                keypair: P256Keypair::import(&bytes)?,
            };
            identity.save(&dest)?;
            identity.did()
        }
    };
    // RE-READ FROM DISK, not recomputed from the bytes in hand. The first
    // version derived `restored` from the same `bytes` the check compares
    // against, so it could not fire -- #112's exact shape, in a step the design
    // specifies as protection against a bad write. What must be verified is
    // that the FILE holds the secret, which means reading the file.
    let written = std::fs::read(&dest)?;
    if written != bytes || did_of(from, &written)? != did {
        return Err(Error::Recovery(
            "the secret on disk does not match the one taken from the keychain -- refusing \
             to retire the pointer, so nothing is lost."
                .to_string(),
        ));
    }

    // The pointer goes AFTER the write, never before: a failed write would
    // otherwise leave the workspace with no identity at all.
    // surface-write: identity:seed-id,identity:identity-id
    std::fs::remove_file(kan_dir.join(account_file))?;
    Ok(restored)
}

/// Execute `Plan::Protect`: move the secret into the keychain, verifying it
/// round-trips before anything on disk is disturbed.
pub fn protect_from(
    kan_dir: &Path,
    from: AtRest,
    store: &dyn SecretStore,
) -> Result<(Did, String, Option<String>), Error> {
    // REQ-3.6 / AC-3.6. `KAN_NO_KEYCHAIN` means "behave as though no keychain
    // exists", and a command that writes to it anyway is not honouring that --
    // it is ignoring it. Found by running `protect --yes` with the flag set in
    // a temp workspace and watching it succeed, which wrote a real entry to the
    // author's login keychain. Every other keychain path in this module checks
    // this; the newest one did not.
    if keychain_disabled() {
        return Err(Error::Refused(
            "refusing: KAN_NO_KEYCHAIN is set, which tells kan to behave as though no OS keychain exists -- so `protect`, whose only job is to put a secret INTO it, cannot honour both.\n\nUnset it if you want the keychain."
                .to_string(),
        ));
    }
    let src = kan_dir.join(from.file().expect("an unprotected state names a file"));
    let bytes = std::fs::read(&src)?;
    let did = did_of(from, &bytes)?;

    let account = fresh_account();
    let _warn = SlowKeychainWarning::start("storing this repo's secret in the keychain");
    store.set(service_for(from), &account, &bytes)?;

    // Read back and compare BEFORE the plaintext is touched. A store that
    // silently truncated would otherwise destroy the only copy.
    let stored = store.get(service_for(from), &account)?.ok_or_else(|| {
        Error::Recovery(
            "the keychain returned nothing for the entry just written -- refusing to go \
             further. Nothing on disk has been changed."
                .to_string(),
        )
    })?;
    if stored != bytes || did_of(from, &stored)? != did {
        return Err(Error::Recovery(format!(
            "the keychain did not return what was written to it (account {account}) -- \
             refusing to go further. Nothing on disk has been changed."
        )));
    }

    let pointer = match from {
        AtRest::SeedFile => SEED_ID_FILE,
        _ => IDENTITY_ID_FILE,
    };

    // THE OLD ACCOUNT IS READ HERE, BEFORE THE OVERWRITE, AND RETURNED --
    // because the caller cannot read it afterwards and must not try.
    //
    // The first version had the caller "retire" the stale pointer after this
    // function returned: read `.kan/seed-id`, then delete it. But this write
    // has already replaced that file's contents with the NEW account, so the
    // caller read the new account, reported it as the old one, and DELETED THE
    // POINTER IT HAD JUST WRITTEN -- leaving the secret in the keychain with
    // nothing naming it, and a workspace that could no longer resolve its own
    // identity. In the command whose one job is to move a secret safely.
    //
    // Writing the pointer IS the retirement; there is nothing left to delete.
    // Returning the displaced account is what lets the caller say which entry
    // was orphaned, which is the part that must not be silent.
    let orphaned = std::fs::read_to_string(kan_dir.join(pointer))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty() && *s != account);
    // surface-write: identity:seed-id,identity:identity-id
    std::fs::write(kan_dir.join(pointer), &account)?;
    Ok((did, account, orphaned))
}

/// The keychain-held signing key for this workspace, if it has one.
///
/// **Reads `.kan/identity-id`; never writes it.** The retired
/// `keychain_account` (deleted by REQ-3.5, #183) wrote
/// that file while resolving, so the ADR-77 guard could observe state its own
/// invocation had just created — widening the guard's evidence to include
/// `identity-id` turned every first-run keychain workspace into a refusal.
/// A pure question 1 cannot do that, so the account id is read or the answer
/// is `None`.
///
/// A keychain that cannot be reached at all is `None`, not an error: "I
/// cannot tell whether there is a key here" and "there is no key here" differ,
/// but the caller that matters — `create_workspace_identity` — also consults
/// the log, which is the fact a broken keychain cannot hide.
fn keychain_identity(kan_dir: &Path) -> Result<Option<Identity>, Error> {
    if keychain_disabled() {
        return Ok(None);
    }
    let account = match std::fs::read_to_string(kan_dir.join(IDENTITY_ID_FILE)) {
        Ok(id) if !id.trim().is_empty() => id.trim().to_string(),
        _ => return Ok(None),
    };
    // An unopenable entry stays `None` rather than an error -- #180: that was
    // the one minting path which never consulted the guard, and it is now just
    // another way for question 1 to answer "no identity here".
    let Ok(Some(entry)) = keychain_entry(KEYCHAIN_SERVICE, &account) else {
        return Ok(None);
    };
    let _warn = SlowKeychainWarning::start("reading this repo's signing key");
    match entry.get_secret() {
        Ok(bytes) => Ok(Some(Identity {
            keypair: P256Keypair::import(&bytes)?,
        })),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(Error::KeychainUnreachable {
            detail: e.to_string(),
        }),
    }
}

/// Which identity a caller asked to sign as.
///
/// **A selection, not a redefinition.** `kan identity role add`'s own help
/// says "run kan with `KAN_IDENTITY_FILE` set to the role's key *to write as
/// that role*" — that is a selection, and implementing it as an override of
/// question 1 is what let a missing target invite creating one, shadow an
/// adopted key, and skip validation against `.kan/roles`.
#[derive(Debug, Clone)]
pub enum Selection {
    /// Whatever identity the workspace has.
    Primary,
    /// A specific key file, named by `KAN_IDENTITY_FILE`.
    KeyFile(PathBuf),
}

impl Selection {
    pub fn from_env() -> Self {
        match std::env::var_os(IDENTITY_FILE_ENV) {
            Some(p) => Selection::KeyFile(PathBuf::from(p)),
            None => Selection::Primary,
        }
    }
}

/// **Question 2: which identity should sign *this write*?**
///
/// `Ok(None)` only for `Primary` in a workspace that has no identity yet —
/// the one case where creating one is the caller's next move.
///
/// **A selection naming something absent is always an error.** Never a mint,
/// never a fallback, never a substitution of another key. That single rule
/// removes four of v0.11's five review findings: a missing role key minting an
/// undeclared identity, a missing path silently signing as the human, `adopt`
/// being shadowed by the variable, and the read reporting somebody else's
/// claims as yours.
pub fn signing_identity(kan_dir: &Path, selection: &Selection) -> Result<Option<Identity>, Error> {
    match selection {
        Selection::Primary => workspace_identity(kan_dir),
        Selection::KeyFile(path) => {
            if path.exists() {
                // Deliberately NOT validated against `.kan/roles` here, though
                // `.design/identity-resolution.md` suggests it. Two reasons,
                // and the second is the decisive one:
                //
                // 1. CLAUDE.md's "affordance, not enforcement" -- an operator
                //    who explicitly names a key file has said what they mean.
                //    Undeclared authorship is made LEGIBLE (`kan identity
                //    authors` reports it, `--trust roles` narrows past it)
                //    rather than blocked.
                // 2. It breaks the configuration the variable exists for. In
                //    the CI/`day`/agent workflow, KAN_IDENTITY_FILE *is* the
                //    identity and the workspace never gets a `.kan/identity`
                //    of its own -- so `workspace_identity` is `None` forever
                //    and every write after the first would be refused as an
                //    "undeclared second identity". Measured: adding that rule
                //    took the suite from 41 failures to 78.
                //
                // ADR-77's property is unchanged where it actually lives: no
                // identity is ever CREATED as a side effect of resolution.
                // That is `create_workspace_identity`'s job, and #90's harm is
                // further blunted by `TrustBase::Local` trusting every author
                // in the log rather than one.
                let identity = Identity::load_existing(path)?;
                return Ok(Some(identity));
            }
            // The declared roles are a projection over claims, which this
            // layer cannot see. `Workspace::commit_identity` fills the clause
            // in; raising it empty here keeps this function's dependencies
            // exactly what they were.
            Err(Error::SelectionMissing {
                path: path.display().to_string(),
                declared: String::new(),
            })
        }
    }
}

pub fn identity_evidence(kan_dir: &Path) -> Option<&'static str> {
    if kan_dir.join("identity").exists() {
        return Some("a signing key at .kan/identity");
    }
    if kan_dir.join(SEED_FILE).exists() || kan_dir.join(SEED_ID_FILE).exists() {
        return Some("a root seed for this workspace");
    }
    if kan_dir.join(IDENTITY_ID_FILE).exists() {
        return Some("a signing key filed in the OS keychain");
    }
    None
}

/// **Question 3: may kan *create* an identity here?**
///
/// The only function that writes one, which is what makes the guard a
/// property of the workspace rather than of whichever code path happened to
/// reach it. It refuses on three grounds, in order: the log already holds
/// claims; there is on-disk evidence of an identity (see
/// [`identity_evidence`]); or question 1 resolves one.
///
/// `.design/identity-resolution.md` argued for "no evidence set to maintain",
/// and that turned out to be half right. The old guard's evidence set was
/// wrong in both directions — blind to `.kan/seed-id`, self-triggering on
/// `.kan/identity-id` — but removing it entirely let a seed-rooted workspace
/// with an unreachable keychain re-mint and shadow its own identity, which is
/// v0.11 round 5's B3 defect. The set stays, and is now *correct* rather than
/// absent, because a pure question 1 means nothing writes the evidence while
/// asking.
///
/// The log is checked as well, and it is not an evidence set: it is the one
/// fact a *missing* identity cannot account for. A workspace with claims and
/// no resolvable identity is one whose key went missing (#90), and minting
/// there takes the whole log out of every read.
///
/// This also closes #180 by construction. The old `load_or_create` had five
/// branches that could mint and four of them called the guard; the one that
/// did not — `keyring::Entry::new` failing — is now just another way for
/// question 1 to answer `None`, and every creation route passes through here.
/// On-disk evidence that this workspace **has** an identity, whether or not
/// one can be resolved right now.
///
/// Not a substitute for question 1 — it answers a different question. A
/// workspace whose secret lives in the keychain still holds `.kan/seed-id` or
/// `.kan/identity-id` when the keychain is unreachable or disabled, and there
/// `workspace_identity` honestly returns `None`. **"I cannot tell" must not
/// become "there is none"**, because the difference between them is a second
/// identity that permanently shadows the first.
///
/// `.kan/identity-id` counts here, and it could not before. The old guard had
/// to exclude it because the retired `keychain_account` *wrote* that file while resolving,
/// so counting it made the guard fire on evidence its own invocation had
/// created. Nothing writes it during resolution any more, which is a
/// consequence of REQ-1 rather than a separate fix — making question 1 pure is
/// what let the guard get stronger.
pub fn create_workspace_identity(kan_dir: &Path) -> Result<Identity, Error> {
    // The log first: "this workspace has claims already" is the most
    // informative thing a refusal can say, and it is the evidence a missing
    // identity cannot account for.
    if log_has_claims(kan_dir) {
        return Err(Error::WouldMintSecondIdentity {
            attempt: "creating a new identity".to_string(),
            remedy: "This workspace had an identity and no longer resolves one. Restore the \
                     key, or adopt it with `kan identity adopt --key <path>`. If the key is \
                     in the OS keychain and the keychain is unreachable, fix that first -- \
                     minting here would take every existing claim out of every read."
                .to_string(),
            evidence: "claims in its log".to_string(),
        });
    }
    if let Some(evidence) = identity_evidence(kan_dir) {
        return Err(Error::WouldMintSecondIdentity {
            attempt: "creating a new one".to_string(),
            remedy: "This workspace already has an identity, even if kan cannot resolve it \
                     right now -- an unreachable or disabled keychain is the usual reason. \
                     Fix that, or adopt the key with `kan identity adopt --key <path>`. \
                     Minting here would take every existing claim out of every read."
                .to_string(),
            evidence: evidence.to_string(),
        });
    }
    if workspace_identity(kan_dir)?.is_some() {
        return Err(Error::WouldMintSecondIdentity {
            attempt: "creating an identity for it".to_string(),
            remedy: "Use the identity this workspace already has, or move `.kan/` aside if \
                     you meant to start over."
                .to_string(),
            evidence: "an identity this workspace already resolves".to_string(),
        });
    }
    Seed::create(kan_dir)?.signing_identity()
}

/// Every declared role, in declaration order.
///
/// A missing file is no roles rather than an error — the overwhelmingly
/// common case is a workspace that has never declared one — and a malformed
/// line is skipped rather than fatal, because this file gates nothing (it
/// only *widens* a read), so a hand-edit typo should not take out every
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
        // surface-write: identity:seed,identity:identity,identity:role-key-path
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

/// How long a keychain call may block before kan says what it is waiting on.
///
/// Short enough that a person notices it before they start wondering, long
/// enough that the overwhelmingly common case -- an entry the keychain hands
/// over immediately -- prints nothing at all.
const KEYCHAIN_SLOW_AFTER: std::time::Duration = std::time::Duration::from_millis(1500);

/// Prints, once, if the keychain call it wraps has not returned yet.
///
/// **#90's fourth ask, and the friction that cost the most time building
/// v0.9.** A macOS keychain entry is authorised to *the binary that created
/// it*, so any rebuilt or upgraded kan blocks on an authorization prompt that
/// never arrives in CI, a container, an MCP server, or `day` shelling out.
/// The symptom is a command that simply never returns: no output, no
/// indication anything is being waited on. The module doc already calls that
/// "a hang, not a failure ... the worst shape", and #90 points out the same
/// is true for *callers* of kan, which cannot tell it from a slow fold.
///
/// This does not fix the hang -- that is #30/#69's per-agent identity work.
/// It makes the hang *legible*, which is the difference between a minute of
/// confusion and an afternoon of it.
pub struct SlowKeychainWarning {
    done: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl SlowKeychainWarning {
    /// Whether the watchdog would fire for an operation taking `took`,
    /// against a threshold of `threshold`.
    ///
    /// Exposed for `tests/keychain_visibility.rs`, which has to check both
    /// directions -- that a slow call warns *and* that a prompt one stays
    /// silent -- without needing a genuinely wedged keychain, which is not
    /// something Linux CI can produce and not something a developer should
    /// have to arrange.
    pub fn fired_after(threshold: std::time::Duration, took: std::time::Duration) -> bool {
        let done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = done.clone();
        let fired = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let fired_flag = fired.clone();
        let handle = std::thread::spawn(move || {
            let deadline = std::time::Instant::now() + threshold;
            while std::time::Instant::now() < deadline {
                if flag.load(std::sync::atomic::Ordering::Relaxed) {
                    return;
                }
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            if !flag.load(std::sync::atomic::Ordering::Relaxed) {
                fired_flag.store(true, std::sync::atomic::Ordering::Relaxed);
            }
        });
        std::thread::sleep(took);
        done.store(true, std::sync::atomic::Ordering::Relaxed);
        let _ = handle.join();
        fired.load(std::sync::atomic::Ordering::Relaxed)
    }

    fn start(what: &'static str) -> Self {
        let done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = done.clone();
        // Detached on purpose: if the call returns promptly the thread wakes,
        // sees the flag, and exits without printing. If the process exits
        // first, an unjoined sleeping thread costs nothing.
        std::thread::spawn(move || {
            let deadline = std::time::Instant::now() + KEYCHAIN_SLOW_AFTER;
            while std::time::Instant::now() < deadline {
                if flag.load(std::sync::atomic::Ordering::Relaxed) {
                    return;
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            if flag.load(std::sync::atomic::Ordering::Relaxed) {
                return;
            }
            eprintln!(
                "kan: still waiting on the OS keychain ({what}).\n\
                 \n\
                 On macOS a keychain entry is authorised to the exact binary that created \
                 it, so an upgraded or locally-rebuilt kan is treated as a different \
                 program and the request waits for an authorization prompt -- which never \
                 arrives in CI, a container, an MCP server, or a `day` subprocess.\n\
                 \n\
                 If a prompt is on screen, answer it. Otherwise interrupt and either:\n\
                 - set KAN_IDENTITY_FILE to a dedicated key file (keychain never \
                 consulted), or\n\
                 - set KAN_NO_KEYCHAIN=1 to keep secrets in 0600 files under .kan/.\n\
                 \n\
                 Tracked as #96/#69; #30's per-agent identity work is the real fix."
            );
        });
        Self { done }
    }
}

impl Drop for SlowKeychainWarning {
    fn drop(&mut self) {
        self.done.store(true, std::sync::atomic::Ordering::Relaxed);
    }
}

/// The secret store `protect`/`unprotect` move a secret between.
///
/// **The seam a cold review said was drawn one layer too shallow, and it was
/// right.** v0.12 extracted `at_rest`, the planners and the overwrite guard so
/// the parts that can be wrong became the parts that are checked — and every
/// extracted part was correct. The one defect that could destroy a secret
/// (`protect` deleting the pointer it had just written) was in the executor,
/// which nothing could reach because it called `keyring` directly. The
/// reviewer proved the fix costs nothing by stubbing three calls in a throwaway
/// clone and driving the whole command.
///
/// So the executors take a store. Production passes [`OsKeychain`]; tests pass
/// an in-memory one and exercise the real code path end to end.
pub trait SecretStore {
    fn get(&self, service: &str, account: &str) -> Result<Option<Vec<u8>>, Error>;
    fn set(&self, service: &str, account: &str, bytes: &[u8]) -> Result<(), Error>;
}

/// The real one. Honours `KAN_NO_KEYCHAIN` via [`keychain_entry`], which is
/// still the single door.
pub struct OsKeychain;

impl SecretStore for OsKeychain {
    fn get(&self, service: &str, account: &str) -> Result<Option<Vec<u8>>, Error> {
        let Some(entry) = keychain_entry(service, account)? else {
            return Ok(None);
        };
        match entry.get_secret() {
            Ok(b) => Ok(Some(b)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(Error::KeychainUnreachable {
                detail: e.to_string(),
            }),
        }
    }

    fn set(&self, service: &str, account: &str, bytes: &[u8]) -> Result<(), Error> {
        let entry = keychain_entry(service, account)?
            .ok_or_else(|| Error::Recovery("the keychain is disabled".to_string()))?;
        entry
            .set_secret(bytes)
            .map_err(|e| Error::KeychainUnreachable {
                detail: e.to_string(),
            })
    }
}

/// **The only place in kan that opens a keychain entry.**
///
/// `KAN_NO_KEYCHAIN` is an OPT-OUT, and opt-outs fail open: every call site had
/// to independently remember `keychain_disabled()`, and the default for
/// forgetting is "touch the developer's real login keychain". There were four
/// such sites, and the two newest -- `protect_from` and `unprotect_to`, written
/// against the design doc rather than against this module's conventions --
/// both forgot. Running `kan identity protect --yes` with the flag set wrote a
/// real entry to the author's keychain.
///
/// That is four implementations of one decision, which is the same shape as
/// question 1 having two implementations -- the defect this entire milestone
/// exists to fix, reproduced inside the guard that protects against it.
///
/// So the decision lives here and nowhere else. A fifth path cannot forget,
/// because there is nothing left to remember, and
/// `tests/keychain_one_door.rs` asserts a fifth path cannot be added quietly.
///
/// `Ok(None)` means "kan is behaving as though no keychain exists" -- callers
/// decide whether that is an absence or an error.
fn keychain_entry(service: &str, account: &str) -> Result<Option<keyring::Entry>, Error> {
    if keychain_disabled() {
        return Ok(None);
    }
    keyring::Entry::new(service, account)
        .map(Some)
        .map_err(|e| Error::KeychainUnreachable {
            detail: e.to_string(),
        })
}

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

    pub fn save(&self, path: &Path) -> Result<(), Error> {
        if let Some(parent) = path.parent() {
            // surface-write: identity:seed
            std::fs::create_dir_all(parent)?;
        }
        // surface-write: identity:seed
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
        let Some(entry) = keychain_entry(SEED_KEYCHAIN_SERVICE, &account)? else {
            return Ok(None);
        };
        let _warn = SlowKeychainWarning::start("reading this repo's root seed");
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

    /// Create this workspace's seed: a passphraseless `0600` file, always.
    ///
    /// **REQ-3.1 reversed what this comment used to argue**, and the comment
    /// outlived the change by several commits. It read "preferring the OS
    /// keychain... in the keychain when one is available, in a `0600` file when
    /// it is not", and warned that "taking the file-always reading would have
    /// reopened issue #6". The function now does exactly the file-always thing
    /// that comment called a strictly worse posture.
    ///
    /// The argument is not dismissed, it is outweighed and paid for by a
    /// command: on macOS the at-rest protection ADR-63 bought is delivered by
    /// the trusted-application ACL, which is the same mechanism as #96 -- it
    /// cannot be kept without keeping the hang. `kan identity protect` restores
    /// #6's property deliberately. Full accounting in
    /// `.design/identity-at-rest.md`.
    pub fn create(kan_dir: &Path) -> Result<Self, Error> {
        // surface-write: container:workspace
        std::fs::create_dir_all(kan_dir)?;
        let seed = Self::generate();
        seed.save(&kan_dir.join(SEED_FILE))?;

        // Not a warning any more, and it must not read as one. Before REQ-3
        // this line meant "the keychain was unavailable, so you got the worse
        // outcome"; now the file IS the outcome, and the sentence has to say
        // where the secret is, what the off-disk backup is, and how to move it
        // -- without implying anything went wrong.
        eprintln!(
            "kan: this repo's identity is rooted in {}, a 0600 file readable by \
             anything running as you.\n\
             \n\
             `kan identity phrase` prints its 24-word recovery phrase -- that is the \
             backup, and it is the only copy not on this disk.\n\
             `kan identity protect` moves the secret into the OS keychain if you want \
             it there.",
            kan_dir.join(SEED_FILE).display()
        );
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
