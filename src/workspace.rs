//! Shared setup for every action (`crate::actions`), used by both surfaces
//! (`CLAUDE.md`'s "one surface: CLI + MCP" — this is the plumbing both sit
//! on top of): resolve `.kan/` (ADR-3, sibling to `.git/`), load or create
//! the local identity, and open the log + index.
//!
//! `find_repo_root` walks upward from the current directory to find `.git/`
//! — the same search `git` itself does — so `.kan/` lands beside it no
//! matter which subdirectory `kan` is invoked from (M6, closing issue #3;
//! M3 resolved `.kan/` relative to `cwd` directly, a real but small gap
//! since dogfooding always ran from the repo root).

use std::path::{Path, PathBuf};

use atproto_dasl::Cid;

use crate::{
    claim::{Anchor, AuthorId},
    fold::TrustBase,
    git::GitSubstrate,
    sign::Identity,
    store::{index::Index, log::Log},
};

/// Workspace-owned surface facts: its automatic GitTree connection plus
/// derived overlay files whose inner format belongs to the log module.
pub const SURFACE_VALUES: &[crate::surface::SurfaceValue] = &[
    crate::surface::SurfaceValue::new("repo-config:auto-git-tree", "*"),
    crate::surface::SurfaceValue::new("overlay:repo.car", "*"),
    crate::surface::SurfaceValue::new("overlay:HEAD", "*"),
    crate::surface::SurfaceValue::new("overlay:LOCK", "*"),
];

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("identity error: {0}")]
    Sign(#[from] crate::sign::Error),
    #[error("log error: {0}")]
    Log(#[from] crate::store::log::Error),
    #[error("index error: {0}")]
    Index(#[from] crate::store::index::Error),
    #[error("git error: {0}")]
    Git(#[from] crate::git::Error),
    #[error("{0}")]
    TrustSpec(#[from] crate::fold::trust::SpecError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(
        "{count} claim(s) are in both this workspace's log and its overlay, which should be \
         unreachable: `ingest_published` skips any published record that is already in the \
         log, whoever signed it.\n\n\
         This is an invariant check, not an expected condition — reaching it means the \
         overlay was written by something other than that path, or the log changed \
         underneath an overlay built against an earlier state.\n\n\
         First claim in both: {first}\n\
         Active identity: {did}\n\n\
         Check `kan identity did` against the authors in `.claims/`. If the identity is \
         wrong, recover it with `kan identity adopt` rather than writing anything further; \
         the overlay is disposable, so `rm -rf .kan/overlay .kan/index.sqlite` is safe once \
         the identity is right."
    )]
    LogOverlayOverlap {
        count: usize,
        first: String,
        did: String,
    },
    #[error(
        "this workspace was opened for reading, which resolves no signing identity, and \
         something asked for one anyway.\n\n\
         This is an internal routing error rather than anything you did: read verbs open \
         read-only so that reading a repo never mints, derives or persists a key (#149). \
         Please report it."
    )]
    NoIdentity,
    #[error(
        "no signing identity is reachable here, so there is nothing for `me` to name.\n\n\
         This says nothing about whether the log has claims in it -- it usually does. It \
         means this workspace's key is not where kan looks: KAN_IDENTITY_FILE unset with \
         the key held elsewhere, pointed at a path that does not exist, or a keychain \
         entry this binary cannot read (#96).\n\n\
         Name the author you meant with `--trust did:key:...`, or `kan identity adopt \
         --key <path>` to point this workspace back at its key. Reading never creates an \
         identity, by design (#149)."
    )]
    NoIdentityToName,
}

pub struct Workspace {
    /// Repo root — the directory `.kan/` sits beside. Needed by anything
    /// that writes outside the private store, such as `kan publish`.
    pub root: std::path::PathBuf,
    /// `None` for a workspace opened read-only.
    ///
    /// Private, with [`Workspace::identity`] as the accessor, so that every
    /// place needing a signing identity has to say so and handle its absence.
    /// The field was public and unconditional, and that is precisely how a
    /// read came to resolve one (#149): nothing in the type ever asked
    /// whether it should.
    identity: Option<Identity>,
    pub log: Log,
    /// Claims by **other** authors, read out of the tracked `.claims/` tree
    /// and kept beside `log/` rather than inside it.
    ///
    /// `log/repo.car` stays *claims I authored*, which is what atproto repo
    /// semantics require and what the eventual HostedRelay/AppView reads
    /// from (`.design/durability-log-recovery.md` REQ-4). Mixing another
    /// actor's records into it would make the local log unshippable as a
    /// repo.
    ///
    /// **Disposable, like the index.** Everything here is reconstructible
    /// from `.claims/`, so deleting `.kan/overlay/` costs nothing but the
    /// re-parse. That is what makes refreshing it on open acceptable where
    /// mutating `log/` on a read path would not be.
    pub overlay: Log,
    pub index: Index,
    /// `None` until something needs it, which in practice means until a
    /// write. Computing it costs three `git` subprocesses — 28.2ms of kan's
    /// ~42ms fixed per-invocation cost, roughly 70% — to derive a value that
    /// cannot change for a repo and that no read consults, since every claim
    /// carries its own anchor already (`.design/identity-surface.md` RQ-5).
    anchor: Option<Anchor>,
    pub git: GitSubstrate,
    /// Which claims are in the tracked `.claims/` tree, by subject — built
    /// during the same read `ingest_published` already does, so the
    /// durability column costs no additional I/O.
    pub published: PublishedIndex,
}

/// The content CIDs present in the published tree, per subject.
///
/// **Why the *set of CIDs* and not the `Publication` claim's timestamp.**
/// `kan publish --all` refreshes a subject's file without appending a new
/// `Publication` claim, so a subject brought fully up to date would still
/// look stale under a timestamp comparison — the column would report a gap
/// that the operator had just closed, which is the fastest way to teach
/// someone to ignore a column. Comparing claim-for-claim against what is
/// actually in the file answers the question durability actually asks: if
/// `.kan/` disappeared right now, what would come back?
#[derive(Default)]
pub struct PublishedIndex {
    by_subject: std::collections::HashMap<crate::claim::SubjectRef, std::collections::HashSet<Cid>>,
    /// A hash over every published file's bytes, or `None` when there is no
    /// `.claims/` tree — the freshness key for foreign claims.
    ///
    /// **Bytes rather than filenames**, because `file_name(subject)` is a
    /// sanitized prefix plus a digest *of the subject name*: publishing more
    /// claims rewrites the same file, so a filename-set fingerprint would
    /// miss every update. Bytes are provably fresh and depend on no naming
    /// scheme, which keeps this independent of the `.claims/` format work
    /// (#131/#92).
    ///
    /// Affordable for a measured reason: reading every published file in full
    /// is 0.66ms for 40 files, 15x cheaper than one `git` spawn
    /// (`.design/identity-surface.md` RQ-5). The expensive part of ingestion
    /// is parse and signature verification, and that is what this key skips.
    ///
    /// The tripwire, recorded so it is met rather than rediscovered: this is
    /// O(published bytes). A repo with thousands of published subjects wants
    /// a readdir-level key, which is where content-addressed filenames would
    /// earn their keep.
    content_hash: Option<String>,
    read_errors: Vec<PublishedReadError>,
}

/// One GitTree input the workspace refused while retaining every verified
/// claim. This is invocation metadata, never a claim or index row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublishedReadError {
    pub path: String,
    pub kind: String,
    pub message: String,
}

/// Accumulates the `.claims/` freshness key.
///
/// **Shared by both ingestion paths deliberately.** They must agree byte for
/// byte, or a read-open and a write-open compute different fingerprints over
/// the same unchanged workspace and each invalidates the other's projection —
/// a full rebuild per command, on exactly the repos that have a published
/// tree. Two call sites hashing "the same thing" separately is how that
/// happens, so there is one implementation and no second chance to diverge.
///
/// That is not hypothetical: the first version of this milestone hashed on
/// the read path only, and nothing failed, because every view stayed correct.
/// It would simply have rebuilt the whole projection on every command.
///
/// Order-stable because `GitTree::read_records` sorts its file list; the
/// digest is over the *verified* records' CIDs, so an unverifiable record
/// changes nothing here, exactly as it changes nothing in a view.
#[derive(Default)]
struct ClaimsDigest(Option<sha2::Sha256>);

impl ClaimsDigest {
    fn started() -> Self {
        Self(Some(<sha2::Sha256 as sha2::Digest>::new()))
    }

    fn add(&mut self, cid: &Cid) {
        if let Some(hasher) = &mut self.0 {
            sha2::Digest::update(hasher, cid.to_bytes());
        }
    }

    fn finish(self) -> Option<String> {
        self.0.map(|hasher| {
            sha2::Digest::finalize(hasher)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect()
        })
    }
}

impl PublishedIndex {
    fn record(&mut self, subject: crate::claim::SubjectRef, cid: Cid) {
        self.by_subject.entry(subject).or_default().insert(cid);
    }

    /// Whether anything at all has been published for this subject.
    pub fn is_published(&self, subject: &crate::claim::SubjectRef) -> bool {
        self.by_subject.contains_key(subject)
    }

    pub fn contains(&self, subject: &crate::claim::SubjectRef, cid: &Cid) -> bool {
        self.by_subject
            .get(subject)
            .is_some_and(|cids| cids.contains(cid))
    }

    pub fn is_empty(&self) -> bool {
        self.by_subject.is_empty()
    }

    pub fn read_errors(&self) -> &[PublishedReadError] {
        &self.read_errors
    }
}

fn published_read_error(
    root: &Path,
    error: &crate::transport::git_tree::Error,
) -> PublishedReadError {
    let original = error.diagnostic_path().unwrap_or(".claims/<unknown>");
    let mut relative = Path::new(original)
        .strip_prefix(root)
        .unwrap_or_else(|_| Path::new(original))
        .to_string_lossy()
        .into_owned();
    if relative == crate::transport::git_tree::CLAIMS_DIR {
        relative.push('/');
    }
    let message = error.to_string().replacen(original, &relative, 1);
    PublishedReadError {
        path: relative,
        kind: error.diagnostic_kind().to_string(),
        message,
    }
}

impl Workspace {
    /// Reopens from disk every call, by design: the CLI is one process per
    /// invocation, and `kan mcp` (one long-lived process) mirrors that by
    /// calling `open` fresh per tool call rather than holding one `Workspace`
    /// across calls — cheap at today's scale, and avoids any question of
    /// staleness or concurrent-mutation safety (`docs/DECISIONS.md` ADR-15).
    pub async fn open(cwd: &Path) -> Result<Self, Error> {
        // A writable workspace is a readable one that has not needed its
        // identity yet. Nothing is minted, persisted or created here --
        // `commit_identity` does that, immediately before the first append
        // and after every precondition has passed (REQ-3).
        //
        // The anchor is still resolved EAGERLY, and only on this path. #141:
        // a repo with no commits cannot host a workspace, and `genesis()` is
        // what detects it -- that refusal has to land before anything is
        // written, and it costs three `git` subprocesses that a read has
        // already been excused from paying.
        let mut ws = Self::open_read_only(cwd).await?;
        ws.anchor = Some(Anchor::Workspace(ws.git.genesis()?));
        Ok(ws)
    }

    /// Bring this workspace's identity into existence, if it does not have
    /// one yet, and make the stores writable.
    ///
    /// **The moment a workspace becomes real.** Called immediately before the
    /// first append and after every validation, so a command that is going to
    /// be refused is refused while the repo still looks untouched: no key, no
    /// `seed-id`, no `identity-id`, no `.kan/` (REQ-3).
    ///
    /// **Persist before the append, not after.** REQ-3's text says "only
    /// after the write it was minted for has succeeded", and that order is
    /// the dangerous one: a failure between the append and the persist leaves
    /// a claim signed by a key nothing on disk holds, after which the ADR-77
    /// guard fires and the log is unreadable *and* the key unrecoverable.
    /// Failing the other way round leaves an identity with an empty log,
    /// which is exactly what `kan identity did` produces and costs nothing.
    /// The property REQ-3 is for is its second sentence -- a refused write
    /// leaves nothing behind -- and this order delivers it with no hazard.
    ///
    /// Idempotent, so every write verb can call it without tracking whether
    /// somebody already did.
    pub async fn commit_identity(&mut self) -> Result<(), Error> {
        if self.identity.is_some() {
            return Ok(());
        }
        let kan_dir = self.root.join(".kan");

        // Resolving and persisting stay one step, inside `sign.rs`, because
        // they genuinely are one step: a minted-but-unpersisted key is a
        // hazardous state in its own right, and the defect was never that
        // they were coupled -- only that they ran too early.
        // REQ-1/REQ-2: ask the two questions separately. `signing_identity`
        // resolves a selection and errors if its target is missing;
        // `create_workspace_identity` is the only thing that writes one, and
        // is reached only when this workspace genuinely has none.
        let selection = crate::sign::Selection::from_env();
        let resolved = match crate::sign::signing_identity(&kan_dir, &selection) {
            Ok(resolved) => resolved,
            // REQ-4: name the roles this workspace declares. `sign` cannot --
            // the declared set is a projection over claims and that layer is
            // below the log -- so the clause is filled here, the first place
            // that can see both the selection and the log. This replaces
            // `DeclaredRoleKeyMissing`, which answered the same question by
            // matching the missing path against a registry column that no
            // longer exists, and only for keys kan itself had minted.
            Err(crate::sign::Error::SelectionMissing { path, .. }) => {
                let names: Vec<String> = self
                    .declared_roles()
                    .map(|declared| {
                        declared
                            .roles()
                            .iter()
                            .map(|role| role.name.clone())
                            .collect()
                    })
                    .unwrap_or_default();
                return Err(Error::Sign(crate::sign::Error::SelectionMissing {
                    path,
                    declared: match names.is_empty() {
                        true => String::new(),
                        false => format!(
                            "\n\nThis workspace declares these roles: {}.",
                            names.join(", ")
                        ),
                    },
                }));
            }
            Err(e) => return Err(e.into()),
        };
        let identity = match resolved {
            Some(identity) => identity,
            None => crate::sign::create_workspace_identity(&kan_dir)?,
        };

        // Now the stores can be writable, which is also where `.kan/` comes
        // into existence.
        self.log = Log::open_or_create(&kan_dir.join("log"), &identity).await?;
        self.overlay = Log::open_or_create(&kan_dir.join("overlay"), &identity).await?;
        self.index = Index::open(&kan_dir.join("index.sqlite"))?;
        self.published =
            ingest_published(&self.root, &identity, &self.log, &mut self.overlay).await?;

        // #150's repair, which lives here because this is where the overlay
        // is written and therefore the first moment it CAN be repaired.
        //
        // A read cannot do this -- rebuilding the overlay means re-ingesting
        // `.claims/`, which needs a key to sign the commits with -- and does
        // not need to: `open_read_only` simply declines to project the
        // duplicates, so a poisoned workspace still reads correctly and
        // completely. Reading stopped being the thing that breaks; this is
        // where it stops being the thing that heals.
        //
        // Loud, not silent. #146's warning against tidying this away was
        // about deduping at the INDEX, which would let a workspace open under
        // a wrong identity and report "no subjects yet" against a full log.
        // This repairs the store rather than papering over the read, and says
        // so, because a store that quietly rearranges itself is not one
        // anybody can reason about.
        // Gated on the overlay existing at all, which is the overwhelmingly
        // common case and costs one in-memory root check. The old code got
        // this for free by sitting behind the index-freshness check; hoisting
        // it into `commit_identity` made it unconditional, and it is two
        // `iter_all()` calls -- per-claim signature verification, ADR-13's
        // dominant cost -- so every append paid for a corruption that can
        // only exist where there is an overlay to hold it.
        if self.overlay.current_root().is_some()
            && overlapping(&self.log.iter_all().await?, &self.overlay.iter_all().await?).is_some()
        {
            let log_claims = self.log.iter_all().await?;
            eprintln!(
                "warning: this workspace's overlay held claims the log already had, which \
                 is the corruption in issue #150 -- one read under a role identity, in a \
                 workspace that had published its own claims.\n\
                 \n\
                 Rebuilding the overlay from .claims/. Nothing is lost: the overlay is \
                 derived, and the log was never touched."
            );
            let overlay_dir = kan_dir.join("overlay");
            std::fs::remove_dir_all(&overlay_dir)?;
            self.overlay = Log::open_or_create(&overlay_dir, &identity).await?;
            self.published =
                ingest_published(&self.root, &identity, &self.log, &mut self.overlay).await?;

            // Rebuilt and still overlapping means the repair did not hold,
            // and continuing would hand sqlite the same duplicate. It should
            // be unreachable; if it is reached it names the condition rather
            // than a constraint violation.
            let overlay_claims = self.overlay.iter_all().await?;
            if let Some(first) = overlapping(&log_claims, &overlay_claims) {
                return Err(Error::LogOverlayOverlap {
                    count: overlay_claims
                        .iter()
                        .filter(|(c, _)| log_claims.iter().any(|(l, _)| l == c))
                        .count(),
                    first: first.to_string(),
                    did: identity.did().to_string(),
                });
            }
        }

        self.identity = Some(identity);
        // Deliberately does NOT reproject. Every caller either appends
        // immediately (and `append` reprojects over the new log) or does not
        // read the index at all (`kan identity did`). Reprojecting here meant
        // every write rebuilt the projection twice.
        Ok(())
    }

    /// Open for reading: **no identity is resolved, derived or persisted, and
    /// no anchor is computed** (`.design/identity-surface.md` REQ-2).
    ///
    /// This is the milestone in one function. Every default read folds under
    /// `Local`, which is defined over the claims themselves rather than over
    /// "me", so there is nothing left for a read to need an identity *for* —
    /// and a read that resolves one is a read that can mint one (#149), take
    /// a whole log out of view by re-minting (#90), or block on a keychain
    /// prompt it has no business raising (#96).
    ///
    /// **It creates nothing.** A repo with no `.kan/` reads as an empty
    /// workspace held entirely in memory: no directory, no key, no `seed-id`,
    /// no index file (AC-3). "Read it if it is there" is the whole behaviour.
    ///
    /// **The anchor is skipped, not deferred cheaply.** `genesis()` is three
    /// `git` subprocesses, 28.2ms of kan's ~42ms fixed cost, computing a
    /// value no read consults — every claim carries its own anchor. It is a
    /// write-time concern exactly as identity is, and [`Self::anchor`]
    /// computes it on demand for the one caller that needs it.
    pub async fn open_read_only(cwd: &Path) -> Result<Self, Error> {
        let root = find_repo_root(cwd);
        let kan_dir = root.join(".kan");

        // Still opened, and still first: reads genuinely use git, for the
        // computable relation providers (`fold::relations`). It is one
        // subprocess and it is what turns "not a git repo" into a sentence
        // rather than an empty view.
        let git = GitSubstrate::open(&root)?;

        let mut log = Log::open_read_only(&kan_dir.join("log")).await?;
        let mut overlay = Log::open_read_only(&kan_dir.join("overlay")).await?;

        // A workspace that does not exist gets a projection that does not
        // touch disk. Where `.kan/` *is* present, the index file is fair game
        // — it is disposable derived data inside a workspace that already
        // exists, which is the same rule `Workspace::open` has always used.
        let mut index = if kan_dir.exists() {
            Index::open(&kan_dir.join("index.sqlite"))?
        } else {
            Index::open_in_memory()?
        };

        // Foreign claims are read straight into the projection rather than
        // into `.kan/overlay`, because writing that store would need a
        // signing identity to sign its commit -- which is the whole thing
        // this function exists not to do.
        //
        // Transitional for one release, and the half that survives: #164
        // retires `.kan/overlay` entirely in v0.12, at which point this
        // becomes the only ingestion path. The write path still maintains
        // the overlay meanwhile, and both produce the same rows -- this one
        // reads the overlay too and adds only what it does not already hold,
        // so a read-open and a write-open agree claim for claim.
        let (published, arrived) = read_published(&root, &log, &overlay).await?;

        let fingerprint = index_fingerprint(
            log.current_root(),
            overlay.current_root(),
            published.content_hash.as_deref(),
        );
        // A matching content-addressed freshness key proves the inputs did
        // not move; it does not authenticate the disposable cache bytes.
        // Decode the projection before trusting it. Any damage invalidates
        // the cache and takes the same recomputation path as stale inputs.
        let projection_decodes = index.all_stored_claims().is_ok();
        if fingerprint != index.built_from_root()? || !projection_decodes {
            let log_claims = log.iter_all().await?;
            let mut foreign = overlay.iter_all().await?;
            foreign.extend(arrived);

            // #150's poisoned state, handled by *not projecting* the
            // duplicates rather than by repairing the overlay.
            //
            // The write path discards and rebuilds the overlay, which needs a
            // signing identity to re-ingest — so a read cannot do that, and
            // must not acquire one in order to try. It does not have to:
            // `content_cid` is a PRIMARY KEY, so all a duplicate does is fail
            // the rebuild, and skipping it leaves a workspace that reads
            // correctly and completely. Every claim is still projected, once,
            // from the log.
            //
            // That makes a read of a poisoned workspace *work*, where before
            // this milestone it was the thing that bricked it. The overlay is
            // still repaired by the next write, loudly, exactly as v0.9.2
            // made it.
            let in_log: std::collections::HashSet<&Cid> =
                log_claims.iter().map(|(c, _)| c).collect();
            foreign.retain(|(cid, _)| !in_log.contains(cid));

            index.rebuild(&log_claims, &foreign, fingerprint.as_ref())?;
        }

        Ok(Self {
            root,
            identity: None,
            log,
            overlay,
            index,
            anchor: None,
            git,
            published,
        })
    }

    /// Assemble a workspace from components the caller already holds.
    ///
    /// For tests that need to control the identity or the store paths
    /// directly. Production code goes through [`Self::open`] or
    /// [`Self::open_read_only`], which is the point of the fields being
    /// private: a *writable* workspace is now something you have to ask for
    /// by name rather than something you get by filling in a struct.
    #[doc(hidden)]
    #[allow(clippy::too_many_arguments)]
    pub fn from_parts(
        root: PathBuf,
        identity: Identity,
        log: Log,
        overlay: Log,
        index: Index,
        anchor: Anchor,
        git: GitSubstrate,
        published: PublishedIndex,
    ) -> Self {
        Self {
            root,
            identity: Some(identity),
            log,
            overlay,
            index,
            anchor: Some(anchor),
            git,
            published,
        }
    }

    /// Rebuild the projection from every store this workspace holds, and
    /// record the freshness key the *next* open will compute.
    ///
    /// Both halves were wrong on the write path and had been for as long as
    /// there was an overlay. `append` rebuilt from `log.iter_all()` alone,
    /// dropping every foreign claim from the projection, and recorded the
    /// bare log root where an open computes a fingerprint over log, overlay
    /// and `.claims/`.
    ///
    /// It was invisible because the two mistakes hid each other: the
    /// mismatched key meant the very next open rebuilt from scratch, which
    /// silently restored the foreign claims the write had dropped. So the
    /// only symptom was a full rebuild after every write — a cost, not a
    /// wrong answer, and nothing was watching for it.
    ///
    /// Fixing the key alone would have converted it into a wrong answer, by
    /// telling the next open that a projection missing its foreign claims
    /// was fresh. They have to be fixed together, which is why this is one
    /// method rather than a fix at each call site.
    pub async fn reproject(&mut self) -> Result<(), Error> {
        let log_claims = self.log.iter_all().await?;
        let foreign = self.overlay.iter_all().await?;
        let fingerprint = index_fingerprint(
            self.log.current_root(),
            self.overlay.current_root(),
            self.published.content_hash.as_deref(),
        );
        self.index
            .rebuild(&log_claims, &foreign, fingerprint.as_ref())?;
        Ok(())
    }

    /// Discard and rebuild `.kan/overlay` from `.claims/`, then reproject.
    ///
    /// The overlay is derived, so this costs a re-parse and nothing else. It
    /// exists for callers that move claims INTO the log which the overlay
    /// already holds -- `restore` is the one -- because that leaves the same
    /// claim in both stores, which is precisely what the #150 alarm treats as
    /// corruption.
    pub async fn rebuild_overlay(&mut self) -> Result<(), Error> {
        let identity = self.identity.as_ref().ok_or(Error::NoIdentity)?;
        let overlay_dir = self.root.join(".kan").join("overlay");
        if overlay_dir.exists() {
            std::fs::remove_dir_all(&overlay_dir)?;
        }
        self.overlay = Log::open_or_create(&overlay_dir, identity).await?;
        self.published =
            ingest_published(&self.root, identity, &self.log, &mut self.overlay).await?;
        self.reproject().await
    }

    /// The log and the signing identity together, borrowed disjointly.
    ///
    /// A write needs `&mut log` and `&identity` at once, and going through
    /// [`Self::identity`] borrows the whole `Workspace`. Splitting the borrow
    /// here keeps that a detail of this module rather than a reason to make
    /// the identity field public again.
    pub async fn log_and_identity(&mut self) -> Result<(&mut Log, &Identity), Error> {
        // The single place a write acquires an identity, so "resolve it as
        // late as possible" is enforced by there being nowhere earlier to do
        // it (REQ-3).
        self.commit_identity().await?;
        let identity = self.identity.as_ref().ok_or(Error::NoIdentity)?;
        Ok((&mut self.log, identity))
    }

    /// The DID of the identity a read means by "me", loaded but **never
    /// created**.
    ///
    /// `--trust me` and `--trust roles` name the active identity, so they
    /// genuinely need one — and a read-only workspace holds none. Resolving
    /// it here, from what is already on disk, is what keeps those selectors
    /// working on a read without a read ever minting. A workspace that has
    /// no identity yet gets a sentence saying so rather than a new keypair.
    pub fn active_did(&self) -> Result<String, Error> {
        if let Some(identity) = &self.identity {
            return Ok(identity.did());
        }
        // Question 2, not question 1. "me" is the identity that would SIGN
        // here -- which for a role-scoped caller (`day`, CI, an agent with
        // KAN_IDENTITY_FILE set) is the role, not the workspace's own key.
        // Routing this through `workspace_identity` would answer "what does
        // this workspace have", so a role asking "what did I write" would get
        // the human's claims: the read-side substitution v0.11 round 4 found,
        // reintroduced from the other direction.
        //
        // A selection whose target is missing errors here rather than falling
        // back, for the same reason it does on the write path.
        let selection = crate::sign::Selection::from_env();
        match crate::sign::signing_identity(&self.root.join(".kan"), &selection)? {
            Some(identity) => Ok(identity.did()),
            None => Err(Error::NoIdentityToName),
        }
    }

    /// This workspace's signing identity, or an error naming what needs one.
    ///
    /// Every caller is a write, or a command whose subject *is* the identity
    /// (`kan identity did`). A read reaching this is a routing bug, and the
    /// message says so rather than silently resolving one.
    pub fn identity(&self) -> Result<&Identity, Error> {
        self.identity.as_ref().ok_or(Error::NoIdentity)
    }

    /// The workspace anchor, computed on first use.
    ///
    /// Only `append` consults it, which is why it is no longer resolved on
    /// open: three `git` subprocesses for a constant that reads never look at
    /// (RQ-5).
    pub fn anchor(&mut self) -> Result<Anchor, Error> {
        if let Some(anchor) = &self.anchor {
            return Ok(anchor.clone());
        }
        let anchor = Anchor::Workspace(self.git.genesis()?);
        self.anchor = Some(anchor.clone());
        Ok(anchor)
    }

    /// This process's `AuthorId`. `agent` is always `None`.
    ///
    /// **`KAN_AGENT` is gone** (`.design/v0.7-milestone.md` REQ-6), removed
    /// rather than repaired. It hashed an environment variable into
    /// `AuthorId.agent`, and since `TrustBase::Solo` trusts exactly one
    /// `AuthorId`, setting it silently partitioned the log: claims written
    /// under one value were invisible to every read under another. kan's own
    /// `.mcp.json` set it, so the *shipped* configuration made the agent
    /// surface and the human surface read disjoint views of one log — each
    /// reporting a complete-looking view, neither mentioning the other's
    /// claims existed.
    ///
    /// Its own source called it "not a real keypair and nothing verifies it
    /// against anything," and issue #30's per-agent identity work replaces
    /// it wholesale. Repairing something already scheduled for deletion, in
    /// the release whose theme is that provisional patches cause data loss,
    /// would have been the wrong lesson. Removing it also narrows
    /// `AuthorId` usage rather than widening it, which is the direction #30
    /// wants anyway.
    pub fn my_author(&self) -> Result<AuthorId, Error> {
        Ok(AuthorId {
            did: self.identity()?.did(),
            agent: None,
        })
    }

    /// Trust only this process's own `AuthorId`. **No longer the default** —
    /// v0.11 moved that to [`Self::local_trust`] — but still reachable as
    /// `--trust me`, which is the narrow frame "what did *I* write here"
    /// (`.design/identity-surface.md` REQ-5).
    ///
    /// It stopped being the default because its member is *me*, which is the
    /// single line that made every read resolve an identity in order to know
    /// whom to trust (#149, #90, #121 are all downstream of it).
    pub fn solo_trust(&self) -> Result<TrustBase, Error> {
        Ok(TrustBase::solo(self.my_author()?))
    }

    /// **The default base every read folds under**: every author with a
    /// claim in `.kan/log` (`.design/identity-surface.md` REQ-1).
    ///
    /// Computed here rather than inside `fold` for a reason the fold cannot
    /// work around: `fold` receives the log's claims and the overlay's
    /// together, so it cannot tell which arrived as a committed `.claims/`
    /// file. `Workspace` can, because the index records each claim's origin.
    ///
    /// Takes no identity, reads no key, and mints nothing — which is the
    /// whole point of the milestone.
    pub fn local_trust(&self) -> Result<TrustBase, Error> {
        Ok(TrustBase::local(self.index.log_authors()?))
    }

    /// Resolve `--trust` arguments into the base a read folds under. No
    /// arguments means [`Self::local_trust`] — every author that has written
    /// into this workspace's log — and only an explicit request moves off it.
    ///
    /// **Per-invocation by construction.** Nothing here reads or writes
    /// workspace state, so two reads in one session can name different
    /// author sets in either order, and comparing one subject under two
    /// frames is two reads rather than a sequence of mutations
    /// (`.design/kan-read-contract.md` REQ-2).
    /// `--trust roles` expands to every identity this workspace declared
    /// (`kan identity role add`), all at full weight — and to **nothing
    /// else**. The active identity is *not* injected on top.
    ///
    /// *This paragraph said the opposite until v0.12, and was wrong from the
    /// moment v0.11 narrowed the alias.* It described the active identity as
    /// included, and argued the case at length, while the body below has only
    /// ever mapped the declared set. `tests/trust_vocabulary.rs:203` pins the
    /// narrowing in words. The reason `roles` no longer over-reports is that
    /// `Local` became the default: "everything this workspace wrote" is
    /// already answered, so `roles` is free to mean exactly what it says,
    /// which is what makes `local` minus `roles` a meaningful difference.
    pub fn role_trust_entries(&self) -> Result<Vec<(String, f64)>, Error> {
        Ok(self
            .declared_roles()?
            .roles()
            .iter()
            .map(|role| (role.did.clone(), 1.0))
            .collect())
    }

    /// The roles this workspace has declared, resolved from the log
    /// (`.design/role-declarations.md` REQ-3).
    ///
    /// Supplies the two inputs `roles::declared` needs and does nothing else,
    /// so the rule itself stays pure and testable without a workspace.
    ///
    /// **Resolves the workspace identity, never a selection.** It asks
    /// `sign::workspace_identity` — question 1, "which identity does this
    /// workspace *have*" — rather than `signing_identity`, so a caller running
    /// with `KAN_IDENTITY_FILE` pointed at a role cannot shift which
    /// declarations are honoured. Reads no key it does not already need and
    /// creates nothing: `workspace_identity` is pure by REQ-1.
    ///
    /// An unreachable identity is [`crate::roles::Declared::NoWorkspaceIdentity`]
    /// rather than an error, because "who did this workspace vouch for" is a
    /// legitimate question with a legitimate empty answer, and an erroring
    /// alias would make `--trust roles --trust did:key:…` fail as a whole when one
    /// member could not expand.
    pub fn declared_roles(&self) -> Result<crate::roles::Declared, Error> {
        let workspace_did = match crate::sign::workspace_identity(&self.root.join(".kan")) {
            Ok(Some(identity)) => Some(identity.did()),
            // Unreachable is indistinguishable from absent *for this
            // question*: either way no declaration can be honoured, and
            // saying so beats propagating a keychain error into every read
            // that happens to name `roles` (#96).
            Ok(None) | Err(_) => None,
        };
        Ok(crate::roles::declared(
            &self.index.all_stored_claims()?,
            workspace_did.as_deref(),
        ))
    }

    /// Authors with a claim in this log that no live declaration names —
    /// `local` minus `roles` (`.design/identity-surface.md` REQ-9).
    ///
    /// The signal that an unexpected identity has written here, as **data**
    /// rather than as an absence. #90 and #136 both present as "some claims
    /// are missing from a view", which is the hardest shape to act on; this
    /// is the same fact stated positively, and it is only computable because
    /// `Local` made log membership derivable and `roles` narrowed to mean
    /// what it says.
    pub fn undeclared_log_authors(&self) -> Result<Vec<AuthorId>, Error> {
        let declared: std::collections::HashSet<String> = self
            .declared_roles()?
            .roles()
            .iter()
            .map(|role| role.did.clone())
            .collect();
        let mut out: Vec<AuthorId> = self
            .index
            .log_authors()?
            .into_iter()
            .filter(|author| !declared.contains(&author.did))
            .collect();
        out.sort_by(|a, b| (&a.did, &a.agent).cmp(&(&b.did, &b.agent)));
        Ok(out)
    }

    /// Resolve `--trust` arguments into the base a read folds under. No
    /// arguments means [`Self::local_trust`] — every author that has written
    /// into this workspace's log — and only an explicit request moves off it.
    ///
    /// **Per-invocation by construction.** Nothing here writes workspace
    /// state, so two reads in one session can name different author sets in
    /// either order, and comparing one subject under two frames is two
    /// reads rather than a sequence of mutations
    /// (`.design/kan-read-contract.md` REQ-2). `roles` reads the declared
    /// role list, which is workspace state — but it is *read* per
    /// invocation and never set by one, so the property holds.
    pub fn trust_from(&self, specs: &[String]) -> Result<TrustBase, Error> {
        Ok(self.trust_from_detailed(specs)?.0)
    }

    /// [`Self::trust_from`], plus **why** the base expanded to no authors when
    /// it did (`.design/role-declarations.md` REQ-8).
    ///
    /// The reason is produced here rather than at the render boundary because
    /// this is the only layer that knows which alias produced the emptiness.
    /// An empty base has more than one cause -- `roles` with nothing declared,
    /// and `local` on a log nobody has written to -- and attaching a
    /// roles-flavoured explanation to the second would be a confident wrong
    /// answer, which is the class this milestone exists to remove rather than
    /// relocate.
    pub fn trust_from_detailed(
        &self,
        specs: &[String],
    ) -> Result<(TrustBase, Option<String>), Error> {
        if specs.is_empty() {
            return Ok((self.local_trust()?, None));
        }
        // A lone `me` is `Solo` -- the same base the default used to be, and
        // the narrow frame REQ-5 keeps nameable. Combined with anything else
        // it is just one author among several, so `PeerContested` is right
        // and this special case does not apply.
        // Naming the default explicitly means the default, base and all --
        // otherwise `--trust local` and no argument at all would report
        // different frames for identical views.
        if specs.len() == 1 && specs[0] == crate::fold::trust::LOCAL_ALIAS {
            return Ok((self.local_trust()?, None));
        }
        if specs.len() == 1 && specs[0] == crate::fold::trust::SELF_ALIAS {
            return Ok((
                TrustBase::solo(AuthorId {
                    did: self.active_did()?,
                    agent: None,
                }),
                None,
            ));
        }

        let mut roles_reason: Option<String> = None;
        let mut weights = std::collections::HashMap::new();
        // A weight below 1.0 parses, validates and is stored, but no fold
        // path reads its magnitude -- `TrustBase::trusts` is `weight > 0.0`,
        // membership only (review/full-pass-v0.12 F6). The surface accepted
        // `did=0.5` and returned a view identical to `did=1.0` with nothing
        // said. Warn rather than reject: removing the syntax would break
        // README-taught invocations, and whether to fold magnitudes at all
        // is a design question, not this fix's to settle.
        let mut saw_partial_weight = false;
        for spec in specs {
            if spec == crate::fold::trust::ROLES_ALIAS {
                let declared = self.declared_roles()?;
                // Recorded whenever `roles` contributes nothing, and reported
                // only if the WHOLE base ends up empty -- so `--trust
                // roles --trust did:key:...` still returns the named author's
                // and says nothing misleading about the alias that added none.
                if declared.roles().is_empty() {
                    roles_reason = Some(crate::roles::empty_reason(&declared).to_string());
                }
                for role in declared.roles() {
                    weights.insert(
                        AuthorId {
                            did: role.did.clone(),
                            agent: None,
                        },
                        1.0,
                    );
                }
                continue;
            }
            if spec == crate::fold::trust::LOCAL_ALIAS {
                // Whole `AuthorId`s, agent included -- a legacy
                // `KAN_AGENT` author is a member of `local` on the same
                // footing as any other, because it wrote here (REQ-7).
                for author in self.index.log_authors()? {
                    weights.insert(author, 1.0);
                }
                continue;
            }
            let entry = crate::fold::trust::parse_entry(spec)?;
            if let Some(name) = entry.did.strip_prefix(crate::fold::trust::ROLE_PREFIX) {
                let declared = self.declared_roles()?;
                let roles = declared.roles();
                let found = roles.iter().find(|role| role.name == name);
                let did = match found {
                    Some(role) => role.did.clone(),
                    None => {
                        return Err(crate::fold::trust::SpecError::NoSuchRole {
                            spec: spec.to_string(),
                            // Naming *why* the set is empty rather than only
                            // that it is: "none declared" is a different
                            // problem from "this workspace's identity is
                            // unreachable, so none can be honoured", and a
                            // caller who cannot tell them apart debugs the
                            // wrong one.
                            declared: match roles.is_empty() {
                                true => crate::roles::empty_reason(&declared).to_string(),
                                false => roles
                                    .iter()
                                    .map(|r| r.name.clone())
                                    .collect::<Vec<_>>()
                                    .join(", "),
                            },
                        }
                        .into());
                    }
                };
                saw_partial_weight |= entry.weight < 1.0;
                weights.insert(AuthorId { did, agent: None }, entry.weight);
                continue;
            }
            let did = if entry.did == crate::fold::trust::SELF_ALIAS {
                // `--trust me` names the active identity, so it genuinely
                // needs one -- and on a read-only workspace there is none.
                // Erroring is the honest answer: the question "what did I
                // write here" has no answer without an identity, and
                // resolving one to answer it would mint on a read.
                self.active_did()?
            } else {
                entry.did
            };
            saw_partial_weight |= entry.weight < 1.0;
            weights.insert(AuthorId { did, agent: None }, entry.weight);
        }
        if saw_partial_weight {
            eprintln!(
                "warning: trust weights below 1.0 are not yet folded -- an author is either \
                 included or not, so this view is the same as naming them at full weight. \
                 (weighted folding is a future enrichment)"
            );
        }
        let reason = match weights.is_empty() {
            true => roles_reason,
            false => None,
        };
        Ok((TrustBase::peer_contested(weights), reason))
    }
}

/// The first claim present in both stores, if any.
///
/// The log and the overlay are disjoint by construction — the log holds what
/// was written here, the overlay what `.claims/` published that the log does
/// not already have. `claims.content_cid` is a PRIMARY KEY, so an overlap is
/// a `UNIQUE constraint failed` at index build and, because the overlay is
/// persistent, an unopenable workspace from then on (#150).
fn overlapping<'a>(
    log_claims: &[(Cid, crate::store::log::StoredClaim)],
    overlay_claims: &'a [(Cid, crate::store::log::StoredClaim)],
) -> Option<&'a Cid> {
    let in_log: std::collections::HashSet<&Cid> = log_claims.iter().map(|(c, _)| c).collect();
    overlay_claims
        .iter()
        .map(|(c, _)| c)
        .find(|c| in_log.contains(*c))
}

/// The value the index records as "what I was built from", now that it is
/// built from two stores rather than one.
///
/// With no overlay this is the log's own root **unchanged**, so an index
/// built by an earlier version stays valid and upgrading does not force a
/// spurious full rebuild. Once an overlay exists, both roots are hashed
/// together, so a change in either invalidates the index — which is the
/// property the original skip depended on: not "probably fresh", provably
/// fresh (`.design/v0.4-milestone.md` REQ-5, issue #26).
/// The `.claims/` content hash joins the two roots for a reason the read path
/// forces: a read-only open projects published records straight into the
/// index, so a change in `.claims/` alone must invalidate the projection.
/// Both paths hash it, so a read-open and a write-open agree about freshness
/// rather than each invalidating the other's work on every alternation.
fn index_fingerprint(
    log_root: Option<Cid>,
    overlay_root: Option<Cid>,
    claims_hash: Option<&str>,
) -> Option<Cid> {
    match (log_root, overlay_root, claims_hash) {
        // Unchanged for the commonest workspace there is -- no published
        // tree, no overlay -- so an index built by an earlier version stays
        // valid and upgrading forces no spurious rebuild.
        (log, None, None) => log,
        (log, overlay, claims) => {
            let mut bytes = Vec::new();
            if let Some(log) = &log {
                bytes.extend_from_slice(&log.to_bytes());
            }
            if let Some(overlay) = &overlay {
                bytes.extend_from_slice(&overlay.to_bytes());
            }
            if let Some(claims) = claims {
                bytes.extend_from_slice(claims.as_bytes());
            }
            Some(Cid::from(atproto_repo::compute_cid(&bytes)))
        }
    }
}

/// Read the tracked `.claims/` tree **without a signing identity**: which
/// records are published (for the durability column), and which of them this
/// workspace does not already hold.
///
/// The read-path counterpart to `ingest_published`. It writes nothing —
/// no overlay, no lock, no commit — because a read has no identity to sign a
/// commit with, and the records it returns go straight into the disposable
/// index instead (#164 makes this the only path in v0.12).
///
/// **Own-vs-foreign is decided by log membership, not by identity.** That is
/// both what makes this possible without a key and the more correct test: on
/// a fresh clone a primary-authored record in `.claims/` genuinely *is*
/// foreign to that workspace's log and should be read. Log membership answers
/// "would this duplicate", which is the actual invariant; matching against
/// the active identity only approximates it. It generalises the check v0.9.2
/// introduced for #150.
///
/// A bad record warns and is skipped rather than failing the workspace,
/// exactly as on the write path: `.claims/` is *tracked*, so anyone can
/// hand-edit it and a bad merge can mangle it, and a repo whose every `kan`
/// command aborts because a teammate's merge dropped a line is worse than one
/// that says so and keeps working. The record is still refused, which is the
/// part that matters.
async fn read_published(
    root: &Path,
    log: &Log,
    overlay: &Log,
) -> Result<(PublishedIndex, Vec<(Cid, crate::store::log::StoredClaim)>), Error> {
    let claims_dir = root.join(crate::transport::git_tree::CLAIMS_DIR);
    if !claims_dir.exists() {
        return Ok((PublishedIndex::default(), Vec::new()));
    }

    let tree = crate::transport::git_tree::GitTree::new_reader(root);
    let mut published = PublishedIndex::default();
    let mut arrived = Vec::new();
    let mut digest = ClaimsDigest::started();
    for record in tree.read_all_with_rev() {
        match record {
            Ok((cid, claim, rev)) => {
                published.record(claim.content.subject.clone(), cid.clone());
                digest.add(&cid);
                if log.contains(&cid).await? || overlay.contains(&cid).await? {
                    continue;
                }
                arrived.push((
                    cid.clone(),
                    crate::store::log::StoredClaim {
                        claim,
                        rev: rev.unwrap_or_else(|| cid.to_string()),
                    },
                ));
            }
            Err(e) => {
                eprintln!("warning: skipping a published record: {e}");
                published.read_errors.push(published_read_error(root, &e));
            }
        }
    }
    published.content_hash = digest.finish();
    Ok((published, arrived))
}

/// Read the tracked `.claims/` tree and insert every **foreign-authored**
/// record into the overlay.
///
/// Three things this deliberately does not do.
///
/// **It does not touch `log/`.** Records authored by this identity are
/// skipped entirely: they are already in the log if they were written here,
/// and pulling them back out of `.claims/` is *restore*, a separate operation
/// with its own identity check (`.design/durability-log-recovery.md`
/// REQ-2/REQ-3, deferred to v0.9 with the `kan restore` command).
///
/// **It does not take the write lock unless something is new.** Membership is
/// checked against the already-open overlay first, so the overwhelmingly
/// common case — nothing published since last time — costs one directory read
/// and no lock at all. `Workspace::open` runs on every single CLI invocation,
/// and a lock acquisition per command would be a real regression (day#123
/// measured `Workspace::open` as already the dominant per-call cost).
///
/// **It does not fail the workspace on a bad record.** An unverifiable or
/// malformed record in `.claims/` warns on stderr and is skipped, because
/// `.claims/` is a *tracked* directory that anyone can hand-edit or that a
/// bad merge can mangle — and a repo whose every `kan` command aborts because
/// a teammate's merge dropped a line is worse than one that says so and keeps
/// working. The record is still refused, which is the part that matters:
/// nothing unverifiable ever enters a view.
async fn ingest_published(
    root: &Path,
    identity: &Identity,
    log: &Log,
    overlay: &mut Log,
) -> Result<PublishedIndex, Error> {
    let claims_dir = root.join(crate::transport::git_tree::CLAIMS_DIR);
    if !claims_dir.exists() {
        return Ok(PublishedIndex::default());
    }

    let tree = crate::transport::git_tree::GitTree::new_reader(root);
    let mut published = PublishedIndex::default();
    let mut digest = ClaimsDigest::started();
    let mut pending = Vec::new();
    for record in tree.read_all_with_rev() {
        match record {
            Ok((cid, claim, rev)) => {
                // Recorded before the author test, and for every record
                // regardless of who signed it: durability asks "is this claim
                // in the tree", which is a question about the tree, not about
                // whose claim it is.
                published.record(claim.content.subject.clone(), cid.clone());
                digest.add(&cid);
                // Log membership, not identity -- the SAME rule
                // `read_published` uses. They used to differ (`author.did ==
                // mine` here, log membership there), so a read-open and a
                // write-open projected different row sets while recording the
                // same freshness key, and neither could invalidate the
                // other's work: one command returned two different answers
                // over identical bytes depending on which path last touched a
                // disposable cache.
                //
                // Log membership is also the more correct test on its own
                // terms: on a fresh clone an own-authored record in
                // `.claims/` genuinely is not in this log yet, and pretending
                // otherwise hides it from every view.
                if overlay.contains(&cid).await? {
                    continue;
                }
                // Already in this workspace's own log, so ingesting it would
                // put one claim in both stores (#146 part 2).
                //
                // The author test above is not wrong when this fires — it is
                // right. A *declared role* (ADR-58) genuinely is a different
                // author from the primary identity that wrote the log, so it
                // reads the primary's published records as foreign, correctly.
                // What would be wrong is concluding they therefore belong in
                // the overlay: the overlay exists for claims the log does not
                // have, and these it has.
                //
                // Found by running the supported multi-role flow rather than
                // by reading the code — publish as the primary, declare a
                // role, read as that role — which is the one path the suite
                // did not cover. Without this, that flow duplicates every
                // published claim.
                if log.contains(&cid).await? {
                    continue;
                }
                pending.push(crate::store::log::StoredClaim {
                    claim,
                    // A record published before v0.7.0-beta.1 carries no
                    // `rev`. Falling back to the content CID keeps ordering
                    // *deterministic* across clones — every reader derives
                    // the same value from the same bytes — which a locally
                    // generated TID would not. It orders such claims apart
                    // from timed ones rather than pretending to a time
                    // nobody recorded.
                    rev: rev.unwrap_or_else(|| cid.to_string()),
                });
            }
            Err(e) => {
                eprintln!("warning: skipping a published record: {e}");
                published.read_errors.push(published_read_error(root, &e));
            }
        }
    }

    for stored in pending {
        if let Err(e) = overlay.ingest(stored, identity).await {
            eprintln!("warning: could not ingest a published record: {e}");
        }
    }
    published.content_hash = digest.finish();
    Ok(published)
}

pub fn cwd() -> Result<PathBuf, Error> {
    Ok(std::env::current_dir()?)
}

/// Walks upward from `start` to find the directory containing `.git/` —
/// falls back to `start` unchanged if none is found anywhere above it, so
/// the absence surfaces as `GitSubstrate::open`'s clear "not a git repo"
/// error rather than a silent, different failure here.
fn find_repo_root(start: &Path) -> PathBuf {
    let mut dir = start;
    loop {
        if dir.join(".git").exists() {
            return dir.to_path_buf();
        }
        match dir.parent() {
            Some(parent) => dir = parent,
            None => return start.to_path_buf(),
        }
    }
}
