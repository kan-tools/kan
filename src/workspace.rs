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
}

pub struct Workspace {
    /// Repo root — the directory `.kan/` sits beside. Needed by anything
    /// that writes outside the private store, such as `kan publish`.
    pub root: std::path::PathBuf,
    pub identity: Identity,
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
    pub anchor: Anchor,
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
}

impl Workspace {
    /// Reopens from disk every call, by design: the CLI is one process per
    /// invocation, and `kan mcp` (one long-lived process) mirrors that by
    /// calling `open` fresh per tool call rather than holding one `Workspace`
    /// across calls — cheap at today's scale, and avoids any question of
    /// staleness or concurrent-mutation safety (`docs/DECISIONS.md` ADR-15).
    pub async fn open(cwd: &Path) -> Result<Self, Error> {
        let root = find_repo_root(cwd);
        let kan_dir = root.join(".kan");
        let identity = Identity::load_or_create_for_workspace(&kan_dir)?;
        let mut log = Log::open_or_create(&kan_dir.join("log"), &identity).await?;
        let mut overlay = Log::open_or_create(&kan_dir.join("overlay"), &identity).await?;
        let mut index = Index::open(&kan_dir.join("index.sqlite"))?;

        // REQ-1: a published tree is actually consumed. `GitTree::read_all`
        // already returned byte-complete, signature-verified records and had
        // no caller anywhere outside its own tests (#97) — this is that
        // caller.
        let published = ingest_published(&root, &identity, &mut overlay).await?;

        // Correctness-first (CLAUDE.md house rules), with one cheap,
        // provably-safe skip (issue #26, `.design/v0.4-milestone.md`
        // REQ-5): `Log::current_root` is already resident in memory (no
        // I/O, no MST walk) from `open_or_create` above. When it matches
        // what the index was last `rebuild`t from, content-addressing
        // guarantees the log genuinely hasn't changed a single bit since
        // then — not "probably fresh," provably fresh — so `iter_all`'s
        // per-claim signature verification (ADR-13's dominant cost) can be
        // skipped entirely. Any mismatch (or a fresh/recreated index with
        // no recorded root yet) falls back to exactly the prior
        // unconditional full rebuild; incremental *indexing* (partial
        // updates rather than skip-or-full-rebuild) stays a later
        // optimization, deliberately not what this is.
        let current_root = index_fingerprint(log.current_root(), overlay.current_root());
        if current_root != index.built_from_root()? {
            let mut claims = log.iter_all().await?;
            claims.extend(overlay.iter_all().await?);
            index.rebuild(&claims, current_root.as_ref())?;
        }

        let git = GitSubstrate::open(&root)?;
        let anchor = Anchor::Workspace(git.genesis()?);
        Ok(Self {
            root,
            identity,
            log,
            overlay,
            index,
            anchor,
            git,
            published,
        })
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
    pub fn my_author(&self) -> AuthorId {
        AuthorId {
            did: self.identity.did(),
            agent: None,
        }
    }

    /// Trust only this process's own `AuthorId` — still the default for
    /// every read that names no authors. Whether it is the *right* default
    /// once a workspace holds several role identities is a live question
    /// (#121) that v0.8 deliberately does not settle; what v0.8 adds is that
    /// a read under this base now *discloses* what it excluded
    /// (`fold::excluded_by_trust`), so a narrow default can no longer be
    /// mistaken for a complete view.
    pub fn solo_trust(&self) -> TrustBase {
        TrustBase::solo(self.my_author())
    }

    /// Resolve `--trust` arguments into the base a read folds under. No
    /// arguments means [`Self::solo_trust`] — the default is unchanged, and
    /// only an explicit request moves off it.
    ///
    /// **Per-invocation by construction.** Nothing here reads or writes
    /// workspace state, so two reads in one session can name different
    /// author sets in either order, and comparing one subject under two
    /// frames is two reads rather than a sequence of mutations
    /// (`.design/kan-read-contract.md` REQ-2).
    /// `--trust roles` expands to every identity this workspace declared
    /// (`kan identity role add`) **plus the active one**, all at full
    /// weight.
    ///
    /// The active identity is included because leaving it out would make
    /// the obvious command — "show me everything this workspace's own
    /// identities wrote" — quietly drop the caller's own claims, which is a
    /// smaller version of the bug this milestone exists to fix. A caller
    /// wanting a role hierarchy rather than a flat union names the DIDs and
    /// weights explicitly.
    pub fn role_trust_entries(&self) -> Result<Vec<(String, f64)>, Error> {
        let mut out = vec![(self.identity.did(), 1.0)];
        for role in crate::sign::list_roles(&self.root.join(".kan"))? {
            out.push((role.did, 1.0));
        }
        Ok(out)
    }

    /// Resolve `--trust` arguments into the base a read folds under. No
    /// arguments means [`Self::solo_trust`] — the default is unchanged, and
    /// only an explicit request moves off it.
    ///
    /// **Per-invocation by construction.** Nothing here writes workspace
    /// state, so two reads in one session can name different author sets in
    /// either order, and comparing one subject under two frames is two
    /// reads rather than a sequence of mutations
    /// (`.design/kan-read-contract.md` REQ-2). `roles` reads the declared
    /// role list, which is workspace state — but it is *read* per
    /// invocation and never set by one, so the property holds.
    pub fn trust_from(&self, specs: &[String]) -> Result<TrustBase, Error> {
        if specs.is_empty() {
            return Ok(self.solo_trust());
        }
        let mut weights = std::collections::HashMap::new();
        for spec in specs {
            if spec == crate::fold::trust::ROLES_ALIAS {
                for (did, weight) in self.role_trust_entries()? {
                    weights.insert(AuthorId { did, agent: None }, weight);
                }
                continue;
            }
            let entry = crate::fold::trust::parse_entry(spec)?;
            let did = if entry.did == crate::fold::trust::SELF_ALIAS {
                self.identity.did()
            } else {
                entry.did
            };
            weights.insert(AuthorId { did, agent: None }, entry.weight);
        }
        Ok(TrustBase::peer_contested(weights))
    }
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
fn index_fingerprint(log_root: Option<Cid>, overlay_root: Option<Cid>) -> Option<Cid> {
    match (log_root, overlay_root) {
        (log, None) => log,
        (log, Some(overlay)) => {
            let mut bytes = Vec::new();
            if let Some(log) = &log {
                bytes.extend_from_slice(&log.to_bytes());
            }
            bytes.extend_from_slice(&overlay.to_bytes());
            Some(Cid::from(atproto_repo::compute_cid(&bytes)))
        }
    }
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
    overlay: &mut Log,
) -> Result<PublishedIndex, Error> {
    let claims_dir = root.join(crate::transport::git_tree::CLAIMS_DIR);
    if !claims_dir.exists() {
        return Ok(PublishedIndex::default());
    }

    let tree = crate::transport::git_tree::GitTree::new_reader(root);
    let mine = identity.did();
    let mut published = PublishedIndex::default();
    let mut pending = Vec::new();
    for record in tree.read_all_with_rev() {
        match record {
            Ok((cid, claim, rev)) => {
                // Recorded before the author test, and for every record
                // regardless of who signed it: durability asks "is this claim
                // in the tree", which is a question about the tree, not about
                // whose claim it is.
                published.record(claim.content.subject.clone(), cid.clone());
                if claim.content.author.did == mine {
                    continue;
                }
                if overlay.contains(&cid).await? {
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
            Err(e) => eprintln!("warning: skipping a published record: {e}"),
        }
    }

    for stored in pending {
        if let Err(e) = overlay.ingest(stored, identity).await {
            eprintln!("warning: could not ingest a published record: {e}");
        }
    }
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
