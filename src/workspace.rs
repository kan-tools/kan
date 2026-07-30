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
    pub index: Index,
    pub anchor: Anchor,
    pub git: GitSubstrate,
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
        let identity = Identity::load_or_create(&kan_dir.join("identity"))?;
        let mut log = Log::open_or_create(&kan_dir.join("log"), &identity).await?;
        let mut index = Index::open(&kan_dir.join("index.sqlite"))?;

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
        let current_root = log.current_root();
        if current_root != index.built_from_root()? {
            let claims = log.iter_all().await?;
            index.rebuild(&claims, current_root.as_ref())?;
        }

        let git = GitSubstrate::open(&root)?;
        let anchor = Anchor::Workspace(git.genesis()?);
        Ok(Self {
            root,
            identity,
            log,
            index,
            anchor,
            git,
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
