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

use sha2::Digest;

use crate::{
    claim::{AgentKey, Anchor, AuthorId},
    fold::TrustBase,
    git::GitSubstrate,
    sign::Identity,
    store::{index::Index, log::Log},
};

/// The `KAN_AGENT` environment variable an MCP-server `env` config (or a
/// human's shell) sets to tag claims with a distinct agent identity.
const KAN_AGENT_ENV: &str = "KAN_AGENT";

/// **Placeholder, not a real keypair.** A simple, consistent hash of the
/// `KAN_AGENT` string — enough to make two different agent names produce
/// two distinct, stable `AgentKey`s (closing the *reachability* gap: an
/// `AuthorId.agent` a `PeerContested` trust base can actually tell apart),
/// but this is not a signing key and nothing verifies it against anything.
/// `claim::AgentKey`'s own doc comment ("compressed public key bytes of the
/// signing agent") stays aspirational until a real per-agent-keypair design
/// replaces this (tracked as its own follow-up issue, deliberately not
/// v0.2 — see `docs/DECISIONS.md`).
fn derive_agent_key(name: &str) -> AgentKey {
    sha2::Sha256::digest(name.as_bytes()).to_vec()
}

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

    /// This process's `AuthorId`: `agent: None` (human-direct) unless
    /// `KAN_AGENT` is set, in which case `agent` is a placeholder hash
    /// derived from it (`derive_agent_key`'s doc comment — not a real
    /// per-agent keypair, an honest reachability patch only).
    pub fn my_author(&self) -> AuthorId {
        let agent = std::env::var(KAN_AGENT_ENV)
            .ok()
            .map(|name| derive_agent_key(&name));
        AuthorId {
            did: self.identity.did(),
            agent,
        }
    }

    /// Trust only this exact process's own `AuthorId` (did + current
    /// `KAN_AGENT`, if any) — the default for every read view today. A
    /// `KAN_AGENT`-tagged write is only visible back to a read in the same
    /// `KAN_AGENT` context under this default; a caller wanting to see
    /// *every* locally-known agent's claims together constructs a
    /// `PeerContested` `TrustBase` directly rather than through this helper
    /// (no CLI/MCP surface for that exists yet — v1's real scope is "one
    /// human, one-or-more local agents" with no second human to weigh
    /// against, `fold::trust`'s own doc comment).
    pub fn solo_trust(&self) -> TrustBase {
        TrustBase::solo(self.my_author())
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
