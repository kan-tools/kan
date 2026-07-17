//! Shared setup for every action (`crate::actions`), used by both surfaces
//! (`CLAUDE.md`'s "one surface: CLI + MCP" — this is the plumbing both sit
//! on top of): resolve `.kan/` (ADR-3, sibling to `.git/`), load or create
//! the local identity, and open the log + index.
//!
//! M3 resolves `.kan/` relative to the current directory rather than
//! searching upward for a repo root the way `git` does — a real but small
//! gap, fine for now since dogfooding runs from the repo root anyway; worth
//! revisiting once `kan` is used from subdirectories. `git` itself walks
//! upward to find `.git/`, so `GitSubstrate`/the workspace anchor below
//! aren't affected by that gap even though `.kan/` resolution is (issue #3).

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
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

pub struct Workspace {
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
        let kan_dir = cwd.join(".kan");
        let identity = Identity::load_or_create(&kan_dir.join("identity"))?;
        let mut log = Log::open_or_create(&kan_dir.join("log"), &identity).await?;
        let mut index = Index::open(&kan_dir.join("index.sqlite"))?;

        // Correctness-first (CLAUDE.md house rules): always rebuild from the
        // log before use rather than trusting a possibly-stale index.
        // Fine at today's scale; incremental indexing is a later
        // optimization once fixtures exist to guard it.
        let claims = log.iter_all().await?;
        index.rebuild(&claims)?;

        let git = GitSubstrate::open(cwd)?;
        let anchor = Anchor::Workspace(git.genesis()?);
        Ok(Self {
            identity,
            log,
            index,
            anchor,
            git,
        })
    }

    /// This CLI's own human-direct `AuthorId` (`agent: None`).
    pub fn my_author(&self) -> AuthorId {
        AuthorId {
            did: self.identity.did(),
            agent: None,
        }
    }

    /// Trust only this actor's own author — the default for read views
    /// today, since neither surface writes with an agent key yet. Once
    /// agent-key support exists, callers needing `PeerContested` will
    /// construct that `TrustBase` directly rather than through this helper.
    pub fn solo_trust(&self) -> TrustBase {
        TrustBase::solo(self.my_author())
    }
}

pub fn cwd() -> Result<PathBuf, Error> {
    Ok(std::env::current_dir()?)
}
