//! `Transport` — where claims come from/go to, a different axis than
//! `store/`'s *how they're persisted once here* (`docs/SPEC.md` §10;
//! `.design/v0.5-milestone.md`, sync staging Milestone 0,
//! `.design/sync-layer-architecture-and-staging.md`).
//!
//! `LocalOnly` is the first, honest implementation: one author, one log,
//! nothing to subscribe to. `publish`/`subscribe`'s shapes match
//! `store::log::Log`'s real, already-established signatures rather than
//! `docs/SPEC.md` §10's illustrative `fn publish(&self, &[Claim])` sketch —
//! `Log::append` signs one claim at a time and is the only thing `LocalOnly`
//! wraps, so this is adaptation of an existing pattern, not invention of a
//! new one.
//!
//! Not yet wired into `Workspace`/the CLI/MCP (deliberately — see the
//! milestone doc's REQ-5): a second real implementation (`HostedRelay`,
//! staged later in `.design/sync-layer-architecture-and-staging.md`) needs
//! to exist before the wiring shape can be designed against something real
//! rather than guessed at from one implementation alone.

use std::pin::Pin;

use atproto_dasl::Cid;
use tokio_stream::Stream;

use crate::{
    claim::{Claim, ClaimContent, Did},
    sign::Identity,
    store::log::Log,
};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("log error: {0}")]
    Log(#[from] crate::store::log::Error),
}

/// A stream of claims arriving from `subscribe`. `Item` is a `Result`, not a
/// bare `Claim`, so a future networked transport (`HostedRelay`) can surface
/// mid-stream failures (a dropped connection, a peer's bad record) without a
/// signature change later — `LocalOnly`'s stream never yields anything, so
/// it never needs the `Err` case, but the shape is ready for a transport
/// that does.
pub type ClaimStream = Pin<Box<dyn Stream<Item = Result<Claim, Error>> + Send>>;

pub trait Transport {
    /// Sign and publish one claim, returning its content CID — the exact
    /// shape of `Log::append` (`store::log::Log::append`), which is what
    /// every implementation of this trait ultimately has to honor at least
    /// once (`LocalOnly` directly; a networked transport by relaying to its
    /// own author's local log first, then publishing outward).
    ///
    /// Desugared to `-> impl Future<...> + Send` rather than `async fn`
    /// (clippy's own `async_fn_in_trait` suggestion) so the future stays
    /// `Send` across the trait boundary — kan's tokio runtime is
    /// multi-threaded (`Cargo.toml`'s `rt-multi-thread` feature).
    fn publish(
        &mut self,
        content: ClaimContent,
        identity: &Identity,
    ) -> impl std::future::Future<Output = Result<Cid, Error>> + Send;

    /// Claims published by any of `dids`, as they arrive. `LocalOnly` always
    /// returns an empty stream — correctly, not as a stub — since a single
    /// local log has no other author to subscribe to.
    fn subscribe(
        &self,
        dids: &[Did],
    ) -> impl std::future::Future<Output = Result<ClaimStream, Error>> + Send;
}

/// Wraps `store::log::Log` — one author, one log, no sync. `docs/SPEC.md`
/// §10: "`LocalOnly` (no-op) — BUILD FIRST, SHIP FIRST."
pub struct LocalOnly {
    log: Log,
}

impl LocalOnly {
    pub fn new(log: Log) -> Self {
        Self { log }
    }
}

impl Transport for LocalOnly {
    async fn publish(&mut self, content: ClaimContent, identity: &Identity) -> Result<Cid, Error> {
        Ok(self.log.append(content, identity).await?)
    }

    async fn subscribe(&self, _dids: &[Did]) -> Result<ClaimStream, Error> {
        Ok(Box::pin(tokio_stream::empty()))
    }
}
