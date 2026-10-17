//! kan: local reasoning, global coherence — memory for AI agents.
//!
//! See `docs/SPEC.md` (authoritative) and `docs/HANDOFF.md` (orientation).
#![deny(clippy::disallowed_methods)]
#![deny(clippy::disallowed_types)]

pub mod actions;
pub mod at_claim;
pub mod cid;
pub mod claim;
pub mod cli;
pub mod context;
#[cfg(feature = "evidence-contract")]
pub mod evidence;
#[cfg(feature = "v2-crypto")]
pub mod evidence_crypto;
#[cfg(feature = "v2-crypto")]
pub mod evidence_delivery;
#[cfg(feature = "v2-service")]
pub mod evidence_http;
#[cfg(feature = "v2-crypto")]
pub mod evidence_import;
#[cfg(feature = "v2-storage")]
pub mod evidence_service;
#[cfg(feature = "v2-storage")]
pub mod evidence_store;
pub mod fold;
pub mod git;
pub mod identity;
pub mod json;
pub mod mcp;
#[cfg(feature = "v2-storage")]
pub mod migration_preflight;
pub mod mixed_render;
pub mod mst;
pub mod persistence;
pub mod relations;
pub mod roles;
pub mod sign;
pub mod store;
pub mod surface;
pub mod transport;
pub mod uri;
pub mod workspace;

#[cfg(feature = "v2-storage")]
pub mod evidence_spool;
