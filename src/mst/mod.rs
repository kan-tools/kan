//! The Merkle Search Tree kan's log is stored in.
//!
//! # Why this is first-party
//!
//! kan does not own much of its storage stack — `atproto-dasl` handles CAR and
//! DAG-CBOR, `atproto-repo` still supplies `Commit`, `RecordPath` and
//! `compute_cid`. It owns *this*, because this is the layer where the
//! non-negotiable invariant lives: the tree is what makes a claim findable, and
//! **no operation destroys a subject**.
//!
//! Two published crates have now failed at exactly this layer:
//!
//! - `atrium-repo`'s MST lost data on sequential inserts (ADR-11/12, filed
//!   upstream as atrium-rs/atrium#343).
//! - `atproto-repo` 0.14.5's MST never split: `insert_recursive` computed each
//!   key's layer, discarded it into `_target_height`, and never recursed, so
//!   every key landed in one flat root node that was rewritten in full on every
//!   insert. CAR bytes grew as ~52n², a hard write cliff at ~1,431 claims
//!   against `atproto-dasl`'s 100 MiB default — and the root CID matched no
//!   conformant implementation, which falsified the premise ADR-12 chose that
//!   crate for. It also omitted `l` and `t` where the node schema has them
//!   present-but-nullable, so even a one-entry tree diverged. (kan#204, ADR-90.)
//!
//! After the second, patching someone else's copy was the wrong shape: a
//! `[patch.crates-io]` section is honoured only in the root manifest of the
//! crate being *built*, so it fixes local and CI builds and leaves everyone who
//! runs `cargo install kan` on the broken one.
//!
//! # What conformance means here, and how it is checked
//!
//! `tests/mst_conformance.rs` asserts our root CID equals the one
//! `@atproto/repo` 0.10.10 computes for the same key set. The expected value is
//! **that implementation's output**, not our reading of the spec — ADR-90 exists
//! because our first spec-derived reference used the wrong layer convention and
//! produced a confidently wrong answer that agreed with itself.
//!
//! The convention it got wrong is worth stating here, since it is the one
//! detail that is easy to re-derive incorrectly: **layers decrement strictly.**
//! A layer holding no keys of its own still gets a node containing only a left
//! pointer. Sub-trees do not skip empty layers.
//!
//! # How `insert` works
//!
//! It rebuilds the tree canonically rather than splicing a path. An MST's shape
//! is a pure function of its key *set*, not of insertion order, so this is
//! byte-for-byte what a correct incremental insert would produce; unchanged
//! sub-trees keep their CIDs and are deduplicated by the caller's
//! persisted-block set, so only O(log n) *new* blocks reach the CAR. A true
//! incremental insert is a later optimization and [`Mst::build_canonical`] is
//! the oracle it must be tested against.
//!
//! Rebuilding also **repairs**: sorting the walk before building heals a log
//! that a non-conformant binary has written into. See `.design/mst-migration.md`
//! for why that matters and what it cost to find.

mod entry;
mod key;
mod node;
mod tree;

pub use entry::TreeEntry;
pub use key::{key_height, validate_key};
pub use node::MstNode;
pub use tree::Mst;

/// Errors from tree operations.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid MST node: {reason}")]
    InvalidNode { reason: String },

    #[error("invalid tree entry prefix: {reason}")]
    InvalidPrefix { reason: String },

    #[error("MST node not found: {cid}")]
    NodeNotFound { cid: String },

    /// The tree is not the shape a conformant MST has.
    ///
    /// Raised by `insert`'s post-condition when a rebuild did not preserve the
    /// key set, and by the duplicate-key check. Carries its own explanation
    /// because the recovery advice differs per case and a bare "structure
    /// violation" sent readers to the wrong place.
    #[error("MST structure violation: {reason}")]
    StructureViolation { reason: String },

    #[error("DAG-CBOR encoding error: {0}")]
    Encode(#[from] atproto_dasl::EncodeError),

    #[error("DAG-CBOR decoding error: {0}")]
    Decode(#[from] atproto_dasl::DecodeError),

    #[error("block storage error: {0}")]
    Storage(#[from] atproto_dasl::errors::StorageError),
}

/// Limits applied while walking or building a tree.
#[derive(Debug, Clone)]
pub struct MstConfig {
    /// Refuse to descend past this depth.
    ///
    /// A conformant tree over n keys is ~log₄(n) deep, so this is a guard
    /// against a malformed or hostile tree rather than a real bound: 32 levels
    /// is roughly 4³² keys.
    pub max_depth: usize,
}

impl Default for MstConfig {
    fn default() -> Self {
        Self { max_depth: 32 }
    }
}
