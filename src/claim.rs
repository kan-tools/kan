//! Concrete types for `docs/SPEC.md` §1, §2, §4, §5, §7 — see `docs/DECISIONS.md`
//! ADR-4 (did:key identity) and ADR-5 (ClaimBody/ClaimKind merge) for the
//! implementation choices layered on top of the spec's sketch.

use std::path::PathBuf;

use atproto_dasl::Cid;
use serde::{Deserialize, Serialize};

/// `did:key:...` for local-only v1 (ADR-4); upgradeable to `did:plc` later
/// without re-signing history, since the key itself doesn't change.
pub type Did = String;

/// Compressed public key bytes of the signing agent (§2). `None` means the
/// claim was authored by the human directly, not through an agent.
pub type AgentKey = Vec<u8>;

/// An author-local, freely-chosen identifier for a `Local` subject (§4.1).
/// Meaningless outside the log that minted it.
pub type Rkey = String;

/// A git object hash, kept as hex text rather than a fixed-size array since
/// repos may be SHA-1 or SHA-256.
pub type Sha = String;

/// Hash of a workspace's git genesis/origin (§5) — computed identically by
/// every actor. Anchor computation itself lands with the RelationProvider
/// work (M4); this is just the value type.
pub type GenesisCid = String;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Span {
    pub start: u32,
    pub end: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AuthorId {
    pub did: Did,
    pub agent: Option<AgentKey>,
}

/// §4.1 — `Local` never crosses log boundaries; `Anchor` is content-addressed
/// and computed identically by every actor.
///
/// `Hash` is derived so a fold can group claims by subject in a `HashMap`
/// without a full identity fold — the M2 trivial fold's "each subject is its
/// own class, no `SameAs` yet" case (`fold::identity` builds the real
/// witness-graph merge-classes in M4).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SubjectRef {
    Local(Rkey),
    Anchor(Anchor),
}

/// §5 — strict identity, decided by construction, never asserted. A `SameAs`
/// between two `Anchor`s is a type error, not a claim (§5.1) — enforced by
/// `Anchor` simply not being a valid `RelationKind::SameAs` target in the
/// fold, not by the type system here.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Anchor {
    Workspace(GenesisCid),
    Commit(Sha),
    Blob(Cid),
    FileAt(PathBuf, Sha),
    LineRangeAt(PathBuf, Sha, Span),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SubjectKind {
    Issue,
    Idea,
    Question,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StatusValue {
    Open,
    InProgress,
    Blocked,
    Resolved,
    Closed,
}

/// §4.2, §12.1 — `SameAs` is the only identity-conferring edge. `Rejects` is
/// a local, cross-author suppression (§8), not a retraction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RelationKind {
    SameAs,
    Blocks,
    About,
    ManifestsAt,
    DependsOn,
    Accepts,
    Rejects,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ArtifactRef {
    Commit(Sha),
    FileAt(PathBuf, Sha),
    LineRangeAt(PathBuf, Sha, Span),
    ToolOutput(Cid),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimKind {
    Subject,
    Observation,
    Plan,
    Decision,
    Blocker,
    Resolution,
    Result,
    Status,
    Relation,
    Retraction,
}

/// ADR-5: `ClaimKind` + `Body` (two fields in `docs/SPEC.md` §1's sketch)
/// merged into one enum, so an invalid kind/body pairing is unrepresentable.
/// `kind()` below is the derived method that replaces the separate field.
///
/// Structural variants (`Subject`, `Status`, `Relation`, `Retraction`) are
/// typed because the fold reads them; narrative variants hold opaque text
/// because the fold only needs to know they exist and what they cite.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClaimBody {
    Subject {
        title: String,
        subject_kind: SubjectKind,
    },
    Observation {
        text: String,
    },
    Plan {
        text: String,
    },
    Decision {
        text: String,
    },
    Blocker {
        text: String,
    },
    Resolution {
        text: String,
    },
    Result {
        text: String,
    },
    Status {
        value: StatusValue,
    },
    Relation {
        kind: RelationKind,
        target: SubjectRef,
    },
    /// §8/ADR-6 — cites the CID it supersedes. Retracting a `Retraction` is
    /// the undo mechanism; no separate `Restore` variant exists.
    Retraction {
        supersedes: Cid,
    },
}

impl ClaimBody {
    pub fn kind(&self) -> ClaimKind {
        match self {
            ClaimBody::Subject { .. } => ClaimKind::Subject,
            ClaimBody::Observation { .. } => ClaimKind::Observation,
            ClaimBody::Plan { .. } => ClaimKind::Plan,
            ClaimBody::Decision { .. } => ClaimKind::Decision,
            ClaimBody::Blocker { .. } => ClaimKind::Blocker,
            ClaimBody::Resolution { .. } => ClaimKind::Resolution,
            ClaimBody::Result { .. } => ClaimKind::Result,
            ClaimBody::Status { .. } => ClaimKind::Status,
            ClaimBody::Relation { .. } => ClaimKind::Relation,
            ClaimBody::Retraction { .. } => ClaimKind::Retraction,
        }
    }
}

/// The hashed content of a claim — everything `docs/SPEC.md` §3 puts inside
/// the CID. Deliberately has no `sig` and no explicit id/CID field: identity
/// is `crate::cid::content_cid(&self)`, computed on demand (§1, "no explicit
/// id field").
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimContent {
    pub author: AuthorId,
    pub workspace: Anchor,
    pub subject: SubjectRef,
    pub body: ClaimBody,
    pub cites: Vec<Cid>,
    pub artifacts: Vec<ArtifactRef>,
}

/// A signed claim: `content` plus the signature over `content`'s CID (§3 —
/// "signature signs the CID, so it's OUT of the hashed bytes").
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Claim {
    pub content: ClaimContent,
    #[serde(with = "serde_bytes")]
    pub sig: Vec<u8>,
}
