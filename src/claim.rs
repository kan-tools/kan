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

/// `schemars::JsonSchema` derived directly here (matching `StatusValue`'s
/// own comment/rationale just below) since `mcp::NarrativeParams`/
/// `ResolveParams`/`BlockParams` use this type directly for their `kind`
/// field, the MCP mirror of the CLI's `SubjectKindArg`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub enum SubjectKind {
    Issue,
    Idea,
    Question,
}

/// `schemars::JsonSchema` (alongside `Serialize`/`Deserialize`) lets
/// `mcp::MarkParams` use this type directly instead of a duplicate MCP-side
/// enum — unlike `clap::ValueEnum` (kept out of this file per the CLI
/// layer's `StatusValueArg`), `schemars` doesn't conflict with keeping
/// `claim.rs` free of CLI-specific dependencies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub enum StatusValue {
    Open,
    InProgress,
    Blocked,
    Resolved,
    Closed,
}

/// §4.2 — `SameAs` is the only identity-conferring edge. `Rejects` is not a
/// variant here (ADR-29): it isn't a domain-semantic edge between two
/// subjects the way these are — it's `Retraction`'s cross-author-aware
/// sibling, citing a specific claim CID rather than relating two
/// `SubjectRef`s, so it lives in `ClaimBody::Rejects` instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RelationKind {
    SameAs,
    Blocks,
    About,
    ManifestsAt,
    DependsOn,
    Accepts,
    /// Two subjects pull against each other: satisfying one makes the other
    /// harder, without either blocking or depending on the other (#60).
    ///
    /// **Asserted directed, read symmetric.** The claim records who observed
    /// tension between which ordered pair, because the *nature* of a tension
    /// is perspectival — two actors can hold the same pair in tension for
    /// different reasons, and collapsing that at write time throws the
    /// difference away. "Is in tension with" is then a projection over those
    /// directed assertions (`fold::relations::in_tension_with`), which is the
    /// general rule this repo's `telos/raw-data-and-projections` states:
    /// retain the raw attestations, simplify by determined projection.
    ///
    /// Carries no degree and no reason, deliberately. The reason is the
    /// claim it `cites`; the degree, once anything needs one, is derived by
    /// composing over those witnesses under a chosen enriching base, exactly
    /// as `docs/SPEC.md` §4.3 derives identity confidence — never a stored
    /// number, which would assert a fold output as input (#72).
    InTensionWith,
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
    Rejects,
    Publication,
    /// A kind this build does not recognize (ADR-44).
    Unknown,
}

/// ADR-5: `ClaimKind` + `Body` (two fields in `docs/SPEC.md` §1's sketch)
/// merged into one enum, so an invalid kind/body pairing is unrepresentable.
/// `kind()` below is the derived method that replaces the separate field.
///
/// Structural variants (`Subject`, `Status`, `Relation`, `Retraction`) are
/// typed because the fold reads them; narrative variants hold opaque text
/// because the fold only needs to know they exist and what they cite.
#[derive(Debug, Clone, PartialEq, Eq)]
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
    /// §8/ADR-29 — `Retraction`'s cross-author-aware sibling: a local
    /// suppression of another author's claim, honored only by folds whose
    /// `TrustBase` trusts the rejecter (`fold::identity::
    /// excluded_by_rejection`). Structurally mirrors `Retraction`'s
    /// `supersedes: Cid` shape rather than `Relation`'s `SubjectRef` target —
    /// it suppresses one specific claim, not a whole subject. Retracting a
    /// `Rejects` claim (an ordinary claim CID) is its own undo, no special
    /// casing needed.
    Rejects {
        claim: Cid,
    },
    /// Declares that a subject is published to a sharing layer other than
    /// this author's own log (`.design/git-tree-transport.md`).
    ///
    /// Publication is a *decision about* a subject, so it is a claim rather
    /// than local configuration: attributable, retractable, and itself
    /// publishable, so a clone can see who chose to share a subject. A
    /// config file would have been unattributable, unsynced state in a
    /// system where everything else is a signed claim.
    Publication {
        layer: Layer,
    },
    /// A claim kind this build does not recognize (`docs/SPEC.md` §7.1,
    /// ADR-44).
    ///
    /// Preserved rather than rejected or dropped: `raw` holds the body's
    /// canonical DAG-CBOR, so the claim re-encodes byte-for-byte and stays
    /// CID-verifiable and signature-checkable despite being uninterpretable.
    /// It may be counted, cited, and retracted; it carries no status or
    /// relational meaning into the fold.
    ///
    /// Dropping unknown claims instead would make a newer actor's claims
    /// silently vanish from an older actor's view of a shared tree — the
    /// exact divergence §10's sharing layers exist to avoid.
    Unknown {
        kind: String,
        raw: Vec<u8>,
    },
}

/// Mirrors every *known* [`ClaimBody`] variant, and exists only to carry the
/// derived serde impls.
///
/// `ClaimBody` cannot derive them itself, because the derived
/// `Deserialize` for an externally-tagged enum rejects unknown variants —
/// which is the behavior ADR-44 replaces. The hand-written impls below
/// delegate here for known variants, so their encoding is byte-identical to
/// what kan has always produced; `body_kinds_all_round_trip` fails if this
/// mirror ever drifts from `ClaimBody`.
#[derive(Serialize, Deserialize)]
enum KnownBody {
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
    Retraction {
        supersedes: Cid,
    },
    Rejects {
        claim: Cid,
    },
    Publication {
        layer: Layer,
    },
}

impl From<KnownBody> for ClaimBody {
    fn from(k: KnownBody) -> Self {
        match k {
            KnownBody::Subject {
                title,
                subject_kind,
            } => ClaimBody::Subject {
                title,
                subject_kind,
            },
            KnownBody::Observation { text } => ClaimBody::Observation { text },
            KnownBody::Plan { text } => ClaimBody::Plan { text },
            KnownBody::Decision { text } => ClaimBody::Decision { text },
            KnownBody::Blocker { text } => ClaimBody::Blocker { text },
            KnownBody::Resolution { text } => ClaimBody::Resolution { text },
            KnownBody::Result { text } => ClaimBody::Result { text },
            KnownBody::Status { value } => ClaimBody::Status { value },
            KnownBody::Relation { kind, target } => ClaimBody::Relation { kind, target },
            KnownBody::Retraction { supersedes } => ClaimBody::Retraction { supersedes },
            KnownBody::Rejects { claim } => ClaimBody::Rejects { claim },
            KnownBody::Publication { layer } => ClaimBody::Publication { layer },
        }
    }
}

impl ClaimBody {
    /// `None` for [`ClaimBody::Unknown`], which by definition has no known
    /// representation.
    fn as_known(&self) -> Option<KnownBody> {
        Some(match self.clone() {
            ClaimBody::Subject {
                title,
                subject_kind,
            } => KnownBody::Subject {
                title,
                subject_kind,
            },
            ClaimBody::Observation { text } => KnownBody::Observation { text },
            ClaimBody::Plan { text } => KnownBody::Plan { text },
            ClaimBody::Decision { text } => KnownBody::Decision { text },
            ClaimBody::Blocker { text } => KnownBody::Blocker { text },
            ClaimBody::Resolution { text } => KnownBody::Resolution { text },
            ClaimBody::Result { text } => KnownBody::Result { text },
            ClaimBody::Status { value } => KnownBody::Status { value },
            ClaimBody::Relation { kind, target } => KnownBody::Relation { kind, target },
            ClaimBody::Retraction { supersedes } => KnownBody::Retraction { supersedes },
            ClaimBody::Rejects { claim } => KnownBody::Rejects { claim },
            ClaimBody::Publication { layer } => KnownBody::Publication { layer },
            ClaimBody::Unknown { .. } => return None,
        })
    }
}

impl Serialize for ClaimBody {
    /// Known variants delegate to [`KnownBody`]'s derived impl, so their
    /// bytes are exactly what kan has always written. An `Unknown` re-emits
    /// the DAG-CBOR it was decoded from, which is what keeps its CID valid.
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            ClaimBody::Unknown { kind, raw } => {
                use serde::ser::SerializeMap;
                let value: atproto_dasl::Ipld = atproto_dasl::from_reader(&raw[..])
                    .map_err(|e| serde::ser::Error::custom(format!("unknown body: {e}")))?;
                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry(kind, &value)?;
                map.end()
            }
            known => known
                .as_known()
                .expect("only Unknown has no known form")
                .serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for ClaimBody {
    /// Decodes through [`atproto_dasl::Ipld`] so an unrecognized variant can
    /// be captured rather than rejected. `Ipld` round-trips DAG-CBOR
    /// byte-for-byte, which is what makes an `Unknown` claim verifiable.
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::Error as _;
        let value = atproto_dasl::Ipld::deserialize(deserializer)?;

        let atproto_dasl::Ipld::Map(entries) = &value else {
            return Err(D::Error::custom("claim body is not a single-key map"));
        };
        let Some((kind, body)) = entries.iter().next().filter(|_| entries.len() == 1) else {
            return Err(D::Error::custom("claim body is not a single-key map"));
        };

        let whole = atproto_dasl::to_vec(&value).map_err(D::Error::custom)?;
        let decoded: Result<KnownBody, _> = atproto_dasl::from_reader(&whole[..]);
        match decoded {
            Ok(known) => Ok(known.into()),
            // Unrecognized kind: keep the body's own bytes so it re-encodes
            // exactly (ADR-44). Anything else makes it unverifiable, which
            // would be worse than an honest hard failure.
            Err(_) => Ok(ClaimBody::Unknown {
                kind: kind.clone(),
                raw: atproto_dasl::to_vec(body).map_err(D::Error::custom)?,
            }),
        }
    }
}

/// Where a claim is shared, beyond its author's own log. A closed enum: a
/// layer kan cannot serialize to is not a layer it can honestly claim to
/// publish to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Layer {
    /// The repo's own committed git tree (`transport::git_tree`).
    GitTree,
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
            ClaimBody::Rejects { .. } => ClaimKind::Rejects,
            ClaimBody::Publication { .. } => ClaimKind::Publication,
            ClaimBody::Unknown { .. } => ClaimKind::Unknown,
        }
    }

    /// The narrative text a body carries, if it carries one.
    ///
    /// Exists for the git-tree wire format, which puts narrative text in a
    /// file's Markdown body rather than in its frontmatter — so that a
    /// human editing the visible prose changes the claim's CID and is
    /// detected, instead of the file quietly disagreeing with the record it
    /// claims to be.
    pub fn text(&self) -> Option<&str> {
        match self {
            ClaimBody::Observation { text }
            | ClaimBody::Plan { text }
            | ClaimBody::Decision { text }
            | ClaimBody::Blocker { text }
            | ClaimBody::Resolution { text }
            | ClaimBody::Result { text } => Some(text),
            _ => None,
        }
    }

    /// Replaces the narrative text, for bodies that have one. The inverse of
    /// [`ClaimBody::text`], used to reassemble a claim whose text was
    /// carried outside its frontmatter.
    pub fn with_text(self, replacement: String) -> Self {
        match self {
            ClaimBody::Observation { .. } => ClaimBody::Observation { text: replacement },
            ClaimBody::Plan { .. } => ClaimBody::Plan { text: replacement },
            ClaimBody::Decision { .. } => ClaimBody::Decision { text: replacement },
            ClaimBody::Blocker { .. } => ClaimBody::Blocker { text: replacement },
            ClaimBody::Resolution { .. } => ClaimBody::Resolution { text: replacement },
            ClaimBody::Result { .. } => ClaimBody::Result { text: replacement },
            other => other,
        }
    }
}

/// The hashed content of a claim — everything `docs/SPEC.md` §3 puts inside
/// the CID. Deliberately has no `sig` and no explicit id/CID field: identity
/// is `crate::cid::content_cid(&self)`, computed on demand (§1, "no explicit
/// id field").
///
/// **These fields are frozen** (`docs/SPEC.md` §7.1, ADR-44). Each is an
/// input to every CID kan has ever computed, so changing a name, order,
/// type, or encoding silently invalidates all of history. New fields may be
/// added *only* as `Option<T>` with `skip_serializing_if`, which is measured
/// to leave existing CIDs byte-identical.
///
/// `deny_unknown_fields` is what makes an out-of-date reader honest. Without
/// it, a reader meeting a record from a newer kan deserializes it, silently
/// drops the field it does not know, recomputes a different CID, and reports
/// the claim as **altered since it was signed** — accusing a legitimate
/// claim of tampering. With it, the same reader says `unknown field`, which
/// is true.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
