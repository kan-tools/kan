//! Structured output for the read verbs — kan's machine-readable surface.
//!
//! **Why this exists.** `day` shells out to the `kan` binary rather than
//! linking it (ADR-42), which is the right boundary, and then parsed kan's
//! *prose* to get claims back out — because prose was the only thing on
//! offer. That made every word kan prints a de-facto API with no contract
//! attached, and v0.7's read-surface work (REQ-17, REQ-22) broke it: the
//! changes were improvements by every measure a human cares about, and each
//! was a silent breaking change to the only program consuming them. `day
//! assess docs` began reporting "no docs schema is declared" against a log
//! that plainly declared one.
//!
//! The fix is not to freeze kan's prose. It is to stop asking a consumer to
//! read prose at all. The rendered output stays what it is — for people —
//! and is free to keep improving; anything programmatic reads this instead.
//!
//! **The shapes here are the contract, and they are versioned.** Every
//! payload carries [`SCHEMA_VERSION`], so a consumer can refuse a shape it
//! does not understand rather than silently misparsing it — which is exactly
//! what `day` did for want of a version to check. Field addition follows the
//! same rule as `docs/SPEC.md` §7.1's claim contract: additive only, and
//! `Option` fields are omitted rather than emitted as null, so a consumer
//! pinned to an older shape keeps working.
//!
//! This is deliberately *not* the claim wire format. `transport::git_tree`
//! carries signed, verifiable records; this carries a **rendered view** —
//! the fold's output, already decategorified, with no signatures. Anything
//! that needs to verify a claim reads the log or a published record, not
//! this.

use std::collections::BTreeMap;

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::{
    claim::v1::{Claim, ClaimBody, SubjectRef},
    fold::{state::StateView, FoldedView, SubjectView},
};

/// Bumped only for a change a consumer must react to. Additive fields do not
/// bump it — that is the point of the additive-only rule.
///
/// # The contract, for a consumer pinning to it
///
/// Every payload carries `v`. Check it, and refuse a value you do not
/// understand rather than parsing hopefully — that refusal is the whole
/// reason this field exists.
///
/// Within one version:
///
/// - **Field names are frozen.** A name present in this version will be
///   present, spelled the same, in every later build reporting the same
///   `v`. `tests/json_contract.rs` pins them; a rename or removal fails
///   there, which is the intended way to discover you needed a bump.
/// - **New fields may appear at any time.** A consumer must ignore names it
///   does not know rather than treating them as an error — otherwise kan
///   cannot add anything without breaking you, and the additive rule buys
///   nobody anything.
/// - **`Option` fields are omitted, never `null`.** Absence is the encoding
///   of absence.
/// - **An unrecognized claim kind still serializes**, as `kind: "Unknown"`
///   with no `text`. It is a claim your build cannot interpret, not a
///   parse failure and not a claim that does not exist — dropping it would
///   make a newer actor's claims vanish from an older actor's view of a
///   shared tree (SPEC §7.1, ADR-44).
/// - **A count of zero is emitted, not omitted** (`excluded_by_trust`).
///   "Nothing was excluded" and "this kan is too old to tell you" must not
///   look alike.
///
/// What is *not* promised: the rendered (non-`--json`) output, which is for
/// people and free to keep improving. Anything programmatic reads this.
pub const SCHEMA_VERSION: u32 = 1;

/// One claim, flattened for a reader that is not going to verify it.
#[derive(Debug, Serialize)]
pub struct ClaimJson {
    pub cid: String,
    /// `Observation`, `Decision`, `Status`, … — the `ClaimKind`, as a stable
    /// string rather than a Rust `Debug` rendering.
    pub kind: String,
    /// The subject this claim was filed under. Distinct from the enclosing
    /// view's subject once a `SameAs` merge is in play, which is precisely
    /// the distinction the prose renderer used to lose.
    pub subject: String,
    pub author: String,
    /// Signed-record codec. Omitted on the unchanged v1-only rendering path;
    /// present once a mixed view is required so consumers can retain source
    /// distinctions instead of guessing them from body fields.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub codec: Option<String>,
    /// Cryptographic scope for current claims. Historical local claims are
    /// mapped into the enclosing view but did not sign this field.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// Microseconds since the Unix epoch, as attested by the author. Absent
    /// on claims written before v0.7.0-beta.1.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recorded_at: Option<u64>,
    /// Narrative text, for the kinds that carry it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    /// Subject title, for `Subject` claims.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// Status value, for `Status` claims.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    /// Relation kind and target, for `Relation` claims.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    /// The claim this one supersedes or rejects, for `Retraction`/`Rejects`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supersedes: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub cites: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub artifacts: Vec<String>,
    /// True when a later status on the same subject has replaced this one.
    /// Only ever set on `Status` claims.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub superseded: bool,
}

/// A body-free pointer to the final live claim in a merge class's stable
/// folded order. `recorded_at` is descriptive author-attested metadata; it
/// does not decide which claim is the head.
#[derive(Debug, Serialize)]
pub struct HeadJson {
    pub cid: String,
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recorded_at: Option<u64>,
}

/// The trust base a view was folded under, carried *in the response*.
///
/// Without this a consumer can only assume kan honoured the frame it asked
/// for; with it, the view states its own frame and the assumption becomes a
/// read (`.design/kan-read-contract.md` REQ-3). `Solo` reports its single
/// author at weight `1.0`, so both variants parse identically.
#[derive(Debug, Serialize)]
pub struct TrustJson {
    /// `"Solo"` or `"PeerContested"`.
    pub base: String,
    pub authors: Vec<TrustAuthorJson>,
    /// Why this base expanded to **no authors**, when it did
    /// (`.design/role-declarations.md` REQ-8).
    ///
    /// An empty `authors` list folds to an empty view, and until v0.12 that
    /// was the whole answer — "you declared nothing", "this workspace's own
    /// identity is unreachable so no declaration can be honoured", and
    /// "declarations exist here but none are yours" all rendered as the same
    /// silence. They send an operator after entirely different problems, and
    /// an agent reading `--json` is exactly the consumer that cannot ask a
    /// follow-up question.
    ///
    /// **Additive and omitted when absent**, so every view that had authors
    /// serializes byte-identically to before — the same rule `docs/SPEC.md`
    /// §7.1 sets for claim fields, applied to the read contract.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub empty_reason: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct TrustAuthorJson {
    pub did: String,
    pub weight: f64,
}

impl TrustJson {
    pub fn new(trust: &crate::fold::TrustBase) -> Self {
        Self::with_empty_reason(trust, None)
    }

    /// `reason` is attached **only when the base named no authors**, so a view
    /// that has a frame never carries an explanation of an emptiness it does
    /// not have. Enforced here rather than trusted to callers.
    pub fn with_empty_reason(trust: &crate::fold::TrustBase, reason: Option<&str>) -> Self {
        let authors: Vec<TrustAuthorJson> = trust
            .authors()
            .into_iter()
            .map(|(author, weight)| TrustAuthorJson {
                did: author.did,
                weight,
            })
            .collect();
        Self {
            base: trust.name().to_string(),
            empty_reason: match authors.is_empty() {
                true => reason.map(str::to_string),
                false => None,
            },
            authors,
        }
    }
}

/// One subject's live claims.
#[derive(Debug, Serialize)]
pub struct ShowJson {
    pub v: u32,
    /// The name asked for.
    pub subject: String,
    /// Every name in this merge class. More than one after a trusted
    /// `SameAs`.
    pub subjects: Vec<String>,
    pub claims: Vec<ClaimJson>,
    /// Set when the class bridges an implausible number of subjects — a
    /// probable erroneous `SameAs` (`docs/SPEC.md` §4.5). Surfaced rather
    /// than silently enumerated.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub flagged_oversized: bool,
    /// Relations other subjects assert *at* this one, structured with
    /// provenance so a consumer can cite and attribute them (#103).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub inbound: Vec<InboundEdgeJson>,
    /// The trust base that produced this view (v0.8, REQ-3).
    pub trust: TrustJson,
    /// Live claims on this subject that the trust base excluded. Zero is
    /// emitted, not skipped: "no exclusions" and "this kan is too old to
    /// say" must not look alike to a consumer.
    pub excluded_by_trust: usize,
    /// Present on the top-level `show` envelope. Omitted only when this
    /// `ShowJson` is nested inside `show --all`, whose outer envelope owns it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub published_read_error_count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub published_read_errors: Option<Vec<PublishedReadErrorJson>>,
}

#[derive(Clone, Debug, Serialize)]
pub struct PublishedReadErrorJson {
    pub path: String,
    pub kind: String,
    pub message: String,
}

impl From<&crate::workspace::PublishedReadError> for PublishedReadErrorJson {
    fn from(error: &crate::workspace::PublishedReadError) -> Self {
        Self {
            path: error.path.clone(),
            kind: error.kind.clone(),
            message: error.message.clone(),
        }
    }
}

/// A relation another subject asserts pointing at this one — structured with
/// its own `cid` and `author` so a consumer can cite, attribute, and follow
/// it, rather than the rendered string the human `show` prints (#103). Mirrors
/// an outbound relation `ClaimJson`, with `source` where outbound has
/// `target`. The rendered `show` output keeps its string form; this is the
/// `--json` envelope only.
#[derive(Debug, Serialize)]
pub struct InboundEdgeJson {
    pub cid: String,
    /// Always `"Relation"`, so the shape matches an outbound entry's `kind`.
    pub kind: String,
    pub relation: String,
    /// The subject asserting the edge — the analogue of outbound's `target`.
    pub source: String,
    pub author: String,
}

impl InboundEdgeJson {
    /// Build from a relation claim pointing at the shown subject. Returns
    /// `None` for a non-`Relation` claim (the caller only ever passes
    /// relations, but the shape is total rather than panicking).
    pub fn from_claim(cid: &atproto_dasl::Cid, claim: &Claim) -> Option<Self> {
        let ClaimBody::Relation { kind, .. } = &claim.content.body else {
            return None;
        };
        Some(Self {
            cid: cid.to_string(),
            kind: "Relation".to_string(),
            relation: format!("{kind:?}"),
            source: subject_name(&claim.content.subject),
            author: claim.content.author.did.clone(),
        })
    }
}

pub fn current_claim_kind_name(body: &crate::claim::ClaimBody) -> String {
    use crate::claim::ClaimBody;
    match body {
        ClaimBody::Subject { .. } => "Subject",
        ClaimBody::Observation { .. } => "Observation",
        ClaimBody::Plan { .. } => "Plan",
        ClaimBody::Decision { .. } => "Decision",
        ClaimBody::Blocker { .. } => "Blocker",
        ClaimBody::Resolution { .. } => "Resolution",
        ClaimBody::Result { .. } => "Result",
        ClaimBody::Status { .. } => "Status",
        ClaimBody::Relation { .. } => "Relation",
        ClaimBody::Retraction { .. } => "Retraction",
        ClaimBody::Rejection { .. } => "Rejection",
        ClaimBody::PublicationIntent { .. } => "PublicationIntent",
        ClaimBody::Lineage { .. } => "Lineage",
        ClaimBody::RoleNaming { .. } => "RoleNaming",
    }
    .to_string()
}

/// One subject's settled state.
#[derive(Debug, Serialize)]
pub struct StatusEntryJson {
    pub subject: String,
    pub subjects: Vec<String>,
    /// `Settled`, `Confirmed`, `Contested`, or `Unclassified`.
    pub state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cid: Option<String>,
    /// Trusted, visible, live claims in this folded merge class.
    pub claim_count: usize,
    /// Counts by the same stable kind names [`ClaimJson`] emits.
    pub kind_counts: BTreeMap<String, usize>,
    /// The final live claim in the fold's deterministic order.
    pub head: HeadJson,
    /// Domain-separated digest of the ordered visible claim CIDs.
    pub revision: String,
    /// Live claims on this subject the trust base excluded.
    pub excluded_by_trust: usize,
    /// `unpublished` | `published` | `stale` — whether this subject would
    /// survive losing `.kan/` (`.design/durability-log-recovery.md` REQ-5).
    /// Emitted always, not only when there is a gap: a field that appears
    /// only on bad news cannot be distinguished from an older kan that does
    /// not report it at all.
    pub durability: String,
}

#[derive(Debug, Serialize)]
pub struct StatusJson {
    pub v: u32,
    /// Domain-separated digest of the visible classes and trust frame.
    pub revision: String,
    pub subjects: Vec<StatusEntryJson>,
    pub trust: TrustJson,
    /// Total live claims excluded by the trust base across the whole log —
    /// including on subjects that are absent from `subjects` entirely
    /// because every claim naming them was excluded. Without this a
    /// wholly-filtered subject is indistinguishable from one that was never
    /// written.
    pub excluded_by_trust: usize,
    pub published_read_error_count: usize,
    pub published_read_errors: Vec<PublishedReadErrorJson>,
}

#[derive(Debug, Serialize)]
pub struct IssuesJson {
    pub v: u32,
    pub subjects: Vec<StatusEntryJson>,
    pub trust: TrustJson,
    pub excluded_by_trust: usize,
    pub published_read_error_count: usize,
    pub published_read_errors: Vec<PublishedReadErrorJson>,
}

/// A budgeted context assembly, including what it left out.
#[derive(Debug, Serialize)]
pub struct ContextJson {
    pub v: u32,
    pub claims: Vec<ClaimJson>,
    pub tokens: usize,
    pub budget: usize,
    /// How many claims did not fit. A budgeted view that cannot say what it
    /// withheld is indistinguishable from a complete one.
    pub omitted_claims: usize,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub omitted_subjects: Vec<String>,
    pub trust: TrustJson,
    /// Distinct from `omitted_claims`: that is what the *budget* withheld,
    /// this is what the *trust base* never offered. A caller raising
    /// `--budget` recovers the first and never the second.
    pub excluded_by_trust: usize,
    pub published_read_error_count: usize,
    pub published_read_errors: Vec<PublishedReadErrorJson>,
}

/// Every subject's live claims, from one `Workspace::open`.
///
/// Each subject has the ordinary `show` shape except for workspace-wide
/// published-read diagnostics, which appear once on this outer envelope.
///
/// **Why this exists, and why it is a bulk *read* rather than a faster one.**
/// `day` answers a single witness by reading the whole claim graph, which
/// meant one `kan show` per subject: on day's own 40-subject log, `day status`
/// spent 1.99s of its 2.76s inside 41 kan invocations (#123). That cost is
/// almost entirely `Workspace::open` — an empty log costs ~30ms per call and
/// `kan identity did`, which reads no log at all, costs the same. So no
/// optimisation *inside* a read helps: only collapsing 41 process startups
/// into one does.
///
/// Each entry is a full [`ShowJson`], deliberately including its own `trust`
/// even though every entry repeats it. A consumer already parsing `show
/// --json` for one subject parses these unchanged, which is worth far more
/// than the few hundred bytes of repetition — the ask (`.design/
/// kan-read-contract.md` REQ-5) was explicitly to reduce the invocation
/// *count*, not to shrink the payload.
#[derive(Debug, Serialize)]
pub struct ShowAllJson {
    pub v: u32,
    /// The trust base every entry was folded under — the same for all of
    /// them, since one fold produced the whole response.
    pub trust: TrustJson,
    /// Live claims excluded by that trust base across the entire log,
    /// including on subjects absent from `subjects` because every claim
    /// naming them was excluded.
    pub excluded_by_trust: usize,
    pub published_read_error_count: usize,
    pub published_read_errors: Vec<PublishedReadErrorJson>,
    pub subjects: Vec<ShowJson>,
}

/// A complete `ShowJson` hydration for selected visible merge classes.
///
/// This is intentionally a separate envelope from [`ShowAllJson`]: ADR-71's
/// complete graph-transfer response stays unchanged, while a selected reader
/// can prove that zero subjects matched and how wide the pre-selection view
/// was without guessing from an absent array entry.
#[derive(Debug, Serialize)]
pub struct ShowSelectedJson {
    pub v: u32,
    pub trust: TrustJson,
    pub excluded_by_trust: usize,
    pub published_read_error_count: usize,
    pub published_read_errors: Vec<PublishedReadErrorJson>,
    /// Folded merge classes before selection, not the number of alias names.
    pub visible_subjects: usize,
    /// Deduplicated folded merge classes after selection.
    pub matched_subjects: usize,
    pub subjects: Vec<ShowJson>,
}

/// This workspace's declared signing identities. The active one is listed
/// separately rather than folded into `roles`, because "who am I writing as"
/// and "who has this workspace declared" are different questions and a
/// consumer picking a role to write as needs both.
#[derive(Debug, Serialize)]
pub struct RolesJson {
    pub v: u32,
    pub active: String,
    pub roles: Vec<RoleJson>,
}

/// **No `key_path` since v0.12** (`.design/role-declarations.md` REQ-4). A
/// declaration binds a name to a DID; where that DID's key happens to sit is
/// local, unverifiable from the claim, and was already fiction for any
/// keychain-rooted workspace, whose primary row named a `.kan/identity` that
/// never existed. A consumer wanting to write as a role sets
/// `KAN_IDENTITY_FILE` to a path it already knows.
#[derive(Debug, Serialize)]
pub struct RoleJson {
    pub name: String,
    pub did: String,
}

/// A `SubjectRef` as a plain name, matching what the read verbs accept back.
pub fn subject_name(subject: &SubjectRef) -> String {
    match subject {
        SubjectRef::Local(rkey) => rkey.to_string(),
        other => format!("{other:?}"),
    }
}

impl ClaimJson {
    pub fn new(cid: &atproto_dasl::Cid, claim: &Claim, superseded: bool) -> Self {
        let body = &claim.content.body;
        let mut out = Self {
            cid: cid.to_string(),
            kind: claim_kind_name(body),
            subject: subject_name(&claim.content.subject),
            author: claim.content.author.did.clone(),
            codec: None,
            scope: None,
            recorded_at: claim.content.recorded_at,
            text: body.text().map(str::to_string),
            title: None,
            status: None,
            relation: None,
            target: None,
            supersedes: None,
            cites: claim.content.cites.iter().map(|c| c.to_string()).collect(),
            artifacts: claim
                .content
                .artifacts
                .iter()
                .map(|a| format!("{a:?}"))
                .collect(),
            superseded,
        };
        match body {
            ClaimBody::Subject { title, .. } => out.title = Some(title.clone()),
            ClaimBody::Status { value } => out.status = Some(format!("{value:?}")),
            ClaimBody::Relation { kind, target } => {
                out.relation = Some(format!("{kind:?}"));
                out.target = Some(subject_name(target));
            }
            ClaimBody::Retraction { supersedes } => out.supersedes = Some(supersedes.to_string()),
            ClaimBody::Rejects { claim } => out.supersedes = Some(claim.to_string()),
            _ => {}
        }
        out
    }

    pub fn from_view(claim: &crate::claim::view::ClaimView, superseded: bool) -> Self {
        use crate::claim::{view::ClaimSource, ClaimBody};

        match claim.source() {
            ClaimSource::V1(source) => {
                let mut out = Self::new(claim.claim_id(), source, superseded);
                out.codec = Some(claim.codec().to_string());
                out
            }
            ClaimSource::Claim(source) => {
                let content = source.content();
                let body = content.body();
                let mut out = Self {
                    cid: claim.claim_id().to_string(),
                    kind: current_claim_kind_name(body),
                    subject: content.subject().as_str().to_string(),
                    author: content.author().principal().to_string(),
                    codec: Some(claim.codec().to_string()),
                    scope: Some(content.scope().to_string()),
                    recorded_at: Some(content.recorded_at().micros()),
                    text: match body {
                        ClaimBody::Observation { text }
                        | ClaimBody::Plan { text }
                        | ClaimBody::Decision { text }
                        | ClaimBody::Blocker { text }
                        | ClaimBody::Resolution { text }
                        | ClaimBody::Result { text } => Some(text.as_str().to_string()),
                        _ => None,
                    },
                    title: None,
                    status: None,
                    relation: None,
                    target: None,
                    supersedes: None,
                    cites: content
                        .cites()
                        .as_slice()
                        .iter()
                        .map(|id| id.cid().to_string())
                        .collect(),
                    artifacts: content
                        .artifacts()
                        .as_slice()
                        .iter()
                        .map(|artifact| format!("{artifact:?}"))
                        .collect(),
                    superseded,
                };
                match body {
                    ClaimBody::Subject { title, .. } => {
                        out.title = Some(title.as_str().to_string())
                    }
                    ClaimBody::Status { value } => out.status = Some(format!("{value:?}")),
                    ClaimBody::Relation { relation, target } => {
                        out.relation = Some(format!("{relation:?}"));
                        out.target = Some(target.subject.as_str().to_string());
                    }
                    ClaimBody::Retraction { claim } | ClaimBody::Rejection { claim } => {
                        out.supersedes = Some(claim.cid().to_string())
                    }
                    _ => {}
                }
                out
            }
            ClaimSource::Unsupported(_) => Self {
                cid: claim.claim_id().to_string(),
                kind: "Unknown".to_string(),
                subject: String::new(),
                author: String::new(),
                codec: Some(claim.codec().to_string()),
                scope: None,
                recorded_at: None,
                text: None,
                title: None,
                status: None,
                relation: None,
                target: None,
                supersedes: None,
                cites: Vec::new(),
                artifacts: Vec::new(),
                superseded,
            },
        }
    }
}

/// One stable spelling for a claim kind across full and compact JSON views.
pub fn claim_kind_name(body: &ClaimBody) -> String {
    format!("{:?}", body.kind())
}

pub fn mixed_subject_name(subject: &crate::claim::view::ClaimSubjectId) -> String {
    use crate::claim::view::ClaimSubjectId;
    match subject {
        ClaimSubjectId::V1Local(path) => path.to_string(),
        ClaimSubjectId::V1Anchor(anchor) => format!("{anchor:?}"),
        ClaimSubjectId::Scoped { path, .. } => path.clone(),
    }
}

fn mixed_state_fields(
    state: &crate::fold::claim_view_state::StateView,
) -> (String, Option<String>, Option<String>) {
    use crate::fold::claim_view_state::StateView;
    match state {
        StateView::Unclassified => ("Unclassified".to_string(), None, None),
        StateView::Settled { value, claim } => (
            "Settled".to_string(),
            Some(format!("{value:?}")),
            Some(claim.claim_id().to_string()),
        ),
        StateView::Confirmed { value, by } => (
            "Confirmed".to_string(),
            Some(format!("{value:?}")),
            by.first().map(|claim| claim.claim_id().to_string()),
        ),
        StateView::Contested { open, .. } => (
            "Contested".to_string(),
            None,
            open.first().map(|claim| claim.claim_id().to_string()),
        ),
    }
}

pub fn status_entry_mixed(
    class: &crate::fold::claim_view::SubjectView,
    state: &crate::fold::claim_view_state::StateView,
    excluded_by_trust: usize,
    durability: crate::actions::Durability,
) -> StatusEntryJson {
    use crate::claim::view::ClaimBodyRef;

    let (state, value, cid) = mixed_state_fields(state);
    let subjects: Vec<String> = class.subjects.iter().map(mixed_subject_name).collect();
    let mut kind_counts = BTreeMap::new();
    for claim in &class.claims {
        let kind = match claim.body() {
            Some(ClaimBodyRef::V1(body)) => claim_kind_name(body),
            Some(ClaimBodyRef::Claim(body)) => current_claim_kind_name(body),
            None => "Unknown".to_string(),
        };
        *kind_counts.entry(kind).or_insert(0) += 1;
    }
    let head = class
        .claims
        .last()
        .expect("folded classes contain at least one live claim");
    let head_kind = match head.body() {
        Some(ClaimBodyRef::V1(body)) => claim_kind_name(body),
        Some(ClaimBodyRef::Claim(body)) => current_claim_kind_name(body),
        None => "Unknown".to_string(),
    };
    let recorded_at = match head.source() {
        crate::claim::view::ClaimSource::V1(claim) => claim.content.recorded_at,
        crate::claim::view::ClaimSource::Claim(claim) => {
            Some(claim.content().recorded_at().micros())
        }
        crate::claim::view::ClaimSource::Unsupported(_) => None,
    };
    StatusEntryJson {
        subject: subjects.first().cloned().unwrap_or_default(),
        subjects,
        state,
        value,
        cid,
        claim_count: class.claims.len(),
        kind_counts,
        head: HeadJson {
            cid: head.claim_id().to_string(),
            kind: head_kind,
            recorded_at,
        },
        revision: mixed_subject_revision(class),
        excluded_by_trust,
        durability: durability.name().to_string(),
    }
}

const SUBJECT_REVISION_DOMAIN: &[u8] = b"kan.status.subject-revision.v1";
const VIEW_REVISION_DOMAIN: &[u8] = b"kan.status.view-revision.v1";

fn hash_bytes(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

fn format_revision(bytes: &[u8]) -> String {
    let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    format!("sha256:{hex}")
}

fn subject_revision_bytes(class: &SubjectView) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hash_bytes(&mut hasher, SUBJECT_REVISION_DOMAIN);
    hasher.update((class.claims.len() as u64).to_be_bytes());
    for (cid, _) in &class.claims {
        hash_bytes(&mut hasher, &cid.to_bytes());
    }
    hasher.finalize().into()
}

fn mixed_subject_revision_bytes(class: &crate::fold::claim_view::SubjectView) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hash_bytes(&mut hasher, SUBJECT_REVISION_DOMAIN);
    hasher.update((class.claims.len() as u64).to_be_bytes());
    for claim in &class.claims {
        hash_bytes(&mut hasher, &claim.claim_id().to_bytes());
    }
    hasher.finalize().into()
}

pub fn mixed_subject_revision(class: &crate::fold::claim_view::SubjectView) -> String {
    format_revision(&mixed_subject_revision_bytes(class))
}

pub fn mixed_view_revision(
    view: &crate::fold::claim_view::FoldedView,
    trust: &crate::claim::view::ClaimTrustBase,
    base: &str,
) -> String {
    let mut hasher = Sha256::new();
    hash_bytes(&mut hasher, VIEW_REVISION_DOMAIN);
    hash_bytes(&mut hasher, base.as_bytes());
    let authors = trust.authors();
    hasher.update((authors.len() as u64).to_be_bytes());
    for (author, weight) in authors {
        hash_bytes(&mut hasher, format!("{author:?}").as_bytes());
        hasher.update(weight.to_bits().to_be_bytes());
    }
    hasher.update((view.classes.len() as u64).to_be_bytes());
    for class in &view.classes {
        let primary = class
            .subjects
            .first()
            .map(mixed_subject_name)
            .unwrap_or_default();
        hash_bytes(&mut hasher, primary.as_bytes());
        let mut aliases: Vec<String> = class
            .subjects
            .iter()
            .skip(1)
            .map(mixed_subject_name)
            .collect();
        aliases.sort();
        hasher.update((aliases.len() as u64).to_be_bytes());
        for alias in aliases {
            hash_bytes(&mut hasher, alias.as_bytes());
        }
        hasher.update(mixed_subject_revision_bytes(class));
    }
    format_revision(&hasher.finalize())
}

/// Revision for one merge class, over visible CID bytes only.
pub fn subject_revision(class: &SubjectView) -> String {
    format_revision(&subject_revision_bytes(class))
}

/// Revision for the whole visible fold under one trust frame.
///
/// Hidden claims and wholly hidden subject names are absent because this
/// walks only the already trust-filtered [`FoldedView`]. The trust base is
/// still part of the preimage so two frames that happen to admit the same
/// claim set do not collide accidentally.
pub fn view_revision(view: &FoldedView, trust: &crate::fold::TrustBase) -> String {
    let mut hasher = Sha256::new();
    hash_bytes(&mut hasher, VIEW_REVISION_DOMAIN);
    hash_bytes(&mut hasher, trust.name().as_bytes());

    let authors = trust.authors();
    hasher.update((authors.len() as u64).to_be_bytes());
    for (author, weight) in authors {
        hash_bytes(&mut hasher, author.did.as_bytes());
        match author.agent {
            Some(agent) => {
                hasher.update([1]);
                hash_bytes(&mut hasher, &agent);
            }
            None => hasher.update([0]),
        }
        hasher.update(weight.to_bits().to_be_bytes());
    }

    hasher.update((view.classes.len() as u64).to_be_bytes());
    for class in &view.classes {
        let primary = class.subjects.first().map(subject_name).unwrap_or_default();
        hash_bytes(&mut hasher, primary.as_bytes());
        let mut aliases: Vec<String> = class.subjects.iter().skip(1).map(subject_name).collect();
        aliases.sort();
        hasher.update((aliases.len() as u64).to_be_bytes());
        for alias in aliases {
            hash_bytes(&mut hasher, alias.as_bytes());
        }
        hasher.update(subject_revision_bytes(class));
    }
    format_revision(&hasher.finalize())
}

/// Classification name and winning value for a merge class.
///
/// The action layer supplies the classification because computed Git edges
/// require a workspace. Reclassifying here with an empty edge set made JSON
/// report `Contested` where the rendered surface, correctly using ancestry,
/// reported `Settled`.
pub fn state_fields(state: &StateView) -> (String, Option<String>, Option<String>) {
    match state {
        StateView::Unclassified => ("Unclassified".to_string(), None, None),
        StateView::Settled { value, claim } => (
            "Settled".to_string(),
            Some(format!("{value:?}")),
            Some(claim.0.to_string()),
        ),
        StateView::Confirmed { value, by } => (
            "Confirmed".to_string(),
            Some(format!("{value:?}")),
            by.first().map(|(c, _)| c.to_string()),
        ),
        StateView::Contested { open, .. } => (
            "Contested".to_string(),
            None,
            open.first().map(|(c, _)| c.to_string()),
        ),
    }
}

pub fn status_entry(
    class: &SubjectView,
    state: &StateView,
    excluded: &ExcludedByTrust,
    durability: crate::actions::Durability,
) -> StatusEntryJson {
    let (state, value, cid) = state_fields(state);
    let subjects: Vec<String> = class.subjects.iter().map(subject_name).collect();
    let mut kind_counts = BTreeMap::new();
    for (_, claim) in &class.claims {
        *kind_counts
            .entry(claim_kind_name(&claim.content.body))
            .or_insert(0) += 1;
    }
    let (head_cid, head_claim) = class
        .claims
        .last()
        .expect("folded classes contain at least one live claim");
    StatusEntryJson {
        subject: subjects.first().cloned().unwrap_or_default(),
        subjects,
        state,
        value,
        cid,
        claim_count: class.claims.len(),
        kind_counts,
        head: HeadJson {
            cid: head_cid.to_string(),
            kind: claim_kind_name(&head_claim.content.body),
            recorded_at: head_claim.content.recorded_at,
        },
        revision: subject_revision(class),
        excluded_by_trust: excluded.for_class(class),
        durability: durability.name().to_string(),
    }
}

/// Every merge class in `view`, in the fold's own stable order.
pub fn all_status(
    view: &FoldedView,
    excluded: &ExcludedByTrust,
    classify: impl Fn(&SubjectView) -> StateView,
    durability: impl Fn(&SubjectView) -> crate::actions::Durability,
) -> Vec<StatusEntryJson> {
    view.classes
        .iter()
        .map(|c| status_entry(c, &classify(c), excluded, durability(c)))
        .collect()
}

/// `fold::excluded_by_trust`'s per-subject counts, with the lookups the read
/// surfaces need. Wrapping the map keeps the merge-class summing in one
/// place: a class can span several `SubjectRef`s after a `SameAs`, and each
/// of those names may have had claims excluded independently.
pub struct ExcludedByTrust(std::collections::HashMap<SubjectRef, usize>);

impl ExcludedByTrust {
    pub fn new(map: std::collections::HashMap<SubjectRef, usize>) -> Self {
        Self(map)
    }

    /// Excluded claims naming exactly this subject.
    pub fn for_subject(&self, subject: &SubjectRef) -> usize {
        self.0.get(subject).copied().unwrap_or(0)
    }

    /// Excluded claims naming any subject in this merge class.
    pub fn for_class(&self, class: &SubjectView) -> usize {
        class.subjects.iter().map(|s| self.for_subject(s)).sum()
    }

    /// Every excluded claim in the log, including those on subjects that no
    /// longer appear in the view at all.
    pub fn total(&self) -> usize {
        self.0.values().sum()
    }
}
