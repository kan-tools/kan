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

use serde::Serialize;

use crate::{
    claim::{Claim, ClaimBody, SubjectRef},
    fold::{state::StateView, FoldedView, SubjectView},
};

/// Bumped only for a change a consumer must react to. Additive fields do not
/// bump it — that is the point of the additive-only rule.
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
}

#[derive(Debug, Serialize)]
pub struct TrustAuthorJson {
    pub did: String,
    pub weight: f64,
}

impl TrustJson {
    pub fn new(trust: &crate::fold::TrustBase) -> Self {
        Self {
            base: trust.name().to_string(),
            authors: trust
                .authors()
                .into_iter()
                .map(|(author, weight)| TrustAuthorJson {
                    did: author.did,
                    weight,
                })
                .collect(),
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
    /// Live claims on this subject the trust base excluded.
    pub excluded_by_trust: usize,
}

#[derive(Debug, Serialize)]
pub struct StatusJson {
    pub v: u32,
    pub subjects: Vec<StatusEntryJson>,
    pub trust: TrustJson,
    /// Total live claims excluded by the trust base across the whole log —
    /// including on subjects that are absent from `subjects` entirely
    /// because every claim naming them was excluded. Without this a
    /// wholly-filtered subject is indistinguishable from one that was never
    /// written.
    pub excluded_by_trust: usize,
}

#[derive(Debug, Serialize)]
pub struct IssuesJson {
    pub v: u32,
    pub subjects: Vec<StatusEntryJson>,
    pub trust: TrustJson,
    pub excluded_by_trust: usize,
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
            kind: format!("{:?}", body.kind()),
            subject: subject_name(&claim.content.subject),
            author: claim.content.author.did.clone(),
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
}

/// Classification name and winning value for a merge class.
pub fn state_of(class: &SubjectView) -> (String, Option<String>, Option<String>) {
    match crate::fold::state::classify(&class.claims, &[]) {
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

pub fn status_entry(class: &SubjectView, excluded: &ExcludedByTrust) -> StatusEntryJson {
    let (state, value, cid) = state_of(class);
    let subjects: Vec<String> = class.subjects.iter().map(subject_name).collect();
    StatusEntryJson {
        subject: subjects.first().cloned().unwrap_or_default(),
        subjects,
        state,
        value,
        cid,
        excluded_by_trust: excluded.for_class(class),
    }
}

/// Every merge class in `view`, in the fold's own stable order.
pub fn all_status(view: &FoldedView, excluded: &ExcludedByTrust) -> Vec<StatusEntryJson> {
    view.classes
        .iter()
        .map(|c| status_entry(c, excluded))
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
