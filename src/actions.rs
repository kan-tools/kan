//! The one action layer both surfaces sit on top of (`CLAUDE.md`'s "one
//! surface: CLI + MCP" — `cli` and `mcp` are thin, presentation-only
//! wrappers around exactly these functions; neither surface has logic the
//! other doesn't share).

use std::path::PathBuf;

use atproto_dasl::Cid;

use crate::{
    claim::{
        ArtifactRef, ClaimBody, ClaimContent, ClaimKind, RelationKind, Rkey, Span, StatusValue,
        SubjectKind, SubjectRef,
    },
    context::{self, TiktokenEstimator, TokenEstimator},
    fold::{self, state::StateView, FoldedView, SubjectView},
    relations,
    workspace::Workspace,
};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Workspace(#[from] crate::workspace::Error),
    #[error(transparent)]
    Log(#[from] crate::store::log::Error),
    #[error(transparent)]
    Index(#[from] crate::store::index::Error),
    #[error(transparent)]
    Git(#[from] crate::git::Error),
    #[error("invalid CID {0:?}: {1}")]
    InvalidCid(String, atproto_dasl::DecodeError),
    #[error("no such claim: {0}")]
    UnknownClaim(Cid),
    #[error(
        "you can't retract another author's claim ({0}, authored by someone else) -- use `kan reject` instead"
    )]
    NotYourClaim(Cid),
    #[error("you can't reject your own claim ({0}) -- use `kan retract` instead")]
    CantRejectOwnClaim(Cid),
    #[error("--title and --kind must be given together (ClaimBody::Subject needs both)")]
    TitleKindRequireEachOther,
}

const GENERAL_SUBJECT: &str = "general";

/// What a write verb actually did — enough for both surfaces to render
/// their own confirmation without a second fold pass: the CLI's default is
/// still a bare CID (`{cid}` — see `cli::run`'s `--verbose` handling, which
/// needs the scripting-compatible bare form kept separate from this), but
/// `--verbose` and every MCP write tool render `confirmation()`.
pub struct AppendResult {
    pub cid: Cid,
    pub subject: SubjectRef,
    pub kind: ClaimKind,
}

impl AppendResult {
    pub fn confirmation(&self) -> String {
        format!(
            "recorded {:?} on {:?}  ({})",
            self.kind, self.subject, self.cid
        )
    }
}

/// Two claims from one agent action (`kan resolve`/`kan block`): a narrative
/// claim (`Resolution`/`Blocker`) plus the `Status` claim it's paired with,
/// `cites`-linked to it. An agent never has to think about "narrative vs.
/// structural" — resolving/blocking something *is* asserting its status.
/// `subject` is REQ-7's independent, optional third claim (`--title`/
/// `--kind` writing `ClaimBody::Subject`) — unrelated to the narrative/status
/// pairing itself, just riding along on the same call.
pub struct PairedAppendResult {
    pub narrative: AppendResult,
    pub status: AppendResult,
    pub subject: Option<AppendResult>,
}

impl PairedAppendResult {
    pub fn confirmation(&self) -> String {
        let mut out = format!(
            "{}\n{}",
            self.narrative.confirmation(),
            self.status.confirmation()
        );
        if let Some(subject) = &self.subject {
            out.push('\n');
            out.push_str(&subject.confirmation());
        }
        out
    }
}

/// A narrative claim (`Observation`/`Plan`/`Decision`) plus REQ-7's optional
/// `Subject` claim (`--title`/`--kind`) written alongside it. The bare-CID
/// default (`cli::run`'s scripting-compatible contract) stays the narrative
/// claim's CID regardless of whether `subject` is present, matching
/// `PairedAppendResult`'s own convention.
pub struct NarrativeResult {
    pub narrative: AppendResult,
    pub subject: Option<AppendResult>,
}

impl NarrativeResult {
    pub fn confirmation(&self) -> String {
        match &self.subject {
            Some(subject) => format!(
                "{}\n{}",
                self.narrative.confirmation(),
                subject.confirmation()
            ),
            None => self.narrative.confirmation(),
        }
    }
}

/// REQ-7: `--title`/`--kind` are required together, checked *before* any
/// claim is written (a call site validates with this before its own
/// `append` calls) — `ClaimBody::Subject`'s two fields are both
/// non-optional, so there's no sensible partial write.
fn validate_title_kind(title: &Option<String>, kind: &Option<SubjectKind>) -> Result<(), Error> {
    if title.is_some() != kind.is_some() {
        return Err(Error::TitleKindRequireEachOther);
    }
    Ok(())
}

/// Writes `ClaimBody::Subject { title, subject_kind }` when both are given
/// (validated by `validate_title_kind` at the call site's entry, so by the
/// time this runs the only possibilities are "both" or "neither").
async fn maybe_subject_claim(
    ws: &mut Workspace,
    subject: SubjectRef,
    title: Option<String>,
    kind: Option<SubjectKind>,
) -> Result<Option<AppendResult>, Error> {
    match (title, kind) {
        (Some(title), Some(subject_kind)) => Ok(Some(
            append(
                ws,
                subject,
                ClaimBody::Subject {
                    title,
                    subject_kind,
                },
                vec![],
                None,
            )
            .await?,
        )),
        _ => Ok(None),
    }
}

fn parse_cids(raw: Vec<String>) -> Result<Vec<Cid>, Error> {
    let mut cites = Vec::with_capacity(raw.len());
    for r in raw {
        let cid: Cid = r.parse().map_err(|e| Error::InvalidCid(r.clone(), e))?;
        cites.push(cid);
    }
    Ok(cites)
}

/// `--file <path>[:<start>-<end>]` (REQ-9) — opt-in, on top of the automatic
/// commit anchor `append` always attaches. The trailing `:start-end` is only
/// treated as a line range if it actually parses as one; otherwise the whole
/// string is the path (a colon can legitimately appear in a path).
/// `head_sha` is the same commit `append`'s automatic `ArtifactRef::Commit`
/// uses — a `FileAt`/`LineRangeAt` anchor is "this file, as of that commit,"
/// not a separately-anchored artifact.
fn parse_file_artifact(raw: &str, head_sha: &crate::claim::Sha) -> ArtifactRef {
    if let Some(idx) = raw.rfind(':') {
        let (path, range) = (&raw[..idx], &raw[idx + 1..]);
        if let Some((start, end)) = range.split_once('-') {
            if let (Ok(start), Ok(end)) = (start.parse::<u32>(), end.parse::<u32>()) {
                return ArtifactRef::LineRangeAt(
                    PathBuf::from(path),
                    head_sha.clone(),
                    Span { start, end },
                );
            }
        }
    }
    ArtifactRef::FileAt(PathBuf::from(raw), head_sha.clone())
}

/// Every write verb's shared append path. Always attaches the current `HEAD`
/// commit as `ArtifactRef::Commit` (REQ-8, `docs/SPEC.md` §6.2's "anchor to
/// the tightest git object you can" as a real default, not just a
/// recommendation nobody follows) — zero agent effort, no flag needed.
/// `file`, if given, attaches a more specific `FileAt`/`LineRangeAt`
/// artifact on top (REQ-9).
async fn append(
    ws: &mut Workspace,
    subject: SubjectRef,
    body: ClaimBody,
    cites: Vec<Cid>,
    file: Option<String>,
) -> Result<AppendResult, Error> {
    let kind = body.kind();
    let head = ws.git.head_commit()?;
    let mut artifacts = vec![ArtifactRef::Commit(head.clone())];
    if let Some(raw) = file {
        artifacts.push(parse_file_artifact(&raw, &head));
    }
    let content = ClaimContent {
        author: ws.my_author(),
        workspace: ws.anchor.clone(),
        subject: subject.clone(),
        body,
        cites,
        artifacts,
    };
    let cid = ws.log.append(content, &ws.identity).await?;
    let claims = ws.log.iter_all().await?;
    ws.index.rebuild(&claims)?;
    Ok(AppendResult { cid, subject, kind })
}

#[allow(clippy::too_many_arguments)]
async fn narrative(
    ws: &mut Workspace,
    text: String,
    subject: Option<String>,
    cites: Vec<String>,
    file: Option<String>,
    title: Option<String>,
    kind: Option<SubjectKind>,
    make_body: impl FnOnce(String) -> ClaimBody,
) -> Result<NarrativeResult, Error> {
    validate_title_kind(&title, &kind)?;
    let subject_ref = SubjectRef::Local(Rkey::from(
        subject.unwrap_or_else(|| GENERAL_SUBJECT.to_string()),
    ));
    let cites = parse_cids(cites)?;
    let narrative = append(ws, subject_ref.clone(), make_body(text), cites, file).await?;
    let subject = maybe_subject_claim(ws, subject_ref, title, kind).await?;
    Ok(NarrativeResult { narrative, subject })
}

#[allow(clippy::too_many_arguments)]
pub async fn observe(
    ws: &mut Workspace,
    text: String,
    subject: Option<String>,
    cites: Vec<String>,
    file: Option<String>,
    title: Option<String>,
    kind: Option<SubjectKind>,
) -> Result<NarrativeResult, Error> {
    narrative(ws, text, subject, cites, file, title, kind, |text| {
        ClaimBody::Observation { text }
    })
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn plan(
    ws: &mut Workspace,
    text: String,
    subject: Option<String>,
    cites: Vec<String>,
    file: Option<String>,
    title: Option<String>,
    kind: Option<SubjectKind>,
) -> Result<NarrativeResult, Error> {
    narrative(ws, text, subject, cites, file, title, kind, |text| {
        ClaimBody::Plan { text }
    })
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn decide(
    ws: &mut Workspace,
    text: String,
    subject: Option<String>,
    cites: Vec<String>,
    file: Option<String>,
    title: Option<String>,
    kind: Option<SubjectKind>,
) -> Result<NarrativeResult, Error> {
    narrative(ws, text, subject, cites, file, title, kind, |text| {
        ClaimBody::Decision { text }
    })
    .await
}

/// A directed, situated identity claim (`docs/SPEC.md` §4.2): asserts `a`
/// and `b` are the same subject from this author's perspective. A single
/// `SameAs` is one witness in the identity fold's merge-class computation,
/// not an immediate, unconditional merge — whether it's honored depends on
/// the viewer's `TrustBase`.
pub async fn same(
    ws: &mut Workspace,
    a: &str,
    b: &str,
    cites: Vec<String>,
    file: Option<String>,
) -> Result<AppendResult, Error> {
    let cites = parse_cids(cites)?;
    let body = ClaimBody::Relation {
        kind: RelationKind::SameAs,
        target: SubjectRef::Local(Rkey::from(b)),
    };
    append(ws, SubjectRef::Local(Rkey::from(a)), body, cites, file).await
}

/// A domain-semantic edge between two subjects (`docs/SPEC.md` §6):
/// `ClaimBody::Relation { kind, target: b }` for any of REQ-1's 5
/// non-identity `RelationKind`s. `SameAs` stays `kan same`'s alone (REQ-2) —
/// the CLI/MCP layers are what actually keep it out of reach here (this
/// function itself doesn't re-check `kind`, since every caller already
/// narrows to the 5 non-identity kinds at the argument-parsing boundary).
pub async fn relate(
    ws: &mut Workspace,
    a: &str,
    kind: RelationKind,
    b: &str,
    cites: Vec<String>,
    file: Option<String>,
) -> Result<AppendResult, Error> {
    let cites = parse_cids(cites)?;
    let body = ClaimBody::Relation {
        kind,
        target: SubjectRef::Local(Rkey::from(b)),
    };
    append(ws, SubjectRef::Local(Rkey::from(a)), body, cites, file).await
}

/// Asserts a subject is resolved: writes `ClaimBody::Resolution` (a
/// narrative claim — the fold never needs to reduce or contest it) plus
/// `ClaimBody::Status { value: Resolved }` (the structural, poset-classified
/// kind `fold::state` reduces, `docs/SPEC.md` §7), `cites`-linked to the
/// Resolution. One agent action, two claims, correct provenance — an agent
/// never has to think about "narrative vs. structural." `issues` also
/// treats a live `Resolution` as "done" on its own, independent of this
/// pairing — see its doc.
#[allow(clippy::too_many_arguments)]
pub async fn resolve(
    ws: &mut Workspace,
    subject: &str,
    text: &str,
    cites: Vec<String>,
    file: Option<String>,
    title: Option<String>,
    kind: Option<SubjectKind>,
) -> Result<PairedAppendResult, Error> {
    validate_title_kind(&title, &kind)?;
    let cites = parse_cids(cites)?;
    let subject_ref = SubjectRef::Local(Rkey::from(subject));
    let narrative = append(
        ws,
        subject_ref.clone(),
        ClaimBody::Resolution {
            text: text.to_string(),
        },
        cites,
        file,
    )
    .await?;
    let status = append(
        ws,
        subject_ref.clone(),
        ClaimBody::Status {
            value: StatusValue::Resolved,
        },
        vec![narrative.cid.clone()],
        None,
    )
    .await?;
    let subject = maybe_subject_claim(ws, subject_ref, title, kind).await?;
    Ok(PairedAppendResult {
        narrative,
        status,
        subject,
    })
}

/// Asserts a subject is blocked: writes `ClaimBody::Blocker` plus
/// `ClaimBody::Status { value: Blocked }`, `cites`-linked to the Blocker —
/// same pairing discipline as `resolve`.
pub async fn block(
    ws: &mut Workspace,
    subject: &str,
    text: &str,
    file: Option<String>,
    title: Option<String>,
    kind: Option<SubjectKind>,
) -> Result<PairedAppendResult, Error> {
    validate_title_kind(&title, &kind)?;
    let subject_ref = SubjectRef::Local(Rkey::from(subject));
    let narrative = append(
        ws,
        subject_ref.clone(),
        ClaimBody::Blocker {
            text: text.to_string(),
        },
        vec![],
        file,
    )
    .await?;
    let status = append(
        ws,
        subject_ref.clone(),
        ClaimBody::Status {
            value: StatusValue::Blocked,
        },
        vec![narrative.cid.clone()],
        None,
    )
    .await?;
    let subject = maybe_subject_claim(ws, subject_ref, title, kind).await?;
    Ok(PairedAppendResult {
        narrative,
        status,
        subject,
    })
}

/// Writes a bare `ClaimBody::Status { value }` claim with no paired
/// narrative — the entry point for `Open`/`InProgress`/`Closed`, which have
/// no natural narrative-kind pairing.
pub async fn mark(
    ws: &mut Workspace,
    subject: &str,
    value: StatusValue,
    file: Option<String>,
) -> Result<AppendResult, Error> {
    let subject_ref = SubjectRef::Local(Rkey::from(subject));
    append(ws, subject_ref, ClaimBody::Status { value }, vec![], file).await
}

/// Writes `ClaimBody::Retraction { supersedes: cid }`, filed under the
/// target claim's own subject (matching existing test/library convention).
/// Checks the target's author matches the caller's own `AuthorId` *before*
/// writing — a clear, immediate CLI error instead of silently writing an
/// inert claim that `fold::identity::excluded_by_retraction` will ignore
/// anyway (that fold-level enforcement, ADR-16, stays the source of truth;
/// this is a friendlier write-time echo of it). Works uniformly for
/// "retract a retraction" (ADR-6's undo mechanism) — no special-casing
/// needed, `retract` just takes any CID.
pub async fn retract(
    ws: &mut Workspace,
    cid: &str,
    file: Option<String>,
) -> Result<AppendResult, Error> {
    let target_cid: Cid = cid
        .parse()
        .map_err(|e| Error::InvalidCid(cid.to_string(), e))?;
    let target = ws
        .log
        .get_stored(target_cid.clone())
        .await?
        .ok_or_else(|| Error::UnknownClaim(target_cid.clone()))?;
    if target.claim.content.author != ws.my_author() {
        return Err(Error::NotYourClaim(target_cid));
    }
    let subject = target.claim.content.subject.clone();
    let body = ClaimBody::Retraction {
        supersedes: target_cid,
    };
    append(ws, subject, body, vec![], file).await
}

/// Writes `ClaimBody::Rejects { claim: cid }` — a cross-author suppression
/// (`docs/SPEC.md` §8, ADR-29), honored only by folds whose `TrustBase`
/// trusts the rejecter (`fold::identity::excluded_by_rejection`). Checks the
/// target's author does *not* match the caller's own `AuthorId` before
/// writing — `retract`'s check in reverse: no single call should have two
/// possible fold-time meanings depending on facts the caller may not track
/// (REQ-5), so `reject`ing your own claim is a clear write-time error
/// pointing at `kan retract`, not a silent dispatch to it.
pub async fn reject(
    ws: &mut Workspace,
    cid: &str,
    file: Option<String>,
) -> Result<AppendResult, Error> {
    let target_cid: Cid = cid
        .parse()
        .map_err(|e| Error::InvalidCid(cid.to_string(), e))?;
    let target = ws
        .log
        .get_stored(target_cid.clone())
        .await?
        .ok_or_else(|| Error::UnknownClaim(target_cid.clone()))?;
    if target.claim.content.author == ws.my_author() {
        return Err(Error::CantRejectOwnClaim(target_cid));
    }
    let subject = target.claim.content.subject.clone();
    let body = ClaimBody::Rejects { claim: target_cid };
    append(ws, subject, body, vec![], file).await
}

/// A single subject's live claims, rendered — `fold` + `render` for one
/// subject (`docs/SPEC.md` §9's "decategorify only at render").
pub fn show(ws: &Workspace, subject: &str) -> Result<String, Error> {
    let claims = ws.index.all_stored_claims()?;
    let view = fold::fold(claims, &ws.solo_trust());
    let subject_ref = SubjectRef::Local(Rkey::from(subject));

    let mut out = String::new();
    match view.subject(&subject_ref) {
        None => out.push_str(&format!("{subject}: no claims{}\n", subject_hint(&view))),
        Some(subject_view) => {
            if subject_view.subjects.len() > 1 {
                out.push_str(&format!(
                    "{subject} (merged with {:?}):\n",
                    subject_view.subjects
                ));
                // REQ-19/AC-11: name at least one witness (author +
                // direction), not just the flat merged subject list —
                // `docs/SPEC.md` §4.3's "never silently promote a long weak
                // chain to strict identity" needs the witness itself
                // visible, not just its conclusion.
                for w in &subject_view.witnesses {
                    out.push_str(&format!(
                        "  merged by {:?}: {:?} -> {:?}  ({})\n",
                        w.author, w.from, w.to, w.claim_cid
                    ));
                }
            }
            if subject_view.flagged_oversized {
                out.push_str(
                    "  warning: this merge-class bridges an unusually large number of \
                     subjects — probable erroneous SameAs assertion, review before trusting it\n",
                );
            }
            out.push_str(&format!(
                "{subject} ({} live claim(s)):\n",
                subject_view.claims.len()
            ));
            for (cid, claim) in &subject_view.claims {
                out.push_str(&format!(
                    "  {cid}  {:?}  {:?}\n",
                    claim.content.body.kind(),
                    claim.content.body
                ));
            }
            let related = related_subjects_by_file(&view, subject_view, &ws.git);
            if !related.is_empty() {
                out.push_str(&format!("  related subjects (same file): {related:?}\n"));
            }
        }
    }
    Ok(out)
}

/// REQ-20: subjects sharing a `GitSameFile` edge with `subject_view`, via
/// any of their claims — minimal scope, a read-only surfacing of
/// already-computed data, not a new ranking/scoring mechanism.
/// `relations::compute_default` only sees edges within the claim slice it's
/// given, and a same-file relation is inherently cross-subject, so this
/// runs it over every live claim in `view` (not just `subject_view`'s own),
/// then keeps only edges that cross from `subject_view` into some other
/// class.
fn related_subjects_by_file(
    view: &FoldedView,
    subject_view: &SubjectView,
    git: &crate::git::GitSubstrate,
) -> std::collections::BTreeSet<String> {
    let all_claims: Vec<(Cid, crate::claim::Claim)> = view
        .classes
        .iter()
        .flat_map(|c| c.claims.iter().cloned())
        .collect();
    let edges = relations::compute_default(&all_claims, git);
    let mine: std::collections::HashSet<&Cid> =
        subject_view.claims.iter().map(|(cid, _)| cid).collect();

    let mut related = std::collections::BTreeSet::new();
    for edge in &edges {
        if edge.kind != relations::ComputedEdgeKind::SameFile {
            continue;
        }
        let other = match (mine.contains(&edge.from), mine.contains(&edge.to)) {
            (true, false) => &edge.to,
            (false, true) => &edge.from,
            _ => continue,
        };
        if let Some(owner) = view
            .classes
            .iter()
            .find(|c| c.claims.iter().any(|(cid, _)| cid == other))
        {
            if owner.subjects != subject_view.subjects {
                related.insert(format!("{:?}", owner.subjects));
            }
        }
    }
    related
}

/// One subject's (or every subject's) `Settled | Confirmed | Contested`
/// state, or "most recent live claim" for subjects with no `Status` claims
/// yet (`fold::state`, M4b).
pub fn status(ws: &Workspace, subject: Option<&str>) -> Result<String, Error> {
    let claims = ws.index.all_stored_claims()?;
    let view = fold::fold(claims, &ws.solo_trust());

    let mut out = String::new();
    match subject {
        Some(subject) => {
            let subject_ref = SubjectRef::Local(Rkey::from(subject));
            match view.subject(&subject_ref) {
                None => out.push_str(&format!("{subject}: no claims{}\n", subject_hint(&view))),
                Some(subject_view) => {
                    let state = classify_subject(ws, subject_view);
                    write_state(&mut out, subject, subject_view, state);
                }
            }
        }
        None => {
            if view.classes.is_empty() {
                out.push_str("no subjects yet\n");
            }
            for subject_view in &view.classes {
                let label = format!("{:?}", subject_view.subjects);
                let state = classify_subject(ws, subject_view);
                write_state(&mut out, &label, subject_view, state);
            }
        }
    }
    Ok(out)
}

/// A same-fold-pass "did you mean one of these" hint for a subject lookup
/// that missed — no extra fold, no fuzzy matching, just the subjects that
/// actually exist, so a typo doesn't silently read as "this subject has
/// never been mentioned" when it's actually "you spelled it differently
/// last time."
fn subject_hint(view: &FoldedView) -> String {
    if view.classes.is_empty() {
        return String::new();
    }
    let names: Vec<String> = view
        .classes
        .iter()
        .map(|c| format!("{:?}", c.subjects))
        .collect();
    format!(" (existing subjects: {})", names.join(", "))
}

/// `fold::state::classify` needs the computed `Ancestry`/`SameFile` edges
/// for `subject_view`'s own claims — shared by `status`/`issues` so each
/// subject's edges are computed exactly once per call, not once per
/// caller-and-purpose (`issues` used to call this twice: once to check
/// "is this done," once more to render it).
fn classify_subject(ws: &Workspace, subject_view: &SubjectView) -> StateView {
    let edges = relations::compute_default(&subject_view.claims, &ws.git);
    fold::state::classify(&subject_view.claims, &edges)
}

fn write_state(out: &mut String, label: &str, subject_view: &SubjectView, state: StateView) {
    match state {
        StateView::Unclassified => match subject_view.claims.last() {
            None => out.push_str(&format!("{label}: no claims\n")),
            Some((cid, claim)) => out.push_str(&format!(
                "{label}: {:?} — {:?}  ({cid})\n",
                claim.content.body.kind(),
                claim.content.body
            )),
        },
        StateView::Settled { value, claim } => {
            out.push_str(&format!(
                "{label}: Settled({value:?})  ({})\n",
                claim.as_ref().0
            ));
        }
        StateView::Confirmed { value, by } => {
            let cids: Vec<String> = by.iter().map(|(cid, _)| cid.to_string()).collect();
            out.push_str(&format!("{label}: Confirmed({value:?}, by: {cids:?})\n"));
        }
        StateView::Contested { resolved, open } => {
            let open_desc: Vec<String> = open
                .iter()
                .map(|(cid, c)| format!("{:?}@{cid}", fold::state::value_of(c)))
                .collect();
            let resolved_desc: Vec<String> =
                resolved.iter().map(|(cid, _)| cid.to_string()).collect();
            out.push_str(&format!(
                "{label}: Contested(open: {open_desc:?}, resolved: {resolved_desc:?})\n"
            ));
        }
    }
}

/// The "issue-like view across subjects" (`.design/kan-spine.md` CLI
/// table): every merge-class that's issue-*eligible* and isn't done yet
/// (REQ-8, fixing a real shipped bug: a pure-knowledge subject with only
/// narrative claims — `spine` itself, on this very repo — used to be listed
/// as an open issue purely because it had never been resolved, which is a
/// different thing from ever having been *opened*).
///
/// Eligibility (checked first, before "done" is even considered): a class
/// is only in scope when it has at least one live `Status` claim (any
/// value — presence of the claim kind is the signal, not which value) or
/// its most recent live `Subject` claim declares `SubjectKind::Issue`. A
/// class with neither signal is excluded entirely, not merely marked done —
/// the common case for pure-knowledge subjects that were never meant to be
/// tracked as issues at all.
///
/// "Done" (for an eligible class) means either the state fold settled on
/// `Resolved`/`Closed` (structural `Status` claims), or the class has a
/// live `ClaimBody::Resolution` — the narrative signal `kan resolve`
/// writes, and in practice the only one most subjects will ever have,
/// since v1's CLI has no verb for authoring bare `Status` claims besides
/// `kan mark`. No subject is special-cased here (there's no more built-in
/// "session" bookkeeping subject, `docs/DECISIONS.md`'s boundary-rule ADR) —
/// every subject is judged purely on eligibility + doneness, the same way.
pub fn issues(ws: &Workspace) -> Result<String, Error> {
    let claims = ws.index.all_stored_claims()?;
    let view = fold::fold(claims, &ws.solo_trust());

    let mut out = String::new();
    let mut shown = 0usize;
    for subject_view in &view.classes {
        let has_status_claim = subject_view
            .claims
            .iter()
            .any(|(_, c)| matches!(c.content.body, ClaimBody::Status { .. }));
        let declared_issue =
            subject_view
                .claims
                .iter()
                .rev()
                .find_map(|(_, c)| match &c.content.body {
                    ClaimBody::Subject { subject_kind, .. } => Some(*subject_kind),
                    _ => None,
                })
                == Some(SubjectKind::Issue);
        if !has_status_claim && !declared_issue {
            continue;
        }
        let has_resolution = subject_view
            .claims
            .iter()
            .any(|(_, c)| matches!(c.content.body, ClaimBody::Resolution { .. }));
        let state = classify_subject(ws, subject_view);
        let done = has_resolution
            || matches!(
                state,
                StateView::Settled {
                    value: StatusValue::Resolved | StatusValue::Closed,
                    ..
                }
            );
        if done {
            continue;
        }
        shown += 1;
        let label = format!("{:?}", subject_view.subjects);
        write_state(&mut out, &label, subject_view, state);
    }
    if shown == 0 {
        out.push_str("no open issues\n");
    }
    Ok(out)
}

/// Budgeted context assembly (`crate::context`, REQ-14/AC-7): the
/// maximal-value live claim set that fits under `budget` tokens.
pub fn context(ws: &Workspace, budget: usize) -> Result<String, Error> {
    let claims = ws.index.all_stored_claims()?;
    let view = fold::fold(claims, &ws.solo_trust());
    let estimator = TiktokenEstimator::cl100k();
    let selected = context::assemble(&view, budget, &estimator);

    let mut out = String::new();
    let mut total = 0usize;
    for (cid, claim) in &selected {
        let text = context::render_claim(claim);
        total += estimator.estimate(&text);
        out.push_str(&format!("{cid}  {text}\n"));
    }
    out.push_str(&format!(
        "-- {} claim(s), ~{total}/{budget} tokens --\n",
        selected.len()
    ));
    Ok(out)
}
