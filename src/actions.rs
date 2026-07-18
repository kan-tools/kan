//! The one action layer both surfaces sit on top of (`CLAUDE.md`'s "one
//! surface: CLI + MCP" — `cli` and `mcp` are thin, presentation-only
//! wrappers around exactly these functions; neither surface has logic the
//! other doesn't share).

use atproto_dasl::Cid;

use crate::{
    claim::{ClaimBody, ClaimContent, ClaimKind, RelationKind, Rkey, StatusValue, SubjectRef},
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
    #[error("invalid CID {0:?}: {1}")]
    InvalidCid(String, atproto_dasl::DecodeError),
    #[error("no such claim: {0}")]
    UnknownClaim(Cid),
    #[error("you can't retract another author's claim ({0}, authored by someone else)")]
    NotYourClaim(Cid),
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
pub struct PairedAppendResult {
    pub narrative: AppendResult,
    pub status: AppendResult,
}

impl PairedAppendResult {
    pub fn confirmation(&self) -> String {
        format!(
            "{}\n{}",
            self.narrative.confirmation(),
            self.status.confirmation()
        )
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

async fn append(
    ws: &mut Workspace,
    subject: SubjectRef,
    body: ClaimBody,
    cites: Vec<Cid>,
) -> Result<AppendResult, Error> {
    let kind = body.kind();
    let content = ClaimContent {
        author: ws.my_author(),
        workspace: ws.anchor.clone(),
        subject: subject.clone(),
        body,
        cites,
        artifacts: vec![],
    };
    let cid = ws.log.append(content, &ws.identity).await?;
    let claims = ws.log.iter_all().await?;
    ws.index.rebuild(&claims)?;
    Ok(AppendResult { cid, subject, kind })
}

async fn narrative(
    ws: &mut Workspace,
    text: String,
    subject: Option<String>,
    cites: Vec<String>,
    make_body: impl FnOnce(String) -> ClaimBody,
) -> Result<AppendResult, Error> {
    let subject = SubjectRef::Local(Rkey::from(
        subject.unwrap_or_else(|| GENERAL_SUBJECT.to_string()),
    ));
    let cites = parse_cids(cites)?;
    append(ws, subject, make_body(text), cites).await
}

pub async fn observe(
    ws: &mut Workspace,
    text: String,
    subject: Option<String>,
    cites: Vec<String>,
) -> Result<AppendResult, Error> {
    narrative(ws, text, subject, cites, |text| ClaimBody::Observation {
        text,
    })
    .await
}

pub async fn plan(
    ws: &mut Workspace,
    text: String,
    subject: Option<String>,
    cites: Vec<String>,
) -> Result<AppendResult, Error> {
    narrative(ws, text, subject, cites, |text| ClaimBody::Plan { text }).await
}

pub async fn decide(
    ws: &mut Workspace,
    text: String,
    subject: Option<String>,
    cites: Vec<String>,
) -> Result<AppendResult, Error> {
    narrative(ws, text, subject, cites, |text| ClaimBody::Decision {
        text,
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
) -> Result<AppendResult, Error> {
    let cites = parse_cids(cites)?;
    let body = ClaimBody::Relation {
        kind: RelationKind::SameAs,
        target: SubjectRef::Local(Rkey::from(b)),
    };
    append(ws, SubjectRef::Local(Rkey::from(a)), body, cites).await
}

/// Asserts a subject is resolved: writes `ClaimBody::Resolution` (a
/// narrative claim — the fold never needs to reduce or contest it) plus
/// `ClaimBody::Status { value: Resolved }` (the structural, poset-classified
/// kind `fold::state` reduces, `docs/SPEC.md` §7), `cites`-linked to the
/// Resolution. One agent action, two claims, correct provenance — an agent
/// never has to think about "narrative vs. structural." `issues` also
/// treats a live `Resolution` as "done" on its own, independent of this
/// pairing — see its doc.
pub async fn resolve(
    ws: &mut Workspace,
    subject: &str,
    text: &str,
    cites: Vec<String>,
) -> Result<PairedAppendResult, Error> {
    let cites = parse_cids(cites)?;
    let subject_ref = SubjectRef::Local(Rkey::from(subject));
    let narrative = append(
        ws,
        subject_ref.clone(),
        ClaimBody::Resolution {
            text: text.to_string(),
        },
        cites,
    )
    .await?;
    let status = append(
        ws,
        subject_ref,
        ClaimBody::Status {
            value: StatusValue::Resolved,
        },
        vec![narrative.cid.clone()],
    )
    .await?;
    Ok(PairedAppendResult { narrative, status })
}

/// Asserts a subject is blocked: writes `ClaimBody::Blocker` plus
/// `ClaimBody::Status { value: Blocked }`, `cites`-linked to the Blocker —
/// same pairing discipline as `resolve`.
pub async fn block(
    ws: &mut Workspace,
    subject: &str,
    text: &str,
) -> Result<PairedAppendResult, Error> {
    let subject_ref = SubjectRef::Local(Rkey::from(subject));
    let narrative = append(
        ws,
        subject_ref.clone(),
        ClaimBody::Blocker {
            text: text.to_string(),
        },
        vec![],
    )
    .await?;
    let status = append(
        ws,
        subject_ref,
        ClaimBody::Status {
            value: StatusValue::Blocked,
        },
        vec![narrative.cid.clone()],
    )
    .await?;
    Ok(PairedAppendResult { narrative, status })
}

/// Writes a bare `ClaimBody::Status { value }` claim with no paired
/// narrative — the entry point for `Open`/`InProgress`/`Closed`, which have
/// no natural narrative-kind pairing.
pub async fn mark(
    ws: &mut Workspace,
    subject: &str,
    value: StatusValue,
) -> Result<AppendResult, Error> {
    let subject_ref = SubjectRef::Local(Rkey::from(subject));
    append(ws, subject_ref, ClaimBody::Status { value }, vec![]).await
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
pub async fn retract(ws: &mut Workspace, cid: &str) -> Result<AppendResult, Error> {
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
    append(ws, subject, body, vec![]).await
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
        }
    }
    Ok(out)
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
/// table): every merge-class that isn't done yet. "Done" means either the
/// state fold settled on `Resolved`/`Closed` (structural `Status` claims),
/// or the class has a live `ClaimBody::Resolution` — the narrative signal
/// `kan resolve` writes, and in practice the only one most subjects will
/// ever have, since v1's CLI has no verb for authoring `Status` claims
/// directly. No subject is special-cased here (there's no more built-in
/// "session" bookkeeping subject, `docs/DECISIONS.md`'s boundary-rule ADR) —
/// every subject is judged purely on whether it's done, the same way.
pub fn issues(ws: &Workspace) -> Result<String, Error> {
    let claims = ws.index.all_stored_claims()?;
    let view = fold::fold(claims, &ws.solo_trust());

    let mut out = String::new();
    let mut shown = 0usize;
    for subject_view in &view.classes {
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
