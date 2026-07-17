//! The one action layer both surfaces sit on top of (`CLAUDE.md`'s "one
//! surface: CLI + MCP" — `cli` and `mcp` are thin, presentation-only
//! wrappers around exactly these functions; neither surface has logic the
//! other doesn't share).

use atproto_dasl::Cid;

use crate::{
    claim::{ClaimBody, ClaimContent, RelationKind, Rkey, StatusValue, SubjectRef},
    context::{self, TiktokenEstimator, TokenEstimator},
    fold::{self, state::StateView, SubjectView},
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
}

const GENERAL_SUBJECT: &str = "general";
const SESSION_SUBJECT: &str = "session";

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
) -> Result<Cid, Error> {
    let content = ClaimContent {
        author: ws.my_author(),
        workspace: ws.anchor.clone(),
        subject,
        body,
        cites,
        artifacts: vec![],
    };
    let claim_cid = ws.log.append(content, &ws.identity).await?;
    let claims = ws.log.iter_all().await?;
    ws.index.rebuild(&claims)?;
    Ok(claim_cid)
}

async fn narrative(
    ws: &mut Workspace,
    text: String,
    subject: Option<String>,
    cites: Vec<String>,
    make_body: impl FnOnce(String) -> ClaimBody,
) -> Result<Cid, Error> {
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
) -> Result<Cid, Error> {
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
) -> Result<Cid, Error> {
    narrative(ws, text, subject, cites, |text| ClaimBody::Plan { text }).await
}

pub async fn decide(
    ws: &mut Workspace,
    text: String,
    subject: Option<String>,
    cites: Vec<String>,
) -> Result<Cid, Error> {
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
pub async fn same(ws: &mut Workspace, a: &str, b: &str) -> Result<Cid, Error> {
    let body = ClaimBody::Relation {
        kind: RelationKind::SameAs,
        target: SubjectRef::Local(Rkey::from(b)),
    };
    append(ws, SubjectRef::Local(Rkey::from(a)), body, vec![]).await
}

/// Asserts a subject is resolved (`ClaimBody::Resolution`). Distinct from
/// `ClaimBody::Status { value: Resolved }`: this is a narrative claim (the
/// fold never needs to reduce or contest it), while `Status` is the
/// structural, poset-classified kind `fold::state` reduces (`docs/SPEC.md`
/// §7). `issues` treats a live `Resolution` as "done" too — see its doc.
pub async fn resolve(ws: &mut Workspace, subject: &str, text: &str) -> Result<Cid, Error> {
    let body = ClaimBody::Resolution {
        text: text.to_string(),
    };
    append(ws, SubjectRef::Local(Rkey::from(subject)), body, vec![]).await
}

pub async fn session_start(ws: &mut Workspace) -> Result<Cid, Error> {
    session_record(ws, "session started".to_string()).await
}

pub async fn session_end(ws: &mut Workspace, notes: Option<String>) -> Result<Cid, Error> {
    let text = match notes {
        Some(notes) => format!("session ended: {notes}"),
        None => "session ended".to_string(),
    };
    session_record(ws, text).await
}

async fn session_record(ws: &mut Workspace, text: String) -> Result<Cid, Error> {
    append(
        ws,
        SubjectRef::Local(Rkey::from(SESSION_SUBJECT)),
        ClaimBody::Observation { text },
        vec![],
    )
    .await
}

/// A single subject's live claims, rendered — `fold` + `render` for one
/// subject (`docs/SPEC.md` §9's "decategorify only at render").
pub fn show(ws: &Workspace, subject: &str) -> Result<String, Error> {
    let claims = ws.index.all_stored_claims()?;
    let view = fold::fold(claims, &ws.solo_trust());
    let subject_ref = SubjectRef::Local(Rkey::from(subject));

    let mut out = String::new();
    match view.subject(&subject_ref) {
        None => out.push_str(&format!("{subject}: no claims\n")),
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
                None => out.push_str(&format!("{subject}: no claims\n")),
                Some(subject_view) => write_state(ws, &mut out, subject, subject_view),
            }
        }
        None => {
            if view.classes.is_empty() {
                out.push_str("no subjects yet\n");
            }
            for subject_view in &view.classes {
                let label = format!("{:?}", subject_view.subjects);
                write_state(ws, &mut out, &label, subject_view);
            }
        }
    }
    Ok(out)
}

fn write_state(ws: &Workspace, out: &mut String, label: &str, subject_view: &SubjectView) {
    let edges = relations::compute_default(&subject_view.claims, &ws.git);
    match fold::state::classify(&subject_view.claims, &edges) {
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
/// directly. The bookkeeping "session" subject is never an issue.
pub fn issues(ws: &Workspace) -> Result<String, Error> {
    let claims = ws.index.all_stored_claims()?;
    let view = fold::fold(claims, &ws.solo_trust());
    let session = SubjectRef::Local(Rkey::from(SESSION_SUBJECT));

    let mut out = String::new();
    let mut shown = 0usize;
    for subject_view in &view.classes {
        if subject_view.subjects == [session.clone()] || is_done(ws, subject_view) {
            continue;
        }
        shown += 1;
        let label = format!("{:?}", subject_view.subjects);
        write_state(ws, &mut out, &label, subject_view);
    }
    if shown == 0 {
        out.push_str("no open issues\n");
    }
    Ok(out)
}

fn is_done(ws: &Workspace, subject_view: &SubjectView) -> bool {
    let has_resolution = subject_view
        .claims
        .iter()
        .any(|(_, c)| matches!(c.content.body, ClaimBody::Resolution { .. }));
    if has_resolution {
        return true;
    }
    let edges = relations::compute_default(&subject_view.claims, &ws.git);
    matches!(
        fold::state::classify(&subject_view.claims, &edges),
        StateView::Settled {
            value: StatusValue::Resolved | StatusValue::Closed,
            ..
        }
    )
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
