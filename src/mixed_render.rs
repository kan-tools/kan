//! Display-boundary adapter for the source-preserving mixed-codec fold.
//!
//! The released v1 renderers remain the fast, byte-stable path. These
//! functions are selected only when a current claim is visible in the
//! projection; once selected, every claim in the class is rendered from its
//! typed source rather than converted into a synthetic v1 claim.

use std::collections::HashMap;

use atproto_dasl::Cid;

use crate::{
    actions::{Durability, Error},
    claim::{
        v1::{Rkey, SubjectRef},
        view::{ClaimBodyRef, ClaimSource, ClaimSubjectId, ClaimView},
        ClaimBody, StatusValue, SubjectKind,
    },
    context::{TiktokenEstimator, TokenEstimator},
    fold::{
        claim_view::{self, FoldedView, SubjectView},
        claim_view_state::{self, StateView},
        TrustBase,
    },
    json,
    workspace::{MixedWorkspaceProjection, Workspace},
};

pub fn is_needed(projection: &MixedWorkspaceProjection) -> bool {
    projection
        .claims()
        .iter()
        .any(|claim| !matches!(claim.source(), ClaimSource::V1(_)))
}

fn subject_id(projection: &MixedWorkspaceProjection, path: &str) -> ClaimSubjectId {
    match projection.legacy_scope() {
        Some(scope) => ClaimSubjectId::Scoped {
            scope,
            path: path.to_string(),
        },
        None => ClaimSubjectId::V1Local(Rkey::from(path)),
    }
}

fn excluded(projection: &MixedWorkspaceProjection) -> HashMap<ClaimSubjectId, usize> {
    claim_view::excluded_by_trust(projection.claims(), projection.legacy_scope())
}

fn excluded_for_class(excluded: &HashMap<ClaimSubjectId, usize>, class: &SubjectView) -> usize {
    class
        .subjects
        .iter()
        .map(|subject| excluded.get(subject).copied().unwrap_or(0))
        .sum()
}

fn excluded_note(count: usize, trust: &TrustBase, empty_reason: Option<&str>) -> String {
    if count == 0 {
        return String::new();
    }
    let mut note = format!(
        "  note: {count} live claim(s) here are excluded by this view's trust base ({}) \
         -- pass --trust <did>[=<weight>] (or --trust me) to widen it\n",
        trust.name()
    );
    if let Some(reason) = empty_reason {
        note.push_str(&format!("  note: the frame is empty because {reason}\n"));
    }
    note
}

fn trust_json(
    projection: &MixedWorkspaceProjection,
    selected: &TrustBase,
    empty_reason: Option<&str>,
) -> json::TrustJson {
    use crate::claim::view::ClaimAuthor;

    let mut authors = std::collections::BTreeMap::<String, f64>::new();
    for (author, weight) in projection.trust().authors() {
        let did = match author {
            ClaimAuthor::V1(author) => author.did,
            ClaimAuthor::Principal(principal) => principal,
        };
        authors
            .entry(did)
            .and_modify(|selected| *selected = f64::max(*selected, weight))
            .or_insert(weight);
    }
    let authors = authors
        .into_iter()
        .map(|(did, weight)| json::TrustAuthorJson { did, weight })
        .collect::<Vec<_>>();
    json::TrustJson {
        base: selected.name().to_string(),
        empty_reason: authors
            .is_empty()
            .then(|| empty_reason.map(str::to_string))
            .flatten(),
        authors,
    }
}

fn render_claim(claim: &ClaimView) -> String {
    match claim.source() {
        ClaimSource::V1(source) => crate::context::render_claim(source),
        ClaimSource::Claim(source) => {
            let content = source.content();
            let detail = match content.body() {
                ClaimBody::Subject {
                    title,
                    subject_kind,
                } => format!("{subject_kind:?} \"{}\"", title.as_str()),
                ClaimBody::Observation { text }
                | ClaimBody::Plan { text }
                | ClaimBody::Decision { text }
                | ClaimBody::Blocker { text }
                | ClaimBody::Resolution { text }
                | ClaimBody::Result { text } => text.as_str().to_string(),
                ClaimBody::Status { value } => format!("{value:?}"),
                ClaimBody::Relation { relation, target } => {
                    format!("{relation:?} {}:{}", target.scope, target.subject.as_str())
                }
                ClaimBody::Retraction { claim } => format!("supersedes {}", claim.cid()),
                ClaimBody::Rejection { claim } => format!("rejects {}", claim.cid()),
                ClaimBody::PublicationIntent { target } => format!("publish to {target:?}"),
                ClaimBody::Lineage {
                    child,
                    relationship,
                } => format!("{relationship:?} {}", child.as_str()),
                ClaimBody::RoleNaming { principal, name } => {
                    format!("declares role `{}`: {}", name.as_str(), principal.as_str())
                }
            };
            format!(
                "[{}] {}: {detail}",
                content.subject().as_str(),
                json::current_claim_kind_name(content.body())
            )
        }
        ClaimSource::Unsupported(source) => format!(
            "unreadable claim using codec `{}` — this build preserves but cannot interpret it",
            source.codec()
        ),
    }
}

fn detail_lines(claim: &ClaimView, indent: &str) -> String {
    let mut out = String::new();
    match claim.source() {
        ClaimSource::V1(source) => {
            if let Some(micros) = source.content.recorded_at {
                out.push_str(&format!("{indent}recorded: {micros}µs since epoch\n"));
            }
            out.push_str(&format!(
                "{indent}author:   {}\n",
                source.content.author.did
            ));
            for cited in &source.content.cites {
                out.push_str(&format!("{indent}cites:    {cited}\n"));
            }
        }
        ClaimSource::Claim(source) => {
            let content = source.content();
            out.push_str(&format!(
                "{indent}recorded: {}µs since epoch\n",
                content.recorded_at().micros()
            ));
            out.push_str(&format!(
                "{indent}author:   {}\n{indent}scope:    {}\n",
                content.author().principal(),
                content.scope()
            ));
            for cited in content.cites().as_slice() {
                out.push_str(&format!("{indent}cites:    {}\n", cited.cid()));
            }
        }
        ClaimSource::Unsupported(_) => {}
    }
    out.push_str(&format!("{indent}codec:    {}\n", claim.codec()));
    let judgments = claim.judgments();
    out.push_str(&format!(
        "{indent}validity: {:?}\n{indent}standing: {:?}\n{indent}admission: {:?}\n{indent}trust:     {:?}\n",
        judgments.cryptographic_validity,
        judgments.identity_state_standing,
        judgments.scope_admission,
        judgments.view_trust,
    ));
    out
}

fn classify(class: &SubjectView) -> StateView {
    // Signed citation edges are codec-independent and handled by the mixed
    // reducer itself. Git-derived ancestry remains a v1-only enrichment; a
    // class that required this adapter therefore cannot safely fabricate it.
    claim_view_state::classify(&class.effective_claims(), &[])
}

fn subject_label(class: &SubjectView) -> String {
    class
        .subjects
        .iter()
        .map(json::mixed_subject_name)
        .collect::<Vec<_>>()
        .join(" = ")
}

fn subject_ref(subject: &ClaimSubjectId) -> Option<SubjectRef> {
    match subject {
        ClaimSubjectId::V1Local(path) => Some(SubjectRef::Local(path.clone())),
        ClaimSubjectId::Scoped { path, .. } => Some(SubjectRef::Local(Rkey::from(path.as_str()))),
        ClaimSubjectId::V1Anchor(anchor) => Some(SubjectRef::Anchor(anchor.clone())),
    }
}

fn durability(ws: &Workspace, class: &SubjectView) -> Durability {
    let subjects: Vec<SubjectRef> = class.subjects.iter().filter_map(subject_ref).collect();
    if !subjects
        .iter()
        .any(|subject| ws.published.is_published(subject))
    {
        return Durability::Unpublished;
    }
    if class.claims.iter().all(|claim| {
        subjects
            .iter()
            .any(|subject| ws.published.contains(subject, claim.claim_id()))
    }) {
        Durability::Published
    } else {
        Durability::Stale
    }
}

fn write_state(
    out: &mut String,
    label: &str,
    class: &SubjectView,
    state: &StateView,
    d: Durability,
) {
    match state {
        StateView::Unclassified => match class.claims.last() {
            Some(claim) => out.push_str(&format!(
                "{label}: {} — {}  ({})  [{}]\n",
                claim
                    .body()
                    .map(|body| match body {
                        ClaimBodyRef::V1(body) => json::claim_kind_name(body),
                        ClaimBodyRef::Claim(body) => json::current_claim_kind_name(body),
                    })
                    .unwrap_or_else(|| "Unknown".to_string()),
                render_claim(claim),
                claim.claim_id(),
                d.name()
            )),
            None => out.push_str(&format!("{label}: no claims\n")),
        },
        StateView::Settled { value, claim } => out.push_str(&format!(
            "{label}: Settled({value:?})  ({})  [{}]\n",
            claim.claim_id(),
            d.name()
        )),
        StateView::Confirmed { value, by } => out.push_str(&format!(
            "{label}: Confirmed({value:?}, by: {:?})  [{}]\n",
            by.iter()
                .map(|claim| claim.claim_id().to_string())
                .collect::<Vec<_>>(),
            d.name()
        )),
        StateView::Contested { resolved, open } => out.push_str(&format!(
            "{label}: Contested(open: {:?}, resolved: {:?})  [{}]\n",
            open.iter()
                .map(|claim| claim.claim_id().to_string())
                .collect::<Vec<_>>(),
            resolved
                .iter()
                .map(|claim| claim.claim_id().to_string())
                .collect::<Vec<_>>(),
            d.name()
        )),
    }
}

fn relation_target(
    claim: &ClaimView,
    legacy_scope: Option<crate::identity::scope_inception::ScopeId>,
) -> Option<ClaimSubjectId> {
    match claim.body()? {
        ClaimBodyRef::V1(crate::claim::v1::ClaimBody::Relation { target, .. }) => match target {
            SubjectRef::Local(path) => Some(match legacy_scope {
                Some(scope) => ClaimSubjectId::Scoped {
                    scope,
                    path: path.clone(),
                },
                None => ClaimSubjectId::V1Local(path.clone()),
            }),
            SubjectRef::Anchor(anchor) => Some(ClaimSubjectId::V1Anchor(anchor.clone())),
        },
        ClaimBodyRef::Claim(ClaimBody::Relation { target, .. }) => Some(ClaimSubjectId::Scoped {
            scope: target.scope,
            path: target.subject.as_str().to_string(),
        }),
        _ => None,
    }
}

fn relation_kind(claim: &ClaimView) -> Option<String> {
    match claim.body()? {
        ClaimBodyRef::V1(crate::claim::v1::ClaimBody::Relation { kind, .. }) => {
            Some(format!("{kind:?}"))
        }
        ClaimBodyRef::Claim(ClaimBody::Relation { relation, .. }) => Some(format!("{relation:?}")),
        _ => None,
    }
}

fn inbound<'a>(
    view: &'a FoldedView,
    targets: &[ClaimSubjectId],
    own: Option<&[ClaimSubjectId]>,
    legacy_scope: Option<crate::identity::scope_inception::ScopeId>,
) -> Vec<&'a ClaimView> {
    let mut claims = Vec::new();
    for class in &view.classes {
        if own == Some(class.subjects.as_slice()) {
            continue;
        }
        for claim in &class.claims {
            if !claim_view::participates(claim) {
                continue;
            }
            if relation_target(claim, legacy_scope).is_some_and(|target| targets.contains(&target))
            {
                claims.push(claim);
            }
        }
    }
    claims
}

pub fn show(
    ws: &Workspace,
    projection: &MixedWorkspaceProjection,
    subject: &str,
    trust: &TrustBase,
    empty_reason: Option<&str>,
) -> Result<String, Error> {
    let view = projection.fold();
    if subject.starts_with("bafy") {
        if let Ok(cid) = subject.parse::<Cid>() {
            if let Some(claim) = projection
                .claims()
                .iter()
                .find(|claim| claim.claim_id() == &cid)
            {
                return Ok(format!(
                    "{cid}  {}\n{}",
                    render_claim(claim),
                    detail_lines(claim, "      ")
                ));
            }
        }
    }
    let wanted = subject_id(projection, subject);
    let excluded = excluded(projection);
    let mut out = String::new();
    match view.subject(&wanted) {
        None => {
            out.push_str(&format!("{subject}: no claims\n"));
            out.push_str(&excluded_note(
                excluded.get(&wanted).copied().unwrap_or(0),
                trust,
                empty_reason,
            ));
        }
        Some(class) => {
            if class.subjects.len() > 1 {
                out.push_str(&format!(
                    "{subject} (merged with {:?}):\n",
                    class
                        .subjects
                        .iter()
                        .map(json::mixed_subject_name)
                        .collect::<Vec<_>>()
                ));
            }
            if class.flagged_oversized {
                out.push_str(
                    "  warning: this merge-class is unusually large; review its SameAs witnesses\n",
                );
            }
            out.push_str(&format!(
                "{subject} ({} live claim(s)):\n",
                class.claims.len()
            ));
            out.push_str(&excluded_note(
                excluded_for_class(&excluded, class),
                trust,
                empty_reason,
            ));
            let live_status = classify(class).live_cids();
            for claim in &class.claims {
                out.push_str(&format!(
                    "  {}  {}\n",
                    claim.claim_id(),
                    render_claim(claim)
                ));
                if !claim_view::participates(claim) {
                    out.push_str(
                        "      (inspectable only — this claim does not participate in fold effects)\n",
                    );
                }
                if matches!(
                    claim.body(),
                    Some(
                        ClaimBodyRef::V1(crate::claim::v1::ClaimBody::Status { .. })
                            | ClaimBodyRef::Claim(ClaimBody::Status { .. })
                    )
                ) && claim_view::participates(claim)
                    && !live_status.contains(claim.claim_id())
                {
                    out.push_str("      (superseded by a later status on this subject)\n");
                }
                out.push_str(&detail_lines(claim, "      "));
            }
            let incoming = inbound(
                &view,
                &class.subjects,
                Some(&class.subjects),
                projection.legacy_scope(),
            );
            if !incoming.is_empty() {
                out.push_str("  edges pointing here:\n");
                for claim in incoming {
                    let source = claim
                        .subject_id(projection.legacy_scope())
                        .map(|id| json::mixed_subject_name(&id))
                        .unwrap_or_else(|| "unknown".to_string());
                    out.push_str(&format!(
                        "    {source} {} this\n",
                        relation_kind(claim).unwrap_or_else(|| "Relation".to_string())
                    ));
                }
            }
        }
    }
    let _ = ws; // retained for parity with the released action boundary
    Ok(out)
}

pub fn status(
    ws: &Workspace,
    projection: &MixedWorkspaceProjection,
    subject: Option<&str>,
    trust: &TrustBase,
    empty_reason: Option<&str>,
) -> String {
    let view = projection.fold();
    let excluded = excluded(projection);
    let mut out = String::new();
    match subject {
        Some(path) => {
            let wanted = subject_id(projection, path);
            match view.subject(&wanted) {
                Some(class) => {
                    write_state(
                        &mut out,
                        path,
                        class,
                        &classify(class),
                        durability(ws, class),
                    );
                    out.push_str(&excluded_note(
                        excluded_for_class(&excluded, class),
                        trust,
                        empty_reason,
                    ));
                }
                None => {
                    out.push_str(&format!("{path}: no claims\n"));
                    out.push_str(&excluded_note(
                        excluded.get(&wanted).copied().unwrap_or(0),
                        trust,
                        empty_reason,
                    ));
                }
            }
        }
        None => {
            if view.classes.is_empty() {
                out.push_str("no subjects yet\n");
            }
            for class in &view.classes {
                write_state(
                    &mut out,
                    &subject_label(class),
                    class,
                    &classify(class),
                    durability(ws, class),
                );
            }
            out.push_str(&excluded_note(excluded.values().sum(), trust, empty_reason));
        }
    }
    out
}

fn is_open_issue(class: &SubjectView, state: &StateView) -> bool {
    let effective = class.effective_claims();
    let has_status = effective.iter().any(|claim| {
        matches!(
            claim.body(),
            Some(
                ClaimBodyRef::V1(crate::claim::v1::ClaimBody::Status { .. })
                    | ClaimBodyRef::Claim(ClaimBody::Status { .. })
            )
        )
    });
    let declared_issue = effective
        .iter()
        .rev()
        .find_map(|claim| match claim.body()? {
            ClaimBodyRef::V1(crate::claim::v1::ClaimBody::Subject { subject_kind, .. }) => {
                Some(*subject_kind == crate::claim::v1::SubjectKind::Issue)
            }
            ClaimBodyRef::Claim(ClaimBody::Subject { subject_kind, .. }) => {
                Some(*subject_kind == SubjectKind::Issue)
            }
            _ => None,
        })
        .unwrap_or(false);
    if !has_status && !declared_issue {
        return false;
    }
    let has_resolution = effective.iter().any(|claim| {
        matches!(
            claim.body(),
            Some(
                ClaimBodyRef::V1(crate::claim::v1::ClaimBody::Resolution { .. })
                    | ClaimBodyRef::Claim(ClaimBody::Resolution { .. })
            )
        )
    });
    let done = has_resolution
        || matches!(
            state,
            StateView::Settled {
                value: StatusValue::Resolved | StatusValue::Closed,
                ..
            }
        );
    !done
}

pub fn issues(
    ws: &Workspace,
    projection: &MixedWorkspaceProjection,
    trust: &TrustBase,
    empty_reason: Option<&str>,
) -> String {
    let view = projection.fold();
    let excluded = excluded(projection);
    let mut out = String::new();
    let mut shown = 0;
    for class in &view.classes {
        let state = classify(class);
        if is_open_issue(class, &state) {
            shown += 1;
            write_state(
                &mut out,
                &subject_label(class),
                class,
                &state,
                durability(ws, class),
            );
        }
    }
    if shown == 0 {
        out.push_str("no open issues\n");
    }
    out.push_str(&excluded_note(excluded.values().sum(), trust, empty_reason));
    out
}

fn inbound_json(
    projection: &MixedWorkspaceProjection,
    view: &FoldedView,
    class: Option<&SubjectView>,
    wanted: &ClaimSubjectId,
) -> Vec<json::InboundEdgeJson> {
    let claims = class.map_or_else(
        || {
            inbound(
                view,
                std::slice::from_ref(wanted),
                None,
                projection.legacy_scope(),
            )
        },
        |class| {
            inbound(
                view,
                &class.subjects,
                Some(&class.subjects),
                projection.legacy_scope(),
            )
        },
    );
    let mut out = claims
        .into_iter()
        .filter_map(|claim| {
            Some(json::InboundEdgeJson {
                cid: claim.claim_id().to_string(),
                kind: "Relation".to_string(),
                relation: relation_kind(claim)?,
                source: claim
                    .subject_id(projection.legacy_scope())
                    .map(|id| json::mixed_subject_name(&id))?,
                author: claim.principal()?.to_string(),
            })
        })
        .collect::<Vec<_>>();
    out.sort_by(|a, b| (&a.source, &a.relation, &a.cid).cmp(&(&b.source, &b.relation, &b.cid)));
    out
}

fn show_entry(
    ws: &Workspace,
    projection: &MixedWorkspaceProjection,
    view: &FoldedView,
    class: &SubjectView,
    excluded: &HashMap<ClaimSubjectId, usize>,
    trust: &TrustBase,
    empty_reason: Option<&str>,
) -> json::ShowJson {
    let state = classify(class);
    let live = state.live_cids();
    let subjects = class
        .subjects
        .iter()
        .map(json::mixed_subject_name)
        .collect::<Vec<_>>();
    let subject = subjects.first().cloned().unwrap_or_default();
    let wanted = class.subjects.first().expect("folded class has a subject");
    let _ = ws;
    json::ShowJson {
        v: json::SCHEMA_VERSION,
        subject,
        subjects,
        claims: class
            .claims
            .iter()
            .map(|claim| {
                let is_status = matches!(
                    claim.body(),
                    Some(
                        ClaimBodyRef::V1(crate::claim::v1::ClaimBody::Status { .. })
                            | ClaimBodyRef::Claim(ClaimBody::Status { .. })
                    )
                );
                json::ClaimJson::from_view(claim, is_status && !live.contains(claim.claim_id()))
            })
            .collect(),
        flagged_oversized: class.flagged_oversized,
        inbound: inbound_json(projection, view, Some(class), wanted),
        trust: trust_json(projection, trust, empty_reason),
        excluded_by_trust: excluded_for_class(excluded, class),
        published_read_error_count: None,
        published_read_errors: None,
    }
}

fn to_json<T: serde::Serialize>(value: &T) -> Result<String, Error> {
    serde_json::to_string_pretty(value)
        .map(|mut value| {
            value.push('\n');
            value
        })
        .map_err(|error| Error::Usage(format!("could not serialize output: {error}")))
}

pub fn show_json(
    ws: &Workspace,
    projection: &MixedWorkspaceProjection,
    subject: &str,
    trust: &TrustBase,
    empty_reason: Option<&str>,
) -> Result<String, Error> {
    let view = projection.fold();
    let excluded = excluded(projection);
    let wanted = subject_id(projection, subject);
    let class = view.subject(&wanted);
    let mut entry = class.map_or_else(
        || json::ShowJson {
            v: json::SCHEMA_VERSION,
            subject: subject.to_string(),
            subjects: vec![subject.to_string()],
            claims: Vec::new(),
            flagged_oversized: false,
            inbound: inbound_json(projection, &view, None, &wanted),
            trust: trust_json(projection, trust, empty_reason),
            excluded_by_trust: excluded.get(&wanted).copied().unwrap_or(0),
            published_read_error_count: None,
            published_read_errors: None,
        },
        |class| show_entry(ws, projection, &view, class, &excluded, trust, empty_reason),
    );
    entry.subject = subject.to_string();
    entry.published_read_error_count = Some(ws.published.read_errors().len());
    entry.published_read_errors = Some(
        ws.published
            .read_errors()
            .iter()
            .map(json::PublishedReadErrorJson::from)
            .collect(),
    );
    to_json(&entry)
}

pub fn show_all_json(
    ws: &Workspace,
    projection: &MixedWorkspaceProjection,
    trust: &TrustBase,
    empty_reason: Option<&str>,
) -> Result<String, Error> {
    let view = projection.fold();
    let excluded = excluded(projection);
    let subjects = view
        .classes
        .iter()
        .map(|class| show_entry(ws, projection, &view, class, &excluded, trust, empty_reason))
        .collect();
    to_json(&json::ShowAllJson {
        v: json::SCHEMA_VERSION,
        trust: trust_json(projection, trust, empty_reason),
        excluded_by_trust: excluded.values().sum(),
        published_read_error_count: ws.published.read_errors().len(),
        published_read_errors: ws
            .published
            .read_errors()
            .iter()
            .map(json::PublishedReadErrorJson::from)
            .collect(),
        subjects,
    })
}

pub fn show_selected_json(
    ws: &Workspace,
    projection: &MixedWorkspaceProjection,
    exact: &[String],
    prefixes: &[String],
    trust: &TrustBase,
    empty_reason: Option<&str>,
) -> Result<String, Error> {
    let view = projection.fold();
    let excluded = excluded(projection);
    let visible_subjects = view.classes.len();
    let selected = view.classes.iter().filter(|class| {
        class
            .subjects
            .iter()
            .map(json::mixed_subject_name)
            .any(|name| {
                exact.iter().any(|wanted| wanted == &name)
                    || prefixes.iter().any(|prefix| name.starts_with(prefix))
            })
    });
    let subjects: Vec<_> = selected
        .map(|class| show_entry(ws, projection, &view, class, &excluded, trust, empty_reason))
        .collect();
    to_json(&json::ShowSelectedJson {
        v: json::SCHEMA_VERSION,
        trust: trust_json(projection, trust, empty_reason),
        excluded_by_trust: excluded.values().sum(),
        published_read_error_count: ws.published.read_errors().len(),
        published_read_errors: ws
            .published
            .read_errors()
            .iter()
            .map(json::PublishedReadErrorJson::from)
            .collect(),
        visible_subjects,
        matched_subjects: subjects.len(),
        subjects,
    })
}

fn status_entry(
    ws: &Workspace,
    class: &SubjectView,
    excluded: &HashMap<ClaimSubjectId, usize>,
) -> json::StatusEntryJson {
    json::status_entry_mixed(
        class,
        &classify(class),
        excluded_for_class(excluded, class),
        durability(ws, class),
    )
}

pub fn status_json(
    ws: &Workspace,
    projection: &MixedWorkspaceProjection,
    subject: Option<&str>,
    trust: &TrustBase,
    empty_reason: Option<&str>,
) -> Result<String, Error> {
    let view = projection.fold();
    let excluded = excluded(projection);
    let subjects = match subject {
        Some(path) => view
            .subject(&subject_id(projection, path))
            .map(|class| vec![status_entry(ws, class, &excluded)])
            .unwrap_or_default(),
        None => view
            .classes
            .iter()
            .map(|class| status_entry(ws, class, &excluded))
            .collect(),
    };
    to_json(&json::StatusJson {
        v: json::SCHEMA_VERSION,
        revision: json::mixed_view_revision(&view, projection.trust(), trust.name()),
        subjects,
        trust: trust_json(projection, trust, empty_reason),
        excluded_by_trust: excluded.values().sum(),
        published_read_error_count: ws.published.read_errors().len(),
        published_read_errors: ws
            .published
            .read_errors()
            .iter()
            .map(json::PublishedReadErrorJson::from)
            .collect(),
    })
}

pub fn issues_json(
    ws: &Workspace,
    projection: &MixedWorkspaceProjection,
    trust: &TrustBase,
    empty_reason: Option<&str>,
) -> Result<String, Error> {
    let view = projection.fold();
    let excluded = excluded(projection);
    let subjects = view
        .classes
        .iter()
        .filter_map(|class| {
            if is_open_issue(class, &classify(class)) {
                Some(status_entry(ws, class, &excluded))
            } else {
                None
            }
        })
        .collect();
    to_json(&json::IssuesJson {
        v: json::SCHEMA_VERSION,
        subjects,
        trust: trust_json(projection, trust, empty_reason),
        excluded_by_trust: excluded.values().sum(),
        published_read_error_count: ws.published.read_errors().len(),
        published_read_errors: ws
            .published
            .read_errors()
            .iter()
            .map(json::PublishedReadErrorJson::from)
            .collect(),
    })
}

fn context_kind_value(claim: &ClaimView) -> i64 {
    match claim.body() {
        Some(ClaimBodyRef::V1(body)) => match body.kind() {
            crate::claim::v1::ClaimKind::Status => 5,
            crate::claim::v1::ClaimKind::Decision
            | crate::claim::v1::ClaimKind::Blocker
            | crate::claim::v1::ClaimKind::Resolution => 4,
            crate::claim::v1::ClaimKind::Plan | crate::claim::v1::ClaimKind::Result => 3,
            crate::claim::v1::ClaimKind::Observation
            | crate::claim::v1::ClaimKind::Subject
            | crate::claim::v1::ClaimKind::Relation
            | crate::claim::v1::ClaimKind::Publication
            | crate::claim::v1::ClaimKind::RoleDeclaration => 2,
            crate::claim::v1::ClaimKind::Retraction | crate::claim::v1::ClaimKind::Rejects => 1,
            crate::claim::v1::ClaimKind::Unknown => 0,
        },
        Some(ClaimBodyRef::Claim(body)) => match body {
            ClaimBody::Status { .. } => 5,
            ClaimBody::Decision { .. }
            | ClaimBody::Blocker { .. }
            | ClaimBody::Resolution { .. } => 4,
            ClaimBody::Plan { .. } | ClaimBody::Result { .. } => 3,
            ClaimBody::Observation { .. }
            | ClaimBody::Subject { .. }
            | ClaimBody::Relation { .. }
            | ClaimBody::PublicationIntent { .. }
            | ClaimBody::Lineage { .. }
            | ClaimBody::RoleNaming { .. } => 2,
            ClaimBody::Retraction { .. } | ClaimBody::Rejection { .. } => 1,
        },
        None => 0,
    }
}

#[derive(Default)]
struct ContextAssembly {
    selected: Vec<ClaimView>,
    omitted_claims: usize,
    omitted_subjects: Vec<String>,
}

fn assemble_context(
    projection: &MixedWorkspaceProjection,
    view: &FoldedView,
    budget: usize,
    estimator: &dyn TokenEstimator,
) -> ContextAssembly {
    let mut queues = view
        .classes
        .iter()
        .map(|class| {
            let mut queue = class
                .claims
                .iter()
                .enumerate()
                .map(|(index, claim)| {
                    let tokens = estimator.estimate(&render_claim(claim));
                    let score = context_kind_value(claim) * 1_000_000 + index as i64;
                    (score, claim.clone(), tokens)
                })
                .collect::<Vec<_>>();
            queue.sort_by_key(|(score, ..)| std::cmp::Reverse(*score));
            queue
        })
        .collect::<Vec<_>>();

    let mut remaining = budget;
    let mut selected = Vec::new();
    loop {
        let mut order = (0..queues.len()).collect::<Vec<_>>();
        order.sort_by_key(|&index| {
            let best = queues[index]
                .iter()
                .find(|(_, _, tokens)| *tokens <= remaining)
                .map(|(score, ..)| *score);
            (std::cmp::Reverse(best), index)
        });
        let mut progressed = false;
        for index in order {
            if let Some(position) = queues[index]
                .iter()
                .position(|(_, _, tokens)| *tokens <= remaining)
            {
                let (_, claim, tokens) = queues[index].remove(position);
                remaining -= tokens;
                selected.push(claim);
                progressed = true;
            }
        }
        if !progressed {
            break;
        }
    }

    let mut omitted_claims = 0;
    let mut omitted_subjects = Vec::new();
    for queue in queues {
        omitted_claims += queue.len();
        for (_, claim, _) in queue {
            if let Some(subject) = claim.subject_id(projection.legacy_scope()) {
                let subject = json::mixed_subject_name(&subject);
                if !omitted_subjects.contains(&subject) {
                    omitted_subjects.push(subject);
                }
            }
        }
    }
    omitted_subjects.sort();
    ContextAssembly {
        selected,
        omitted_claims,
        omitted_subjects,
    }
}

fn superseded_statuses(view: &FoldedView) -> std::collections::HashSet<Cid> {
    let mut superseded = std::collections::HashSet::new();
    for class in &view.classes {
        let live = classify(class).live_cids();
        for claim in &class.claims {
            if matches!(
                claim.body(),
                Some(
                    ClaimBodyRef::V1(crate::claim::v1::ClaimBody::Status { .. })
                        | ClaimBodyRef::Claim(ClaimBody::Status { .. })
                )
            ) && claim_view::participates(claim)
                && !live.contains(claim.claim_id())
            {
                superseded.insert(claim.claim_id().clone());
            }
        }
    }
    superseded
}

pub fn context(
    projection: &MixedWorkspaceProjection,
    budget: usize,
    trust: &TrustBase,
    empty_reason: Option<&str>,
) -> String {
    let view = projection.fold();
    let estimator = TiktokenEstimator::cl100k();
    let assembled = assemble_context(projection, &view, budget, &estimator);
    let superseded = superseded_statuses(&view);
    let mut out = String::new();
    let mut total = 0;
    for claim in &assembled.selected {
        let text = render_claim(claim);
        total += estimator.estimate(&text);
        let mark = if superseded.contains(claim.claim_id()) {
            "  (superseded)"
        } else {
            ""
        };
        out.push_str(&format!("{}  {text}{mark}\n", claim.claim_id()));
    }
    out.push_str(&format!(
        "-- {} claim(s), ~{total}/{budget} tokens --\n",
        assembled.selected.len()
    ));
    if assembled.omitted_claims > 0 {
        out.push_str(&format!(
            "-- {} claim(s) omitted to fit the budget, across {} subject(s): {} --\n",
            assembled.omitted_claims,
            assembled.omitted_subjects.len(),
            assembled.omitted_subjects.join(", ")
        ));
        out.push_str("-- raise --budget to see more --\n");
    }
    let excluded = excluded(projection);
    out.push_str(&excluded_note(excluded.values().sum(), trust, empty_reason));
    out
}

pub fn context_json(
    ws: &Workspace,
    projection: &MixedWorkspaceProjection,
    budget: usize,
    trust: &TrustBase,
    empty_reason: Option<&str>,
) -> Result<String, Error> {
    let view = projection.fold();
    let estimator = TiktokenEstimator::cl100k();
    let assembled = assemble_context(projection, &view, budget, &estimator);
    let superseded = superseded_statuses(&view);
    let mut tokens = 0;
    let claims = assembled
        .selected
        .iter()
        .map(|claim| {
            tokens += estimator.estimate(&render_claim(claim));
            json::ClaimJson::from_view(claim, superseded.contains(claim.claim_id()))
        })
        .collect();
    let excluded = excluded(projection);
    to_json(&json::ContextJson {
        v: json::SCHEMA_VERSION,
        claims,
        tokens,
        budget,
        omitted_claims: assembled.omitted_claims,
        omitted_subjects: assembled.omitted_subjects,
        trust: trust_json(projection, trust, empty_reason),
        excluded_by_trust: excluded.values().sum(),
        published_read_error_count: ws.published.read_errors().len(),
        published_read_errors: ws
            .published
            .read_errors()
            .iter()
            .map(json::PublishedReadErrorJson::from)
            .collect(),
    })
}
