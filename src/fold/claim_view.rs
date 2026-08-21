//! Source-preserving mixed-codec fold primitives.

use std::collections::{HashMap, HashSet, VecDeque};

use atproto_dasl::Cid;

use crate::{
    claim::{
        v1,
        view::{ClaimAuthor, ClaimBodyRef, ClaimSubjectId, ClaimView},
        ClaimBody, RelationKind,
    },
    identity::{scope_inception::ScopeId, CryptographicValidity, ViewTrust},
};

#[derive(Debug, Clone, PartialEq)]
pub struct SubjectView {
    pub subjects: Vec<ClaimSubjectId>,
    pub claims: Vec<ClaimView>,
    pub witnesses: Vec<SameAsWitness>,
    pub flagged_oversized: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SameAsWitness {
    pub claim_cid: Cid,
    pub author: ClaimAuthor,
    pub from: ClaimSubjectId,
    pub to: ClaimSubjectId,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct FoldedView {
    pub classes: Vec<SubjectView>,
    /// Future codecs remain visible even though this fold cannot assign them
    /// a subject or body semantics.
    pub unsupported: Vec<ClaimView>,
}

impl FoldedView {
    pub fn subject(&self, subject: &ClaimSubjectId) -> Option<&SubjectView> {
        self.classes
            .iter()
            .find(|class| class.subjects.contains(subject))
    }
}

impl SubjectView {
    pub fn effective_claims(&self) -> Vec<ClaimView> {
        self.claims
            .iter()
            .filter(|claim| participates(claim))
            .cloned()
            .collect()
    }
}

/// Whether an inspectable claim may exercise scope reach in the fold. V1
/// retains its released compatibility behavior; current claims require an
/// affirmative admission result (or an explicitly scope-free operation).
pub fn participates(claim: &ClaimView) -> bool {
    match claim.source() {
        crate::claim::view::ClaimSource::V1(_) => true,
        crate::claim::view::ClaimSource::Claim(_) => matches!(
            claim.judgments().scope_admission,
            crate::identity::ScopeAdmission::Admitted
                | crate::identity::ScopeAdmission::NotApplicable
        ),
        crate::claim::view::ClaimSource::Unsupported(_) => false,
    }
}

/// Count otherwise-live claims omitted solely by the selected view-trust
/// frame. As in the released fold, retracted and trusted-rejected claims are
/// excluded for their own reasons and are not misreported as trust filtering.
pub fn excluded_by_trust(
    claims: &[ClaimView],
    legacy_scope: Option<ScopeId>,
) -> HashMap<ClaimSubjectId, usize> {
    let retracted = excluded_by_retraction(claims);
    let rejected = excluded_by_rejection(claims, &retracted);
    let mut out = HashMap::new();
    for claim in claims {
        if retracted.contains(claim.claim_id())
            || rejected.contains(claim.claim_id())
            || claim.judgments().cryptographic_validity != CryptographicValidity::Valid
            || !matches!(claim.judgments().view_trust, ViewTrust::Excluded)
        {
            continue;
        }
        if let Some(subject) = claim.subject_id(legacy_scope) {
            *out.entry(subject).or_insert(0) += 1;
        }
    }
    out
}

pub fn fold(mut claims: Vec<ClaimView>, legacy_scope: Option<ScopeId>) -> FoldedView {
    claims.sort_by(|left, right| {
        left.rev().cmp(right.rev()).then_with(|| {
            left.claim_id()
                .to_string()
                .cmp(&right.claim_id().to_string())
        })
    });
    let excluded = excluded_by_retraction(&claims);
    let rejected = excluded_by_rejection(&claims, &excluded);
    let live = |claim: &&ClaimView| {
        !excluded.contains(claim.claim_id())
            && !rejected.contains(claim.claim_id())
            && claim.judgments().cryptographic_validity == CryptographicValidity::Valid
            && !matches!(claim.judgments().view_trust, ViewTrust::Excluded)
    };

    let unsupported = claims
        .iter()
        .filter(|claim| claim.subject_id(legacy_scope).is_none())
        .cloned()
        .collect();
    let live_claims: Vec<&ClaimView> = claims.iter().filter(live).collect();
    let (classes, witnesses) = merge_classes(&live_claims, legacy_scope);
    let mut views = Vec::new();
    for subjects in classes {
        let class_claims: Vec<ClaimView> = live_claims
            .iter()
            .filter(|claim| {
                claim
                    .subject_id(legacy_scope)
                    .is_some_and(|subject| subjects.contains(&subject))
            })
            .map(|claim| (*claim).clone())
            .collect();
        if class_claims.is_empty() {
            continue;
        }
        let class_witnesses = witnesses
            .iter()
            .filter(|witness| subjects.contains(&witness.from) || subjects.contains(&witness.to))
            .cloned()
            .collect();
        views.push(SubjectView {
            flagged_oversized: subjects.len() > super::identity::COMPONENT_SIZE_GUARDRAIL,
            subjects,
            claims: class_claims,
            witnesses: class_witnesses,
        });
    }
    FoldedView {
        classes: views,
        unsupported,
    }
}

fn excluded_by_retraction(claims: &[ClaimView]) -> HashSet<Cid> {
    let authors: HashMap<Cid, ClaimAuthor> = claims
        .iter()
        .filter_map(|claim| {
            claim
                .author()
                .map(|author| (claim.claim_id().clone(), author))
        })
        .collect();
    let mut ordered: Vec<&ClaimView> = claims.iter().collect();
    ordered.sort_by(|left, right| {
        right.rev().cmp(left.rev()).then_with(|| {
            right
                .claim_id()
                .to_string()
                .cmp(&left.claim_id().to_string())
        })
    });
    let mut excluded = HashSet::new();
    let mut targeted_by_effective = HashSet::new();
    for claim in ordered {
        if !participates(claim) {
            continue;
        }
        let Some(target) = retraction_target(claim) else {
            continue;
        };
        let Some(retractor) = claim.author() else {
            continue;
        };
        let Some(target_author) = authors.get(&target) else {
            continue;
        };
        if !may_retract(&retractor, target_author)
            || targeted_by_effective.contains(claim.claim_id())
        {
            continue;
        }
        targeted_by_effective.insert(target.clone());
        excluded.insert(target);
    }
    excluded
}

pub(crate) fn may_retract(retractor: &ClaimAuthor, target: &ClaimAuthor) -> bool {
    match (retractor, target) {
        (ClaimAuthor::V1(left), ClaimAuthor::V1(right)) => left == right,
        (ClaimAuthor::Principal(left), ClaimAuthor::Principal(right)) => left == right,
        (ClaimAuthor::Principal(left), ClaimAuthor::V1(right)) => left == &right.did,
        (ClaimAuthor::V1(_), ClaimAuthor::Principal(_)) => false,
    }
}

fn retraction_target(claim: &ClaimView) -> Option<Cid> {
    match claim.body()? {
        ClaimBodyRef::V1(v1::ClaimBody::Retraction { supersedes }) => Some(supersedes.clone()),
        ClaimBodyRef::Claim(ClaimBody::Retraction { claim }) => Some(claim.cid().clone()),
        _ => None,
    }
}

fn excluded_by_rejection(claims: &[ClaimView], retracted: &HashSet<Cid>) -> HashSet<Cid> {
    claims
        .iter()
        .filter(|claim| !retracted.contains(claim.claim_id()))
        .filter(|claim| participates(claim))
        .filter(|claim| !matches!(claim.judgments().view_trust, ViewTrust::Excluded))
        .filter_map(|claim| match claim.body()? {
            ClaimBodyRef::V1(v1::ClaimBody::Rejects { claim }) => Some(claim.clone()),
            ClaimBodyRef::Claim(ClaimBody::Rejection { claim }) => Some(claim.cid().clone()),
            _ => None,
        })
        .collect()
}

fn merge_classes(
    claims: &[&ClaimView],
    legacy_scope: Option<ScopeId>,
) -> (Vec<Vec<ClaimSubjectId>>, Vec<SameAsWitness>) {
    let mut all_subjects = HashSet::new();
    let mut witnesses = Vec::new();
    for claim in claims {
        let Some(from) = claim.subject_id(legacy_scope) else {
            continue;
        };
        all_subjects.insert(from.clone());
        if !participates(claim) {
            continue;
        }
        let Some(to) = same_as_target(claim, legacy_scope) else {
            continue;
        };
        all_subjects.insert(to.clone());
        if matches!(from, ClaimSubjectId::V1Anchor(_)) || matches!(to, ClaimSubjectId::V1Anchor(_))
        {
            continue;
        }
        let Some(author) = claim.author() else {
            continue;
        };
        witnesses.push(SameAsWitness {
            claim_cid: claim.claim_id().clone(),
            author,
            from,
            to,
        });
    }

    let mut adjacency: HashMap<ClaimSubjectId, Vec<ClaimSubjectId>> = HashMap::new();
    for witness in &witnesses {
        adjacency
            .entry(witness.from.clone())
            .or_default()
            .push(witness.to.clone());
        adjacency
            .entry(witness.to.clone())
            .or_default()
            .push(witness.from.clone());
    }
    let mut subjects: Vec<_> = all_subjects.into_iter().collect();
    subjects.sort_by_key(|subject| format!("{subject:?}"));
    let mut visited = HashSet::new();
    let mut classes = Vec::new();
    for start in subjects {
        if !visited.insert(start.clone()) {
            continue;
        }
        let mut class = vec![start.clone()];
        let mut queue = VecDeque::from([start]);
        while let Some(subject) = queue.pop_front() {
            for neighbor in adjacency.get(&subject).into_iter().flatten() {
                if visited.insert(neighbor.clone()) {
                    class.push(neighbor.clone());
                    queue.push_back(neighbor.clone());
                }
            }
        }
        class.sort_by_key(|subject| format!("{subject:?}"));
        classes.push(class);
    }
    (classes, witnesses)
}

fn same_as_target(claim: &ClaimView, legacy_scope: Option<ScopeId>) -> Option<ClaimSubjectId> {
    match claim.body()? {
        ClaimBodyRef::V1(v1::ClaimBody::Relation {
            kind: v1::RelationKind::SameAs,
            target,
        }) => match target {
            v1::SubjectRef::Local(path) => Some(match legacy_scope {
                Some(scope) => ClaimSubjectId::Scoped {
                    scope,
                    path: path.clone(),
                },
                None => ClaimSubjectId::V1Local(path.clone()),
            }),
            v1::SubjectRef::Anchor(anchor) => Some(ClaimSubjectId::V1Anchor(anchor.clone())),
        },
        ClaimBodyRef::Claim(ClaimBody::Relation {
            relation: RelationKind::SameAs,
            target,
        }) => Some(ClaimSubjectId::Scoped {
            scope: target.scope,
            path: target.subject.as_str().to_string(),
        }),
        _ => None,
    }
}
