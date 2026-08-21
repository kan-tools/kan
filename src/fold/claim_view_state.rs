//! Status reduction over the source-preserving mixed-codec claim view.

use std::collections::{HashMap, HashSet};

use atproto_dasl::Cid;

use crate::{
    claim::{
        v1,
        view::{ClaimAuthor, ClaimBodyRef, ClaimSource, ClaimView},
        ClaimBody, StatusValue,
    },
    relations::{ComputedEdge, ComputedEdgeKind},
};

#[derive(Debug, Clone, PartialEq)]
pub enum StateView {
    Unclassified,
    Settled {
        value: StatusValue,
        claim: Box<ClaimView>,
    },
    Confirmed {
        value: StatusValue,
        by: Vec<ClaimView>,
    },
    Contested {
        resolved: Vec<ClaimView>,
        open: Vec<ClaimView>,
    },
}

impl StateView {
    pub fn live_cids(&self) -> HashSet<Cid> {
        match self {
            Self::Unclassified => HashSet::new(),
            Self::Settled { claim, .. } => [claim.claim_id().clone()].into_iter().collect(),
            Self::Confirmed { by, .. } => by.iter().map(|claim| claim.claim_id().clone()).collect(),
            Self::Contested { open, .. } => {
                open.iter().map(|claim| claim.claim_id().clone()).collect()
            }
        }
    }
}

pub fn classify(class_claims: &[ClaimView], computed_edges: &[ComputedEdge]) -> StateView {
    classify_with(class_claims, |_| computed_edges.to_vec())
}

/// Reduce the latest status position per exact source-author key, obtaining
/// computed ancestry only when the surviving positions actually disagree.
pub fn classify_with<F>(class_claims: &[ClaimView], computed_edges: F) -> StateView
where
    F: FnOnce(&[ClaimView]) -> Vec<ComputedEdge>,
{
    let mut order = Vec::new();
    let mut positions: HashMap<ClaimAuthor, ClaimView> = HashMap::new();
    for claim in class_claims {
        if status_value(claim).is_none() {
            continue;
        }
        let Some(author) = claim.author() else {
            continue;
        };
        if !positions.contains_key(&author) {
            order.push(author.clone());
        }
        positions.insert(author, claim.clone());
    }

    let live: Vec<ClaimView> = order
        .into_iter()
        .map(|author| positions.remove(&author).expect("author was inserted"))
        .collect();
    let Some(first_value) = live.first().and_then(status_value) else {
        return StateView::Unclassified;
    };
    if live.len() == 1 {
        return StateView::Settled {
            value: first_value,
            claim: Box::new(live.into_iter().next().expect("one live position")),
        };
    }
    if live
        .iter()
        .all(|claim| status_value(claim) == Some(first_value))
    {
        return StateView::Confirmed {
            value: first_value,
            by: live,
        };
    }

    let computed_edges = computed_edges(&live);
    let dominated = dominated_cids(&live, &computed_edges);
    let (resolved, open): (Vec<_>, Vec<_>) = live
        .into_iter()
        .partition(|claim| dominated.contains(claim.claim_id()));
    if open.len() == 1 {
        let claim = open.into_iter().next().expect("one open position");
        return StateView::Settled {
            value: status_value(&claim).expect("status position"),
            claim: Box::new(claim),
        };
    }
    if let Some(first_open) = open.first() {
        let value = status_value(first_open).expect("status position");
        if open.iter().all(|claim| status_value(claim) == Some(value)) {
            return StateView::Confirmed { value, by: open };
        }
    }
    StateView::Contested { resolved, open }
}

fn status_value(claim: &ClaimView) -> Option<StatusValue> {
    match claim.body()? {
        ClaimBodyRef::V1(v1::ClaimBody::Status { value }) => Some(match value {
            v1::StatusValue::Open => StatusValue::Open,
            v1::StatusValue::InProgress => StatusValue::InProgress,
            v1::StatusValue::Blocked => StatusValue::Blocked,
            v1::StatusValue::Resolved => StatusValue::Resolved,
            v1::StatusValue::Closed => StatusValue::Closed,
        }),
        ClaimBodyRef::Claim(ClaimBody::Status { value }) => Some(*value),
        _ => None,
    }
}

fn dominated_cids(live: &[ClaimView], computed_edges: &[ComputedEdge]) -> HashSet<Cid> {
    let live_cids: HashSet<&Cid> = live.iter().map(ClaimView::claim_id).collect();
    let mut dominated = HashSet::new();
    for claim in live {
        match claim.source() {
            ClaimSource::V1(source) => {
                for cited in &source.content.cites {
                    if cited != claim.claim_id() && live_cids.contains(cited) {
                        dominated.insert(cited.clone());
                    }
                }
            }
            ClaimSource::Claim(source) => {
                for cited in source.content().cites().as_slice() {
                    if cited.cid() != claim.claim_id() && live_cids.contains(cited.cid()) {
                        dominated.insert(cited.cid().clone());
                    }
                }
            }
            ClaimSource::Unsupported(_) => {}
        }
    }
    for edge in computed_edges {
        if edge.kind == ComputedEdgeKind::Ancestry
            && live_cids.contains(&edge.from)
            && live_cids.contains(&edge.to)
        {
            dominated.insert(edge.from.clone());
        }
    }
    dominated
}
