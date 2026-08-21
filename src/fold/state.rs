//! State fold (`docs/SPEC.md` §9 step 2): per merge-class, classify
//! `Status`-kind claims into `Settled | Confirmed | Contested` over the
//! causal poset built from intra-author supersession plus cross-author
//! edges (attested `cites` ⊔ computed `Ancestry` edges from
//! `crate::relations`).
//!
//! Only `Status`-kind claims enter this poset — narrative kinds
//! (`Observation`/`Plan`/…) never conflict, so they stay a flat
//! append-only log at the `fold::fold` stage (see that module's doc
//! comment).

use std::collections::{HashMap, HashSet};

use atproto_dasl::Cid;

use crate::{
    claim::v1::{AuthorId, Claim, ClaimBody, ClaimKind, StatusValue},
    relations::{ComputedEdge, ComputedEdgeKind},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StateView {
    /// No `Status` claims at all in this merge-class yet.
    Unclassified,
    /// Exactly one live position — either only one trusted author ever
    /// asserted a status, or ordering (attested `cites` or computed
    /// `Ancestry`) resolved multiple disagreeing positions down to one
    /// surviving, later claim (§9's "computably-ordered" tier). Boxed:
    /// `Claim` is much larger than the other variants' payloads, and
    /// clippy flags the resulting enum-size skew otherwise.
    Settled {
        value: StatusValue,
        claim: Box<(Cid, Claim)>,
    },
    /// Every live position agrees, regardless of ordering.
    Confirmed {
        value: StatusValue,
        by: Vec<(Cid, Claim)>,
    },
    /// Two or more live positions disagree and nothing orders them — §9's
    /// default "contest" tier. `resolved` holds positions a poset edge
    /// dominated (kept, for legibility, not silently dropped); `open`
    /// holds the surviving, still-incomparable disagreement.
    Contested {
        resolved: Vec<(Cid, Claim)>,
        open: Vec<(Cid, Claim)>,
    },
}

impl StateView {
    /// CIDs of the status claims this view considers *live* — the surviving
    /// antichain. Anything else is superseded, which is what read surfaces
    /// need in order to stop presenting a replaced status as a peer of the
    /// one that replaced it (`.design/v0.7-milestone.md` REQ-20).
    pub fn live_cids(&self) -> std::collections::HashSet<Cid> {
        match self {
            StateView::Unclassified => Default::default(),
            StateView::Settled { claim, .. } => [claim.0.clone()].into_iter().collect(),
            StateView::Confirmed { by, .. } => by.iter().map(|(c, _)| c.clone()).collect(),
            // `resolved` were dominated by a poset edge and are kept for
            // legibility, not because they still stand — only `open` is live.
            StateView::Contested { open, .. } => open.iter().map(|(c, _)| c.clone()).collect(),
        }
    }
}

pub fn value_of(claim: &Claim) -> StatusValue {
    match &claim.content.body {
        ClaimBody::Status { value } => *value,
        other => unreachable!("state::value_of called on non-Status body {other:?}"),
    }
}

/// Classify with an already-computed edge set. This remains the reference
/// entry point for callers and tests that already have enrichment in hand;
/// production Git-backed reads use [`classify_with`] so unused ancestry is
/// never computed.
pub fn classify(class_claims: &[(Cid, Claim)], computed_edges: &[ComputedEdge]) -> StateView {
    classify_with(class_claims, |_| computed_edges.to_vec())
}

/// Classify while obtaining computed edges only if live positions disagree.
///
/// `class_claims` must already be trust-filtered and chronologically ordered
/// (oldest first), exactly what `fold::fold`'s `SubjectView.claims` provides.
/// The callback receives only the latest live Status position per author and
/// is not invoked for no status, one position, or an all-agreeing set. That
/// call boundary is the structural guarantee behind kan#202: a caller cannot
/// accidentally compute Git ancestry before the fold knows it will consume
/// an `Ancestry` edge.
pub fn classify_with<F>(class_claims: &[(Cid, Claim)], computed_edges: F) -> StateView
where
    F: FnOnce(&[(Cid, Claim)]) -> Vec<ComputedEdge>,
{
    let status_claims = class_claims
        .iter()
        .filter(|(_, claim)| claim.content.body.kind() == ClaimKind::Status);

    // Intra-author supersession is strict (§9): only the latest claim per
    // author is a live position. `class_claims` is already chronological,
    // so a later insert simply overwrites the earlier one; `order`
    // preserves first-seen author order for stable, deterministic output.
    let mut order: Vec<AuthorId> = Vec::new();
    let mut positions: HashMap<AuthorId, (Cid, Claim)> = HashMap::new();
    for (cid, claim) in status_claims {
        let author = claim.content.author.clone();
        if !positions.contains_key(&author) {
            order.push(author.clone());
        }
        positions.insert(author, (cid.clone(), claim.clone()));
    }

    let live: Vec<(Cid, Claim)> = order
        .into_iter()
        .map(|author| positions.remove(&author).expect("author was just inserted"))
        .collect();

    let Some(first_value) = live.first().map(|(_, c)| value_of(c)) else {
        return StateView::Unclassified;
    };

    if live.len() == 1 {
        let entry = live.into_iter().next().unwrap();
        return StateView::Settled {
            value: first_value,
            claim: Box::new(entry),
        };
    }

    if live.iter().all(|(_, c)| value_of(c) == first_value) {
        return StateView::Confirmed {
            value: first_value,
            by: live,
        };
    }

    // Disagreement: dominate positions superseded by an attested `cites`
    // edge or a computed `Ancestry` edge to another live position — the
    // "computably-ordered" tier. What's left is the genuinely contested,
    // incomparable remainder.
    let computed_edges = computed_edges(&live);
    let dominated = dominated_cids(&live, &computed_edges);
    let (resolved, open): (Vec<_>, Vec<_>) = live
        .into_iter()
        .partition(|(cid, _)| dominated.contains(cid));

    if open.len() == 1 {
        let entry = open.into_iter().next().unwrap();
        let value = value_of(&entry.1);
        return StateView::Settled {
            value,
            claim: Box::new(entry),
        };
    }

    // Domination can resolve a disagreement down to 2+ survivors who no
    // longer actually disagree (the dissenting position was the one that
    // got dominated away) -- that's agreement, not a live contest, even
    // though the *original* live set disagreed before ordering was applied.
    if let Some((_, first_open)) = open.first() {
        let open_value = value_of(first_open);
        if open.iter().all(|(_, c)| value_of(c) == open_value) {
            return StateView::Confirmed {
                value: open_value,
                by: open,
            };
        }
    }

    StateView::Contested { resolved, open }
}

/// A live position is dominated if another live position either attests
/// (via `cites`) that it comes after it, or is computed (`Ancestry`) to be
/// git-later. `cites`/git-ancestry are both backward-only DAGs (§8, §6), so
/// this can't cycle in practice.
fn dominated_cids(live: &[(Cid, Claim)], computed_edges: &[ComputedEdge]) -> HashSet<Cid> {
    let live_cids: HashSet<&Cid> = live.iter().map(|(cid, _)| cid).collect();
    let mut dominated = HashSet::new();

    for (cid, claim) in live {
        for cited in &claim.content.cites {
            if cited != cid && live_cids.contains(cited) {
                dominated.insert(cited.clone());
            }
        }
    }
    for edge in computed_edges {
        if edge.kind == ComputedEdgeKind::Ancestry
            && live_cids.contains(&edge.from)
            && live_cids.contains(&edge.to)
        {
            // `from` is git-earlier, `to` is git-later: `from` is dominated.
            dominated.insert(edge.from.clone());
        }
    }
    dominated
}
