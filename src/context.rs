//! Budgeted context assembly (`docs/HANDOFF.md` "first build" item 7,
//! `docs/SPEC.md` §11, REQ-14): query the live claim graph under a token
//! budget for the maximal-value claim set an agent's context window can
//! afford.
//!
//! No spec-mandated ranking algorithm exists (deliberately — this is
//! product surface, not a HARD-specified invariant like the fold). v1's
//! choice, documented here rather than left implicit: value a claim by its
//! kind (`Status`/`Decision`/`Blocker`/`Resolution` — the claims that most
//! directly answer "what's true right now" — outrank narrative claims,
//! which outrank `Relation`/`Retraction` bookkeeping), with recency as a
//! same-kind tiebreak. Selection is round-robin across merge-classes rather
//! than one global greedy pass, so one chatty subject can't starve the
//! budget for everything else — an agent's context benefits from breadth
//! across what it's tracking, not exhaustive depth on one thing.

use atproto_dasl::Cid;

use crate::{
    claim::{Claim, ClaimBody, ClaimKind},
    fold::FoldedView,
};

/// A reasonable default when `--budget` is omitted — a small slice of a
/// typical agent context window, not derived from any spec value.
pub const DEFAULT_BUDGET: usize = 4096;

pub trait TokenEstimator {
    fn estimate(&self, text: &str) -> usize;
}

/// `tiktoken-rs`'s cl100k BPE encoding (ADR-9) — not exact for every model
/// kan might feed, but a consistent estimate is sufficient for a soft
/// budget. Uses the crate's singleton so repeated estimates (one per
/// candidate claim) don't each rebuild the BPE tables.
pub struct TiktokenEstimator {
    bpe: &'static tiktoken_rs::CoreBPE,
}

impl TiktokenEstimator {
    pub fn cl100k() -> Self {
        Self {
            bpe: tiktoken_rs::cl100k_base_singleton(),
        }
    }
}

impl TokenEstimator for TiktokenEstimator {
    fn estimate(&self, text: &str) -> usize {
        self.bpe.encode_ordinary(text).len()
    }
}

/// The text an agent would actually see for this claim — what gets token-
/// counted and what `context` output renders, kept as one function so the
/// two never drift apart. Prose, not a `{:?}` Debug dump: extracts each
/// variant's actual content instead of printing Rust's struct/enum syntax,
/// since this is meant to read like something worth putting in an agent's
/// context window, not a debug log line.
pub fn render_claim(claim: &Claim) -> String {
    let subject = format!("{:?}", claim.content.subject);
    let kind = claim.content.body.kind();
    let detail = match &claim.content.body {
        ClaimBody::Subject {
            title,
            subject_kind,
        } => format!("{subject_kind:?} \"{title}\""),
        ClaimBody::Observation { text }
        | ClaimBody::Plan { text }
        | ClaimBody::Decision { text }
        | ClaimBody::Blocker { text }
        | ClaimBody::Resolution { text }
        | ClaimBody::Result { text } => text.clone(),
        ClaimBody::Status { value } => format!("{value:?}"),
        ClaimBody::Relation { kind, target } => format!("{kind:?} {target:?}"),
        ClaimBody::Retraction { supersedes } => format!("supersedes {supersedes}"),
    };
    format!("[{subject}] {kind:?}: {detail}")
}

fn kind_value(kind: ClaimKind) -> i64 {
    match kind {
        ClaimKind::Status => 5,
        ClaimKind::Decision | ClaimKind::Blocker | ClaimKind::Resolution => 4,
        ClaimKind::Plan | ClaimKind::Result => 3,
        ClaimKind::Observation | ClaimKind::Subject | ClaimKind::Relation => 2,
        ClaimKind::Retraction => 1,
    }
}

/// Per merge-class, highest-value-first (recency as a same-kind tiebreak —
/// `class.claims` is already chronological, so a later index means later in
/// time), each tagged with its estimated token cost.
fn scored_queue(
    claims: &[(Cid, Claim)],
    estimator: &dyn TokenEstimator,
) -> Vec<(Cid, Claim, usize)> {
    let mut scored: Vec<(i64, usize, Cid, Claim, usize)> = claims
        .iter()
        .enumerate()
        .map(|(i, (cid, claim))| {
            let tokens = estimator.estimate(&render_claim(claim));
            let score = kind_value(claim.content.body.kind()) * 1_000_000 + i as i64;
            (score, i, cid.clone(), claim.clone(), tokens)
        })
        .collect();
    scored.sort_by_key(|s| std::cmp::Reverse(s.0));
    scored
        .into_iter()
        .map(|(_, _, cid, claim, tokens)| (cid, claim, tokens))
        .collect()
}

/// AC-7: deterministic for a fixed claim set + budget, and the returned
/// set's total estimated tokens never exceeds `budget`. Determinism follows
/// from `view.classes` already being in a stable order
/// (`fold::identity::merge_classes`'s sorted subjects) and `scored_queue`'s
/// sort including an explicit index tiebreak — no hashmap-iteration-order
/// dependence anywhere in the selection.
pub fn assemble(
    view: &FoldedView,
    budget: usize,
    estimator: &dyn TokenEstimator,
) -> Vec<(Cid, Claim)> {
    let mut queues: Vec<Vec<(Cid, Claim, usize)>> = view
        .classes
        .iter()
        .map(|class| scored_queue(&class.claims, estimator))
        .collect();

    let mut remaining = budget;
    let mut selected = Vec::new();
    loop {
        let mut progressed = false;
        for queue in queues.iter_mut() {
            // The highest-value claim in this class that currently fits —
            // not just the front, since a cheaper, lower-value claim later
            // in the queue might still fit even when the front doesn't.
            if let Some(pos) = queue.iter().position(|(_, _, tokens)| *tokens <= remaining) {
                let (cid, claim, tokens) = queue.remove(pos);
                remaining -= tokens;
                selected.push((cid, claim));
                progressed = true;
            }
        }
        if !progressed {
            break;
        }
    }
    selected
}
