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
        ClaimBody::Rejects { claim } => format!("rejects {claim}"),
        ClaimBody::Publication { layer } => format!("published to {layer:?}"),
        // Uninterpretable, but present and verifiable — say so rather than
        // rendering nothing, so a reader can tell the difference between a
        // subject with three claims and one with three it can read plus one
        // it cannot (ADR-44).
        ClaimBody::Unknown { kind, raw } => {
            format!(
                "unreadable claim of kind `{kind}` ({} bytes) — this build does not \
                     understand it",
                raw.len()
            )
        }
    };
    format!("[{subject}] {kind:?}: {detail}")
}

fn kind_value(kind: ClaimKind) -> i64 {
    match kind {
        ClaimKind::Status => 5,
        ClaimKind::Decision | ClaimKind::Blocker | ClaimKind::Resolution => 4,
        ClaimKind::Plan | ClaimKind::Result => 3,
        ClaimKind::Observation | ClaimKind::Subject | ClaimKind::Relation => 2,
        // Structural like Relation: it says where a subject is shared, not
        // what is true about it, so it is worth carrying but not at the
        // expense of narrative.
        ClaimKind::Publication => 2,
        ClaimKind::Retraction | ClaimKind::Rejects => 1,
        // Carries no meaning this build can act on, so it must not displace
        // a claim that does — but it is still worth surfacing if room
        // remains.
        ClaimKind::Unknown => 0,
    }
}

/// Per merge-class, highest-value-first (recency as a same-kind tiebreak —
/// `class.claims` is already chronological, so a later index means later in
/// time), each tagged with its estimated token cost.
fn scored_queue(
    claims: &[(Cid, Claim)],
    estimator: &dyn TokenEstimator,
) -> Vec<(i64, Cid, Claim, usize)> {
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
        .map(|(score, _, cid, claim, tokens)| (score, cid, claim, tokens))
        .collect()
}

/// AC-7: deterministic for a fixed claim set + budget, and the returned
/// set's total estimated tokens never exceeds `budget`. Determinism follows
/// from `view.classes` already being in a stable order
/// (`fold::identity::merge_classes`'s sorted subjects) and `scored_queue`'s
/// sort including an explicit index tiebreak — no hashmap-iteration-order
/// dependence anywhere in the selection.
/// What `assemble` chose, and what it had to leave out.
///
/// The omission counts are the point. `context` used to print only what it
/// kept: at budget 150 over 14 claims it emitted five observations and
/// dropped the only `Status{Blocked}` and its `Blocker` narrative with no
/// signal at all, and budget 0 rendered identically to an empty log. A
/// budgeted view that cannot say what it withheld is indistinguishable from
/// a complete one, which makes it unsafe to reason from
/// (`.design/v0.7-milestone.md` REQ-19).
#[derive(Debug, Default)]
pub struct Assembled {
    pub selected: Vec<(Cid, Claim)>,
    pub omitted_claims: usize,
    /// Subjects with at least one claim omitted, in stable order.
    pub omitted_subjects: Vec<String>,
}

/// AC-7: deterministic for a fixed claim set + budget, and the returned
/// set's total estimated tokens never exceeds `budget`.
pub fn assemble(
    view: &FoldedView,
    budget: usize,
    estimator: &dyn TokenEstimator,
) -> Vec<(Cid, Claim)> {
    assemble_reporting(view, budget, estimator).selected
}

/// [`assemble`], also reporting what was left out (REQ-19).
pub fn assemble_reporting(
    view: &FoldedView,
    budget: usize,
    estimator: &dyn TokenEstimator,
) -> Assembled {
    let mut queues: Vec<Vec<(i64, Cid, Claim, usize)>> = view
        .classes
        .iter()
        .map(|class| scored_queue(&class.claims, estimator))
        .collect();

    let mut remaining = budget;
    let mut selected = Vec::new();
    loop {
        // Round-robin still gives every subject a turn, so one chatty
        // subject cannot starve the rest -- that part was always right. What
        // was wrong is the order *within* a pass: it followed
        // `view.classes`, which is lexical by subject name, so `task-1`'s
        // Observation outranked `task-3`'s `Status{Blocked}` purely because
        // the string sorts first. `kind_value`'s scoring was applied only
        // within a class and never across them, inverting the module's own
        // stated purpose. Ordering each pass by the best claim currently
        // available in each queue keeps the fairness and lets value decide
        // who goes first when the budget runs out mid-pass.
        let mut order: Vec<usize> = (0..queues.len()).collect();
        order.sort_by_key(|&i| {
            let best = queues[i]
                .iter()
                .find(|(_, _, _, tokens)| *tokens <= remaining)
                .map(|(score, ..)| *score);
            // Exhausted or unaffordable queues sort last; ties break by
            // class index so the result stays deterministic.
            (std::cmp::Reverse(best), i)
        });

        let mut progressed = false;
        for i in order {
            // The highest-value claim in this class that currently fits --
            // not just the front, since a cheaper, lower-value claim later
            // in the queue might still fit even when the front doesn't.
            if let Some(pos) = queues[i]
                .iter()
                .position(|(_, _, _, tokens)| *tokens <= remaining)
            {
                let (_, cid, claim, tokens) = queues[i].remove(pos);
                remaining -= tokens;
                selected.push((cid, claim));
                progressed = true;
            }
        }
        if !progressed {
            break;
        }
    }

    let mut omitted_claims = 0;
    let mut omitted_subjects = Vec::new();
    for queue in &queues {
        omitted_claims += queue.len();
        for (_, _, claim, _) in queue {
            let subject = format!("{:?}", claim.content.subject);
            if !omitted_subjects.contains(&subject) {
                omitted_subjects.push(subject);
            }
        }
    }
    omitted_subjects.sort();

    Assembled {
        selected,
        omitted_claims,
        omitted_subjects,
    }
}
