//! AC-7 (`.design/kan-spine.md`): `kan context --budget N` returns a claim
//! set whose total token estimate is ≤ N and is deterministic for a fixed
//! claim set + budget.

use kan::{
    claim::{Anchor, AuthorId, ClaimBody, ClaimContent, Rkey, StatusValue, SubjectRef},
    context::{self, TiktokenEstimator, TokenEstimator},
    fold::{self, TrustBase},
};

fn author() -> AuthorId {
    AuthorId {
        did: "did:key:solo".to_string(),
        agent: None,
    }
}

fn claim(subject: &str, body: ClaimBody) -> (atproto_dasl::Cid, kan::claim::Claim) {
    let content = ClaimContent {
        author: author(),
        workspace: Anchor::Workspace("test-workspace".to_string()),
        subject: SubjectRef::Local(Rkey::from(subject)),
        body,
        cites: vec![],
        artifacts: vec![],
        recorded_at: None,
    };
    let cid = kan::cid::content_cid(&content).unwrap();
    (
        cid,
        kan::claim::Claim {
            content,
            sig: vec![],
        },
    )
}

fn fixture() -> fold::FoldedView {
    let claims = vec![
        claim(
            "issue-1",
            ClaimBody::Observation {
                text: "a fairly long observation about something that happened during testing"
                    .to_string(),
            },
        ),
        claim(
            "issue-1",
            ClaimBody::Status {
                value: StatusValue::Open,
            },
        ),
        claim(
            "issue-2",
            ClaimBody::Decision {
                text: "decided to use approach B instead of approach A for this one".to_string(),
            },
        ),
        claim(
            "issue-3",
            ClaimBody::Plan {
                text: "plan to refactor the module before adding the new feature".to_string(),
            },
        ),
    ];
    let stored: Vec<_> = claims
        .into_iter()
        .enumerate()
        .map(|(i, (cid, c))| {
            (
                cid,
                kan::store::log::StoredClaim {
                    claim: c,
                    rev: format!("{i:013}"),
                },
            )
        })
        .collect();
    let trust = TrustBase::solo(author());
    fold::fold(stored, &trust)
}

/// `render_claim` extracts actual claim content, not a `{:?}` Debug dump —
/// no stray `ClaimBody::Observation { text: ... }`-shaped syntax in the
/// rendered text.
#[test]
fn render_claim_produces_prose_not_a_debug_dump() {
    let (_, claim) = claim(
        "bug-42",
        ClaimBody::Observation {
            text: "crashes on startup".to_string(),
        },
    );
    let rendered = context::render_claim(&claim);
    assert!(rendered.contains("crashes on startup"));
    assert!(rendered.contains("bug-42"));
    assert!(
        !rendered.contains("ClaimBody"),
        "rendered text should not leak Rust type syntax: {rendered:?}"
    );
    assert!(
        !rendered.contains("{ text:"),
        "rendered text should not leak struct-literal syntax: {rendered:?}"
    );
}

#[test]
fn ac7_stays_within_budget() {
    let view = fixture();
    let estimator = TiktokenEstimator::cl100k();
    let selected = context::assemble(&view, 20, &estimator);

    let total: usize = selected
        .iter()
        .map(|(_, c)| estimator.estimate(&context::render_claim(c)))
        .sum();
    assert!(total <= 20, "total tokens {total} exceeded budget of 20");
}

#[test]
fn ac7_deterministic_for_fixed_claims_and_budget() {
    let view = fixture();
    let estimator = TiktokenEstimator::cl100k();

    let first = context::assemble(&view, 60, &estimator);
    let second = context::assemble(&view, 60, &estimator);

    let first_cids: Vec<_> = first.iter().map(|(cid, _)| cid.clone()).collect();
    let second_cids: Vec<_> = second.iter().map(|(cid, _)| cid.clone()).collect();
    assert_eq!(first_cids, second_cids);
}

#[test]
fn zero_budget_selects_nothing() {
    let view = fixture();
    let estimator = TiktokenEstimator::cl100k();
    let selected = context::assemble(&view, 0, &estimator);
    assert!(selected.is_empty());
}

/// A generous budget should be able to fit everything in this small
/// fixture.
#[test]
fn generous_budget_selects_every_live_claim() {
    let view = fixture();
    let estimator = TiktokenEstimator::cl100k();
    let selected = context::assemble(&view, 10_000, &estimator);
    let total_live: usize = view.classes.iter().map(|c| c.claims.len()).sum();
    assert_eq!(selected.len(), total_live);
}
