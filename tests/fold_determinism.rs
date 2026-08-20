//! `docs/SETUP-TODO.md` Phase 4: `fold` is a pure, deterministic function of
//! (claim set, enrichment) — `docs/SPEC.md` §9's first INVARIANT. The
//! existing fixtures (`tests/identity_fold.rs`, `tests/state_fold.rs`,
//! `tests/index_and_fold.rs`) all rely on this implicitly by calling `fold`
//! once per assertion; this test makes the property itself the assertion,
//! calling `fold` twice on the identical (claims, trust) input — including
//! a `PeerContested` enrichment, since that's the case with more than one
//! trusted timeline to get wrong — and requiring the full result to match.

use std::collections::HashMap;

use kan::{
    claim::v1::{Anchor, AuthorId, ClaimBody, ClaimContent, RelationKind, Rkey, SubjectRef},
    fold::{self, TrustBase},
    sign::Identity,
    store::log::Log,
};

fn content(author: &AuthorId, subject: &str, body: ClaimBody) -> ClaimContent {
    ClaimContent {
        author: author.clone(),
        workspace: Anchor::Workspace("test-workspace".to_string()),
        subject: SubjectRef::Local(Rkey::from(subject)),
        body,
        cites: vec![],
        artifacts: vec![],
        recorded_at: None,
    }
}

#[tokio::test]
async fn fold_is_deterministic_for_a_fixed_claim_set_and_enrichment() {
    let dir = tempfile::tempdir().unwrap();
    let human = Identity::generate();
    let agent_a = AuthorId {
        did: human.did(),
        agent: Some(vec![1, 2, 3]),
    };
    let agent_b = AuthorId {
        did: human.did(),
        agent: Some(vec![4, 5, 6]),
    };

    let mut log = Log::open_or_create(&dir.path().join("log"), &human)
        .await
        .unwrap();
    log.append(
        content(
            &agent_a,
            "bug-42",
            ClaimBody::Observation {
                text: "crashes on startup".to_string(),
            },
        ),
        &human,
    )
    .await
    .unwrap();
    log.append(
        content(
            &agent_b,
            "issue-7",
            ClaimBody::Observation {
                text: "reported by a user".to_string(),
            },
        ),
        &human,
    )
    .await
    .unwrap();
    log.append(
        content(
            &agent_a,
            "bug-42",
            ClaimBody::Relation {
                kind: RelationKind::SameAs,
                target: SubjectRef::Local(Rkey::from("issue-7")),
            },
        ),
        &human,
    )
    .await
    .unwrap();

    let claims = log.iter_all().await.unwrap();
    let trust = TrustBase::PeerContested {
        weights: HashMap::from([(agent_a, 1.0), (agent_b, 0.7)]),
    };

    let first = fold::fold(claims.clone(), &trust);
    let second = fold::fold(claims, &trust);

    assert_eq!(first.classes.len(), second.classes.len());
    for (a, b) in first.classes.iter().zip(second.classes.iter()) {
        assert_eq!(a.subjects, b.subjects);
        assert_eq!(a.flagged_oversized, b.flagged_oversized);
        assert_eq!(a.claims.len(), b.claims.len());
        for ((cid_a, claim_a), (cid_b, claim_b)) in a.claims.iter().zip(b.claims.iter()) {
            assert_eq!(cid_a, cid_b);
            assert_eq!(claim_a, claim_b);
        }
    }
}

/// `review/full-pass-v0.12` F9: the fold is a function of the claim *set*,
/// not its enumeration order. Two `Status` claims by one author on one
/// subject sharing a `rev` (which cross-log `.claims/` ingestion makes
/// reachable) must fold to the same live status regardless of input order.
/// Before the `(rev, cid)` tiebreak, the stable sort preserved input order,
/// so classify's last-insert-wins picked whichever the caller listed last.
#[test]
fn fold_is_independent_of_claim_input_order() {
    use kan::store::log::StoredClaim;

    let who = AuthorId {
        did: "did:key:zTestSameRev".to_string(),
        agent: None,
    };
    let mk = |value: kan::claim::v1::StatusValue| {
        let content = ClaimContent {
            author: who.clone(),
            workspace: Anchor::Workspace("test-workspace".to_string()),
            subject: SubjectRef::Local(Rkey::from("bug-42")),
            body: ClaimBody::Status { value },
            cites: vec![],
            artifacts: vec![],
            recorded_at: None,
        };
        let cid = kan::cid::content_cid(&content).unwrap();
        // Identical rev on purpose: the collision the tiebreak must resolve.
        (
            cid,
            StoredClaim {
                claim: kan::claim::v1::Claim {
                    content,
                    sig: vec![],
                },
                rev: "3333333333333".to_string(),
            },
        )
    };
    let open = mk(kan::claim::v1::StatusValue::Open);
    let resolved = mk(kan::claim::v1::StatusValue::Resolved);
    let trust = TrustBase::solo(who.clone());

    let forward = fold::fold(vec![open.clone(), resolved.clone()], &trust);
    let reversed = fold::fold(vec![resolved, open], &trust);

    let live_status = |v: &fold::FoldedView| {
        v.classes
            .iter()
            .flat_map(|c| &c.claims)
            .find_map(|(_, claim)| match &claim.content.body {
                ClaimBody::Status { value } => Some(*value),
                _ => None,
            })
    };
    assert_eq!(
        live_status(&forward),
        live_status(&reversed),
        "two same-rev status claims folded to different live statuses \
         depending on input order -- the fold is not a function of the set"
    );
}
