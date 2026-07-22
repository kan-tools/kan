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
    claim::{Anchor, AuthorId, ClaimBody, ClaimContent, RelationKind, Rkey, SubjectRef},
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
