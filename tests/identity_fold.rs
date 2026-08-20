//! M4a: the real identity fold. AC-5 from `.design/kan-spine.md` (a `SameAs`
//! merge followed by retraction of the `SameAs` claim re-derives the split
//! component from the retained witness edge set, not a stale cache), plus
//! trust gating (the "Settled under Solo trust" half of AC-4 — the
//! "Contested under PeerContested" half needs classify(), M4b) and the
//! component-size guardrail.

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

fn observation(text: &str) -> ClaimBody {
    ClaimBody::Observation {
        text: text.to_string(),
    }
}

fn same_as(target: &str) -> ClaimBody {
    ClaimBody::Relation {
        kind: RelationKind::SameAs,
        target: SubjectRef::Local(target.to_string()),
    }
}

#[tokio::test]
async fn ac5_sameas_merges_then_retraction_resplits() {
    let dir = tempfile::tempdir().unwrap();
    let identity = Identity::generate();
    let author = AuthorId {
        did: identity.did(),
        agent: None,
    };
    let trust = TrustBase::solo(author.clone());
    let mut log = Log::open_or_create(&dir.path().join("log"), &identity)
        .await
        .unwrap();

    log.append(
        content(&author, "bug-42", observation("crashes on startup")),
        &identity,
    )
    .await
    .unwrap();
    log.append(
        content(&author, "issue-7", observation("reported by a user")),
        &identity,
    )
    .await
    .unwrap();

    // Initially separate classes.
    let claims = log.iter_all().await.unwrap();
    let view = fold::fold(claims, &trust);
    assert_eq!(view.classes.len(), 2);

    // Merge them.
    let same_as_cid = log
        .append(content(&author, "bug-42", same_as("issue-7")), &identity)
        .await
        .unwrap();

    let claims = log.iter_all().await.unwrap();
    let view = fold::fold(claims, &trust);
    assert_eq!(
        view.classes.len(),
        1,
        "SameAs should merge the two subjects into one class"
    );
    let merged = view
        .subject(&SubjectRef::Local("bug-42".to_string()))
        .unwrap();
    assert!(merged
        .subjects
        .contains(&SubjectRef::Local("issue-7".to_string())));
    // 2 narrative claims + the SameAs claim itself, all live.
    assert_eq!(merged.claims.len(), 3);

    // Retract the SameAs claim.
    log.append(
        content(
            &author,
            "bug-42",
            ClaimBody::Retraction {
                supersedes: same_as_cid,
            },
        ),
        &identity,
    )
    .await
    .unwrap();

    let claims = log.iter_all().await.unwrap();
    let view = fold::fold(claims, &trust);
    assert_eq!(
        view.classes.len(),
        2,
        "retracting the SameAs should re-split into two classes, re-derived from the \
         retained witness edges — not a stale cached union-find state"
    );
    let bug42 = view
        .subject(&SubjectRef::Local("bug-42".to_string()))
        .unwrap();
    let issue7 = view
        .subject(&SubjectRef::Local("issue-7".to_string()))
        .unwrap();
    assert!(!bug42
        .subjects
        .contains(&SubjectRef::Local("issue-7".to_string())));
    assert_ne!(bug42.subjects, issue7.subjects);
}

/// An untrusted author's SameAs claim doesn't merge anything — trust gates
/// which witnesses even enter the identity-fold graph.
#[tokio::test]
async fn untrusted_sameas_is_not_honored() {
    let dir = tempfile::tempdir().unwrap();
    let owner = Identity::generate();
    let owner_author = AuthorId {
        did: owner.did(),
        agent: None,
    };
    let stranger = Identity::generate();
    let stranger_author = AuthorId {
        did: stranger.did(),
        agent: None,
    };

    let mut log = Log::open_or_create(&dir.path().join("log"), &owner)
        .await
        .unwrap();
    log.append(
        content(&owner_author, "bug-42", observation("owner's claim")),
        &owner,
    )
    .await
    .unwrap();
    // The stranger asserts bug-42 is the same as issue-7, but nobody trusts them.
    log.append(
        content(&stranger_author, "bug-42", same_as("issue-7")),
        &stranger,
    )
    .await
    .unwrap();

    let claims = log.iter_all().await.unwrap();
    let trust = TrustBase::solo(owner_author);
    let view = fold::fold(claims, &trust);

    // Only bug-42 shows up (the stranger's claims are entirely untrusted,
    // including the SameAs witness), and it isn't merged with issue-7.
    assert_eq!(view.classes.len(), 1);
    let bug42 = view
        .subject(&SubjectRef::Local("bug-42".to_string()))
        .unwrap();
    assert_eq!(
        bug42.subjects,
        vec![SubjectRef::Local("bug-42".to_string())]
    );
}

/// `docs/SPEC.md` §8: "Cross-author 'retraction' is NOT possible (you can't
/// write to another's log)." A `Retraction` only takes effect against a claim
/// from the exact same author — structurally, not as a trust decision. Uses
/// `PeerContested` trusting *both* authors equally to prove the point: even a
/// fully-trusted stranger's `Retraction` of someone else's claim is inert,
/// which a `SoloTrust`-only test (never trusting the stranger at all) can't
/// distinguish from ordinary trust gating.
#[tokio::test]
async fn cross_author_retraction_is_not_honored_even_when_fully_trusted() {
    let dir = tempfile::tempdir().unwrap();
    let owner = Identity::generate();
    let owner_author = AuthorId {
        did: owner.did(),
        agent: None,
    };
    let stranger = Identity::generate();
    let stranger_author = AuthorId {
        did: stranger.did(),
        agent: None,
    };

    let mut log = Log::open_or_create(&dir.path().join("log"), &owner)
        .await
        .unwrap();
    let original = log
        .append(
            content(&owner_author, "bug-42", observation("owner's claim")),
            &owner,
        )
        .await
        .unwrap();
    // The stranger tries to retract the owner's claim -- not their own log.
    log.append(
        content(
            &stranger_author,
            "bug-42",
            ClaimBody::Retraction {
                supersedes: original.clone(),
            },
        ),
        &stranger,
    )
    .await
    .unwrap();

    let claims = log.iter_all().await.unwrap();
    let trust = TrustBase::PeerContested {
        weights: HashMap::from([(owner_author, 1.0), (stranger_author, 1.0)]),
    };
    let view = fold::fold(claims, &trust);

    let bug42 = view
        .subject(&SubjectRef::Local("bug-42".to_string()))
        .unwrap();
    let live_cids: Vec<_> = bug42.claims.iter().map(|(cid, _)| cid.clone()).collect();
    assert!(
        live_cids.contains(&original),
        "the owner's claim must stay live -- a stranger can't retract it, \
         no matter how much the viewer trusts that stranger"
    );
}

/// AC-4 (Solo half): two AgentKeys under one Did each make a claim about the
/// same subject. Under Solo trust restricted to one of them, only that
/// agent's claim is visible — trivially "Settled" since there's only one
/// timeline. (The PeerContested "Contested" half needs classify(), M4b.)
#[tokio::test]
async fn solo_trust_sees_only_the_trusted_author() {
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
        content(&agent_a, "issue-1", observation("agent A says: flaky")),
        &human,
    )
    .await
    .unwrap();
    log.append(
        content(&agent_b, "issue-1", observation("agent B says: fixed")),
        &human,
    )
    .await
    .unwrap();

    let claims = log.iter_all().await.unwrap();
    let trust = TrustBase::solo(agent_a.clone());
    let view = fold::fold(claims, &trust);

    let issue1 = view
        .subject(&SubjectRef::Local("issue-1".to_string()))
        .unwrap();
    assert_eq!(issue1.claims.len(), 1);
    assert_eq!(issue1.claims[0].1.content.author, agent_a);
}

/// PeerContested trusts both agents — both claims are visible in the same
/// class (contest *classification* is M4b; this just proves both are seen).
#[tokio::test]
async fn peer_contested_sees_all_weighted_authors() {
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
        content(&agent_a, "issue-1", observation("agent A says: flaky")),
        &human,
    )
    .await
    .unwrap();
    log.append(
        content(&agent_b, "issue-1", observation("agent B says: fixed")),
        &human,
    )
    .await
    .unwrap();

    let claims = log.iter_all().await.unwrap();
    let weights = HashMap::from([(agent_a, 1.0), (agent_b, 0.5)]);
    let trust = TrustBase::PeerContested { weights };
    let view = fold::fold(claims, &trust);

    let issue1 = view
        .subject(&SubjectRef::Local("issue-1".to_string()))
        .unwrap();
    assert_eq!(issue1.claims.len(), 2);
}

/// AC-7: `docs/SPEC.md` §5.1's "SameAs between two Anchors is a TYPE ERROR,
/// not a claim" — a `SameAs` witness where either side is a
/// `SubjectRef::Anchor` is excluded from merge-class computation, the same
/// way an untrusted witness is. Unit-tested directly (no CLI path
/// constructs an `Anchor` subject yet).
#[tokio::test]
async fn sameas_touching_an_anchor_is_not_honored() {
    let dir = tempfile::tempdir().unwrap();
    let identity = Identity::generate();
    let author = AuthorId {
        did: identity.did(),
        agent: None,
    };
    let trust = TrustBase::solo(author.clone());
    let mut log = Log::open_or_create(&dir.path().join("log"), &identity)
        .await
        .unwrap();

    let anchor = SubjectRef::Anchor(Anchor::Commit("deadbeef".to_string()));
    log.append(
        ClaimContent {
            author: author.clone(),
            workspace: Anchor::Workspace("test-workspace".to_string()),
            subject: SubjectRef::Local("bug-42".to_string()),
            body: ClaimBody::Relation {
                kind: RelationKind::SameAs,
                target: anchor.clone(),
            },
            cites: vec![],
            artifacts: vec![],
            recorded_at: None,
        },
        &identity,
    )
    .await
    .unwrap();
    log.append(
        content(&author, "bug-42", observation("still its own subject")),
        &identity,
    )
    .await
    .unwrap();

    let claims = log.iter_all().await.unwrap();
    let view = fold::fold(claims, &trust);

    // bug-42 stays its own class, not merged with the Anchor subject.
    let bug42 = view
        .subject(&SubjectRef::Local("bug-42".to_string()))
        .unwrap();
    assert_eq!(
        bug42.subjects,
        vec![SubjectRef::Local("bug-42".to_string())]
    );
    assert!(!bug42.subjects.contains(&anchor));
}

/// AC-5 (first half): a `Rejects` claim from an author the viewing
/// `TrustBase` trusts excludes the target claim from that viewer's fold.
#[tokio::test]
async fn rejects_claim_excluded_when_viewer_trusts_the_rejecter() {
    let dir = tempfile::tempdir().unwrap();
    let owner = Identity::generate();
    let owner_author = AuthorId {
        did: owner.did(),
        agent: None,
    };
    let stranger = Identity::generate();
    let stranger_author = AuthorId {
        did: stranger.did(),
        agent: None,
    };

    let mut log = Log::open_or_create(&dir.path().join("log"), &owner)
        .await
        .unwrap();
    let original = log
        .append(
            content(&owner_author, "bug-42", observation("owner's claim")),
            &owner,
        )
        .await
        .unwrap();
    log.append(
        content(
            &stranger_author,
            "bug-42",
            ClaimBody::Rejects {
                claim: original.clone(),
            },
        ),
        &stranger,
    )
    .await
    .unwrap();

    let claims = log.iter_all().await.unwrap();
    let trust = TrustBase::PeerContested {
        weights: HashMap::from([(owner_author, 1.0), (stranger_author, 1.0)]),
    };
    let view = fold::fold(claims, &trust);

    let bug42 = view
        .subject(&SubjectRef::Local("bug-42".to_string()))
        .unwrap();
    let live_cids: Vec<_> = bug42.claims.iter().map(|(cid, _)| cid.clone()).collect();
    assert!(
        !live_cids.contains(&original),
        "a Rejects claim from a trusted author must exclude its target"
    );
}

/// AC-5 (second half): the same `Rejects` claim, from an author the viewing
/// `TrustBase` does *not* trust, leaves the target claim live.
#[tokio::test]
async fn rejects_claim_from_untrusted_author_is_not_honored() {
    let dir = tempfile::tempdir().unwrap();
    let owner = Identity::generate();
    let owner_author = AuthorId {
        did: owner.did(),
        agent: None,
    };
    let stranger = Identity::generate();
    let stranger_author = AuthorId {
        did: stranger.did(),
        agent: None,
    };

    let mut log = Log::open_or_create(&dir.path().join("log"), &owner)
        .await
        .unwrap();
    let original = log
        .append(
            content(&owner_author, "bug-42", observation("owner's claim")),
            &owner,
        )
        .await
        .unwrap();
    log.append(
        content(
            &stranger_author,
            "bug-42",
            ClaimBody::Rejects {
                claim: original.clone(),
            },
        ),
        &stranger,
    )
    .await
    .unwrap();

    let claims = log.iter_all().await.unwrap();
    let trust = TrustBase::solo(owner_author);
    let view = fold::fold(claims, &trust);

    let bug42 = view
        .subject(&SubjectRef::Local("bug-42".to_string()))
        .unwrap();
    let live_cids: Vec<_> = bug42.claims.iter().map(|(cid, _)| cid.clone()).collect();
    assert!(
        live_cids.contains(&original),
        "a Rejects claim from an untrusted author must not exclude its target"
    );
}

/// REQ-6: a rejected `SameAs` witness must also stop contributing to
/// identity computation for a viewer who trusts the rejecter — the same
/// threading point `excluded_by_retraction` already has in `merge_classes`.
#[tokio::test]
async fn rejected_sameas_witness_does_not_merge_when_rejecter_is_trusted() {
    let dir = tempfile::tempdir().unwrap();
    let owner = Identity::generate();
    let owner_author = AuthorId {
        did: owner.did(),
        agent: None,
    };
    let stranger = Identity::generate();
    let stranger_author = AuthorId {
        did: stranger.did(),
        agent: None,
    };

    let mut log = Log::open_or_create(&dir.path().join("log"), &owner)
        .await
        .unwrap();
    log.append(
        content(&owner_author, "bug-42", observation("owner's claim")),
        &owner,
    )
    .await
    .unwrap();
    let same_as_cid = log
        .append(content(&owner_author, "bug-42", same_as("issue-7")), &owner)
        .await
        .unwrap();
    log.append(
        content(
            &stranger_author,
            "bug-42",
            ClaimBody::Rejects { claim: same_as_cid },
        ),
        &stranger,
    )
    .await
    .unwrap();

    let claims = log.iter_all().await.unwrap();
    let trust = TrustBase::PeerContested {
        weights: HashMap::from([(owner_author, 1.0), (stranger_author, 1.0)]),
    };
    let view = fold::fold(claims, &trust);

    let bug42 = view
        .subject(&SubjectRef::Local("bug-42".to_string()))
        .unwrap();
    assert_eq!(
        bug42.subjects,
        vec![SubjectRef::Local("bug-42".to_string())],
        "a rejected SameAs witness (rejecter trusted) must not merge the subjects"
    );
}

#[tokio::test]
async fn oversized_component_is_flagged() {
    let dir = tempfile::tempdir().unwrap();
    let identity = Identity::generate();
    let author = AuthorId {
        did: identity.did(),
        agent: None,
    };
    let trust = TrustBase::solo(author.clone());
    let mut log = Log::open_or_create(&dir.path().join("log"), &identity)
        .await
        .unwrap();

    // Chain subject-0 -> subject-1 -> ... -> subject-30 via SameAs: one
    // connected component of 31 subjects, past the guardrail of 25.
    for i in 0..30 {
        log.append(
            content(
                &author,
                &format!("subject-{i}"),
                same_as(&format!("subject-{}", i + 1)),
            ),
            &identity,
        )
        .await
        .unwrap();
    }

    let claims = log.iter_all().await.unwrap();
    let view = fold::fold(claims, &trust);
    assert_eq!(view.classes.len(), 1);
    assert!(view.classes[0].flagged_oversized);
}

/// `review/full-pass-v0.12` F9: retracting a retraction-of-a-retraction
/// reinstates the first retraction, so the original claim is excluded
/// again. The old forward pass with an undo map left the original *live*
/// across a chain this long (X, R1⊃X, R2⊃R1, R3⊃R2), because it never
/// replayed a reinstated retraction. A retraction is effective iff it is
/// not itself the target of an effective retraction.
#[tokio::test]
async fn retracting_a_retraction_of_a_retraction_reinstates_the_first() {
    let dir = tempfile::tempdir().unwrap();
    let owner = Identity::generate();
    let who = AuthorId {
        did: owner.did(),
        agent: None,
    };
    let mut log = Log::open_or_create(&dir.path().join("log"), &owner)
        .await
        .unwrap();

    let x = log
        .append(content(&who, "bug", observation("the finding")), &owner)
        .await
        .unwrap();
    let r1 = log
        .append(
            content(
                &who,
                "bug",
                ClaimBody::Retraction {
                    supersedes: x.clone(),
                },
            ),
            &owner,
        )
        .await
        .unwrap();
    let r2 = log
        .append(
            content(
                &who,
                "bug",
                ClaimBody::Retraction {
                    supersedes: r1.clone(),
                },
            ),
            &owner,
        )
        .await
        .unwrap();
    // R3 retracts R2, so R2 is inert, so R1 is effective again, so X is
    // excluded.
    log.append(
        content(
            &who,
            "bug",
            ClaimBody::Retraction {
                supersedes: r2.clone(),
            },
        ),
        &owner,
    )
    .await
    .unwrap();

    let claims = log.iter_all().await.unwrap();
    let trust = TrustBase::solo(who);
    let view = fold::fold(claims, &trust);
    let live: Vec<_> = view
        .subject(&SubjectRef::Local("bug".to_string()))
        .map(|s| s.claims.iter().map(|(cid, _)| cid.clone()).collect())
        .unwrap_or_default();

    assert!(
        !live.contains(&x),
        "R3 neutralises R2, reinstating R1, so the original finding must be \
         excluded again -- it was left live: {live:?}"
    );
    assert!(
        !live.contains(&r2),
        "R2 is retracted by the effective R3 and must not be live"
    );
    // Sanity: two effective retractions (R1, R3) remain visible narrative.
    assert!(
        live.contains(&r1),
        "R1 is effective again and should be visible"
    );
}

/// F9, the simpler chain the old code did get right — kept so the fixpoint
/// rewrite cannot regress it: retracting a retraction reinstates the
/// original claim.
#[tokio::test]
async fn retracting_a_retraction_reinstates_the_original() {
    let dir = tempfile::tempdir().unwrap();
    let owner = Identity::generate();
    let who = AuthorId {
        did: owner.did(),
        agent: None,
    };
    let mut log = Log::open_or_create(&dir.path().join("log"), &owner)
        .await
        .unwrap();

    let x = log
        .append(content(&who, "bug", observation("the finding")), &owner)
        .await
        .unwrap();
    let r1 = log
        .append(
            content(
                &who,
                "bug",
                ClaimBody::Retraction {
                    supersedes: x.clone(),
                },
            ),
            &owner,
        )
        .await
        .unwrap();
    log.append(
        content(
            &who,
            "bug",
            ClaimBody::Retraction {
                supersedes: r1.clone(),
            },
        ),
        &owner,
    )
    .await
    .unwrap();

    let claims = log.iter_all().await.unwrap();
    let view = fold::fold(claims, &TrustBase::solo(who));
    let live: Vec<_> = view
        .subject(&SubjectRef::Local("bug".to_string()))
        .map(|s| s.claims.iter().map(|(cid, _)| cid.clone()).collect())
        .unwrap_or_default();
    assert!(
        live.contains(&x),
        "retracting the retraction must reinstate the original: {live:?}"
    );
}
