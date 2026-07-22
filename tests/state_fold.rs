//! M4b's state fold (`fold::state`): `Settled | Confirmed | Contested`
//! classification over a merge-class's `Status`-kind claims. AC-4
//! (`.design/kan-spine.md`) — the "Contested under PeerContested, Settled
//! under Solo" fixture identity_fold.rs left for this milestone — and
//! AC-10 (a `GitAncestry`-computed edge orders two claims with zero
//! attested `cites`) live here.

use std::{collections::HashMap, process::Command};

use atproto_dasl::Cid;
use kan::{
    claim::{
        Anchor, ArtifactRef, AuthorId, Claim, ClaimBody, ClaimContent, Rkey, StatusValue,
        SubjectRef,
    },
    fold::{self, state::StateView, TrustBase},
    git::GitSubstrate,
    relations,
    sign::Identity,
    store::log::Log,
};

fn author(did: &str, agent: Option<Vec<u8>>) -> AuthorId {
    AuthorId {
        did: did.to_string(),
        agent,
    }
}

fn status_claim(
    who: &AuthorId,
    subject: &str,
    value: StatusValue,
    cites: Vec<Cid>,
    artifacts: Vec<ArtifactRef>,
) -> (Cid, Claim) {
    let content = ClaimContent {
        author: who.clone(),
        workspace: Anchor::Workspace("test-workspace".to_string()),
        subject: SubjectRef::Local(Rkey::from(subject)),
        body: ClaimBody::Status { value },
        cites,
        artifacts,
        recorded_at: None,
    };
    let cid = kan::cid::content_cid(&content).unwrap();
    (
        cid,
        Claim {
            content,
            sig: vec![],
        },
    )
}

#[test]
fn no_status_claims_is_unclassified() {
    let who = author("did:key:solo", None);
    let content = ClaimContent {
        author: who,
        workspace: Anchor::Workspace("test-workspace".to_string()),
        subject: SubjectRef::Local(Rkey::from("issue-1")),
        body: ClaimBody::Observation {
            text: "just a note".to_string(),
        },
        cites: vec![],
        artifacts: vec![],
        recorded_at: None,
    };
    let cid = kan::cid::content_cid(&content).unwrap();
    let claims = vec![(
        cid,
        Claim {
            content,
            sig: vec![],
        },
    )];

    assert_eq!(fold::state::classify(&claims, &[]), StateView::Unclassified);
}

#[test]
fn single_author_status_is_settled() {
    let who = author("did:key:solo", None);
    let claim = status_claim(&who, "issue-1", StatusValue::Open, vec![], vec![]);

    match fold::state::classify(std::slice::from_ref(&claim), &[]) {
        StateView::Settled { value, claim: got } => {
            assert_eq!(value, StatusValue::Open);
            assert_eq!(got.0, claim.0);
        }
        other => panic!("expected Settled, got {other:?}"),
    }
}

#[test]
fn agreeing_authors_are_confirmed() {
    let a = author("did:key:a", None);
    let b = author("did:key:b", None);
    let claim_a = status_claim(&a, "issue-1", StatusValue::Resolved, vec![], vec![]);
    let claim_b = status_claim(&b, "issue-1", StatusValue::Resolved, vec![], vec![]);

    match fold::state::classify(&[claim_a, claim_b], &[]) {
        StateView::Confirmed { value, by } => {
            assert_eq!(value, StatusValue::Resolved);
            assert_eq!(by.len(), 2);
        }
        other => panic!("expected Confirmed, got {other:?}"),
    }
}

#[test]
fn disagreeing_authors_with_no_ordering_are_contested() {
    let a = author("did:key:a", None);
    let b = author("did:key:b", None);
    let claim_a = status_claim(&a, "issue-1", StatusValue::Open, vec![], vec![]);
    let claim_b = status_claim(&b, "issue-1", StatusValue::Resolved, vec![], vec![]);

    match fold::state::classify(&[claim_a, claim_b], &[]) {
        StateView::Contested { resolved, open } => {
            assert!(resolved.is_empty());
            assert_eq!(open.len(), 2);
        }
        other => panic!("expected Contested, got {other:?}"),
    }
}

/// Attested `cites` is enough to resolve disagreement without any computed
/// edge — the later (citing) claim's position wins, and the fold reports a
/// single `Settled` answer rather than a contest.
#[test]
fn attested_cites_resolves_disagreement_to_settled() {
    let a = author("did:key:a", None);
    let b = author("did:key:b", None);
    let claim_a = status_claim(&a, "issue-1", StatusValue::Open, vec![], vec![]);
    let claim_b = status_claim(
        &b,
        "issue-1",
        StatusValue::Resolved,
        vec![claim_a.0.clone()],
        vec![],
    );

    match fold::state::classify(&[claim_a.clone(), claim_b.clone()], &[]) {
        StateView::Settled { value, claim: got } => {
            assert_eq!(value, StatusValue::Resolved);
            assert_eq!(got.0, claim_b.0);
        }
        other => panic!("expected Settled, got {other:?}"),
    }
}

/// Domination can resolve a 3-way disagreement down to 2+ survivors who no
/// longer actually disagree with each other -- the dissenting position was
/// the one dominated away. That's agreement (`Confirmed`), not a live
/// contest, even though the *original* live set (before ordering) disagreed.
#[test]
fn domination_down_to_agreeing_survivors_is_confirmed_not_contested() {
    let a = author("did:key:a", None);
    let b = author("did:key:b", None);
    let c = author("did:key:c", None);
    let claim_a = status_claim(&a, "issue-1", StatusValue::Open, vec![], vec![]);
    // b cites (and so dominates) a, and agrees with c.
    let claim_b = status_claim(
        &b,
        "issue-1",
        StatusValue::Resolved,
        vec![claim_a.0.clone()],
        vec![],
    );
    let claim_c = status_claim(&c, "issue-1", StatusValue::Resolved, vec![], vec![]);

    match fold::state::classify(&[claim_a, claim_b, claim_c], &[]) {
        StateView::Confirmed { value, by } => {
            assert_eq!(value, StatusValue::Resolved);
            assert_eq!(by.len(), 2);
        }
        other => panic!("expected Confirmed, got {other:?}"),
    }
}

/// AC-4: two `AgentKey`s under one `Did` disagree on a subject's status.
/// Under `PeerContested` (both trusted), the disagreement is genuinely
/// contested. Under `SoloTrust` restricted to one of them, only that
/// author's position is visible at all — trivially `Settled`, since
/// there's only ever one timeline.
#[tokio::test]
async fn ac4_contested_under_peer_settled_under_solo() {
    let dir = tempfile::tempdir().unwrap();
    let human = Identity::generate();
    let agent_a = author(&human.did(), Some(vec![1, 2, 3]));
    let agent_b = author(&human.did(), Some(vec![4, 5, 6]));

    let mut log = Log::open_or_create(&dir.path().join("log"), &human)
        .await
        .unwrap();

    let content = |who: &AuthorId, value: StatusValue| ClaimContent {
        author: who.clone(),
        workspace: Anchor::Workspace("test-workspace".to_string()),
        subject: SubjectRef::Local(Rkey::from("issue-1")),
        body: ClaimBody::Status { value },
        cites: vec![],
        artifacts: vec![],
        recorded_at: None,
    };
    log.append(content(&agent_a, StatusValue::Open), &human)
        .await
        .unwrap();
    log.append(content(&agent_b, StatusValue::Resolved), &human)
        .await
        .unwrap();

    let claims = log.iter_all().await.unwrap();
    let peer = TrustBase::PeerContested {
        weights: HashMap::from([(agent_a.clone(), 1.0), (agent_b.clone(), 1.0)]),
    };
    let view = fold::fold(claims.clone(), &peer);
    let issue1 = view
        .subject(&SubjectRef::Local("issue-1".to_string()))
        .unwrap();
    match fold::state::classify(&issue1.claims, &[]) {
        StateView::Contested { open, .. } => assert_eq!(open.len(), 2),
        other => panic!("expected Contested under PeerContested, got {other:?}"),
    }

    let solo = TrustBase::solo(agent_a.clone());
    let view = fold::fold(claims, &solo);
    let issue1 = view
        .subject(&SubjectRef::Local("issue-1".to_string()))
        .unwrap();
    match fold::state::classify(&issue1.claims, &[]) {
        StateView::Settled { value, .. } => assert_eq!(value, StatusValue::Open),
        other => panic!("expected Settled under SoloTrust, got {other:?}"),
    }
}

fn git(dir: &std::path::Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .args(args)
        .current_dir(dir)
        .output()
        .expect("failed to run git");
    assert!(
        output.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_string()
}

/// AC-10: a `GitAncestry`-computed edge correctly orders two claims
/// anchored to different commits on the same branch with zero attested
/// `cites` between them.
#[test]
fn ac10_git_ancestry_orders_claims_with_zero_attested_cites() {
    let dir = tempfile::tempdir().unwrap();
    git(dir.path(), &["init", "-q"]);
    git(
        dir.path(),
        &[
            "-c",
            "user.email=kan-test@example.com",
            "-c",
            "user.name=kan-test",
            "commit",
            "-q",
            "--allow-empty",
            "-m",
            "first",
        ],
    );
    let sha1 = git(dir.path(), &["rev-parse", "HEAD"]);
    git(
        dir.path(),
        &[
            "-c",
            "user.email=kan-test@example.com",
            "-c",
            "user.name=kan-test",
            "commit",
            "-q",
            "--allow-empty",
            "-m",
            "second",
        ],
    );
    let sha2 = git(dir.path(), &["rev-parse", "HEAD"]);

    let a = author("did:key:a", None);
    let b = author("did:key:b", None);
    let earlier = status_claim(
        &a,
        "issue-1",
        StatusValue::Open,
        vec![],
        vec![ArtifactRef::Commit(sha1)],
    );
    let later = status_claim(
        &b,
        "issue-1",
        StatusValue::Resolved,
        vec![],
        vec![ArtifactRef::Commit(sha2)],
    );
    let claims = vec![earlier, later.clone()];

    let substrate = GitSubstrate::open(dir.path()).unwrap();
    let edges = relations::compute_default(&claims, &substrate);
    assert!(
        edges
            .iter()
            .any(|e| e.kind == relations::ComputedEdgeKind::Ancestry),
        "GitAncestry should have found an ordering edge between the two commits"
    );

    match fold::state::classify(&claims, &edges) {
        StateView::Settled { value, claim: got } => {
            assert_eq!(
                value,
                StatusValue::Resolved,
                "the later commit's claim should win"
            );
            assert_eq!(got.0, later.0);
        }
        other => panic!("expected Settled via computed GitAncestry edge, got {other:?}"),
    }
}

/// Genesis is a pure function of the repo's history — computed twice on the
/// same repo, it's identical (`docs/SPEC.md` §5's "computed identically by
/// every actor").
#[test]
fn genesis_is_deterministic() {
    let dir = tempfile::tempdir().unwrap();
    git(dir.path(), &["init", "-q"]);
    git(
        dir.path(),
        &[
            "-c",
            "user.email=kan-test@example.com",
            "-c",
            "user.name=kan-test",
            "commit",
            "-q",
            "--allow-empty",
            "-m",
            "init",
        ],
    );

    let first = GitSubstrate::open(dir.path()).unwrap().genesis().unwrap();
    let second = GitSubstrate::open(dir.path()).unwrap().genesis().unwrap();
    assert_eq!(first, second);
}
