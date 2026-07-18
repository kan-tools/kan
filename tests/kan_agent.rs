//! AC-8: `KAN_AGENT=test-agent kan observe "x"` produces a claim whose
//! `AuthorId.agent` is `Some(...)` and differs from an unset-env-var run's
//! `None`; two different `KAN_AGENT` values in the same repo produce two
//! distinct `AuthorId`s that a `PeerContested` trust base can genuinely
//! tell apart. An actual end-to-end proof: the two `AuthorId`s come from
//! real `kan` subprocess invocations (real signing, real `KAN_AGENT`
//! plumbing through `Workspace::my_author`), not hand-constructed structs —
//! only the `PeerContested` trust base itself is assembled at the library
//! level, reading the real claims back out of the log those subprocesses
//! wrote to.

use std::{collections::HashMap, path::Path, process::Command};

use kan::{
    claim::{ClaimBody, SubjectRef},
    fold::{self, TrustBase},
    sign::Identity,
    store::log::Log,
};

fn git_repo() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let run = |args: &[&str]| {
        let status = Command::new("git")
            .args(args)
            .current_dir(dir.path())
            .status()
            .expect("failed to run git");
        assert!(status.success(), "git {args:?} failed");
    };
    run(&["init", "-q"]);
    run(&[
        "-c",
        "user.email=kan-test@example.com",
        "-c",
        "user.name=kan-test",
        "commit",
        "-q",
        "--allow-empty",
        "-m",
        "init",
    ]);
    dir
}

fn kan_with_env(dir: &Path, args: &[&str], env: &[(&str, &str)]) -> bool {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_kan"));
    cmd.args(args).current_dir(dir);
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.output()
        .expect("failed to run kan binary")
        .status
        .success()
}

#[tokio::test]
async fn kan_agent_produces_distinct_authorids_a_peercontested_trust_base_tells_apart() {
    let dir = git_repo();

    assert!(kan_with_env(
        dir.path(),
        &["observe", "no agent", "--subject", "bug-42"],
        &[],
    ));
    assert!(kan_with_env(
        dir.path(),
        &["observe", "agent a says hi", "--subject", "bug-42"],
        &[("KAN_AGENT", "agent-a")],
    ));
    assert!(kan_with_env(
        dir.path(),
        &["observe", "agent b says hi", "--subject", "bug-42"],
        &[("KAN_AGENT", "agent-b")],
    ));

    let identity = Identity::load_or_create(&dir.path().join(".kan/identity")).unwrap();
    let mut log = Log::open_or_create(&dir.path().join(".kan/log"), &identity)
        .await
        .unwrap();
    let claims = log.iter_all().await.unwrap();

    let author_of = |needle: &str| {
        claims
            .iter()
            .find_map(|(_, stored)| match &stored.claim.content.body {
                ClaimBody::Observation { text } if text == needle => {
                    Some(stored.claim.content.author.clone())
                }
                _ => None,
            })
            .unwrap_or_else(|| panic!("no claim with text {needle:?}"))
    };

    let no_agent = author_of("no agent");
    let agent_a = author_of("agent a says hi");
    let agent_b = author_of("agent b says hi");

    // Same human identity throughout -- only the agent tag differs.
    assert_eq!(no_agent.did, agent_a.did);
    assert_eq!(no_agent.did, agent_b.did);

    assert!(no_agent.agent.is_none());
    assert!(agent_a.agent.is_some());
    assert!(agent_b.agent.is_some());
    assert_ne!(agent_a.agent, agent_b.agent);
    assert_ne!(agent_a, no_agent);
    assert_ne!(agent_b, no_agent);

    // A PeerContested trust base weighting both tagged agents can genuinely
    // tell them apart: both claims are visible, distinctly attributed, and
    // the untrusted (weight-absent) no-agent claim is excluded.
    let peer_contested = TrustBase::PeerContested {
        weights: HashMap::from([(agent_a.clone(), 1.0), (agent_b.clone(), 1.0)]),
    };
    let view = fold::fold(claims.clone(), &peer_contested);
    let bug42 = view
        .subject(&SubjectRef::Local("bug-42".to_string()))
        .unwrap();
    let authors: Vec<_> = bug42
        .claims
        .iter()
        .map(|(_, c)| c.content.author.clone())
        .collect();
    assert_eq!(bug42.claims.len(), 2);
    assert!(authors.contains(&agent_a));
    assert!(authors.contains(&agent_b));
    assert!(!authors.contains(&no_agent));

    // The default read path (Solo trust of just the no-agent identity, what
    // `Workspace::solo_trust` produces for a `kan show` run with no
    // `KAN_AGENT` set) stays exactly as narrow as before this patch -- it
    // does not implicitly start seeing agent-tagged claims.
    let solo = TrustBase::solo(no_agent.clone());
    let view = fold::fold(claims, &solo);
    let bug42 = view
        .subject(&SubjectRef::Local("bug-42".to_string()))
        .unwrap();
    assert_eq!(bug42.claims.len(), 1);
    assert_eq!(bug42.claims[0].1.content.author, no_agent);
}
