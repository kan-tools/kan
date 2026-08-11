//! `.design/v0.7-milestone.md` REQ-3/REQ-4 — concurrent appends, and
//! durability of the root pointer.
//!
//! `tests/log_cross_process_stress.rs` despite its name is *sequential*: a
//! fresh `Log` per append, one after another, in one process. That is a real
//! risk surface (ADR-13's incremental CAR writer) but it is not concurrency,
//! and it is why the defect these tests cover survived a 105-test suite.
//!
//! Here the appends genuinely race, in separate OS processes, the way `kan`
//! actually runs — one process per command, several agents plus `day`
//! (ADR-42) all shelling out to the same binary.

use kan::{
    claim::{Anchor, AuthorId, ClaimBody, ClaimContent, Rkey, SubjectRef},
    sign::Identity,
    store::log::Log,
};

const CHILD_ENV: &str = "KAN_CONCURRENCY_CHILD";
const DIR_ENV: &str = "KAN_CONCURRENCY_DIR";

fn content(identity: &Identity, text: &str) -> ClaimContent {
    ClaimContent {
        author: AuthorId {
            did: identity.did(),
            agent: None,
        },
        workspace: Anchor::Workspace("genesis".to_string()),
        subject: SubjectRef::Local(Rkey::from("shared")),
        body: ClaimBody::Observation {
            text: text.to_string(),
        },
        cites: vec![],
        artifacts: vec![],
        recorded_at: None,
    }
}

/// AC-4. N separate processes append to one log at once; every claim must be
/// reachable from the final root.
///
/// Before the write lock: five concurrent `kan observe` calls returned five
/// distinct CIDs and five exit-0 successes, and two claims survived. The
/// losers' blocks reached the CAR but were unreachable from the winning
/// root, so no kan command could ever see them again.
#[tokio::test(flavor = "multi_thread")]
async fn concurrent_processes_do_not_lose_appends() {
    // Child: append exactly one claim, tagged with our index, then exit.
    if let Ok(idx) = std::env::var(CHILD_ENV) {
        let dir = std::path::PathBuf::from(std::env::var(DIR_ENV).unwrap());
        // LOAD, never generate. The parent wrote this key before spawning, and
        // every child must sign as that one identity — the scenario is one
        // workspace under concurrent commands ("several agents plus `day`
        // shelling out to the same binary", above), not eight strangers.
        //
        // v0.12 REQ-3.5 briefly rewrote this to `Identity::generate()` +
        // `save()` along with 28 genuinely incidental fixtures, which made the
        // eight children mint eight DIDs and race to overwrite a key file
        // nothing then read. Nothing went red — the reachability assertion
        // still held — so it was caught by a cold review counting distinct
        // authors in the final log: 1 before, 9 after.
        let identity = Identity::load_existing(&dir.join("identity")).unwrap();
        let mut log = Log::open_or_create(&dir.join("log"), &identity)
            .await
            .unwrap();
        // Do every expensive, variable-cost step (identity load, CAR read)
        // *before* the barrier, then all children enter `append` together.
        // Without this the children serialize on their own startup jitter and
        // the test passes even with the lock removed — verified by negative
        // control, and the reason this barrier is not incidental scaffolding.
        while !dir.join("GO").exists() {
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        log.append(content(&identity, &format!("claim-{idx}")), &identity)
            .await
            .unwrap();
        return;
    }

    const N: usize = 8;
    let dir = tempfile::tempdir().unwrap();
    let identity = Identity::generate();
    identity.save(&dir.path().join("identity")).unwrap();

    // Seed one claim so the CAR, HEAD and header already exist — the
    // interesting race is contention over an *existing* root, not the
    // first-writer case.
    {
        let mut log = Log::open_or_create(&dir.path().join("log"), &identity)
            .await
            .unwrap();
        log.append(content(&identity, "seed"), &identity)
            .await
            .unwrap();
    }

    let exe = std::env::current_exe().unwrap();
    let children: Vec<_> = (0..N)
        .map(|i| {
            std::process::Command::new(&exe)
                .args([
                    "concurrent_processes_do_not_lose_appends",
                    "--exact",
                    "--nocapture",
                ])
                .env(CHILD_ENV, i.to_string())
                .env(DIR_ENV, dir.path())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .unwrap()
        })
        .collect();

    // Let every child finish opening the log, then release them at once.
    std::thread::sleep(std::time::Duration::from_millis(500));
    std::fs::write(dir.path().join("GO"), "").unwrap();

    for mut child in children {
        assert!(child.wait().unwrap().success(), "a child append failed");
    }

    let mut log = Log::open_or_create(&dir.path().join("log"), &identity)
        .await
        .unwrap();
    let stored = log.iter_all().await.unwrap();

    let texts: std::collections::BTreeSet<String> = stored
        .iter()
        .filter_map(|(_, s)| match &s.claim.content.body {
            ClaimBody::Observation { text } => Some(text.clone()),
            _ => None,
        })
        .collect();

    let missing: Vec<String> = (0..N)
        .map(|i| format!("claim-{i}"))
        .filter(|t| !texts.contains(t))
        .collect();
    assert!(
        missing.is_empty(),
        "{} of {N} concurrent appends were lost and are unreachable from the \
         final root: {missing:?}",
        missing.len()
    );
    assert_eq!(
        stored.len(),
        N + 1,
        "seed claim plus every concurrent append"
    );

    // ONE WORKSPACE, ONE IDENTITY — the premise of the whole scenario, and
    // until v0.12 nothing checked it.
    //
    // A fixture rewrite made each child mint its own key, so eight processes
    // signed as eight different DIDs and raced to overwrite a key file nothing
    // read. Every assertion above still passed: reachability does not care who
    // signed. A cold review found it by counting distinct authors (1 before,
    // 9 after), which is exactly the check that was missing, so it lives here
    // now instead of in a reviewer's head.
    let authors: std::collections::BTreeSet<&str> = stored
        .iter()
        .map(|(_, s)| s.claim.content.author.did.as_str())
        .collect();
    assert_eq!(
        authors.len(),
        1,
        "every append must be signed by the workspace's single identity, but {} \
         distinct authors reached the log: {:?}. Concurrent commands in ONE \
         workspace share ONE key -- if a child minted its own, this test is no \
         longer exercising the race it exists for.",
        authors.len(),
        authors
    );
}

/// REQ-1 under contention: distinct processes must not mint the same
/// `recorded_at`, or byte-identical content collides again and the append-
/// overwrites-append defect returns through the back door.
#[tokio::test(flavor = "multi_thread")]
async fn concurrent_appends_get_strictly_distinct_recording_times() {
    if std::env::var(CHILD_ENV).is_ok() {
        return; // this test spawns no children; guard against the shared harness
    }
    let dir = tempfile::tempdir().unwrap();
    let identity = Identity::generate();
    identity.save(&dir.path().join("identity")).unwrap();

    // Separate `Log` instances over one directory, each unaware of the
    // others — the in-process analogue of separate commands, and enough to
    // exercise the reload-and-floor path without spawning.
    let mut times = Vec::new();
    for i in 0..12 {
        let mut log = Log::open_or_create(&dir.path().join("log"), &identity)
            .await
            .unwrap();
        log.append(content(&identity, &format!("c{i}")), &identity)
            .await
            .unwrap();
        let stored = log.iter_all().await.unwrap();
        times = stored
            .iter()
            .filter_map(|(_, s)| s.claim.content.recorded_at)
            .collect();
    }

    let unique: std::collections::BTreeSet<u64> = times.iter().copied().collect();
    assert_eq!(
        unique.len(),
        times.len(),
        "every append must carry a distinct recorded_at, including across \
         separate Log instances over the same directory"
    );
}

/// AC-5, the prevention half: `HEAD` is replaced atomically, so a reader
/// never observes a partial root, and no temp file is left behind.
#[tokio::test]
async fn head_is_replaced_atomically_and_leaves_no_debris() {
    if std::env::var(CHILD_ENV).is_ok() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let identity = Identity::generate();
    identity.save(&dir.path().join("identity")).unwrap();
    let log_dir = dir.path().join("log");
    let mut log = Log::open_or_create(&log_dir, &identity).await.unwrap();

    for i in 0..3 {
        log.append(content(&identity, &format!("claim-{i}")), &identity)
            .await
            .unwrap();
        let head = std::fs::read_to_string(log_dir.join("HEAD")).unwrap();
        assert!(
            head.trim().parse::<atproto_dasl::Cid>().is_ok(),
            "HEAD must always hold a complete, parseable CID -- never a \
             truncated one from an interrupted write"
        );
        assert!(
            !log_dir.join("HEAD.tmp").exists(),
            "the atomic-rename temp file must not survive a completed append"
        );
    }
}

/// `review/full-pass-v0.12` F1 (`.design/v0.12.0-beta.3-review-fixes.md`
/// REQ-1): a writer that opened during recovery — CAR present, `HEAD` not
/// yet — must not roll back a writer that landed between its open and its
/// append.
///
/// Deterministic version of the review's repro: deleting `HEAD` holds the
/// first-append window open, which is exactly the state a process observes
/// when it opens between another's block persist and `HEAD` write.
#[tokio::test(flavor = "multi_thread")]
async fn a_recovering_writer_adopts_a_head_written_after_its_open() {
    let dir = tempfile::tempdir().unwrap();
    let identity = Identity::generate();
    identity.save(&dir.path().join("identity")).unwrap();
    let log_dir = dir.path().join("log");

    {
        let mut log = Log::open_or_create(&log_dir, &identity).await.unwrap();
        log.append(content(&identity, "claim-1"), &identity)
            .await
            .unwrap();
    }
    std::fs::remove_file(log_dir.join("HEAD")).unwrap();

    // A opens inside the window and holds its recovered view across B's
    // whole append — the interleaving `reload_if_stale`'s early return
    // turned into a rollback.
    let mut a = Log::open_or_create(&log_dir, &identity).await.unwrap();
    {
        let mut b = Log::open_or_create(&log_dir, &identity).await.unwrap();
        b.append(content(&identity, "claim-2"), &identity)
            .await
            .unwrap();
    }
    a.append(content(&identity, "claim-3"), &identity)
        .await
        .unwrap();

    let mut reread = Log::open_or_create(&log_dir, &identity).await.unwrap();
    let stored = reread.iter_all().await.unwrap();
    let texts: std::collections::BTreeSet<String> = stored
        .iter()
        .filter_map(|(_, s)| match &s.claim.content.body {
            ClaimBody::Observation { text } => Some(text.clone()),
            _ => None,
        })
        .collect();
    for want in ["claim-1", "claim-2", "claim-3"] {
        assert!(
            texts.contains(want),
            "{want} is unreachable from the final root; a recovering writer \
             overwrote HEAD with its stale recovered lineage (got {texts:?})"
        );
    }
    assert_eq!(stored.len(), 3);
}

const RECOVERING_CHILD_ENV: &str = "KAN_RECOVERING_CHILD";
const RECOVERING_DIR_ENV: &str = "KAN_RECOVERING_DIR";

/// The same window, contended by 6 recovering processes at once: every
/// append must survive, not just the last writer's.
#[tokio::test(flavor = "multi_thread")]
async fn concurrent_recovering_writers_all_survive() {
    if let Ok(idx) = std::env::var(RECOVERING_CHILD_ENV) {
        let dir = std::path::PathBuf::from(std::env::var(RECOVERING_DIR_ENV).unwrap());
        let identity = Identity::load_existing(&dir.join("identity")).unwrap();
        // Open *before* the barrier, while HEAD is missing — every child
        // takes the recovery path, which is the configuration under test.
        let mut log = Log::open_or_create(&dir.join("log"), &identity)
            .await
            .unwrap();
        while !dir.join("GO").exists() {
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        log.append(content(&identity, &format!("claim-{idx}")), &identity)
            .await
            .unwrap();
        return;
    }

    const N: usize = 6;
    let dir = tempfile::tempdir().unwrap();
    let identity = Identity::generate();
    identity.save(&dir.path().join("identity")).unwrap();

    {
        let mut log = Log::open_or_create(&dir.path().join("log"), &identity)
            .await
            .unwrap();
        log.append(content(&identity, "seed"), &identity)
            .await
            .unwrap();
    }
    std::fs::remove_file(dir.path().join("log").join("HEAD")).unwrap();

    let exe = std::env::current_exe().unwrap();
    let children: Vec<_> = (0..N)
        .map(|i| {
            std::process::Command::new(&exe)
                .args([
                    "concurrent_recovering_writers_all_survive",
                    "--exact",
                    "--nocapture",
                ])
                .env(RECOVERING_CHILD_ENV, i.to_string())
                .env(RECOVERING_DIR_ENV, dir.path())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .unwrap()
        })
        .collect();

    std::thread::sleep(std::time::Duration::from_millis(500));
    std::fs::write(dir.path().join("GO"), "").unwrap();

    for mut child in children {
        assert!(child.wait().unwrap().success(), "a child append failed");
    }

    let mut log = Log::open_or_create(&dir.path().join("log"), &identity)
        .await
        .unwrap();
    let stored = log.iter_all().await.unwrap();
    let texts: std::collections::BTreeSet<String> = stored
        .iter()
        .filter_map(|(_, s)| match &s.claim.content.body {
            ClaimBody::Observation { text } => Some(text.clone()),
            _ => None,
        })
        .collect();
    let missing: Vec<String> = (0..N)
        .map(|i| format!("claim-{i}"))
        .filter(|t| !texts.contains(t))
        .collect();
    assert!(
        missing.is_empty(),
        "{} of {N} recovering writers were rolled back by a later one's \
         stale HEAD rewrite: {missing:?}",
        missing.len()
    );
    assert!(texts.contains("seed"), "the pre-window claim must survive too");
    assert_eq!(stored.len(), N + 1);
}
