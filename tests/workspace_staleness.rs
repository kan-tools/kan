//! AC-4 (`.design/v0.4-milestone.md`, issue #26): `Workspace::open` skips
//! `Log::iter_all` + `Index::rebuild` when the log's current root CID
//! matches what the index was last built from. Verified black-box, with
//! no instrumentation added to production code: `Index::all_stored_claims`
//! (what every read verb — `show`/`status`/`issues`/`context` — actually
//! consumes) never re-verifies signatures or re-derives content from the
//! log, so directly tampering with the index's stored bytes and then
//! observing whether a subsequent `Workspace::open` leaves that tampering
//! in place (skip — root unchanged) or overwrites it with the log's true
//! content (full rebuild — root changed) is a direct, purely behavioral
//! proof of which path actually ran.

use std::process::Command;

use kan::{actions, sign::Identity, store::index::Index, workspace::Workspace};

/// A git repo with a pre-made `.kan/identity` and the keychain switched off,
/// so opening a workspace here never reaches the OS keychain.
///
/// Both parts are needed, and finding that out is the point: a key file alone
/// still has the keychain consulted to encrypt that key at rest (ADR-66), so
/// only `KAN_NO_KEYCHAIN` actually keeps this off the keychain.
///
/// Why it matters here — this is the one identity-touching test file that ran
/// against the real keychain. An entry is authorised to the exact binary that
/// created it, so *any* rebuild of this test target makes the request hang
/// waiting for a prompt no test run will answer (#96). Not hypothetical:
/// adding a single dev-dependency changed this binary and hung this test.
///
/// The env var is process-global, which is safe here only because it is set
/// before any workspace is opened and no test in this file wants it unset.
fn git_repo() -> tempfile::TempDir {
    std::env::set_var(kan::sign::NO_KEYCHAIN_ENV, "1");
    let dir = tempfile::tempdir().unwrap();
    let kan_dir = dir.path().join(".kan");
    std::fs::create_dir_all(&kan_dir).unwrap();
    Identity::generate()
        .save(&kan_dir.join("identity"))
        .unwrap();
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

/// Directly rewrites the index's stored bytes for `content_cid`, changing
/// the claim's `Observation` text — bypassing `Log`/`actions` entirely, the
/// same way a stale-but-unrebuilt index would diverge from the log's true
/// content in principle (it never can in practice, since every write path
/// rebuilds; this test manufactures the divergence directly to observe
/// whether `Workspace::open` heals it).
fn tamper_with_stored_text(index_path: &std::path::Path, content_cid: &str, new_text: &str) {
    let conn = rusqlite::Connection::open(index_path).unwrap();
    let raw: Vec<u8> = conn
        .query_row(
            "SELECT raw FROM claims_v2 WHERE content_cid = ?1",
            [content_cid],
            |r| r.get(0),
        )
        .unwrap();
    let mut stored: kan::store::log::StoredClaim = atproto_dasl::from_slice(&raw).unwrap();
    match &mut stored.claim.content.body {
        kan::claim::ClaimBody::Observation { text } => *text = new_text.to_string(),
        other => panic!("expected an Observation claim, got {other:?}"),
    }
    let tampered_raw = atproto_dasl::to_vec(&stored).unwrap();
    conn.execute(
        "UPDATE claims_v2 SET raw = ?1 WHERE content_cid = ?2",
        rusqlite::params![tampered_raw, content_cid],
    )
    .unwrap();
}

#[tokio::test]
async fn open_skips_rebuild_when_the_log_root_is_unchanged() {
    let dir = git_repo();

    let mut ws = Workspace::open(dir.path()).await.unwrap();
    let result = actions::observe(
        &mut ws,
        "original text".to_string(),
        Some("bug-42".to_string()),
        vec![],
        None,
        None,
        None,
        None,
    )
    .await
    .unwrap();
    drop(ws);

    let index_path = dir.path().join(".kan/index.sqlite");
    tamper_with_stored_text(&index_path, &result.narrative.cid.to_string(), "TAMPERED");

    // No log write happened in between -- the root is unchanged, so
    // `Workspace::open` should skip the rebuild and leave the tampered
    // index content in place.
    let ws = Workspace::open(dir.path()).await.unwrap();
    let show_out = actions::show(&ws, "bug-42", &ws.solo_trust().unwrap()).unwrap();
    assert!(
        show_out.contains("TAMPERED"),
        "expected the skip to leave tampered index content in place, got: {show_out}"
    );
    drop(ws);

    // Control: a write changes the log's root, so the *next* open must
    // detect the mismatch and do the full rebuild, overwriting the
    // tampered row with the log's true (untampered) content.
    let mut ws = Workspace::open(dir.path()).await.unwrap();
    actions::observe(
        &mut ws,
        "unrelated second claim".to_string(),
        Some("issue-7".to_string()),
        vec![],
        None,
        None,
        None,
        None,
    )
    .await
    .unwrap();
    drop(ws);

    let ws = Workspace::open(dir.path()).await.unwrap();
    let show_out = actions::show(&ws, "bug-42", &ws.solo_trust().unwrap()).unwrap();
    assert!(
        show_out.contains("original text") && !show_out.contains("TAMPERED"),
        "expected the full rebuild (triggered by the intervening write) to \
         overwrite the tampered content with the log's true content, got: {show_out}"
    );
}

#[test]
fn index_built_from_root_round_trips() {
    let dir = tempfile::tempdir().unwrap();
    let mut index = Index::open(&dir.path().join("index.sqlite")).unwrap();

    // Fresh index: no meta row yet.
    assert_eq!(index.built_from_root().unwrap(), None);

    let cid: atproto_dasl::Cid = "bafyreif4au544xcim6pd62nvks5vhgdj5u3tdkqecg4zvjsfqxfj66lnai"
        .parse()
        .unwrap();
    index.rebuild(&[], &[], Some(&cid)).unwrap();
    assert_eq!(index.built_from_root().unwrap(), Some(cid));

    // A subsequent rebuild with no root (log went back to empty, in
    // principle) overwrites rather than leaving the old value stuck.
    index.rebuild(&[], &[], None).unwrap();
    assert_eq!(index.built_from_root().unwrap(), None);
}
