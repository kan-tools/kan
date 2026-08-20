//! Two kan binaries, one `.kan/index.sqlite`.
//!
//! This is not a hypothetical configuration. `day` shells out to the
//! *installed* `kan` (ADR-42) while a checkout builds and runs its own, so a
//! repo under active development routinely sees both against one workspace —
//! and the index is the one file they share.
//!
//! v0.11 gives the projection an `origin` column, and the first attempt kept
//! the table called `claims`. That breaks the older binary outright, which
//! was found by running the released one rather than by reasoning about it:
//!
//! ```text
//! $ kan observe ...        # v0.9.2, after a v0.11 build touched the workspace
//! error: sqlite error: NOT NULL constraint failed: claims.origin
//! ```
//!
//! `CREATE TABLE IF NOT EXISTS` leaves the newer table in place, and the
//! older binary's `INSERT` names no `origin`. A disposable cache made every
//! command fail — the store was fine and unreachable, which is the failure
//! shape this project keeps meeting (#150).
//!
//! So the version lives in the *table name*. These tests pin both directions
//! of that: this version does not touch what an older one owns, and an older
//! one's leftovers do not change what this version reads.

use kan::{
    claim::v1::{Anchor, AuthorId, ClaimBody, ClaimContent, Rkey, SubjectRef},
    sign::Identity,
    store::{index::Index, log::Log},
};

/// The `claims` table exactly as kan ≤ v0.10 created it, with a row in it.
fn write_a_legacy_index(path: &std::path::Path) {
    let conn = rusqlite::Connection::open(path).unwrap();
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS claims (
            content_cid TEXT PRIMARY KEY,
            rev         TEXT NOT NULL,
            author_did  TEXT NOT NULL,
            subject_key TEXT NOT NULL,
            kind        TEXT NOT NULL,
            raw         BLOB NOT NULL
         );
         CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
         INSERT INTO claims (content_cid, rev, author_did, subject_key, kind, raw)
            VALUES ('bafyOLD', '3l', 'did:key:zOld', 'Local(\"old\")', 'Observation', x'00');
         INSERT INTO meta (key, value) VALUES ('built_from_root', 'bafyOLDROOT');",
    )
    .unwrap();
}

fn content(did: &str, subject: &str, text: &str) -> ClaimContent {
    ClaimContent {
        author: AuthorId {
            did: did.to_string(),
            agent: None,
        },
        workspace: Anchor::Workspace("test-workspace".to_string()),
        subject: SubjectRef::Local(Rkey::from(subject)),
        body: ClaimBody::Observation {
            text: text.to_string(),
        },
        cites: vec![],
        artifacts: vec![],
        recorded_at: None,
    }
}

/// This version leaves an older version's projection **byte-for-byte alone**:
/// its table, its rows, and its `built_from_root` freshness key.
///
/// The freshness key matters as much as the table. Sharing one
/// `built_from_root` would have each binary concluding a projection the
/// *other* built was up to date, so each would read the other's shape — a
/// quieter failure than the crash, and a worse one.
#[tokio::test]
async fn this_version_does_not_disturb_an_older_binarys_projection() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("index.sqlite");
    write_a_legacy_index(&path);

    let identity = Identity::generate();
    let mut log = Log::open_or_create(&dir.path().join("log"), &identity)
        .await
        .unwrap();
    log.append(content(&identity.did(), "new", "written now"), &identity)
        .await
        .unwrap();
    let claims = log.iter_all().await.unwrap();

    let mut index = Index::open(&path).unwrap();
    index
        .rebuild(&claims, &[], log.current_root().as_ref())
        .unwrap();
    assert_eq!(index.len().unwrap(), 1);
    drop(index);

    let conn = rusqlite::Connection::open(&path).unwrap();
    let legacy_rows: i64 = conn
        .query_row("SELECT COUNT(*) FROM claims", [], |r| r.get(0))
        .expect(
            "the older binary's `claims` table was dropped -- it would rebuild, but a \
                 kan that deletes another kan's cache on every read is not one either can \
                 share a workspace with",
        );
    assert_eq!(
        legacy_rows, 1,
        "an older binary's projected rows were deleted"
    );
    let legacy_root: String = conn
        .query_row(
            "SELECT value FROM meta WHERE key = 'built_from_root'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        legacy_root, "bafyOLDROOT",
        "the older binary's freshness key was overwritten, so it will now trust a \
         projection this version built"
    );
}

/// And the converse: an older binary's leftovers do not leak into what this
/// version reads. Its rows are not this version's rows, and its
/// `built_from_root` is not this version's freshness signal.
#[tokio::test]
async fn an_older_binarys_leftovers_do_not_leak_into_this_version() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("index.sqlite");
    write_a_legacy_index(&path);

    let index = Index::open(&path).unwrap();
    assert!(
        index.is_empty().unwrap(),
        "an older binary's rows were counted as this version's projection"
    );
    assert_eq!(
        index.built_from_root().unwrap(),
        None,
        "an older binary's `built_from_root` was read as this version's, which would skip \
         the rebuild and leave every read answering from an empty projection"
    );
    assert!(
        index.log_authors().unwrap().is_empty(),
        "an older binary's rows became members of TrustBase::Local"
    );
}
