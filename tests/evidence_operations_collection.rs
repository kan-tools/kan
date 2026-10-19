#![cfg(feature = "v2-crypto")]
use kan::{
    evidence_capture::{Health, Observer, Outcome},
    evidence_operations::{Journal, WorkerStatus},
    evidence_operations_collection as collection,
    evidence_spool::Spool,
    sign::Identity,
};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
struct Fixture {
    _dir: tempfile::TempDir,
    source: PathBuf,
    root: PathBuf,
    spool: PathBuf,
}
fn digest(path: &Path) -> Vec<u8> {
    Sha256::digest(std::fs::read(path).unwrap()).to_vec()
}
fn health(n: u64) -> Health {
    Health {
        attempt: format!("{:064x}", 1),
        observer: Observer::Collector,
        observed: n,
        locally_queued: n - 1,
        unconfirmed: 1,
        recording_gap: true,
        remote_acknowledged: false,
        status: Some(200),
        outcome: Some(Outcome::Completed),
    }
}
impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("health");
        let root = dir.path().join("collection");
        let spool = dir.path().join("queue");
        let id = Identity::generate();
        Spool::create(
            &spool,
            &format!("{:064x}", 3),
            id.did().as_str(),
            id.did().as_str(),
            1 << 20,
        )
        .unwrap();
        let mut j = Journal::create(&source, &spool).unwrap();
        j.record(&health(1)).unwrap();
        j.save_worker(&WorkerStatus {
            sampled_at: 1,
            state: "idle".into(),
            queue: Some(Spool::open(&spool).unwrap().status().unwrap()),
            nonempty_since: None,
            last_ack_at: None,
            last_ack_position: None,
            consecutive_failures: 0,
            retry_seconds: 0,
            telemetry_failures: 7,
        })
        .unwrap();
        Self {
            _dir: dir,
            source,
            root,
            spool,
        }
    }
    fn path(&self, id: &str) -> PathBuf {
        self.root.join(format!("generation-{id}.sqlite"))
    }
}
#[test]
fn adoption_rotation_and_history_preserve_bytes_scope_and_worker_history() {
    let f = Fixture::new();
    let source = digest(&f.source);
    collection::adopt(&f.source, &f.root).unwrap();
    assert_eq!(digest(&f.source), source);
    let first = collection::generations(&f.root, 0, 1).unwrap();
    assert_eq!(first.next, Some(1));
    let old = &first.generations[0];
    let sealed = digest(&f.path(&old.id));
    let h = collection::history(&f.root, &old.id).unwrap();
    assert_eq!(h.observed, 1);
    assert!(h.journal.scope.contains("not a collection total"));
    assert_eq!(digest(&f.path(&old.id)), sealed);
    let mut active = Journal::open(&f.root).unwrap();
    active.check_binding(&f.spool, None).unwrap();
    let snapshot = active.snapshot().unwrap();
    assert_eq!(snapshot.observed, 0);
    assert_eq!(
        snapshot.active_generation.as_deref(),
        Some(first.active.as_str())
    );
    assert_eq!(snapshot.worker.unwrap().telemetry_failures, 7);
    assert_eq!(snapshot.journal.reserve_bytes, 262144);
    active.record(&health(2)).unwrap();
    assert!(
        collection::rotate(&f.root).is_err(),
        "active writer holds shared lock"
    );
    assert!(
        Journal::open(&f.path(&first.active)).is_err(),
        "direct generation access bypasses collection locking"
    );
    drop(active);
    collection::rotate(&f.root).unwrap();
    let all = collection::generations(&f.root, 0, 100).unwrap();
    assert_eq!(all.generations.len(), 3);
    assert_eq!(
        collection::history(&f.root, &first.active)
            .unwrap()
            .observed,
        2
    );
    assert_eq!(
        Journal::open(&f.root).unwrap().snapshot().unwrap().observed,
        0
    );
    assert_eq!(digest(&f.source), source);
    assert_eq!(digest(&f.path(&old.id)), sealed);
    assert!(
        collection::history(&f.root, &all.active).is_err(),
        "active generation is not sealed history"
    );
    assert!(all.totals.contains("not additive"));
    assert!(
        collection::adopt(&f.source, &f.root).is_err(),
        "cannot reuse destination"
    );
}
#[test]
fn source_writer_refuses_adoption_before_creating_destination() {
    let f = Fixture::new();
    let held = Journal::open(&f.source).unwrap();
    assert!(collection::adopt(&f.source, &f.root).is_err());
    assert!(!f.root.exists());
    drop(held);
    collection::adopt(&f.source, &f.root).unwrap();
}
#[test]
fn interrupted_rotation_only_selects_published_generation() {
    use collection::Boundary::*;
    for boundary in [
        StagedGeneration,
        SealedHistory,
        StagedManifest,
        PublishedManifest,
        DirectorySynced,
    ] {
        let f = Fixture::new();
        collection::adopt(&f.source, &f.root).unwrap();
        let before = collection::generations(&f.root, 0, 100).unwrap();
        Journal::open(&f.root).unwrap().record(&health(2)).unwrap();
        let old = digest(&f.path(&before.active));
        assert!(collection::rotate_with_hook(&f.root, |b| if b == boundary {
            Err("synthetic interruption".into())
        } else {
            Ok(())
        })
        .is_err());
        let after = collection::generations(&f.root, 0, 100).unwrap();
        let published = matches!(boundary, PublishedManifest | DirectorySynced);
        assert_eq!(after.active != before.active, published, "{boundary:?}");
        assert_eq!(
            digest(&f.path(&before.active)),
            old,
            "sealed source bytes changed"
        );
        let live = Journal::open(&f.root).unwrap().snapshot().unwrap();
        assert_eq!(live.observed, if published { 0 } else { 2 });
        if published {
            assert_eq!(
                collection::history(&f.root, &before.active)
                    .unwrap()
                    .observed,
                2
            );
        }
        collection::rotate(&f.root).unwrap(); // old staged files remain unselected
        assert_eq!(
            collection::generations(&f.root, 0, 100)
                .unwrap()
                .generations
                .len(),
            if published { 4 } else { 3 }
        );
    }
}
#[test]
fn interrupted_adoption_keeps_original_and_never_guesses_a_manifest() {
    use collection::Boundary::*;
    for boundary in [
        StagedGeneration,
        SealedHistory,
        StagedManifest,
        PublishedManifest,
        DirectorySynced,
    ] {
        let f = Fixture::new();
        let original = digest(&f.source);
        assert!(
            collection::adopt_with_hook(&f.source, &f.root, |b| if b == boundary {
                Err("synthetic interruption".into())
            } else {
                Ok(())
            })
            .is_err()
        );
        assert_eq!(digest(&f.source), original);
        assert_eq!(
            Journal::open(&f.root).is_ok(),
            matches!(boundary, PublishedManifest | DirectorySynced)
        );
    }
}
#[test]
fn sealed_corruption_blocks_history_and_rotation_without_poisoning_active_poll() {
    let f = Fixture::new();
    collection::adopt(&f.source, &f.root).unwrap();
    let before = collection::generations(&f.root, 0, 100).unwrap();
    let path = f.path(&before.generations[0].id);
    let mut damaged = std::fs::read(&path).unwrap();
    damaged[200] ^= 1;
    std::fs::write(&path, damaged).unwrap();
    assert!(collection::history(&f.root, &before.generations[0].id).is_err());
    assert!(collection::rotate(&f.root).is_err());
    assert!(Journal::open(&f.root)
        .unwrap()
        .snapshot()
        .unwrap()
        .journal
        .scope
        .contains("sealed history excluded"));
    assert_eq!(
        collection::generations(&f.root, 0, 100).unwrap().active,
        before.active
    );
}
#[test]
fn malformed_membership_and_bounds_are_rejected_without_repair() {
    let f = Fixture::new();
    collection::adopt(&f.source, &f.root).unwrap();
    let path = f.root.join("manifest.json");
    let original = std::fs::read(&path).unwrap();
    let value: serde_json::Value = serde_json::from_slice(&original).unwrap();
    for mutation in 0..5 {
        let mut bad = value.clone();
        match mutation {
            0 => bad["version"] = 99.into(),
            1 => bad["active"] = "../../outside".into(),
            2 => bad["generations"][1]["id"] = bad["generations"][0]["id"].clone(),
            3 => bad["binding"]["scope"] = "wrong-scope".into(),
            _ => bad["active"] = bad["generations"][0]["id"].clone(),
        };
        let bytes = serde_json::to_vec(&bad).unwrap();
        std::fs::write(&path, &bytes).unwrap();
        assert!(Journal::open(&f.root).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
    }
    std::fs::write(&path, original).unwrap();
    assert!(collection::generations(&f.root, 0, 101).is_err());
    assert!(collection::generations(&f.root, 9999, 1).is_err());
}
#[cfg(unix)]
#[test]
fn symlinks_public_paths_and_hardlinked_generations_are_refused() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let f = Fixture::new();
    collection::adopt(&f.source, &f.root).unwrap();
    let alias = f._dir.path().join("alias");
    symlink(&f.root, &alias).unwrap();
    assert!(Journal::open(&alias).is_err());
    let active = collection::generations(&f.root, 0, 100).unwrap().active;
    std::fs::hard_link(f.path(&active), f._dir.path().join("hardlink")).unwrap();
    assert!(Journal::open(&f.root).is_err());
    std::fs::remove_file(f._dir.path().join("hardlink")).unwrap();
    std::fs::set_permissions(&f.root, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(Journal::open(&f.root).is_err());
    std::fs::set_permissions(&f.root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let manifest = f.root.join("manifest.json");
    std::fs::remove_file(&manifest).unwrap();
    symlink(f._dir.path().join("missing"), &manifest).unwrap();
    assert!(Journal::open(&f.root).is_err());
    assert!(collection::rotate(&f.root).is_err());
    assert!(Journal::open(&f.path(&active)).is_err());
}

#[cfg(unix)]
#[test]
fn source_aliases_and_malformed_coordination_files_cannot_bypass_lifetime_locks() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let f = Fixture::new();
    let alias = f._dir.path().join("hardlinked-source");
    std::fs::hard_link(&f.source, &alias).unwrap();
    assert!(Journal::open(&alias).is_err());
    assert!(collection::adopt(&f.source, &f.root).is_err());
    assert!(!f.root.exists());
    std::fs::remove_file(&alias).unwrap();
    let lock = f._dir.path().join("health.lock");
    let before = digest(&f.source);
    std::fs::write(&lock, b"not a coordination lock").unwrap();
    assert!(Journal::open(&f.source).is_err());
    std::fs::write(&lock, b"").unwrap();
    std::fs::set_permissions(&lock, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(Journal::open(&f.source).is_err());
    std::fs::remove_file(&lock).unwrap();
    symlink(f._dir.path().join("missing"), &lock).unwrap();
    assert!(Journal::open(&f.source).is_err());
    assert_eq!(digest(&f.source), before);
}

#[test]
fn wal_format_is_refused_before_sqlite_can_create_untracked_sidecars() {
    for legacy in [false, true] {
        let f = Fixture::new();
        let connection = rusqlite::Connection::open(&f.source).unwrap();
        if legacy {
            connection
                .execute_batch("DROP TABLE control; DROP TABLE reserve; PRAGMA user_version=1")
                .unwrap();
        }
        let mode: String = connection
            .query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))
            .unwrap();
        assert_eq!(mode, "wal");
        drop(connection);
        std::fs::remove_file(f._dir.path().join("health.lock")).unwrap();
        let original = digest(&f.source);
        let files = || {
            let mut names = std::fs::read_dir(f._dir.path())
                .unwrap()
                .map(|e| e.unwrap().file_name())
                .collect::<Vec<_>>();
            names.sort();
            names
        };
        let before = files();
        assert!(
            Journal::open(&f.source).is_err(),
            "WAL-format journals must be refused before SQLite access"
        );
        assert!(collection::adopt(&f.source, &f.root).is_err());
        assert!(
            !f.root.exists(),
            "unsupported source cannot publish a collection"
        );
        assert_eq!(digest(&f.source), original);
        assert_eq!(
            files(),
            before,
            "refusal must not create WAL or SHM sidecars"
        );
    }
}
