#![cfg(feature = "v2-crypto")]
use kan::{evidence_workspace::Workspace, sign::Identity};
use serde_json::json;
use std::io::Write;
fn identity(n: u8) -> Identity {
    let mut f = tempfile::NamedTempFile::new().unwrap();
    f.write_all(&[n; 32]).unwrap();
    Identity::load_existing(f.path()).unwrap()
}
fn private_directory() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    dir
}
#[test]
fn encrypted_workspace_survives_restart_and_refuses_wrong_keys_substitution_and_overwrite() {
    let dir = private_directory();
    let path = dir.path().join("workspace.sqlite");
    let value = json!({"title":"unique private owner view","targets":["a"],"text":"hidden needle"});
    let w = Workspace::open(&path, identity(6), [8; 32]).unwrap();
    w.put("view", "first", value.clone()).unwrap();
    w.put("view", "first", value.clone()).unwrap();
    assert!(w.put("view", "first", json!({"different":true})).is_err());
    w.put("search-page", "page", json!({"raw":"source secret"}))
        .unwrap();
    drop(w);
    let bytes = std::fs::read(&path).unwrap();
    for plain in [
        "unique private owner view",
        "hidden needle",
        "source secret",
    ] {
        assert!(!bytes.windows(plain.len()).any(|b| b == plain.as_bytes()));
    }
    assert!(Workspace::open(&path, identity(7), [8; 32]).is_err());
    assert!(Workspace::open(&path, identity(6), [9; 32]).is_err());
    let w = Workspace::open(&path, identity(6), [8; 32]).unwrap();
    assert_eq!(w.get("view", "first").unwrap(), Some(value.clone()));
    assert_eq!(w.views().unwrap(), vec![value]);
    drop(w);
    let db = rusqlite::Connection::open(&path).unwrap();
    let copied: Vec<u8> = db
        .query_row(
            "SELECT body FROM entries WHERE kind='search-page'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    db.execute("UPDATE entries SET body=? WHERE kind='view'", [copied])
        .unwrap();
    drop(db);
    let w = Workspace::open(&path, identity(6), [8; 32]).unwrap();
    assert!(w.get("view", "first").is_err());
    assert!(w.views().is_err());
}
#[test]
fn large_projection_chunks_are_authenticated_and_hot_journals_are_not_implicitly_recovered() {
    let dir = private_directory();
    let path = dir.path().join("workspace.sqlite");
    let w = Workspace::open(&path, identity(6), [8; 32]).unwrap();
    let value = json!({"text":"x".repeat(2*1024*1024)});
    w.put("search-page", "large", value.clone()).unwrap();
    assert_eq!(w.get("search-page", "large").unwrap(), Some(value));
    assert!(w
        .put("view", "oversized", json!({"text":"x".repeat(262144)}))
        .is_err());
    drop(w);
    std::fs::write(dir.path().join("workspace.sqlite-journal"), b"interrupted").unwrap();
    assert!(Workspace::open(&path, identity(6), [8; 32]).is_err());
}
#[cfg(unix)]
#[test]
fn workspace_refuses_public_files_symlinks_and_hardlinks() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let dir = private_directory();
    let path = dir.path().join("workspace.sqlite");
    drop(Workspace::open(&path, identity(6), [8; 32]).unwrap());
    let alias = dir.path().join("alias.sqlite");
    symlink(&path, &alias).unwrap();
    assert!(Workspace::open(&alias, identity(6), [8; 32]).is_err());
    std::fs::remove_file(&alias).unwrap();
    std::fs::hard_link(&path, &alias).unwrap();
    assert!(Workspace::open(&path, identity(6), [8; 32]).is_err());
    std::fs::remove_file(&alias).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(Workspace::open(&path, identity(6), [8; 32]).is_err());
}

#[test]
fn workspace_crash_fixture() {
    let Some(path) = std::env::var_os("KAN_WORKSPACE_CRASH_FIXTURE") else {
        return;
    };
    let db = rusqlite::Connection::open(path).unwrap();
    db.execute_batch("PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA cache_size=1; BEGIN IMMEDIATE; UPDATE entries SET body=zeroblob(length(body));").unwrap();
    // Deliberately bypass Drop so SQLite cannot roll back the simulated crash.
    std::process::exit(0);
}

#[test]
fn explicit_workspace_recovery_rolls_back_only_the_new_copy_and_verifies_every_entry() {
    let dir = private_directory();
    let path = dir.path().join("workspace.sqlite");
    let value = json!({"title":"preserve the owner declaration"});
    let large = json!({"text":"source evidence".repeat(12000)});
    let w = Workspace::open(&path, identity(6), [8; 32]).unwrap();
    w.put("view", "first", value.clone()).unwrap();
    w.put("search-page", "large", large.clone()).unwrap();
    assert!(Workspace::recover(
        &path,
        &dir.path().join("active.sqlite"),
        identity(6),
        [8; 32]
    )
    .is_err());
    assert!(!dir.path().join("active.sqlite").exists());
    drop(w);
    assert!(std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "workspace_crash_fixture", "--nocapture"])
        .env("KAN_WORKSPACE_CRASH_FIXTURE", &path)
        .status()
        .unwrap()
        .success());
    let journal = dir.path().join("workspace.sqlite-journal");
    let source_bytes = std::fs::read(&path).unwrap();
    let journal_bytes = std::fs::read(&journal).unwrap();
    assert_eq!(
        &journal_bytes[..8],
        &[0xd9, 0xd5, 0x05, 0xf9, 0x20, 0xa1, 0x63, 0xd7]
    );
    assert!(Workspace::open(&path, identity(6), [8; 32]).is_err());
    let output = dir.path().join("recovered.sqlite");
    let report = Workspace::recover(&path, &output, identity(6), [8; 32]).unwrap();
    assert_eq!(report["authenticated_entries"]["view"], 1);
    assert_eq!(report["rollback_journal_present"], true);
    assert_eq!(report["activation"], "not-performed");
    let restored = Workspace::open(&output, identity(6), [8; 32]).unwrap();
    assert_eq!(restored.get("view", "first").unwrap(), Some(value));
    assert_eq!(restored.get("search-page", "large").unwrap(), Some(large));
    drop(restored);
    assert_eq!(std::fs::read(&path).unwrap(), source_bytes);
    assert_eq!(std::fs::read(&journal).unwrap(), journal_bytes);
    assert!(Workspace::recover(&path, &output, identity(6), [8; 32]).is_err());
    assert!(Workspace::recover(
        &path,
        &dir.path().join("wrong-key.sqlite"),
        identity(6),
        [9; 32]
    )
    .is_err());
    assert_eq!(std::fs::read(&journal).unwrap(), journal_bytes);
}

#[test]
fn workspace_recovery_cli_preserves_history_and_rejects_corrupt_entries_and_journals() {
    let dir = private_directory();
    let path = dir.path().join("workspace.sqlite");
    let w = Workspace::open(&path, identity(6), [8; 32]).unwrap();
    w.put("annotation", "first", json!({"text":"owner note"}))
        .unwrap();
    drop(w);
    let mut signing = tempfile::NamedTempFile::new_in(dir.path()).unwrap();
    signing.write_all(&[6; 32]).unwrap();
    let mut key = tempfile::NamedTempFile::new_in(dir.path()).unwrap();
    key.write_all(&[8; 32]).unwrap();
    let output = dir.path().join("cli.sqlite");
    let run = std::process::Command::new(env!("CARGO_BIN_EXE_kan-v2"))
        .arg("recover-workspace")
        .arg(&path)
        .arg(&output)
        .arg("--signing-key")
        .arg(signing.path())
        .arg("--recipient-key")
        .arg(key.path())
        .output()
        .unwrap();
    assert!(
        run.status.success(),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&run.stdout).unwrap();
    assert_eq!(report["authenticated_entries"]["annotation"], 1);
    let db = rusqlite::Connection::open(&path).unwrap();
    db.execute("UPDATE entries SET body=x'00' WHERE kind='annotation'", [])
        .unwrap();
    drop(db);
    assert!(
        Workspace::recover(&path, &dir.path().join("bad.sqlite"), identity(6), [8; 32]).is_err()
    );
    let journal = dir.path().join("workspace.sqlite-journal");
    std::fs::write(&journal, b"invalid journal").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&journal, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    assert!(Workspace::recover(
        &path,
        &dir.path().join("bad-journal.sqlite"),
        identity(6),
        [8; 32]
    )
    .is_err());
    assert_eq!(std::fs::read(&journal).unwrap(), b"invalid journal");
}

#[test]
fn owner_erasure_removes_ciphertexts_and_fences_delayed_results_across_restart_and_recovery() {
    use kan::evidence_service::{hex, Failure};
    let dir = private_directory();
    let path = dir.path().join("workspace.sqlite");
    let workspace = Workspace::open(&path, identity(6), [8; 32]).unwrap();
    workspace
        .put(
            "annotation",
            "remove",
            json!({"body":"private derived content"}),
        )
        .unwrap();
    workspace
        .put(
            "annotation",
            "keep",
            json!({"body":"unrelated retained note"}),
        )
        .unwrap();
    let db = rusqlite::Connection::open(&path).unwrap();
    let (removed_id, old_bytes): (String, Vec<u8>) = db
        .query_row(
            "SELECT id,body FROM entries WHERE kind='annotation' ORDER BY rowid LIMIT 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    drop(db);
    let selections = vec![
        ("annotation".into(), "remove".into()),
        ("analysis-result".into(), "running-job".into()),
    ];
    let plan = workspace
        .preview_erasure(&selections, hex(&[7; 32]))
        .unwrap();
    assert!(workspace
        .preview_erasure(&[("binding".into(), "binding".into())], hex(&[7; 32]))
        .is_err());
    assert!(workspace.put("erasure", "fake", json!({})).is_err());
    assert!(
        Workspace::open_for_erasure(&path, identity(6), [8; 32]).is_err(),
        "active workspace users fence maintenance"
    );
    assert_eq!(
        workspace.apply_erasure(&plan).unwrap_err(),
        Failure::Unavailable
    );
    drop(workspace);
    let workspace = Workspace::open_for_erasure(&path, identity(6), [8; 32]).unwrap();
    assert!(Workspace::open(&path, identity(6), [8; 32]).is_err());
    assert_eq!(
        workspace.apply_erasure(&plan).unwrap()["state"],
        "workspace-entries-erased"
    );
    workspace.apply_erasure(&plan).unwrap();
    assert!(workspace.get("annotation", "remove").unwrap().is_none());
    assert_eq!(
        workspace.annotations().unwrap(),
        vec![json!({"body":"unrelated retained note"})]
    );
    assert_eq!(
        workspace
            .put(
                "analysis-result",
                "running-job",
                json!({"result":"late provider response"})
            )
            .unwrap_err(),
        Failure::AccessLimited
    );
    assert_eq!(
        workspace
            .put(
                "annotation",
                "remove",
                json!({"body":"private derived content"})
            )
            .unwrap_err(),
        Failure::AccessLimited
    );
    drop(workspace);
    let bytes = std::fs::read(&path).unwrap();
    assert!(
        !bytes.windows(old_bytes.len()).any(|b| b == old_bytes),
        "deleted ciphertext is zeroed in the managed SQLite file"
    );
    let db = rusqlite::Connection::open(&path).unwrap();
    assert_eq!(
        db.query_row("PRAGMA user_version", [], |r| r.get::<_, u32>(0))
            .unwrap(),
        2,
        "older binaries must refuse this profile"
    );
    assert_eq!(
        db.query_row(
            "SELECT count(*) FROM entries WHERE kind='erasure'",
            [],
            |r| r.get::<_, u32>(0)
        )
        .unwrap(),
        2
    );
    // Simulate stale bytes reintroduced through unmanaged database manipulation.
    db.execute(
        "INSERT INTO entries VALUES('annotation',?,?)",
        rusqlite::params![removed_id, old_bytes],
    )
    .unwrap();
    drop(db);
    let workspace = Workspace::open(&path, identity(6), [8; 32]).unwrap();
    assert!(workspace.get("annotation", "remove").unwrap().is_none());
    assert_eq!(workspace.annotations().unwrap().len(), 1);
    drop(workspace);
    assert!(Workspace::recover(
        &path,
        &dir.path().join("invalid-recovery.sqlite"),
        identity(6),
        [8; 32]
    )
    .is_err());
    let workspace = Workspace::open_for_erasure(&path, identity(6), [8; 32]).unwrap();
    workspace.apply_erasure(&plan).unwrap(); // retry scrubs authorized identities again
    drop(workspace);
    let recovered = dir.path().join("recovered.sqlite");
    Workspace::recover(&path, &recovered, identity(6), [8; 32]).unwrap();
    let workspace = Workspace::open(&recovered, identity(6), [8; 32]).unwrap();
    assert!(workspace.get("annotation", "remove").unwrap().is_none());
    assert_eq!(
        workspace
            .put("analysis-result", "running-job", json!({}))
            .unwrap_err(),
        Failure::AccessLimited
    );
    assert_eq!(workspace.annotations().unwrap().len(), 1);
}

#[test]
fn workspace_erasure_refuses_a_stale_plan_without_partially_erasing_other_entries() {
    let dir = private_directory();
    let workspace =
        Workspace::open(&dir.path().join("workspace.sqlite"), identity(6), [8; 32]).unwrap();
    workspace
        .put(
            "annotation",
            "note",
            json!({"body":"retain on stale preview"}),
        )
        .unwrap();
    let plan = workspace
        .preview_erasure(
            &[
                ("annotation".into(), "note".into()),
                ("analysis-result".into(), "job".into()),
            ],
            kan::evidence_service::hex(&[7; 32]),
        )
        .unwrap();
    workspace
        .put(
            "analysis-result",
            "job",
            json!({"result":"arrived after preview"}),
        )
        .unwrap();
    drop(workspace);
    let workspace =
        Workspace::open_for_erasure(&dir.path().join("workspace.sqlite"), identity(6), [8; 32])
            .unwrap();
    assert_eq!(
        workspace.apply_erasure(&plan).unwrap_err(),
        kan::evidence_service::Failure::Conflict
    );
    assert!(workspace.get("annotation", "note").unwrap().is_some());
    assert!(workspace.get("analysis-result", "job").unwrap().is_some());
    let mut foreign = plan;
    foreign.scope = kan::evidence_service::hex(&[0; 32]);
    assert!(workspace.apply_erasure(&foreign).is_err());
}

#[test]
fn workspace_beyond_old_capacity_reopens_writes_and_streams_recovery() {
    let dir = private_directory();
    let source = dir.path().join("large.sqlite");
    let destination = dir.path().join("recovered.sqlite");
    let w = Workspace::open(&source, identity(6), [8; 32]).unwrap();
    let value = json!({"text":"retained before expansion"});
    w.put("view", "before", value.clone()).unwrap();
    drop(w);
    // SQLite permits unused trailing pages. Sparse extension crosses the former
    // open/recovery cap without a huge encrypted fixture or a large RAM buffer.
    let bytes = 257 * 1024 * 1024;
    std::fs::File::options()
        .write(true)
        .open(&source)
        .unwrap()
        .set_len(bytes)
        .unwrap();
    let w = Workspace::open(&source, identity(6), [8; 32]).unwrap();
    assert_eq!(w.get("view", "before").unwrap(), Some(value.clone()));
    w.put("view", "after", json!({"text":"writes remain available"}))
        .unwrap();
    let db = rusqlite::Connection::open(&source).unwrap();
    // Query on the writer's connection is not exposed; a successful reopened
    // read/write above verifies startup no longer rejects the larger file.
    assert_eq!(
        db.query_row("PRAGMA integrity_check", [], |r| r.get::<_, String>(0))
            .unwrap(),
        "ok"
    );
    drop(db);
    drop(w);
    assert!(std::fs::metadata(&source).unwrap().len() >= bytes);
    let report = Workspace::recover(&source, &destination, identity(6), [8; 32]).unwrap();
    assert_eq!(report["authenticated_entries"]["view"], 2);
    assert_eq!(report["originals"], "retained");
    assert!(std::fs::metadata(&source).unwrap().len() >= bytes);
    let recovered = Workspace::open(&destination, identity(6), [8; 32]).unwrap();
    assert_eq!(recovered.get("view", "before").unwrap(), Some(value));
    assert_eq!(
        recovered.get("view", "after").unwrap().unwrap()["text"],
        "writes remain available"
    );
}
