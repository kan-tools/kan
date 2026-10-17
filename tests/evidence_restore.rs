#![cfg(feature = "v2-crypto")]
use kan::{
    evidence_crypto as crypto, evidence_delivery as delivery,
    evidence_import::{Plan, Selection},
    evidence_restore::{self as restore, Boundary, Pins},
    evidence_service::{hex, Grant, Service},
    evidence_spool::Spool,
    evidence_store::Ledger,
    sign::Identity,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};
const PRIVATE: [u8; 32] = [42; 32];
const SCOPE: [u8; 32] = [43; 32];
struct Fixture {
    root: tempfile::TempDir,
    writer: Identity,
    did: String,
    plan: String,
    through: u64,
}
impl Fixture {
    fn database(&self) -> PathBuf {
        self.root.path().join("archive/archive.sqlite")
    }
    fn pins(&self) -> Pins<'_> {
        Pins {
            expected_plan: &self.plan,
            scope: SCOPE,
            writer: &self.did,
            recipient_private: PRIVATE,
            max_records: 1000,
        }
    }
    fn output(&self) -> PathBuf {
        self.root.path().join("restored")
    }
    fn restore(&self) -> restore::Error {
        restore::restore(&self.database(), &self.output(), &self.pins()).unwrap_err()
    }
}
fn setup() -> (Fixture, Spool, Service) {
    let root = tempfile::tempdir().unwrap();
    let writer = Identity::generate();
    let server = Identity::generate();
    let spool = Spool::create(
        &root.path().join("spool.sqlite"),
        &hex(&SCOPE),
        writer.did().as_str(),
        server.did().as_str(),
        64 * 1024 * 1024,
    )
    .unwrap();
    let service = Service::new(
        Ledger::create(&root.path().join("archive")).unwrap(),
        SCOPE,
        server,
        vec![Grant {
            principal: writer.did().to_string(),
            append: true,
            inventory: true,
        }],
    )
    .unwrap();
    fs::create_dir(root.path().join("frames")).unwrap();
    (
        Fixture {
            root,
            did: writer.did().to_string(),
            writer,
            plan: String::new(),
            through: 0,
        },
        spool,
        service,
    )
}
fn drain(f: &mut Fixture, spool: &mut Spool, service: &mut Service) {
    while let Some(bytes) = spool.head().unwrap() {
        let reply = service.dispatch(&bytes, 1000).unwrap();
        assert!(reply.reply.result.is_ok(), "{:?}", reply.reply.result);
        let plain =
            delivery::decrypt_request(&bytes, &PRIVATE, &SCOPE, f.writer.did().as_str()).unwrap();
        fs::write(
            f.root.path().join(format!("frames/{}.bin", f.through)),
            plain,
        )
        .unwrap();
        f.through += 1;
        spool.acknowledge(&reply.bytes().unwrap()).unwrap();
    }
}
fn imported(large: bool) -> Fixture {
    let (mut f, mut spool, mut service) = setup();
    let source = f.root.path().join("source");
    fs::create_dir(&source).unwrap();
    let bytes = if large {
        (0..11 * 1024 * 1024 + 17)
            .map(|i| (i % 251) as u8)
            .collect()
    } else {
        b"malformed raw CAR".to_vec()
    };
    fs::write(source.join("repo.car"), bytes).unwrap();
    fs::write(source.join("HEAD"), []).unwrap();
    fs::write(source.join("identity"), b"excluded secret").unwrap();
    let plan = Plan::build(
        &source,
        Selection::Store,
        [44; 32],
        crypto::public_key(&PRIVATE).unwrap(),
        &mut spool,
    )
    .unwrap();
    f.plan = plan.id().into();
    plan.enqueue(&f.plan, &mut spool, &f.writer, 1024).unwrap();
    drain(&mut f, &mut spool, &mut service);
    f
}
fn hash(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}
fn forged(
    paths: &[&str],
    change: impl FnOnce(&mut Value),
    mutate: impl Fn(usize, &mut Vec<u8>),
) -> Fixture {
    let (mut f, mut spool, mut service) = setup();
    let files = paths.iter().map(|path| json!({"path":path,"length":3,"sha256":hash(b"raw"),"chunks":[{"length":3,"sha256":hash(b"raw")}]})).collect::<Vec<_>>();
    let mut doc = json!({"profile":1,"source_id":hex(&[44;32]),"selection":"store","recipient":hex(&crypto::public_key(&PRIVATE).unwrap()),
        "route":{"scope":hex(&SCOPE),"writer":f.writer.did().as_str(),"audience":service.issuer()},
        "inventory":{"root":"/synthetic","files":files.iter().map(|v|json!({"path":v["path"],"length":v["length"],"sha256":v["sha256"]})).collect::<Vec<_>>(),"notices":[],"selected_inventory_complete":true},"files":files});
    change(&mut doc);
    let document = serde_json::to_vec(&doc).unwrap();
    let mut h = Sha256::new();
    h.update(b"tools.kan.import.plan.v1\0");
    h.update(&document);
    f.plan = hex(&h.finalize());
    let complete = serde_json::to_vec(&json!({"plan":f.plan,"observation":"selected-snapshot-queued","recovery_verified":false,"independent_backup":false,"ready_for_cutover":false})).unwrap();
    let count = paths.len() + 2;
    for i in 0..count {
        let (kind, file, body) = if i == 0 {
            ("inventory", None, document.clone())
        } else if i + 1 == count {
            ("complete", None, complete.clone())
        } else {
            ("data", Some(i - 1), b"raw".to_vec())
        };
        let header=serde_json::to_vec(&json!({"version":1,"plan":f.plan,"ordinal":i,"kind":kind,"file":file,"part":0,"parts":1})).unwrap();
        let mut frame = b"KANI\x01".to_vec();
        frame.extend_from_slice(&(header.len() as u32).to_be_bytes());
        frame.extend(header);
        frame.extend(body);
        mutate(i, &mut frame);
        let mut op = Sha256::new();
        op.update(b"tools.kan.import.operation.v1\0");
        op.update(f.plan.as_bytes());
        op.update((i as u64).to_be_bytes());
        delivery::queue(
            &mut spool,
            &f.writer,
            &crypto::public_key(&PRIVATE).unwrap(),
            &op.finalize()[..16].try_into().unwrap(),
            &frame,
        )
        .unwrap();
    }
    drain(&mut f, &mut spool, &mut service);
    f
}
fn cli(f: &Fixture, database: &Path, destination: &Path) -> std::process::Output {
    let key = f.root.path().join("key");
    fs::write(&key, PRIVATE).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
    }
    Command::new(env!("CARGO_BIN_EXE_kan-v2"))
        .arg("restore-import")
        .arg(database)
        .arg(destination)
        .args([
            "--expected-plan",
            &f.plan,
            "--scope",
            &hex(&SCOPE),
            "--writer",
            f.writer.did().as_str(),
            "--recipient-key",
        ])
        .arg(key)
        .output()
        .unwrap()
}
#[test]
fn cli_restores_large_backup_with_derived_damage_and_independent_oracle() {
    let f = imported(true);
    let backup = f.root.path().join("backup.sqlite");
    Ledger::open(&f.root.path().join("archive"))
        .unwrap()
        .backup(&backup)
        .unwrap();
    let sql = rusqlite::Connection::open(&backup).unwrap();
    sql.execute_batch("PRAGMA foreign_keys=OFF;").unwrap();
    sql.execute(
        "UPDATE commits SET scope=zeroblob(32), writer='damaged', cid='damaged-'||sequence",
        [],
    )
    .unwrap();
    sql.execute("DELETE FROM bindings", []).unwrap();
    drop(sql);
    let before = hash(&fs::read(&backup).unwrap());
    let out = cli(&f, &backup, &f.output());
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let report: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(
        report,
        serde_json::from_slice::<Value>(&fs::read(f.output().join("report.json")).unwrap())
            .unwrap()
    );
    for file in ["repo.car", "HEAD"] {
        assert_eq!(
            fs::read(f.output().join("files").join(file)).unwrap(),
            fs::read(f.root.path().join("source").join(file)).unwrap()
        );
    }
    assert!(!f.output().join("files/identity").exists());
    assert!(!report["notices"].as_array().unwrap().is_empty());
    assert_eq!(report["verified_selected_file_bytes"], true);
    assert_eq!(report["claim_signatures"], "not-verified");
    assert_eq!(report["ready_for_cutover"], false);
    assert_eq!(report["server_attestation"], false);
    assert_eq!(report["independent_backup"], false);
    assert_eq!(
        report["operations"].as_array().unwrap().len() as u64,
        f.through
    );
    assert_eq!(report["archive_snapshot"]["through"], f.through);
    assert_eq!(before, hash(&fs::read(&backup).unwrap()));
    let oracle = Command::new("python3")
        .args(["-O", "scripts/verify_import_stream.py"])
        .arg(f.root.path().join("frames"))
        .args(["--expected-plan", &f.plan])
        .output()
        .unwrap();
    assert!(
        oracle.status.success(),
        "{}",
        String::from_utf8_lossy(&oracle.stderr)
    );
    let independent: Value = serde_json::from_slice(&oracle.stdout).unwrap();
    for field in [
        "files",
        "plan",
        "source_id",
        "recipient",
        "route",
        "notices",
        "selected_inventory_complete",
    ] {
        assert_eq!(report[field], independent[field], "{field}");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for p in [
            f.output(),
            f.output().join("files"),
            f.output().join("files/repo.car"),
            f.output().join("plan.json"),
            f.output().join("report.json"),
        ] {
            assert_eq!(fs::metadata(p).unwrap().permissions().mode() & 0o077, 0);
        }
    }
}
#[test]
fn explicit_pins_limits_and_occupied_output_fail_closed() {
    let f = imported(false);
    for which in 0..5 {
        let wrong = hex(&[1; 32]);
        let mut pins = f.pins();
        match which {
            0 => pins.expected_plan = &wrong,
            1 => pins.recipient_private = [1; 32],
            2 => pins.scope = [1; 32],
            3 => pins.writer = "did:key:wrong",
            _ => pins.max_records = 1,
        }
        assert!(restore::restore(&f.database(), &f.output(), &pins).is_err());
        assert!(!f.output().exists());
    }
    fs::create_dir(f.output()).unwrap();
    fs::write(f.output().join("sentinel"), b"keep").unwrap();
    f.restore();
    assert_eq!(fs::read(f.output().join("sentinel")).unwrap(), b"keep");
    assert!(!f.output().join("report.json").exists());
}
#[test]
fn missing_duplicate_and_corrupt_evidence_rejected() {
    for case in 0..3 {
        let f = imported(false);
        let sql = rusqlite::Connection::open(f.database()).unwrap();
        sql.execute_batch("PRAGMA foreign_keys=OFF;").unwrap();
        match case {
            0 => {
                sql.execute(
                    "DELETE FROM commits WHERE sequence=(SELECT MAX(sequence) FROM commits)",
                    [],
                )
                .unwrap();
            }
            1 => {
                // Rewrite only derived uniqueness fields while duplicating authoritative bytes.
                sql.execute("INSERT INTO commits(sequence,cid,scope,writer,operation,position,previous,manifest,receipt) SELECT (SELECT MAX(sequence)+1 FROM commits),'duplicate',zeroblob(32),'duplicate',operation,position,previous,manifest,receipt FROM commits WHERE sequence=1",[]).unwrap();
            }
            _ => {
                sql.execute("UPDATE objects SET bytes=x'00'", []).unwrap();
            }
        }
        drop(sql);
        f.restore();
        assert!(!f.output().join("report.json").exists());
    }
}
#[test]
fn unsafe_paths_prefixes_and_filesystem_collisions_rejected() {
    for paths in [
        vec!["../escape"],
        vec!["/absolute"],
        vec!["a//b"],
        vec!["a\\b"],
        vec!["a:b"],
        vec!["a", "a"],
        vec!["a", "a/b"],
    ] {
        let f = forged(&paths, |_| {}, |_, _| {});
        f.restore();
        assert!(!f.output().exists());
        assert!(!f.root.path().join("escape").exists());
    }
    #[cfg(unix)]
    {
        let f = imported(false);
        std::os::unix::fs::symlink(f.root.path().join("source"), f.output()).unwrap();
        f.restore();
        assert!(!f.root.path().join("source/report.json").exists());
    }
    let f = forged(&["A", "a"], |_| {}, |_, _| {});
    // On case-sensitive filesystems these are distinct valid paths; case folding must fail create-new.
    let result = restore::restore(&f.database(), &f.output(), &f.pins());
    if result.is_err() {
        assert!(!f.output().join("report.json").exists());
    }
}
#[test]
fn signed_hostile_frames_and_plans_never_publish_success() {
    for case in 0..9 {
        let f = forged(
            &["repo.car"],
            |doc| match case {
                0 => doc["files"][0]["chunks"][0]["sha256"] = json!(hex(&[0; 32])),
                1 => {
                    doc["files"][0]["sha256"] = json!(hex(&[0; 32]));
                    doc["inventory"]["files"][0]["sha256"] = json!(hex(&[0; 32]));
                }
                2 => doc["route"]["audience"] = json!("did:key:wrong"),
                3 => doc["files"][0]["chunks"][0]["length"] = json!(524289),
                _ => {}
            },
            |ordinal, frame| match case {
                4 if ordinal == 1 => frame[0] = 0,
                5 if ordinal == 1 => *frame.last_mut().unwrap() = b'!',
                6 if ordinal == 2 => *frame.last_mut().unwrap() = b'!',
                7 if ordinal == 0 => frame[5..9].copy_from_slice(&5000u32.to_be_bytes()),
                8 if ordinal == 0 => {
                    let n = u32::from_be_bytes(frame[5..9].try_into().unwrap()) as usize;
                    let mut doc: Value = serde_json::from_slice(&frame[9 + n..]).unwrap();
                    doc["source_id"] = json!(hex(&[1; 32]));
                    frame.truncate(9 + n);
                    frame.extend(serde_json::to_vec(&doc).unwrap());
                }
                _ => {}
            },
        );
        f.restore();
        assert!(!f.output().join("report.json").exists(), "case {case}");
    }
}
#[test]
fn nested_files_and_plan_namespace_are_preserved() {
    let f = forged(
        &["deep/nested/raw.car", "plan.json", "report.json"],
        |_| {},
        |_, _| {},
    );
    restore::restore(&f.database(), &f.output(), &f.pins()).unwrap();
    for path in ["deep/nested/raw.car", "plan.json", "report.json"] {
        assert_eq!(
            fs::read(f.output().join("files").join(path)).unwrap(),
            b"raw"
        );
    }
}
#[test]
fn interrupted_restore_child() {
    let Ok(dir) = std::env::var("KAN_RESTORE_CRASH_ROOT") else {
        return;
    };
    let plan = std::env::var("KAN_RESTORE_CRASH_PLAN").unwrap();
    let writer = std::env::var("KAN_RESTORE_CRASH_WRITER").unwrap();
    let point = std::env::var("KAN_RESTORE_CRASH_POINT").unwrap();
    let root = Path::new(&dir);
    let _ = restore::restore_observed(
        &root.join("archive/archive.sqlite"),
        &root.join("restored"),
        &Pins {
            expected_plan: &plan,
            scope: SCOPE,
            writer: &writer,
            recipient_private: PRIVATE,
            max_records: 1000,
        },
        |b| {
            if format!("{b:?}") == point {
                std::process::exit(73);
            }
        },
    );
    panic!("did not reach interruption");
}
#[test]
fn abrupt_process_exit_leaves_partial_output_without_completion() {
    for point in [
        Boundary::DirectoryCreated,
        Boundary::ChunkWritten,
        Boundary::FilesSynced,
        Boundary::BeforeReport,
    ] {
        let f = imported(false);
        let output = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "interrupted_restore_child", "--nocapture"])
            .env("KAN_RESTORE_CRASH_ROOT", f.root.path())
            .env("KAN_RESTORE_CRASH_PLAN", &f.plan)
            .env("KAN_RESTORE_CRASH_WRITER", f.writer.did().as_str())
            .env("KAN_RESTORE_CRASH_POINT", format!("{point:?}"))
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(73),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(f.output().exists());
        assert!(!f.output().join("report.json").exists());
        f.restore();
        assert!(!f.output().join("report.json").exists());
    }
}

#[test]
fn raw_frontier_and_records_remain_pinned_across_concurrent_owner_writes() {
    let f = imported(false);
    let reader = kan::evidence_store::RecoveryReader::open(&f.database()).unwrap();
    let before = reader.snapshot().unwrap();
    let sql = rusqlite::Connection::open(f.database()).unwrap();
    sql.execute_batch("PRAGMA foreign_keys=OFF;").unwrap();
    sql.execute("INSERT INTO commits(sequence,cid,scope,writer,operation,position,previous,manifest,receipt) SELECT (SELECT MAX(sequence)+1 FROM commits),'duplicate',zeroblob(32),'duplicate',operation,position,previous,manifest,receipt FROM commits WHERE sequence=1",[]).unwrap();
    assert_eq!(reader.snapshot().unwrap(), before);
    assert!(reader.record(before.through + 1).is_err());
    assert_eq!(
        kan::evidence_store::RecoveryReader::open(&f.database())
            .unwrap()
            .snapshot()
            .unwrap()
            .through,
        before.through + 1
    );
}
