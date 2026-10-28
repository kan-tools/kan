#![cfg(feature = "v2-storage")]
//! Reviewer probe (temporary; copied into tests/ only for execution, then removed).
//! Scope A: profile-2 admitted-only gate across every entry point, with exact reasons,
//! byte preservation, precommit refusal, admitted-only continuity, and CLI behavior.
use kan::{
    evidence_attestation::{self as proof, Context, Frontier, Purpose},
    evidence_service::{hex, Command as Operation, Failure, Grant, Request, Service, SignedRequest},
    evidence_store::{
        attested::{Archive, Binding, Recovery},
        Ledger, RecoveryReader,
    },
    sign::Identity,
};
use sha2::{Digest, Sha256};
use std::{io::Write, path::Path, process::Command};

const REASON: &str = "retained-verified prefix requires copy profile";

fn identity(byte: u8) -> Identity {
    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(&[byte; 32]).unwrap();
    Identity::load_existing(file.path()).unwrap()
}
fn binding() -> Binding {
    Binding { archive: [8; 32], scope: [9; 32], issuer: identity(7).did().to_string() }
}
fn grant_for(writer: u8) -> Grant {
    Grant { principal: identity(writer).did().to_string(), append: true, inventory: false }
}
fn request_to(writer: u8, audience: &str, op: u8, position: u64, previous: Option<String>) -> Vec<u8> {
    let w = identity(writer);
    SignedRequest::sign(
        Request {
            version: 1,
            scope: hex(&[9; 32]),
            audience: audience.into(),
            principal: w.did().to_string(),
            expires: None,
            command: Operation::Append {
                id: hex(&[op; 16]),
                position,
                previous,
                ciphertext: hex(format!("payload {writer} {op}").as_bytes()),
            },
        },
        &w,
    )
    .unwrap()
    .bytes()
    .unwrap()
}
fn ctx(b: &Binding) -> Context<'_> {
    Context { issuer: &b.issuer, archive: b.archive, scope: b.scope }
}
fn conn(root: &Path) -> rusqlite::Connection {
    rusqlite::Connection::open(root.join("archive.sqlite")).unwrap()
}
/// Same construction as tests/evidence_attested_followups.rs::upgraded, single H, n rows.
fn upgraded(n: usize, then_admit: bool) -> (tempfile::TempDir, Vec<tempfile::TempDir>) {
    let target = tempfile::tempdir().unwrap();
    let b = binding();
    drop(Archive::create(target.path(), b.clone()).unwrap());
    let mut sources = Vec::new();
    let mut records = Vec::new();
    for i in 0..n {
        let writer = 20 + i as u8;
        let dir = tempfile::tempdir().unwrap();
        let ledger = Ledger::create(dir.path()).unwrap();
        let mut service = Service::new(ledger, [9; 32], identity(11), vec![grant_for(writer)]).unwrap();
        let req = request_to(writer, identity(11).did().as_str(), 1, 0, None);
        assert!(service.dispatch(&req, 100 + i as u64).unwrap().reply.result.is_ok());
        drop(service);
        let reader = RecoveryReader::open(&dir.path().join("archive.sqlite")).unwrap();
        records.push(reader.record(1).unwrap());
        drop(reader);
        let c = conn(target.path());
        c.execute("ATTACH DATABASE ? AS src", [dir.path().join("archive.sqlite").to_str().unwrap()]).unwrap();
        c.execute_batch(
            "INSERT INTO objects SELECT * FROM src.objects;
             INSERT INTO commits(cid,scope,writer,operation,position,previous,manifest,receipt)
               SELECT cid,scope,writer,operation,position,previous,manifest,receipt FROM src.commits ORDER BY sequence;
             INSERT INTO bindings SELECT * FROM src.bindings;",
        )
        .unwrap();
        sources.push(dir);
    }
    let mut frontier = Frontier::default();
    for (i, r) in records.iter().enumerate() {
        let p = proof::issue(&identity(7), &ctx(&b), &r.manifest, &r.receipt, &frontier, Purpose::RetainedVerified, 900_000 + i as u64).unwrap();
        conn(target.path()).execute("INSERT INTO attestations VALUES(?,?)", rusqlite::params![i as i64 + 1, p.bytes()]).unwrap();
        frontier = p.frontier().clone();
    }
    if then_admit {
        // Append one admitted row by raw SQL+proof (no API path can do this now).
        // Build it via a fresh admitted-only archive's record would require a different chain;
        // instead we only test pure-prefix files here.
    }
    conn(target.path()).execute_batch("PRAGMA wal_checkpoint(TRUNCATE)").unwrap();
    (target, sources)
}
fn digest(path: &Path) -> Vec<Option<(usize, String)>> {
    [path.to_path_buf(), Path::new(&format!("{}-wal", path.display())).to_path_buf()]
        .iter()
        .map(|p| std::fs::read(p).ok().filter(|b| !b.is_empty()).map(|b| (b.len(), format!("{:x}", Sha256::digest(&b)))))
        .collect()
}
fn proofs(path: &Path) -> Vec<Vec<u8>> {
    let c = rusqlite::Connection::open(path).unwrap();
    let mut s = c.prepare("SELECT envelope FROM attestations ORDER BY sequence").unwrap();
    let rows = s.query_map([], |r| r.get(0)).unwrap().map(Result::unwrap).collect();
    rows
}
fn reason<T>(r: Result<T, kan::evidence_store::Error>) -> String {
    match r {
        Ok(_) => "ACCEPTED".into(),
        Err(e) => e.to_string(),
    }
}

/// PA1: every library entry point refuses a single-H plan-less prefix with the exact reason,
/// and the source bytes (main DB + non-empty WAL) are unchanged.
#[test]
fn pa1_every_entry_point_refuses_with_exact_reason_and_preserves_bytes() {
    let (target, _s) = upgraded(2, false);
    let db = target.path().join("archive.sqlite");
    let before = digest(&db);
    let before_proofs = proofs(&db);
    let open = reason(Archive::open(target.path(), binding()));
    let resume = reason(Archive::resume_initialization(target.path(), binding()));
    let verify = reason(Archive::verify_file(&db, binding()));
    let out = tempfile::tempdir().unwrap();
    let rebuilt = out.path().join("rebuilt.sqlite");
    let rec = Recovery::open(&db, binding()).expect("Recovery::open only binds; rebuild audits");
    let rebuild = reason(rec.rebuild(&rebuilt));
    drop(rec);
    println!("open={open}\nresume={resume}\nverify_file={verify}\nrebuild={rebuild}");
    for (name, r) in [("open", &open), ("resume", &resume), ("verify_file", &verify), ("rebuild", &rebuild)] {
        assert!(r.contains(REASON), "{name}: {r}");
    }
    assert_eq!(digest(&db), before, "source main/WAL bytes changed");
    assert_eq!(proofs(&db), before_proofs);
    // Rebuild created only a new empty file; no profile marker or tables committed.
    let meta = std::fs::metadata(&rebuilt).unwrap();
    let c = rusqlite::Connection::open_with_flags(&rebuilt, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    let uv: i64 = c.query_row("PRAGMA user_version", [], |r| r.get(0)).unwrap();
    let tables: i64 = c.query_row("SELECT count(*) FROM sqlite_schema", [], |r| r.get(0)).unwrap();
    println!("rebuilt len={} user_version={uv} schema_objects={tables}", meta.len());
    assert_eq!((uv, tables), (0, 0));
    // The legacy profile-1 readers also refuse the file (no laundering through profile 1).
    assert!(Ledger::open(target.path()).is_err());
    assert!(RecoveryReader::open(&db).is_err());
    assert!(Ledger::verify_file(&db).is_err());
}

/// PA2: an RV proof inserted under an existing verified handle: admit refuses with Corrupt,
/// stages nothing, writes nothing; backup output (if any) cannot verify.
#[test]
fn pa2_existing_handle_admission_and_backup_refuse_without_writes() {
    let temp = tempfile::tempdir().unwrap();
    let mut archive = Archive::create(temp.path(), binding()).unwrap();
    let issuer = binding().issuer;
    let first = archive.admit(&request_to(6, &issuer, 0, 0, None), &identity(7), &grant_for(6), 100).unwrap();
    let config = binding();
    let rv = proof::issue(&identity(7), &ctx(&config), &first.record.manifest, &first.record.receipt, &Frontier::default(), Purpose::RetainedVerified, 101).unwrap();
    conn(temp.path()).execute("UPDATE attestations SET envelope=? WHERE sequence=1", [rv.bytes()]).unwrap();
    let count = |t: &str| -> i64 { conn(temp.path()).query_row(&format!("SELECT count(*) FROM {t}"), [], |r| r.get(0)).unwrap() };
    let before = (count("objects"), count("commits"), count("attestations"));
    let r = archive.admit(&request_to(6, &issuer, 1, 1, Some(first.record.manifest.cid().to_string())), &identity(7), &grant_for(6), 102);
    println!("admit after RV swap: {:?}", r.as_ref().err());
    assert_eq!(r.err(), Some(Failure::Corrupt));
    assert_eq!((count("objects"), count("commits"), count("attestations")), before, "refused admission wrote/staged");
    let v = archive.verify().unwrap_err().to_string();
    assert!(v.contains(REASON), "{v}");
    let backup = temp.path().join("b.sqlite");
    let b = reason(archive.backup(&backup));
    println!("backup={b} output_exists={}", backup.exists());
    assert!(b.contains(REASON), "{b}");
    if backup.exists() {
        assert!(Archive::verify_file(&backup, binding()).is_err(), "retained backup must stay refused");
    }
}

/// PA3: admitted-only histories remain valid across every entry point (no over-refusal).
#[test]
fn pa3_admitted_only_history_still_valid_everywhere() {
    let temp = tempfile::tempdir().unwrap();
    let issuer = binding().issuer;
    let mut archive = Archive::create(temp.path(), binding()).unwrap();
    let mut prev = None;
    for i in 0..4u8 {
        let a = archive.admit(&request_to(6, &issuer, i, i as u64, prev.clone()), &identity(7), &grant_for(6), 100 + i as u64).unwrap();
        assert_eq!(a.attestation.purpose(), Purpose::Admitted);
        prev = Some(a.record.manifest.cid().to_string());
    }
    let frontier = archive.verify().unwrap();
    assert_eq!(frontier.through, 4);
    let backup = temp.path().join("b.sqlite");
    assert_eq!(archive.backup(&backup).unwrap().commits, 4);
    drop(archive);
    let reopened = Archive::open(temp.path(), binding()).unwrap();
    assert_eq!(reopened.verify().unwrap(), frontier);
    drop(reopened);
    let db = temp.path().join("archive.sqlite");
    assert_eq!(Archive::verify_file(&db, binding()).unwrap().commits, 4);
    let rebuilt = temp.path().join("r.sqlite");
    assert_eq!(Recovery::open(&backup, binding()).unwrap().rebuild(&rebuilt).unwrap().commits, 4);
    assert_eq!(proofs(&rebuilt), proofs(&db));
    // Exact retry of an admitted record still returns its stored proof.
    let mut a = Archive::open(temp.path(), binding()).unwrap();
    let retry = a.admit(&request_to(6, &issuer, 0, 0, None), &identity(7), &grant_for(6), 300).unwrap();
    assert!(retry.record.duplicate);
    assert_eq!(retry.attestation.purpose(), Purpose::Admitted);
}

/// PA4: CLI verify/backup/recover with explicit pins refuse an RV-prefix file, preserve bytes,
/// create no backup output, and leave only an unmarked empty recovery output.
#[test]
fn pa4_cli_entry_points_refuse_plan_less_prefix() {
    fn run(args: &[&str]) -> std::process::Output {
        Command::new(env!("CARGO_BIN_EXE_kan-v2")).args(args).output().unwrap()
    }
    let (target, _s) = upgraded(1, false);
    let db = target.path().join("archive.sqlite");
    let before = digest(&db);
    let b = binding();
    let (ah, sh) = (hex(&b.archive), hex(&b.scope));
    let pins = ["--proof-archive", ah.as_str(), "--proof-scope", sh.as_str(), "--proof-issuer", b.issuer.as_str()];
    let out = tempfile::tempdir().unwrap();
    let backup = out.path().join("backup.sqlite");
    let rebuilt = out.path().join("rebuilt.sqlite");
    let unpinned = out.path().join("u.sqlite");
    let cases: Vec<(&str, Vec<&str>)> = vec![
        ("verify", [vec!["verify", db.to_str().unwrap()], pins.to_vec()].concat()),
        ("backup", [vec!["backup", target.path().to_str().unwrap(), backup.to_str().unwrap()], pins.to_vec()].concat()),
        ("recover", [vec!["recover", db.to_str().unwrap(), rebuilt.to_str().unwrap()], pins.to_vec()].concat()),
        ("verify-unpinned", vec!["verify", db.to_str().unwrap()]),
        ("recover-unpinned", vec!["recover", db.to_str().unwrap(), unpinned.to_str().unwrap()]),
    ];
    for (name, args) in cases {
        let o = run(&args);
        let stderr = String::from_utf8_lossy(&o.stderr);
        println!("{name}: status={:?} stdout_len={} stderr={}", o.status.code(), o.stdout.len(), stderr.trim());
        assert!(!o.status.success(), "{name}");
        assert!(o.stdout.is_empty(), "{name} printed success JSON");
        if !name.ends_with("unpinned") {
            assert!(stderr.contains(REASON), "{name}: {stderr}");
        }
    }
    assert!(!backup.exists(), "backup opens/audits before creating output");
    let c = rusqlite::Connection::open_with_flags(&rebuilt, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    assert_eq!(c.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0)).unwrap(), 0);
    assert_eq!(digest(&db), before);
}
