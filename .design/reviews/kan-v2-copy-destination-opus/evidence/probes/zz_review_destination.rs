//! REVIEWER PROBES (cold review of d9b2110). Temporary; copied into tests/ only
//! while running, then removed. Synthetic fixtures only. Each probe prints
//! PROBE lines; asserts encode the contract claim being challenged.
#![cfg(feature = "v2-storage")]
use kan::{
    evidence_attestation::Purpose,
    evidence_copy_plan::Target,
    evidence_service::{self as service, Command, Grant, Request, Service, SignedRequest},
    evidence_store::{
        attested,
        copied::{Archive, Budget, Recovery},
        copy_upgrade::PlannedCopy,
        Ledger, RecoveryReader, MAX_CHUNK,
    },
    sign::Identity,
};
use std::{
    io::Write,
    path::{Path, PathBuf},
};

fn identity(n: u8) -> Identity {
    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(&[n; 32]).unwrap();
    Identity::load_existing(file.path()).unwrap()
}
fn request(writer: u8, audience: u8, n: u8, previous: Option<String>) -> Vec<u8> {
    let signer = identity(writer);
    SignedRequest::sign(
        Request {
            version: 1,
            scope: service::hex(&[1; 32]),
            principal: signer.did().to_string(),
            audience: identity(audience).did().to_string(),
            expires: None,
            command: Command::Append {
                id: service::hex(&[n + 1; 16]),
                position: n as u64,
                previous,
                ciphertext: service::hex(b"synthetic opaque payload"),
            },
        },
        &signer,
    )
    .unwrap()
    .bytes()
    .unwrap()
}
fn grant(writer: u8) -> Grant {
    Grant {
        principal: identity(writer).did().to_string(),
        append: true,
        inventory: false,
    }
}
/// Returns (source db path, list of original request bytes).
fn fixture_h(parent: &Path, records: usize, staged: usize, h: u8) -> (PathBuf, Vec<Vec<u8>>) {
    let root = parent.join("source");
    let mut s = Service::new(Ledger::create(&root).unwrap(), [1; 32], identity(h), vec![grant(6)]).unwrap();
    let mut previous = None;
    let mut reqs = Vec::new();
    for n in 0..records {
        let bytes = request(6, h, n as u8, previous);
        assert!(s.dispatch(&bytes, 100 + n as u64).unwrap().reply.result.is_ok());
        previous = Some(service::append_manifest(&bytes).unwrap().cid().to_string());
        reqs.push(bytes);
    }
    drop(s);
    let mut ledger = Ledger::open(&root).unwrap();
    for n in 0..staged {
        ledger.stage(&vec![n as u8; 17 + n]).unwrap();
    }
    drop(ledger);
    (root.join("archive.sqlite"), reqs)
}
fn fixture(parent: &Path, records: usize, staged: usize) -> PathBuf {
    fixture_h(parent, records, staged, 7).0
}
fn source_h(path: &Path, h: u8) -> PlannedCopy {
    PlannedCopy::open(
        path,
        Target { scope: [1; 32], issuer: identity(8).did().to_string() },
        identity(h).did().to_string(),
        [9; 32],
    )
    .unwrap()
}
fn source(path: &Path) -> PlannedCopy {
    source_h(path, 7)
}
fn binding(s: &PlannedCopy) -> attested::Binding {
    attested::Binding { archive: s.plan().archive_id(), scope: [1; 32], issuer: identity(8).did().to_string() }
}
fn small() -> Budget {
    Budget { objects: 1, records: 1, bytes: MAX_CHUNK }
}
fn finish(a: &mut Archive, s: &PlannedCopy) {
    for n in 0..40 {
        if a.verify().unwrap().copy.source_copy_complete {
            return;
        }
        a.copy_batch(s, &identity(8), 1000 + n, small()).unwrap();
    }
    panic!("did not finish");
}
fn counts(db: &Path) -> (i64, i64, i64, i64) {
    let c = rusqlite::Connection::open_with_flags(db, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    let q = |t: &str| c.query_row(&format!("SELECT count(*) FROM {t}"), [], |r| r.get::<_, i64>(0)).unwrap();
    (q("objects"), q("commits"), q("attestations"), q("upgrade_objects"))
}
fn rows(db: &Path) -> Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let c = rusqlite::Connection::open_with_flags(db, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    let mut q = c.prepare("SELECT manifest,receipt,envelope FROM commits JOIN attestations USING(sequence) ORDER BY sequence").unwrap();
    q.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).unwrap().map(Result::unwrap).collect()
}
fn read_opt(p: &Path) -> Option<Vec<u8>> {
    std::fs::read(p).ok()
}
fn cli(args: &[&str]) -> std::process::Output {
    std::process::Command::new(env!("CARGO_BIN_EXE_kan-v2")).args(args).output().unwrap()
}
fn show(label: &str, o: &std::process::Output) {
    println!(
        "PROBE {label}: exit={:?} stdout={} stderr={}",
        o.status.code(),
        String::from_utf8_lossy(&o.stdout).trim().replace('\n', " "),
        String::from_utf8_lossy(&o.stderr).trim().replace('\n', " ")
    );
}
fn private_key(dir: &Path, n: u8) -> PathBuf {
    let key = dir.join(format!("key-{n}"));
    std::fs::write(&key, [n; 32]).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    key
}
struct Cli {
    scope: String,
    issuer: String,
    old: String,
    nonce: String,
}
fn cli_ids() -> Cli {
    Cli {
        scope: service::hex(&[1; 32]),
        issuer: identity(8).did().to_string(),
        old: identity(7).did().to_string(),
        nonce: service::hex(&[9; 32]),
    }
}
fn copy_plan(db: &Path, plan: &Path, ids: &Cli) -> std::process::Output {
    cli(&["copy-plan", db.to_str().unwrap(), plan.to_str().unwrap(), "--scope", &ids.scope, "--issuer", &ids.issuer, "--historical-issuer", &ids.old, "--nonce", &ids.nonce])
}
fn copy_batch(db: &Path, root: &Path, plan: &Path, key: &Path, pin: &str, ids: &Cli, extra: &[&str]) -> std::process::Output {
    let mut a = vec!["copy-batch", db.to_str().unwrap(), root.to_str().unwrap(), "--plan", plan.to_str().unwrap(), "--key", key.to_str().unwrap(), "--copy-profile", "--proof-archive", pin, "--proof-scope", &ids.scope, "--proof-issuer", &ids.issuer];
    a.extend(extra);
    cli(&a)
}

/// P-A: the CLI's private plan artifact can be created under a SQLite sidecar
/// name belonging to the pinned source. Backup/recovery destinations refuse
/// this (sqlite_destination); does copy-plan?
#[test]
fn probe_a_plan_artifact_at_source_sidecar_name() {
    let t = tempfile::tempdir().unwrap();
    let db = fixture(t.path(), 2, 1);
    let ids = cli_ids();
    let src_dir = db.parent().unwrap();
    for (i, suffix) in ["-journal", "-wal", "-shm"].iter().enumerate() {
        let plan = PathBuf::from(format!("{}{}", db.display(), suffix));
        let existed = plan.exists();
        let main_before = std::fs::read(&db).unwrap();
        let out = copy_plan(&db, &plan, &ids);
        show(&format!("A{i} copy-plan PLAN=<source>{suffix} (existed_before={existed})"), &out);
        let created = out.status.success();
        println!("PROBE A{i} plan exists after copy-plan: {} ; source main unchanged: {}", plan.exists(), std::fs::read(&db).unwrap() == main_before);
        if !created {
            continue;
        }
        let pin = serde_json::from_slice::<serde_json::Value>(&out.stdout).unwrap()["archive"].as_str().unwrap().to_owned();
        let plan_bytes = std::fs::read(&plan).unwrap();
        // The same user-facing path the design documents: copy-batch next.
        let key = private_key(t.path(), 8);
        let root = t.path().join(format!("copy-{i}"));
        let out = copy_batch(&db, &root, &plan, &key, &pin, &ids, &[]);
        show(&format!("A{i} copy-batch with that plan"), &out);
        println!("PROBE A{i} plan bytes intact after copy-batch: {:?}", read_opt(&plan).map(|b| b == plan_bytes));
        // Ordinary legacy writer open of the source (e.g. the old service restarting).
        let opened = Ledger::open(src_dir).map(|_| ());
        println!("PROBE A{i} legacy Ledger::open(source) -> {opened:?}");
        println!("PROBE A{i} plan bytes intact after legacy source open: {:?}", read_opt(&plan).map(|b| b == plan_bytes));
        println!("PROBE A{i} source main unchanged after all: {}", std::fs::read(&db).unwrap() == main_before);
        let reopened = PlannedCopy::open(&db, Target { scope: [1; 32], issuer: ids.issuer.clone() }, ids.old.clone(), [9; 32]).map(|p| service::hex(&p.plan().archive_id()));
        println!("PROBE A{i} re-plan of source after -> {:?} (pin was {pin})", reopened.as_ref().map(|s| s == &pin));
        let _ = std::fs::remove_file(&plan);
    }
}

/// P-B: destination root equal to the source directory (create and --resume),
/// with a live non-empty source WAL held by an in-process legacy writer.
#[test]
fn probe_b_destination_is_source_directory() {
    let t = tempfile::tempdir().unwrap();
    let db = fixture(t.path(), 2, 1);
    let ids = cli_ids();
    let plan = t.path().join("plan.cbor");
    let out = copy_plan(&db, &plan, &ids);
    assert!(out.status.success());
    let pin = serde_json::from_slice::<serde_json::Value>(&out.stdout).unwrap()["archive"].as_str().unwrap().to_owned();
    let key = private_key(t.path(), 8);
    let src_dir = db.parent().unwrap().to_path_buf();
    let wal = PathBuf::from(format!("{}-wal", db.display()));
    let main_before = std::fs::read(&db).unwrap();
    let wal_before = read_opt(&wal);
    println!("PROBE B wal present before: {:?} bytes", wal_before.as_ref().map(Vec::len));
    for extra in [&[][..], &["--resume"][..]] {
        let out = copy_batch(&db, &src_dir, &plan, &key, &pin, &ids, extra);
        show(&format!("B copy-batch DEST=<source dir> {extra:?}"), &out);
        assert!(!out.status.success());
        assert_eq!(std::fs::read(&db).unwrap(), main_before, "source main changed");
        assert_eq!(read_opt(&wal), wal_before, "source WAL changed");
    }
    assert!(PlannedCopy::confirm(&db, &kan::evidence_store::copy_upgrade::read_plan(&plan, &service::unhex(&pin, 32).unwrap().try_into().unwrap()).unwrap(), &service::unhex(&pin, 32).unwrap().try_into().unwrap()).is_ok());
    println!("PROBE B source still confirms against the plan after both refusals");
}

/// P-C: profile-3 schema drift (extra index/trigger/view) at every entry point.
#[test]
fn probe_c_profile3_unsupported_schema() {
    for (i, sql) in [
        "CREATE INDEX extra_len ON upgrade_objects(length)",
        "CREATE TRIGGER extra AFTER INSERT ON upgrade_objects BEGIN SELECT 1; END",
        "CREATE VIEW extra AS SELECT * FROM upgrade_objects",
        "CREATE TABLE upgrade_progress(n INTEGER)",
    ]
    .iter()
    .enumerate()
    {
        let t = tempfile::tempdir().unwrap();
        let db = fixture(t.path(), 2, 1);
        let s = source(&db);
        let root = t.path().join("copy");
        let pins = binding(&s);
        let mut a = Archive::create(&root, &s, pins.clone()).unwrap();
        a.copy_batch(&s, &identity(8), 1000, small()).unwrap();
        drop(a);
        let out = root.join("archive.sqlite");
        rusqlite::Connection::open(&out).unwrap().execute_batch(sql).unwrap();
        let before = std::fs::read(&out).unwrap();
        let open = Archive::open(&root, pins.clone()).map(|_| ());
        let verify = Archive::verify_file(&out, pins.clone()).map(|v| v.copy);
        let resume = Archive::resume_initialization(&root, &s, pins.clone()).map(|_| ());
        let rebuilt = t.path().join("rebuilt.sqlite");
        let rebuild = Recovery::open(&out, pins.clone()).and_then(|r| r.rebuild(&rebuilt)).map(|v| v.copy.source_copy_complete);
        println!("PROBE C{i} [{sql}] open={open:?} verify_file={verify:?} resume={resume:?} rebuild={rebuild:?}");
        assert!(open.is_err() && verify.is_err() && resume.is_err(), "C{i} accepted unsupported schema");
        assert_eq!(std::fs::read(&out).unwrap(), before);
        if rebuild.is_ok() {
            // Rebuild output must carry the exact profile-3 schema, not the drift.
            let c = rusqlite::Connection::open(&rebuilt).unwrap();
            let n: i64 = c.query_row("SELECT count(*) FROM sqlite_schema WHERE name LIKE 'extra%' OR name='upgrade_progress'", [], |r| r.get(0)).unwrap();
            println!("PROBE C{i} rebuild output carries drift objects: {n}");
            assert_eq!(n, 0);
        }
    }
}

/// P-D: every non-profile-3 entry point refuses a profile-3 file (and the
/// reverse), with unchanged bytes.
#[test]
fn probe_d_cross_profile_entry_points() {
    let t = tempfile::tempdir().unwrap();
    let db = fixture(t.path(), 2, 1);
    let s = source(&db);
    let root = t.path().join("copy");
    let pins = binding(&s);
    let mut a = Archive::create(&root, &s, pins.clone()).unwrap();
    finish(&mut a, &s);
    a.admit(&request(9, 8, 0, None), &identity(8), &grant(9), 300).unwrap();
    drop(a);
    let out = root.join("archive.sqlite");
    let before = std::fs::read(&out).unwrap();
    let r: Vec<(&str, Result<(), String>)> = vec![
        ("Ledger::open", Ledger::open(&root).map(|_| ()).map_err(|e| e.to_string())),
        ("Ledger::resume_initialization", Ledger::resume_initialization(&root).map(|_| ()).map_err(|e| e.to_string())),
        ("Ledger::verify_file", Ledger::verify_file(&out).map(|_| ()).map_err(|e| e.to_string())),
        ("RecoveryReader::open", RecoveryReader::open(&out).map(|_| ()).map_err(|e| e.to_string())),
        ("attested::Archive::open", attested::Archive::open(&root, pins.clone()).map(|_| ()).map_err(|e| e.to_string())),
        ("attested::Archive::resume_initialization", attested::Archive::resume_initialization(&root, pins.clone()).map(|_| ()).map_err(|e| e.to_string())),
        ("attested::Archive::verify_file", attested::Archive::verify_file(&out, pins.clone()).map(|_| ()).map_err(|e| e.to_string())),
        ("attested::Recovery::open", attested::Recovery::open(&out, pins.clone()).map(|_| ()).map_err(|e| e.to_string())),
        ("PlannedCopy::open(profile3 as source)", PlannedCopy::open(&out, Target { scope: [1; 32], issuer: identity(8).did().to_string() }, identity(8).did().to_string(), [3; 32]).map(|_| ()).map_err(|e| e.to_string())),
    ];
    for (name, res) in &r {
        println!("PROBE D {name} on profile-3 -> {res:?}");
        assert!(res.is_err(), "{name} accepted profile 3");
    }
    assert_eq!(std::fs::read(&out).unwrap(), before);
    let ids = cli_ids();
    let pin = service::hex(&pins.archive);
    let p = ["--proof-archive", pin.as_str(), "--proof-scope", ids.scope.as_str(), "--proof-issuer", ids.issuer.as_str()];
    let o = cli(&["verify", out.to_str().unwrap()]);
    show("D cli verify (no pins) on profile-3", &o);
    assert!(!o.status.success());
    let mut v = vec!["verify", out.to_str().unwrap()];
    v.extend(p);
    let o = cli(&v);
    show("D cli verify (profile-2 pins, no --copy-profile) on profile-3", &o);
    assert!(!o.status.success());
    let o = cli(&["read-record", out.to_str().unwrap(), "1"]);
    show("D cli read-record on profile-3", &o);
    assert!(!o.status.success());
    let mut w = vec!["verify", out.to_str().unwrap(), "--copy-profile"];
    w.extend(p);
    let o = cli(&w);
    show("D cli verify --copy-profile on profile-3 (positive control)", &o);
    assert!(o.status.success());
    assert_eq!(std::fs::read(&out).unwrap(), before);

    // Reverse: profile-2 and profile-1 files through every profile-3 entry point.
    let p2root = t.path().join("p2");
    drop(attested::Archive::create(&p2root, pins.clone()).unwrap());
    let p2 = p2root.join("archive.sqlite");
    for (label, rroot, file) in [("profile-2", p2root.as_path(), p2.clone()), ("profile-1", db.parent().unwrap(), db.clone())] {
        let b = std::fs::read(&file).unwrap();
        let res = [
            ("copied::Archive::open", Archive::open(rroot, pins.clone()).map(|_| ()).map_err(|e| e.to_string())),
            ("copied::Archive::resume_initialization", Archive::resume_initialization(rroot, &s, pins.clone()).map(|_| ()).map_err(|e| e.to_string())),
            ("copied::Archive::verify_file", Archive::verify_file(&file, pins.clone()).map(|_| ()).map_err(|e| e.to_string())),
            ("copied::Recovery::open", Recovery::open(&file, pins.clone()).map(|_| ()).map_err(|e| e.to_string())),
        ];
        for (name, res) in &res {
            println!("PROBE D {name} on {label} -> {res:?}");
            assert!(res.is_err(), "{name} accepted {label}");
        }
        let mut w = vec!["verify", file.to_str().unwrap(), "--copy-profile"];
        w.extend(p);
        let o = cli(&w);
        show(&format!("D cli verify --copy-profile on {label}"), &o);
        assert!(!o.status.success());
        assert_eq!(std::fs::read(&file).unwrap(), b, "{label} bytes changed");
    }
}

/// P-E: admission refusal at every incomplete state, before staging.
#[test]
fn probe_e_incomplete_admission_matrix() {
    let t = tempfile::tempdir().unwrap();
    let db = fixture(t.path(), 2, 2);
    let s = source(&db);
    let root = t.path().join("copy");
    let mut a = Archive::create(&root, &s, binding(&s)).unwrap();
    let out = root.join("archive.sqlite");
    let mut states = 0;
    loop {
        let st = a.verify().unwrap().copy;
        if st.source_copy_complete {
            break;
        }
        let before = counts(&out);
        let r = a.admit(&request(9, 8, 0, None), &identity(8), &grant(9), 200);
        let after = counts(&out);
        println!("PROBE E state={st:?} counts(obj,commits,proofs,orig)={before:?} admit={:?} counts_after={after:?}", r.as_ref().map(|_| ()));
        assert!(matches!(r, Err(service::Failure::Conflict)), "{r:?}");
        assert_eq!(before, after, "staged or wrote during incomplete copy");
        a.copy_batch(&s, &identity(8), 1000 + states, small()).unwrap();
        states += 1;
    }
    println!("PROBE E incomplete states exercised: {states}");
    assert!(states >= 5);
    let r = a.admit(&request(9, 8, 0, None), &identity(8), &grant(9), 200).unwrap();
    assert_eq!(r.attestation.purpose(), Purpose::Admitted);
    // Grant checks remain current: no-append and wrong-principal grants refuse.
    let mut g = grant(11);
    g.append = false;
    let before = counts(&out);
    let r1 = a.admit(&request(11, 8, 0, None), &identity(8), &g, 201).map(|_| ());
    let r2 = a.admit(&request(11, 8, 0, None), &identity(8), &grant(10), 201).map(|_| ());
    let r3 = a.admit(&request(11, 7, 0, None), &identity(8), &grant(11), 201).map(|_| ());
    println!("PROBE E no-append={r1:?} wrong-principal={r2:?} historical-audience={r3:?}");
    assert!(matches!(r1, Err(service::Failure::AccessLimited)) && matches!(r2, Err(service::Failure::AccessLimited)) && matches!(r3, Err(service::Failure::AccessLimited)));
    assert_eq!(counts(&out), before);
}

/// P-F: H == C. An exact retry of a copied original request through ordinary
/// admission must not relabel or re-sign, before or after completion.
#[test]
fn probe_f_exact_retry_of_copied_request_with_h_equal_c() {
    let t = tempfile::tempdir().unwrap();
    let (db, reqs) = fixture_h(t.path(), 2, 0, 8);
    let s = source_h(&db, 8);
    let root = t.path().join("copy");
    let mut a = Archive::create(&root, &s, binding(&s)).unwrap();
    let out = root.join("archive.sqlite");
    a.copy_batch(&s, &identity(8), 1000, Budget { objects: 100, records: 1, bytes: MAX_CHUNK }).unwrap();
    let mid = rows(&out);
    let r = a.admit(&reqs[0], &identity(8), &grant(6), 200).map(|x| x.attestation.purpose());
    println!("PROBE F retry of copied seq1 while incomplete -> {r:?}");
    assert!(r.is_err());
    assert_eq!(rows(&out), mid);
    finish(&mut a, &s);
    let done = rows(&out);
    let c0 = counts(&out);
    for (i, req) in reqs.iter().enumerate() {
        let r = a.admit(req, &identity(8), &grant(6), 200).map(|x| x.attestation.purpose());
        println!("PROBE F retry of copied seq{} after completion -> {r:?}", i + 1);
        assert!(!matches!(r, Ok(Purpose::Admitted)));
    }
    assert_eq!(rows(&out), done);
    println!("PROBE F counts before/after retries {c0:?} {:?}", counts(&out));
}

/// P-G: CLI end-to-end against a WAL-backed source held open by a legacy writer:
/// main DB and WAL bytes unchanged through plan, all batches, verify, backup, recover.
#[test]
fn probe_g_cli_wal_source_invariance() {
    let t = tempfile::tempdir().unwrap();
    let db = fixture(t.path(), 3, 2);
    let mut writer = Ledger::open(db.parent().unwrap()).unwrap();
    writer.stage(b"staged into the live WAL before planning").unwrap();
    let wal = PathBuf::from(format!("{}-wal", db.display()));
    let main_before = std::fs::read(&db).unwrap();
    let wal_before = std::fs::read(&wal).unwrap();
    println!("PROBE G wal bytes before: {}", wal_before.len());
    assert!(!wal_before.is_empty());
    let ids = cli_ids();
    let plan = t.path().join("plan.cbor");
    let o = copy_plan(&db, &plan, &ids);
    show("G copy-plan", &o);
    let pin = serde_json::from_slice::<serde_json::Value>(&o.stdout).unwrap()["archive"].as_str().unwrap().to_owned();
    let key = private_key(t.path(), 8);
    let root = t.path().join("copy");
    let mut extra: Vec<&str> = vec!["--objects", "2", "--records", "1"];
    let mut done = false;
    for n in 0..20 {
        let o = copy_batch(&db, &root, &plan, &key, &pin, &ids, &extra);
        if n < 2 {
            show(&format!("G copy-batch #{n}"), &o);
        }
        assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
        let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
        assert_eq!(v["promoted"], false);
        assert_eq!(v["activated"], false);
        if n == 0 {
            extra.push("--resume");
        }
        if v["copy"]["source_copy_complete"] == true {
            show(&format!("G copy-batch final #{n}"), &o);
            done = true;
            break;
        }
    }
    assert!(done);
    let p = ["--copy-profile", "--proof-archive", pin.as_str(), "--proof-scope", ids.scope.as_str(), "--proof-issuer", ids.issuer.as_str()];
    let out = root.join("archive.sqlite");
    let mut v = vec!["verify", out.to_str().unwrap()];
    v.extend(p);
    show("G verify", &cli(&v));
    assert_eq!(std::fs::read(&db).unwrap(), main_before, "source main changed");
    assert_eq!(std::fs::read(&wal).unwrap(), wal_before, "source WAL changed");
    // The later WAL payload outside the frozen recipe must be refused.
    writer.stage(b"later payload").unwrap();
    let o = copy_batch(&db, &root, &plan, &key, &pin, &ids, &["--resume"]);
    show("G copy-batch --resume after a later source stage", &o);
    assert!(!o.status.success());
    drop(writer);
}

/// P-H: CLI lifecycle on an INCOMPLETE copy: verify/backup/recover succeed but
/// report incomplete; the outputs cannot admit; nothing reports promotion.
#[test]
fn probe_h_cli_incomplete_lifecycle() {
    let t = tempfile::tempdir().unwrap();
    let db = fixture(t.path(), 2, 2);
    let ids = cli_ids();
    let plan = t.path().join("plan.cbor");
    let o = copy_plan(&db, &plan, &ids);
    let pin = serde_json::from_slice::<serde_json::Value>(&o.stdout).unwrap()["archive"].as_str().unwrap().to_owned();
    let key = private_key(t.path(), 8);
    let root = t.path().join("copy");
    let o = copy_batch(&db, &root, &plan, &key, &pin, &ids, &["--objects", "1", "--records", "0"]);
    show("H copy-batch objects=1 records=0", &o);
    assert!(o.status.success());
    let o = copy_batch(&db, &root, &plan, &key, &pin, &ids, &["--resume", "--objects", "0", "--records", "5"]);
    show("H copy-batch --resume objects=0 records=5 (cannot advance object phase)", &o);
    let p = ["--copy-profile", "--proof-archive", pin.as_str(), "--proof-scope", ids.scope.as_str(), "--proof-issuer", ids.issuer.as_str()];
    let out = root.join("archive.sqlite");
    let before = std::fs::read(&out).unwrap();
    let mut v = vec!["verify", out.to_str().unwrap()];
    v.extend(p);
    let o = cli(&v);
    show("H verify incomplete", &o);
    assert!(o.status.success());
    let j: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(j["copy"]["source_copy_complete"], false);
    let s = source(&db);
    for command in ["backup", "recover"] {
        let dest = t.path().join(format!("{command}.sqlite"));
        let input = if command == "backup" { root.clone() } else { out.clone() };
        let mut a = vec![command, input.to_str().unwrap(), dest.to_str().unwrap()];
        a.extend(p);
        let o = cli(&a);
        show(&format!("H {command} incomplete"), &o);
        assert!(o.status.success());
        let j: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
        assert_eq!(j["copy"]["source_copy_complete"], false);
        // Place the output as an archive root and try ordinary admission.
        let r2 = t.path().join(format!("{command}-root"));
        std::fs::create_dir(&r2).unwrap();
        std::fs::copy(&dest, r2.join("archive.sqlite")).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(r2.join("archive.sqlite"), std::fs::Permissions::from_mode(0o600)).unwrap();
        let mut a2 = Archive::open(&r2, binding(&s)).unwrap();
        let r = a2.admit(&request(9, 8, 0, None), &identity(8), &grant(9), 200).map(|_| ());
        println!("PROBE H admit on {command} output -> {r:?}");
        assert!(r.is_err());
    }
    assert_eq!(std::fs::read(&out).unwrap(), before);
}

/// P-I: user-facing CLI preconditions refuse before creating output.
#[test]
fn probe_i_cli_preconditions() {
    let t = tempfile::tempdir().unwrap();
    let db = fixture(t.path(), 1, 1);
    let ids = cli_ids();
    let plan = t.path().join("plan.cbor");
    let o = copy_plan(&db, &plan, &ids);
    assert!(o.status.success());
    let pin = serde_json::from_slice::<serde_json::Value>(&o.stdout).unwrap()["archive"].as_str().unwrap().to_owned();
    let key8 = private_key(t.path(), 8);
    let key5 = private_key(t.path(), 5);
    let mut i = 0;
    let mut check = |label: &str, args: Vec<String>, root: &Path| {
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        let o = cli(&refs);
        show(&format!("I{i} {label}"), &o);
        assert!(!o.status.success(), "{label} succeeded");
        assert!(!root.exists(), "{label} created output");
        i += 1;
    };
    let base = |root: &Path, plan: &Path, key: &Path| -> Vec<String> {
        ["copy-batch", db.to_str().unwrap(), root.to_str().unwrap(), "--plan", plan.to_str().unwrap(), "--key", key.to_str().unwrap()].iter().map(|s| s.to_string()).collect()
    };
    let pins: Vec<String> = ["--proof-archive", &pin, "--proof-scope", &ids.scope, "--proof-issuer", &ids.issuer].iter().map(|s| s.to_string()).collect();
    let r = t.path().join("o1");
    let mut a = base(&r, &plan, &key8);
    a.extend(pins.clone());
    check("copy-batch without --copy-profile", a, &r);
    let r = t.path().join("o2");
    let mut a = base(&r, &plan, &key8);
    a.push("--copy-profile".into());
    check("copy-batch --copy-profile without pins", a, &r);
    let r = t.path().join("o3");
    let mut a = base(&r, &plan, &key5);
    a.push("--copy-profile".into());
    a.extend(pins.clone());
    check("copy-batch with key for another issuer", a, &r);
    let shared = t.path().join("shared-plan.cbor");
    std::fs::copy(&plan, &shared).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o644)).unwrap();
    let r = t.path().join("o4");
    let mut a = base(&r, &shared, &key8);
    a.push("--copy-profile".into());
    a.extend(pins.clone());
    check("copy-batch with group/world-readable plan", a, &r);
    let r = t.path().join("o5");
    let mut a = base(&r, &plan, &key8);
    a.push("--copy-profile".into());
    a.extend(pins.clone());
    a.extend(["--bytes".to_string(), (MAX_CHUNK - 1).to_string()]);
    check("copy-batch bytes below MAX_CHUNK", a, &r);
    let r = t.path().join("o6");
    let mut a = base(&r, &plan, &key8);
    a.push("--copy-profile".into());
    a.extend(pins.clone());
    a.push("--resume".into());
    check("copy-batch --resume with no existing output", a, &r);
    let r = t.path().join("o7");
    let mut a: Vec<String> = vec!["init".into(), r.to_str().unwrap().into(), "--copy-profile".into()];
    a.extend(pins.clone());
    check("init --copy-profile", a, &r);
    // copy-plan refuses an existing artifact and leaves its bytes intact.
    let exact = std::fs::read(&plan).unwrap();
    let o = copy_plan(&db, &plan, &ids);
    show("I copy-plan onto existing plan", &o);
    assert!(!o.status.success());
    assert_eq!(std::fs::read(&plan).unwrap(), exact);
    // copy-plan with the source database itself as the plan path.
    let before = std::fs::read(&db).unwrap();
    let o = copy_plan(&db, &db, &ids);
    show("I copy-plan PLAN=<source db>", &o);
    assert!(!o.status.success());
    assert_eq!(std::fs::read(&db).unwrap(), before);
}

/// P-K (documents the contract limit, not a defect claim): a privileged rewrite
/// that deletes the last copied record/proof makes a complete copy look like an
/// incomplete one; resume then signs a NEW proof for that sequence.
#[test]
fn probe_k_privileged_truncation_is_outside_the_fence() {
    let t = tempfile::tempdir().unwrap();
    let db = fixture(t.path(), 2, 1);
    let s = source(&db);
    let root = t.path().join("copy");
    let mut a = Archive::create(&root, &s, binding(&s)).unwrap();
    finish(&mut a, &s);
    drop(a);
    let out = root.join("archive.sqlite");
    let original = rows(&out);
    let c = rusqlite::Connection::open(&out).unwrap();
    c.execute_batch("DELETE FROM attestations WHERE sequence=2; DELETE FROM bindings WHERE first_manifest=(SELECT cid FROM commits WHERE sequence=2); DELETE FROM commits WHERE sequence=2;").unwrap_or_else(|e| {
        println!("PROBE K bindings column name differs ({e}); retry without bindings delete");
        c.execute_batch("DELETE FROM attestations WHERE sequence=2; DELETE FROM commits WHERE sequence=2;").unwrap();
    });
    drop(c);
    let v = Archive::verify_file(&out, binding(&s)).map(|v| v.copy);
    println!("PROBE K verify after privileged truncation -> {v:?}");
    if let Ok(mut a) = Archive::open(&root, binding(&s)) {
        let r = a.copy_batch(&s, &identity(8), 5555, small()).map(|b| b.status);
        let now = rows(&out);
        println!("PROBE K resume -> {r:?}; seq2 proof bytes equal original: {:?}", now.get(1).map(|r| r.2 == original[1].2));
    }
}
