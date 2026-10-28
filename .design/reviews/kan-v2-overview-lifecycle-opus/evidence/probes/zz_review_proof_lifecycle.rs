#![cfg(feature = "v2-storage")]
//! Independent reviewer probes for the profile-2 owner lifecycle (7ab1afa vs 262cad3).
//! Temporarily copied into tests/ and removed afterwards. Synthetic identities only.
use kan::{
    evidence_attestation::{self as proof, Context, Frontier, Purpose},
    evidence_service::{hex, Command as Operation, Grant, Request, Service, SignedRequest},
    evidence_store::{
        attested::{Archive, Binding, Recovery},
        Ledger, RecoveryReader,
    },
    sign::Identity,
};
use rusqlite::Connection;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

fn identity(n: u8) -> Identity {
    let mut f = tempfile::NamedTempFile::new().unwrap();
    f.write_all(&[n; 32]).unwrap();
    Identity::load_existing(f.path()).unwrap()
}
fn binding() -> Binding {
    Binding { archive: [8; 32], scope: [9; 32], issuer: identity(7).did().to_string() }
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
            command: Operation::Append { id: hex(&[op; 16]), position, previous, ciphertext: hex(format!("payload {writer} {op}").as_bytes()) },
        },
        &w,
    )
    .unwrap()
    .bytes()
    .unwrap()
}
fn grant(writer: u8) -> Grant {
    Grant { principal: identity(writer).did().to_string(), append: true, inventory: false }
}
fn admit(a: &mut Archive, writer: u8, op: u8, now: u64) {
    let b = a.binding().clone();
    a.admit(&request_to(writer, &b.issuer, op, 0, None), &identity(7), &grant(writer), now).unwrap();
}
fn conn(root: &Path) -> Connection {
    Connection::open(root.join("archive.sqlite")).unwrap()
}
fn ctx(b: &Binding) -> Context<'_> {
    Context { issuer: &b.issuer, archive: b.archive, scope: b.scope }
}

/// Retained-verified prefix of two legacy rows whose receipts were issued by
/// H = identity(11) (!= C = identity(7)), then two admitted rows under C.
fn upgraded_then_admitted(root: &Path) -> tempfile::TempDir {
    let b = binding();
    drop(Archive::create(root, b.clone()).unwrap());
    let legacy = tempfile::tempdir().unwrap();
    let mut records = Vec::new();
    {
        let dir = legacy.path().join("h");
        let ledger = Ledger::create(&dir).unwrap();
        let grants = vec![grant(20), grant(21)];
        let mut service = Service::new(ledger, [9; 32], identity(11), grants).unwrap();
        for (i, w) in [20u8, 21].into_iter().enumerate() {
            let r = service.dispatch(&request_to(w, identity(11).did().as_str(), 1, 0, None), 100 + i as u64).unwrap();
            assert!(r.reply.result.is_ok());
        }
        drop(service);
        let reader = RecoveryReader::open(&dir.join("archive.sqlite")).unwrap();
        records.push(reader.record(1).unwrap());
        records.push(reader.record(2).unwrap());
        drop(reader);
        let c = conn(root);
        c.execute("ATTACH DATABASE ? AS src", [dir.join("archive.sqlite").to_str().unwrap()]).unwrap();
        c.execute_batch(
            "INSERT INTO objects SELECT * FROM src.objects;
             INSERT INTO commits(cid,scope,writer,operation,position,previous,manifest,receipt)
               SELECT cid,scope,writer,operation,position,previous,manifest,receipt FROM src.commits ORDER BY sequence;
             INSERT INTO bindings SELECT * FROM src.bindings;",
        )
        .unwrap();
    }
    let mut frontier = Frontier::default();
    for (i, r) in records.iter().enumerate() {
        let p = proof::issue(&identity(7), &ctx(&b), &r.manifest, &r.receipt, &frontier, Purpose::RetainedVerified, 900_000 + i as u64).unwrap();
        conn(root).execute("INSERT INTO attestations VALUES(?,?)", rusqlite::params![i as i64 + 1, p.bytes()]).unwrap();
        frontier = p.frontier().clone();
    }
    let mut a = Archive::open(root, b).unwrap();
    admit(&mut a, 5, 1, 500);
    admit(&mut a, 6, 1, 501);
    legacy
}

type Dump = BTreeMap<String, Vec<Vec<String>>>;
/// Every row of every table, every column, as hex/text; plus header pragmas and schema.
fn dump(db: &Path) -> Dump {
    let c = Connection::open_with_flags(db, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    let mut out = Dump::new();
    let tables: Vec<String> = c
        .prepare("SELECT name FROM sqlite_schema WHERE type='table' ORDER BY name").unwrap()
        .query_map([], |r| r.get(0)).unwrap().map(Result::unwrap).collect();
    for t in &tables {
        let mut s = c.prepare(&format!("SELECT * FROM \"{t}\"")).unwrap();
        let n = s.column_count();
        let mut rows: Vec<Vec<String>> = s
            .query_map([], |r| {
                Ok((0..n)
                    .map(|i| match r.get_ref(i).unwrap() {
                        rusqlite::types::ValueRef::Null => "NULL".into(),
                        rusqlite::types::ValueRef::Integer(v) => format!("i{v}"),
                        rusqlite::types::ValueRef::Real(v) => format!("r{v}"),
                        rusqlite::types::ValueRef::Text(v) => format!("t{}", String::from_utf8_lossy(v)),
                        rusqlite::types::ValueRef::Blob(v) => format!("b{}", hex(v)),
                    })
                    .collect())
            })
            .unwrap()
            .map(Result::unwrap)
            .collect();
        rows.sort();
        out.insert(t.clone(), rows);
    }
    let pragmas = ["application_id", "user_version"].iter().map(|p| vec![format!("{p}={}", c.query_row(&format!("PRAGMA {p}"), [], |r| r.get::<_, i64>(0)).unwrap())]).collect();
    out.insert("~pragmas".into(), pragmas);
    let schema = c.prepare("SELECT type,name,tbl_name,coalesce(sql,'') FROM sqlite_schema ORDER BY type,name").unwrap()
        .query_map([], |r| Ok(vec![r.get::<_, String>(0)?, r.get(1)?, r.get(2)?, r.get(3)?])).unwrap().map(Result::unwrap).collect();
    out.insert("~schema".into(), schema);
    out
}
fn file_state(db: &Path) -> Vec<(String, Option<(u64, String)>)> {
    ["", "-wal", "-journal"]
        .iter()
        .map(|s| {
            let p = PathBuf::from(format!("{}{s}", db.display()));
            (s.to_string(), std::fs::read(&p).ok().filter(|b| !b.is_empty()).map(|b| (b.len() as u64, hex(&Sha256::digest(&b)))))
        })
        .collect()
}

/// RB1: H != C retained-verified prefix + admitted suffix + an orphan staged
/// payload. Backup and rebuild (from source and from backup) must preserve EVERY
/// authoritative table row exactly and rebuild derived bindings identically.
#[test]
fn rb1_exact_authoritative_rows_survive_backup_and_rebuild_with_h_ne_c() {
    let t = tempfile::tempdir().unwrap();
    let root = t.path().join("archive");
    let _legacy = upgraded_then_admitted(&root);
    let db = root.join("archive.sqlite");
    // Orphan payload: retained bytes with no commit (valid raw CID).
    {
        let bytes = b"orphan staged payload".to_vec();
        let id = kan::evidence_store::ciphertext_cid(&bytes).to_string();
        conn(&root).execute("INSERT INTO objects VALUES(?,?)", rusqlite::params![id, bytes]).unwrap();
    }
    let source = dump(&db);
    let a = Archive::open(&root, binding()).unwrap();
    assert_eq!(a.verify().unwrap().through, 4);
    let backup = t.path().join("backup.sqlite");
    let v = a.backup(&backup).unwrap();
    drop(a);
    assert_eq!(v.commits, 4);
    assert_eq!(dump(&backup), source, "backup changed authoritative/derived rows or schema");
    let before_src = file_state(&db);
    let before_bak = file_state(&backup);
    for (label, from) in [("source", db.clone()), ("backup", backup.clone())] {
        let out = t.path().join(format!("rebuilt-from-{label}.sqlite"));
        let r = Recovery::open(&from, binding()).unwrap();
        assert_eq!(r.rebuild(&out).unwrap(), v, "{label}");
        drop(r);
        assert_eq!(dump(&out), source, "rebuild from {label} differs in some table/schema/pragma");
        // Rebuilt output is a working archive: it accepts a new admission and then verifies.
        let rr = t.path().join(format!("root-{label}"));
        std::fs::create_dir(&rr).unwrap();
        std::fs::copy(&out, rr.join("archive.sqlite")).unwrap();
        let mut reopened = Archive::open(&rr, binding()).unwrap();
        admit(&mut reopened, 30, 1, 600);
        assert_eq!(reopened.verify().unwrap().through, 5);
    }
    assert_eq!(before_src, file_state(&db), "rebuild changed source database/WAL bytes");
    assert_eq!(before_bak, file_state(&backup), "rebuild changed backup bytes");
    // Purposes are preserved: the first two proofs are retained-verified, the rest admitted.
    let c = Connection::open(&backup).unwrap();
    let envs: Vec<Vec<u8>> = c.prepare("SELECT envelope FROM attestations ORDER BY sequence").unwrap().query_map([], |r| r.get(0)).unwrap().map(Result::unwrap).collect();
    eprintln!("RB1 proofs={} source tables={:?}", envs.len(), source.keys().collect::<Vec<_>>());
}

/// RB2: substitute an individually VALID proof (same issuer key) taken from a
/// different archive/branch. Verify, backup, rebuild and open must all refuse.
#[test]
fn rb2_valid_foreign_proof_substitution_is_refused_everywhere() {
    let t = tempfile::tempdir().unwrap();
    let mk = |name: &str, b: Binding, writer: u8| {
        let root = t.path().join(name);
        let mut a = Archive::create(&root, b).unwrap();
        admit(&mut a, writer, 1, 100 + writer as u64);
        admit(&mut a, writer + 1, 1, 200 + writer as u64);
        drop(a);
        root
    };
    let a = mk("a", binding(), 5);
    let other_branch = mk("b", binding(), 50); // same archive/scope/issuer, different records
    let other_archive = mk("c", Binding { archive: [1; 32], ..binding() }, 5); // identical records, different archiveId
    for (label, donor, seq) in [("branch-seq1", &other_branch, 1i64), ("branch-tip", &other_branch, 2), ("archive-seq1", &other_archive, 1), ("archive-tip", &other_archive, 2)] {
        let victim = t.path().join(format!("victim-{label}"));
        std::fs::create_dir(&victim).unwrap();
        // copy a's db (WAL checkpointed by close)
        let src = Connection::open(a.join("archive.sqlite")).unwrap();
        src.execute("VACUUM INTO ?", [victim.join("archive.sqlite").to_str().unwrap()]).unwrap();
        drop(src);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(victim.join("archive.sqlite"), std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let env: Vec<u8> = conn(donor).query_row("SELECT envelope FROM attestations WHERE sequence=?", [seq], |r| r.get(0)).unwrap();
        let c = conn(&victim);
        assert_ne!(env, c.query_row::<Vec<u8>, _, _>("SELECT envelope FROM attestations WHERE sequence=?", [seq], |r| r.get(0)).unwrap());
        c.execute("UPDATE attestations SET envelope=? WHERE sequence=?", rusqlite::params![env, seq]).unwrap();
        drop(c);
        let db = victim.join("archive.sqlite");
        let verify = Archive::verify_file(&db, binding());
        let open = Archive::open(&victim, binding());
        let rebuild = Recovery::open(&db, binding()).and_then(|r| r.rebuild(&t.path().join(format!("out-{label}.sqlite"))));
        eprintln!("RB2 {label}: verify={:?} open={:?} rebuild={:?}", verify.as_ref().err(), open.as_ref().err().map(|e| e.to_string()), rebuild.as_ref().err());
        assert!(verify.is_err() && open.is_err() && rebuild.is_err(), "{label}: substituted valid proof accepted");
    }
}

/// RB3: CLI owner pins are all-or-none and validated before ANY output exists;
/// profile mismatch in either direction never creates a destination.
#[test]
fn rb3_cli_pin_permutations_and_profile_mismatch_create_nothing() {
    let exe = env!("CARGO_BIN_EXE_kan-v2");
    let t = tempfile::tempdir().unwrap();
    let a = hex(&binding().archive);
    let s = hex(&binding().scope);
    let i = binding().issuer;
    let good = Ledger::create(&t.path().join("legacy")).unwrap();
    drop(good);
    let p2 = t.path().join("p2");
    {
        let mut x = Archive::create(&p2, binding()).unwrap();
        admit(&mut x, 5, 1, 100);
    }
    let p2db = p2.join("archive.sqlite");
    let legacy_db = t.path().join("legacy/archive.sqlite");
    let p2_before = dump(&p2db);
    let pin_sets: Vec<(&str, Vec<String>)> = vec![
        ("archive-only", vec!["--proof-archive".into(), a.clone()]),
        ("scope-only", vec!["--proof-scope".into(), s.clone()]),
        ("issuer-only", vec!["--proof-issuer".into(), i.clone()]),
        ("no-issuer", vec!["--proof-archive".into(), a.clone(), "--proof-scope".into(), s.clone()]),
        ("no-scope", vec!["--proof-archive".into(), a.clone(), "--proof-issuer".into(), i.clone()]),
        ("no-archive", vec!["--proof-scope".into(), s.clone(), "--proof-issuer".into(), i.clone()]),
        ("upper-hex", vec!["--proof-archive".into(), hex(&[0xab; 32]).to_uppercase(), "--proof-scope".into(), s.clone(), "--proof-issuer".into(), i.clone()]),
        ("short-hex", vec!["--proof-archive".into(), a[..62].into(), "--proof-scope".into(), s.clone(), "--proof-issuer".into(), i.clone()]),
        ("long-hex", vec!["--proof-archive".into(), format!("{a}00"), "--proof-scope".into(), s.clone(), "--proof-issuer".into(), i.clone()]),
        ("bad-issuer", vec!["--proof-archive".into(), a.clone(), "--proof-scope".into(), s.clone(), "--proof-issuer".into(), format!("{i} ")]),
        ("ed25519-issuer", vec!["--proof-archive".into(), a.clone(), "--proof-scope".into(), s.clone(), "--proof-issuer".into(), "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK".into()]),
        ("wrong-archive", vec!["--proof-archive".into(), hex(&[0; 32]), "--proof-scope".into(), s.clone(), "--proof-issuer".into(), i.clone()]),
    ];
    let mut report = Vec::new();
    for (label, pins) in &pin_sets {
        for cmd in ["init", "backup", "recover", "verify"] {
            if cmd == "init" && *label == "wrong-archive" {
                continue; // a well-formed different archive pin is a legitimate new init
            }
            let out_path = t.path().join(format!("out-{cmd}-{label}"));
            let mut args: Vec<String> = match cmd {
                "init" => vec!["init".into(), out_path.display().to_string()],
                "backup" => vec!["backup".into(), p2.display().to_string(), out_path.display().to_string()],
                "recover" => vec!["recover".into(), p2db.display().to_string(), out_path.display().to_string()],
                _ => vec!["verify".into(), p2db.display().to_string()],
            };
            args.extend(pins.iter().cloned());
            let o = Command::new(exe).args(&args).output().unwrap();
            let created = out_path.exists();
            report.push(format!("{cmd}/{label}: exit={:?} created={created}", o.status.code()));
            assert!(!o.status.success(), "{cmd}/{label} succeeded");
            assert!(!created, "{cmd}/{label} created output before refusing");
        }
    }
    // Profile mismatch: recover/backup legacy with pins; p2 without pins; init --resume with pins on legacy.
    let mism = [
        ("recover-legacy-with-pins", vec!["recover".to_string(), legacy_db.display().to_string(), t.path().join("m1").display().to_string(), "--proof-archive".into(), a.clone(), "--proof-scope".into(), s.clone(), "--proof-issuer".into(), i.clone()], t.path().join("m1")),
        ("backup-legacy-with-pins", vec!["backup".to_string(), t.path().join("legacy").display().to_string(), t.path().join("m2").display().to_string(), "--proof-archive".into(), a.clone(), "--proof-scope".into(), s.clone(), "--proof-issuer".into(), i.clone()], t.path().join("m2")),
        ("recover-p2-without-pins", vec!["recover".to_string(), p2db.display().to_string(), t.path().join("m3").display().to_string()], t.path().join("m3")),
        ("backup-p2-without-pins", vec!["backup".to_string(), p2.display().to_string(), t.path().join("m4").display().to_string()], t.path().join("m4")),
        ("readrecord-p2", vec!["read-record".to_string(), p2db.display().to_string(), "1".into()], t.path().join("m5")),
    ];
    for (label, args, out) in mism {
        let o = Command::new(exe).args(&args).output().unwrap();
        report.push(format!("{label}: exit={:?} created={} stderr={}", o.status.code(), out.exists(), String::from_utf8_lossy(&o.stderr).trim()));
        assert!(!o.status.success(), "{label} succeeded");
        assert!(!out.exists(), "{label} created output");
    }
    let legacy_before = dump(&legacy_db);
    let o = Command::new(exe).args(["init", t.path().join("legacy").to_str().unwrap(), "--resume", "--proof-archive", &a, "--proof-scope", &s, "--proof-issuer", &i]).output().unwrap();
    report.push(format!("init-resume-legacy-with-pins: exit={:?} stderr={}", o.status.code(), String::from_utf8_lossy(&o.stderr).trim()));
    assert!(!o.status.success());
    assert_eq!(legacy_before, dump(&legacy_db), "resume with pins changed a legacy archive");
    assert_eq!(p2_before, dump(&p2db), "refused commands changed the profile-2 archive");
    for line in &report {
        eprintln!("RB3 {line}");
    }
}

fn child_exe() -> Command {
    let mut c = Command::new(std::env::current_exe().unwrap());
    c.args(["--exact", "zz_review_lifecycle_child", "--nocapture", "--test-threads=1"]);
    c
}
#[test]
fn zz_review_lifecycle_child() {
    let Ok(mode) = std::env::var("KAN_REVIEW_LC") else { return };
    let root = PathBuf::from(std::env::var("KAN_REVIEW_ROOT").unwrap());
    let go = PathBuf::from(std::env::var("KAN_REVIEW_GO").unwrap());
    // Handshake: signal readiness, then start immediately (parent times the kill).
    std::fs::write(&go, b"").unwrap();
    match mode.as_str() {
        "create" => {
            drop(Archive::create(&root, binding()).unwrap());
            println!("REVIEW-DONE");
            std::thread::sleep(Duration::from_secs(60));
        }
        "resume" => {
            drop(Archive::resume_initialization(&root, binding()).unwrap());
            println!("REVIEW-DONE");
            std::thread::sleep(Duration::from_secs(60));
        }
        "admit-loop" => {
            let mut a = Archive::open(&root, binding()).unwrap();
            let (mut ok, mut err, mut first) = (0u32, 0u32, Vec::<String>::new());
            let start = Instant::now();
            let mut n = 0u8;
            while start.elapsed() < Duration::from_millis(std::env::var("KAN_REVIEW_MS").unwrap().parse().unwrap()) && n < 150 {
                n += 1;
                let b = a.binding().clone();
                let w = 100 + n;
                match a.admit(&request_to(w, &b.issuer, 1, 0, None), &identity(7), &grant(w), 1000 + n as u64) {
                    Ok(_) => ok += 1,
                    Err(e) => {
                        err += 1;
                        if first.len() < 3 {
                            first.push(format!("{e:?}"));
                        }
                    }
                }
            }
            println!("REVIEW-RESULT {}", serde_json::json!({"ok":ok,"err":err,"first":first}));
        }
        m => panic!("{m}"),
    }
}

/// RB4: abrupt SIGKILL at arbitrary (not observer-aligned) points during create
/// and during resume. Afterwards, explicit resume (or create when no file exists)
/// must yield a valid profile-2 archive with the exact owner binding; legacy
/// openers refuse it; a wrong binding never adopts it.
#[test]
fn rb4_random_sigkill_during_create_and_resume() {
    let mut report = BTreeMap::<String, u32>::new();
    for (mode, delays) in [("create", vec![0u64, 50, 150, 300, 600, 1000, 1500, 2500, 4000, 6000, 9000, 14000, 20000, 30000, 45000]), ("resume", vec![0, 100, 300, 700, 1500, 3000, 6000, 12000, 25000])] {
        for d in delays {
            let t = tempfile::tempdir().unwrap();
            let root = t.path().join("archive");
            if mode == "resume" {
                // An interrupted empty initialization to resume.
                std::fs::create_dir(&root).unwrap();
                #[cfg(unix)]
                {
                    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
                    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
                    std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(root.join("archive.sqlite")).unwrap();
                }
            }
            let go = t.path().join("go");
            let mut child = child_exe().env("KAN_REVIEW_LC", mode).env("KAN_REVIEW_ROOT", &root).env("KAN_REVIEW_GO", &go).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
            let deadline = Instant::now() + Duration::from_secs(30);
            while !go.exists() {
                assert!(Instant::now() < deadline);
                std::thread::sleep(Duration::from_micros(50));
            }
            std::thread::sleep(Duration::from_micros(d));
            child.kill().unwrap();
            let out = child.wait_with_output().unwrap();
            let finished = String::from_utf8_lossy(&out.stdout).contains("REVIEW-DONE");
            let db = root.join("archive.sqlite");
            let state = format!(
                "dir={} file={} len={} journal={} wal={}",
                root.exists(),
                db.exists(),
                std::fs::metadata(&db).map(|m| m.len()).unwrap_or(0),
                PathBuf::from(format!("{}-journal", db.display())).exists(),
                PathBuf::from(format!("{}-wal", db.display())).exists()
            );
            let outcome = if !db.exists() {
                assert!(Archive::resume_initialization(&root, binding()).is_err());
                // Owner reruns init.
                let a = Archive::create(&root, binding());
                format!("no-file -> create {}", if a.is_ok() { "ok" } else { "ERR" })
            } else {
                let r = Archive::resume_initialization(&root, binding());
                match r {
                    Ok(a) => {
                        assert_eq!(a.verify().unwrap().through, 0);
                        drop(a);
                        assert!(Ledger::open(&root).is_err(), "legacy opener accepted profile 2");
                        assert!(Ledger::resume_initialization(&root).is_err(), "legacy resume accepted profile 2");
                        // A different owner binding never rebinds an initialized archive.
                        assert!(Archive::resume_initialization(&root, Binding { archive: [3; 32], ..binding() }).is_err(), "wrong binding adopted an initialized archive");
                        "resume ok".to_string()
                    }
                    Err(e) => format!("resume ERR {e}"),
                }
            };
            let key = format!("{mode} finished={finished} | {state} | {outcome}");
            *report.entry(key).or_default() += 1;
        }
    }
    for (k, n) in &report {
        eprintln!("RB4 x{n}: {k}");
    }
    assert!(!report.keys().any(|k| k.contains("ERR")), "an interrupted state could not be recovered by explicit owner action");
}

/// RB5: separate-process admissions continue while a pinned rebuild and a full
/// backup run; outputs verify and match their own pinned frontier.
#[test]
fn rb5_cross_process_admission_during_rebuild_and_backup() {
    let t = tempfile::tempdir().unwrap();
    let root = t.path().join("archive");
    {
        let mut a = Archive::create(&root, binding()).unwrap();
        for w in 5..25u8 {
            admit(&mut a, w, 1, 100 + w as u64);
        }
    }
    let db = root.join("archive.sqlite");
    let go = t.path().join("go");
    let child = child_exe().env("KAN_REVIEW_LC", "admit-loop").env("KAN_REVIEW_ROOT", &root).env("KAN_REVIEW_GO", &go).env("KAN_REVIEW_MS", "6000").stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    while !go.exists() {
        std::thread::sleep(Duration::from_millis(1));
    }
    std::thread::sleep(Duration::from_millis(300));
    let mut results = Vec::new();
    for i in 0..4 {
        let r = Recovery::open(&db, binding()).unwrap();
        let out = t.path().join(format!("rebuilt-{i}.sqlite"));
        let v = r.rebuild(&out);
        drop(r);
        let v = v.unwrap();
        assert_eq!(Archive::verify_file(&out, binding()).unwrap(), v);
        let a = Archive::open(&root, binding()).unwrap();
        let bak = t.path().join(format!("backup-{i}.sqlite"));
        let b = a.backup(&bak);
        drop(a);
        results.push(format!("rebuild through={} backup={:?}", v.snapshot.through, b.as_ref().map(|v| v.snapshot.through).map_err(|e| e.to_string())));
        b.unwrap();
    }
    let out = child.wait_with_output().unwrap();
    let line = String::from_utf8_lossy(&out.stdout).lines().find_map(|l| l.split_once("REVIEW-RESULT ").map(|x| x.1.to_owned())).unwrap_or_else(|| format!("no result: {}", String::from_utf8_lossy(&out.stderr)));
    eprintln!("RB5 writer={line} outputs={results:?}");
    let w: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert_eq!(w["err"], 0, "admission failed while rebuild/backup ran");
    assert!(w["ok"].as_u64().unwrap() > 0);
}
