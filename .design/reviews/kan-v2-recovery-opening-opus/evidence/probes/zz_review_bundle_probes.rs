#![cfg(feature = "v2-storage")]
//! TEMPORARY independent reviewer probes (copied into tests/ only for the run,
//! removed before the final identity check). Prints outcomes; classification is
//! done in REPORT.txt, not by assertions here.
use kan::{
    evidence_recovery_commitment::Limits,
    evidence_recovery_member::{Input, Membership, Object, Row},
    evidence_recovery_observation::Context,
    evidence_recovery_replay::{self as replay, Checkpoint},
    evidence_service::unhex,
    evidence_store::bundle::{self, Budget},
};
use rusqlite::{config::DbConfig, Connection};
use serde_json::Value;
use std::{
    path::{Path, PathBuf},
    process::Command,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

fn budget() -> Budget {
    Budget {
        items: 10000,
        acquired_bytes: 32 * 1024 * 1024,
        source_bytes: 64 * 1024 * 1024,
        replay_items: 10000,
        replay_scan_bytes: 128 * 1024 * 1024,
        duration: Duration::from_secs(10),
        cancelled: Arc::new(AtomicBool::new(false)),
    }
}
fn corpus() -> Vec<Value> {
    serde_json::from_str::<Value>(include_str!("../.design/fixtures/recovery-replay-v1.json"))
        .unwrap()["cases"]
        .as_array()
        .unwrap()
        .clone()
}
fn pins(v: &Value) -> Context {
    let c = &v["member"]["context"];
    let bytes = |s: &str| unhex(c[s].as_str().unwrap(), 32).unwrap().try_into().unwrap();
    Context {
        bundle: bytes("bundle"),
        profile: c["profile"].as_u64().unwrap() as u8,
        archive: bytes("archive"),
        scope: bytes("scope"),
        issuer: c["issuer"].as_str().unwrap().into(),
        observer: c["observer"].as_str().unwrap().into(),
    }
}
fn checkpoint(v: &Value) -> Option<Checkpoint> {
    (!v["checkpoint"].is_null()).then(|| Checkpoint {
        context: pins(v),
        sequence: v["checkpoint"][0].as_u64().unwrap(),
        statement: v["checkpoint"][1].as_str().unwrap().parse().unwrap(),
    })
}
fn fixture(name: &str) -> (tempfile::TempDir, PathBuf, Value) {
    let dir = tempfile::tempdir().unwrap();
    let python = std::env::var_os("KAN_TLS_ORACLE_PYTHON").unwrap_or_else(|| "python3".into());
    let out = Command::new(python)
        .arg(".design/tools/recovery_bundle_files.py")
        .arg(dir.path())
        .arg("--case")
        .arg(name)
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let v = corpus().into_iter().find(|v| v["name"] == name).unwrap();
    let path = dir.path().join(format!("{name}.sqlite"));
    (dir, path, v)
}
fn tamper(path: &Path, sql: &str) -> Result<(), String> {
    let c = Connection::open(path).map_err(|e| e.to_string())?;
    c.set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, false)
        .map_err(|e| e.to_string())?;
    c.execute_batch("PRAGMA ignore_check_constraints=ON;")
        .map_err(|e| e.to_string())?;
    c.execute_batch(sql).map_err(|e| e.to_string())
}
fn outcome(r: &Result<bundle::Inspection, bundle::Error>) -> String {
    match r {
        Ok(i) => format!(
            "ACCEPT latest={} restored={} items={} bytes={}",
            i.replay().latest().sequence,
            i.replay().restored(),
            i.items(),
            i.acquired_bytes()
        ),
        Err(e) => format!("REFUSE {e:?}"),
    }
}
fn probe(label: &str, path: &Path, v: &Value, b: Budget) -> String {
    let t = Instant::now();
    let r = bundle::inspect(path, pins(v), checkpoint(v).as_ref(), b);
    let s = outcome(&r);
    println!("PROBE {label} => {s} elapsed_ms={}", t.elapsed().as_millis());
    s
}
fn tampered(label: &str, case: &str, sql: &str) {
    let (_d, path, v) = fixture(case);
    match tamper(&path, sql) {
        Ok(()) => {
            probe(label, &path, &v, budget());
        }
        Err(e) => println!("PROBE {label} => TAMPER-FAILED {e}"),
    }
}
/// Replace `table`'s b-tree with one built under `twin_sql` and identical
/// record layout, keeping the canonical sqlite_schema text (writable_schema).
fn swap_btree(table: &str, twin_sql: &str, fill: &str) -> String {
    format!(
        "{twin_sql}; {fill}; PRAGMA writable_schema=ON; \
         UPDATE sqlite_schema SET rootpage=(SELECT rootpage FROM sqlite_schema WHERE name='twin') WHERE name='{table}'; \
         DELETE FROM sqlite_schema WHERE name='twin'; PRAGMA writable_schema=OFF;"
    )
}

#[test]
fn probes_child() {
    // Child-process helper: leave committed WAL frames or a hot journal behind.
    if let Some(path) = std::env::var_os("KAN_REVIEW_WAL_CHILD") {
        let db = Connection::open(PathBuf::from(path)).unwrap();
        db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0; DELETE FROM observations WHERE sequence=7;").unwrap();
        std::process::exit(72);
    }
    if let Some(path) = std::env::var_os("KAN_REVIEW_HOT_CHILD") {
        let db = Connection::open(PathBuf::from(path)).unwrap();
        db.execute_batch("PRAGMA journal_mode=DELETE; PRAGMA cache_size=1; PRAGMA ignore_check_constraints=ON; BEGIN EXCLUSIVE; UPDATE observations SET envelope=zeroblob(65536);").unwrap();
        std::process::exit(71);
    }
}
fn child(var: &str, path: &Path) -> Option<i32> {
    Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "probes_child", "--nocapture"])
        .env(var, path)
        .output()
        .unwrap()
        .status
        .code()
}
fn sidecar(path: &Path, suffix: &str) -> PathBuf {
    PathBuf::from(format!("{}{suffix}", path.display()))
}

#[test]
fn physical_probes() {
    let p2 = "profile2-restored-failure-observed";
    let p3 = "profile3-restored-failure-observed";
    let later = "later-candidate-keeps-earlier-intent-history";
    // Baseline.
    let (_d, path, v) = fixture(p2);
    probe("A00-baseline-p2", &path, &v, budget());

    // A01 canonical-key spelling the typed parser ACCEPTS (b + uppercase body).
    tampered("A01a-mixed-case-restored-cid", p2,
        "UPDATE restored_objects SET cid='b'||upper(substr(cid,2)) WHERE cid=(SELECT min(cid) FROM restored_objects);");
    tampered("A01b-mixed-case-original-cid", later,
        "UPDATE member_objects SET cid='b'||upper(substr(cid,2)) WHERE cid=(SELECT min(cid) FROM member_objects);");
    tampered("A01c-mixed-case-membership-cid", p3,
        "UPDATE member_membership SET cid='b'||upper(substr(cid,2)) WHERE cid=(SELECT min(cid) FROM member_membership);");
    tampered("A01d-author-spelling-upper-all", p2, "UPDATE restored_objects SET cid=upper(cid) WHERE cid=(SELECT min(cid) FROM restored_objects);");

    // A02 duplicate WITHOUT ROWID keys behind canonical schema text.
    tampered("A02a-duplicate-restored-key", p2, &swap_btree("restored_objects",
        "CREATE TABLE twin(cid TEXT, bytes BLOB, PRIMARY KEY(cid,bytes)) WITHOUT ROWID",
        "INSERT INTO twin SELECT cid,bytes FROM restored_objects; INSERT INTO twin SELECT cid,CAST(bytes||x'00' AS BLOB) FROM restored_objects WHERE cid=(SELECT min(cid) FROM restored_objects)"));
    tampered("A02b-duplicate-membership-key", p3, &swap_btree("member_membership",
        "CREATE TABLE twin(cid TEXT, length INTEGER, PRIMARY KEY(cid,length)) WITHOUT ROWID",
        "INSERT INTO twin SELECT cid,length FROM member_membership; INSERT INTO twin SELECT cid,length+1 FROM member_membership WHERE cid=(SELECT min(cid) FROM member_membership)"));
    tampered("A02c-duplicate-original-key", later, &swap_btree("member_objects",
        "CREATE TABLE twin(cid TEXT, bytes BLOB, PRIMARY KEY(cid,bytes)) WITHOUT ROWID",
        "INSERT INTO twin SELECT cid,bytes FROM member_objects; INSERT INTO twin SELECT cid,CAST(bytes||x'00' AS BLOB) FROM member_objects WHERE cid=(SELECT min(cid) FROM member_objects)"));
    // A03 descending storage order behind ascending schema text.
    tampered("A03a-descending-restored-btree", p2, &swap_btree("restored_objects",
        "CREATE TABLE twin(cid TEXT PRIMARY KEY DESC, bytes BLOB) WITHOUT ROWID",
        "INSERT INTO twin SELECT cid,bytes FROM restored_objects"));
    tampered("A03b-descending-membership-btree", p3, &swap_btree("member_membership",
        "CREATE TABLE twin(cid TEXT PRIMARY KEY DESC, length INTEGER) WITHOUT ROWID",
        "INSERT INTO twin SELECT cid,length FROM member_membership"));
    // A03c control: same swap with ascending twin (must still accept).
    tampered("A03c-ascending-twin-control", p2, &swap_btree("restored_objects",
        "CREATE TABLE twin(cid TEXT PRIMARY KEY, bytes BLOB) WITHOUT ROWID",
        "INSERT INTO twin SELECT cid,bytes FROM restored_objects"));

    // A04 corrupt cells beyond SQLite's 5-MiB length limit.
    let six = 6 * 1024 * 1024;
    tampered("A04a-oversized-original-blob", later, &format!("UPDATE member_objects SET bytes=zeroblob({six}) WHERE cid=(SELECT min(cid) FROM member_objects);"));
    tampered("A04b-oversized-restored-text-key", p2, &format!("UPDATE restored_objects SET cid=printf('%.*c',{six},'b') WHERE cid=(SELECT min(cid) FROM restored_objects);"));
    tampered("A04c-oversized-observation", p2, &format!("UPDATE observations SET envelope=zeroblob({six}) WHERE sequence=3;"));
    tampered("A04d-oversized-identity-text", p2, &format!("UPDATE bundle_identity SET observer=printf('%.*c',{six},'z');"));
    tampered("A04e-oversized-manifest", p2, &format!("UPDATE member_records SET manifest=zeroblob({six}) WHERE sequence=1;"));
    tampered("A04f-oversized-membership-key", p3, &format!("UPDATE member_membership SET cid=printf('%.*c',{six},'b') WHERE cid=(SELECT min(cid) FROM member_membership);"));
    tampered("A04g-between-4MiB-and-5MiB-original", later, "UPDATE member_objects SET bytes=zeroblob(4194305) WHERE cid=(SELECT min(cid) FROM member_objects);");

    // A05 NUL / Unicode keys and identifiers with in-bound byte lengths.
    tampered("A05a-nul-in-59-byte-cid", p2, "UPDATE restored_objects SET cid=substr(cid,1,58)||char(0) WHERE cid=(SELECT max(cid) FROM restored_objects);");
    tampered("A05b-unicode-in-59-byte-cid", p2, "UPDATE restored_objects SET cid=substr(cid,1,57)||char(233) WHERE cid=(SELECT max(cid) FROM restored_objects);");
    tampered("A05c-unicode-issuer-same-bytes", p2, "UPDATE bundle_identity SET issuer=substr(issuer,1,length(issuer)-2)||char(233);");
    tampered("A05d-blob-key", p2, "UPDATE restored_objects SET cid=CAST(cid AS BLOB) WHERE cid=(SELECT max(cid) FROM restored_objects);");
    tampered("A05e-invalid-utf8-text-cid", p2, "UPDATE restored_objects SET cid=CAST(substr(CAST(cid AS BLOB),1,58)||x'ff' AS TEXT) WHERE cid=(SELECT max(cid) FROM restored_objects);");
    // A06 storage classes for integer fields.
    tampered("A06a-real-membership-length", p3, "UPDATE member_membership SET length=length+0.5 WHERE cid=(SELECT min(cid) FROM member_membership);");
    tampered("A06b-text-profile", p2, "UPDATE bundle_identity SET profile='two';");
    tampered("A06c-blob-membership-length", p3, "UPDATE member_membership SET length=x'01' WHERE cid=(SELECT min(cid) FROM member_membership);");
    // A07 cardinality / coordinates.
    tampered("A07a-second-identity-row", p2, "INSERT INTO bundle_identity SELECT 2,bundle,observer,profile,archive,scope,issuer FROM bundle_identity;");
    tampered("A07b-second-plan-row", p3, "INSERT INTO member_plan SELECT 2,envelope FROM member_plan;");
    tampered("A07c-plan-on-profile2", p2, "INSERT INTO member_plan VALUES(1,x'a0');");
    tampered("A07d-record-sequence-gap", "greedy-32-plus-2-loss-partition", "UPDATE member_records SET sequence=sequence+1 WHERE sequence=(SELECT max(sequence) FROM member_records);");
    tampered("A07e-observation-zero", p2, "UPDATE observations SET sequence=0 WHERE sequence=1;");
    // A08 schema-level extras.
    tampered("A08a-analyze-stat1", p2, "ANALYZE;");
    tampered("A08b-schema-text-whitespace", p2, "PRAGMA writable_schema=ON; UPDATE sqlite_schema SET sql=replace(sql,'CHECK(sequence BETWEEN','CHECK(sequence  BETWEEN') WHERE name='observations'; PRAGMA writable_schema=OFF;");
    tampered("A08c-check-dropped-via-writable-schema", p2, "PRAGMA writable_schema=ON; UPDATE sqlite_schema SET sql=replace(sql,' CHECK(typeof(envelope)=''blob'' AND length(envelope) BETWEEN 1 AND 16384)','') WHERE name='observations'; PRAGMA writable_schema=OFF;");
    tampered("A08d-utf16-schema-text-blob", p2, "PRAGMA writable_schema=ON; UPDATE sqlite_schema SET sql=CAST(sql AS BLOB) WHERE name='observations'; PRAGMA writable_schema=OFF;");
    tampered("A08e-malformed-extra-schema-row", p2, "PRAGMA writable_schema=ON; INSERT INTO sqlite_schema VALUES('table','zz','zz',0,'CREATE TABLE zz(');PRAGMA writable_schema=OFF;");
    tampered("A08f-temp-trigger-noop", p2, "CREATE TEMP TRIGGER t AFTER INSERT ON observations BEGIN SELECT 1; END;");

    // A09 WAL with committed but uncheckpointed frames.
    {
        let (d, path, v) = fixture(p2);
        let main_only = d.path().join("main-only.sqlite");
        println!("PROBE A09-wal-child exit={:?}", child("KAN_REVIEW_WAL_CHILD", &path));
        let wal = sidecar(&path, "-wal");
        let shm = sidecar(&path, "-shm");
        std::fs::copy(&path, &main_only).unwrap();
        let (m0, w0) = (std::fs::read(&path).unwrap(), std::fs::read(&wal).unwrap());
        println!("PROBE A09-wal-present wal_bytes={} shm_exists={}", w0.len(), shm.exists());
        probe("A09a-wal-frames-read", &path, &v, budget());
        println!("PROBE A09a-main-unchanged={} wal-unchanged={}", std::fs::read(&path).unwrap() == m0, std::fs::read(&wal).unwrap() == w0);
        probe("A09b-main-file-alone", &main_only, &v, budget());
        std::fs::remove_file(&shm).unwrap();
        probe("A09c-wal-frames-shm-removed", &path, &v, budget());
        use std::os::unix::fs::PermissionsExt;
        println!("PROBE A09c-main-unchanged={} wal-unchanged={} shm_recreated={} shm_mode={:o}",
            std::fs::read(&path).unwrap() == m0, std::fs::read(&wal).unwrap() == w0, shm.exists(),
            std::fs::metadata(&shm).map(|m| m.permissions().mode() & 0o777).unwrap_or(0));
        let mut b = budget();
        b.source_bytes = std::fs::metadata(&path).unwrap().len() + w0.len() as u64 + std::fs::metadata(&shm).unwrap().len() - 1;
        probe("A09d-source-budget-counts-sidecars", &path, &v, b);
    }
    // A10 hot and non-hot rollback journals.
    {
        let (_d, path, v) = fixture(p2);
        println!("PROBE A10-hot-child exit={:?}", child("KAN_REVIEW_HOT_CHILD", &path));
        probe("A10a-hot-journal", &path, &v, budget());
    }
    {
        let (_d, path, v) = fixture(p2);
        let j = sidecar(&path, "-journal");
        std::fs::write(&j, b"").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&j, std::fs::Permissions::from_mode(0o600)).unwrap();
        probe("A10b-empty-nonhot-journal", &path, &v, budget());
        println!("PROBE A10b-journal-still-exists={}", j.exists());
    }
    // A11 sidecar file types.
    {
        let (_d, path, v) = fixture(p2);
        std::fs::create_dir(sidecar(&path, "-shm")).unwrap();
        probe("A11a-shm-directory", &path, &v, budget());
    }
    {
        let (_d, path, v) = fixture(p2);
        let fifo = sidecar(&path, "-wal");
        let s = Command::new("mkfifo").arg("-m").arg("600").arg(&fifo).status().unwrap();
        println!("PROBE A11b-mkfifo status={s:?}");
        probe("A11b-wal-fifo", &path, &v, budget());
    }
    {
        let (d, path, v) = fixture(p2);
        let link = d.path().join("dirlink");
        std::os::unix::fs::symlink(d.path(), &link).unwrap();
        probe("A11c-symlinked-parent-directory", &link.join(path.file_name().unwrap()), &v, budget());
        let hard = d.path().join("second-name.sqlite");
        std::fs::hard_link(&path, &hard).unwrap();
        probe("A11d-main-has-second-hard-link", &path, &v, budget());
    }
    // A12 VM cancellation and deadline inside one long SQLite step (schema load).
    {
        let (_d, path, v) = fixture(p2);
        tamper(&path, "PRAGMA writable_schema=ON; WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i<400000) INSERT INTO sqlite_schema SELECT 'view','v'||i,'v'||i,0,'CREATE VIEW v'||i||' AS SELECT '||i||' AS n' FROM n; PRAGMA writable_schema=OFF;").unwrap();
        let t = Instant::now();
        let c = Connection::open_with_flags(&path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
        let n: i64 = c.query_row("SELECT count(*) FROM sqlite_schema", [], |r| r.get(0)).unwrap();
        drop(c);
        println!("PROBE A12-unbounded-schema-load rows={n} elapsed_ms={} file_bytes={}", t.elapsed().as_millis(), std::fs::metadata(&path).unwrap().len());
        let mut b = budget();
        b.duration = Duration::from_millis(150);
        b.source_bytes = 1 << 40;
        probe("A12a-deadline-during-schema-load", &path, &v, b);
        let mut b = budget();
        b.source_bytes = 1 << 40;
        let flag = b.cancelled.clone();
        let h = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            flag.store(true, Ordering::Relaxed)
        });
        probe("A12b-cancel-during-schema-load", &path, &v, b);
        h.join().unwrap();
    }
    // A13 duration bounds.
    {
        let (_d, path, v) = fixture(p2);
        let mut b = budget();
        b.duration = Duration::from_secs(3601);
        probe("A13a-duration-3601s", &path, &v, b);
        let mut b = budget();
        b.duration = Duration::from_secs(3600);
        probe("A13b-duration-3600s", &path, &v, b);
    }
}

fn generated() -> Vec<Value> {
    let p = std::env::var("KAN_REVIEW_GENERATED").expect("KAN_REVIEW_GENERATED");
    serde_json::from_str::<Value>(&std::fs::read_to_string(Path::new(&p).join("cases.json")).unwrap())
        .unwrap()["cases"]
        .as_array()
        .unwrap()
        .clone()
}
fn pure(v: &Value) -> String {
    let m = &v["member"];
    let raw = |x: &Value| unhex(x.as_str().unwrap(), 4 * 1024 * 1024).unwrap();
    let ctx = pins(v);
    let plan = (!m["plan"].is_null()).then(|| raw(&m["plan"]));
    let cids = |x: &Value| -> Vec<(atproto_dasl::Cid, Vec<u8>)> {
        x.as_array().unwrap().iter().map(|o| (o[0].as_str().unwrap().parse().unwrap(), raw(&o[1]))).collect()
    };
    let membership: Vec<(atproto_dasl::Cid, u64)> = m["membership"].as_array().unwrap().iter()
        .map(|a| (a[0].as_str().unwrap().parse().unwrap(), a[1].as_u64().unwrap())).collect();
    let records: Vec<(u64, Vec<u8>, Vec<u8>, Vec<u8>)> = m["records"].as_array().unwrap().iter()
        .map(|a| (a[0].as_u64().unwrap(), raw(&a[1]), raw(&a[2]), raw(&a[3]))).collect();
    let objects = cids(&m["objects"]);
    let candidates = cids(&v["candidates"]);
    let observations: Vec<Vec<u8>> = v["observations"].as_array().unwrap().iter().map(raw).collect();
    let membership: Vec<_> = membership.iter().map(|(cid, length)| Membership { cid, length: *length }).collect();
    let records: Vec<_> = records.iter().map(|(sequence, manifest, receipt, proof)| Row { sequence: *sequence, manifest, receipt, proof }).collect();
    let objects: Vec<_> = objects.iter().map(|(cid, bytes)| Object { cid, bytes }).collect();
    let candidates: Vec<_> = candidates.iter().map(|(cid, bytes)| Object { cid, bytes }).collect();
    let observations: Vec<_> = observations.iter().map(Vec::as_slice).collect();
    let r = replay::verify(
        Input { context: &ctx, plan: plan.as_deref(), membership: &membership, records: &records, objects: &objects },
        &candidates, &observations, None,
        Limits { items: 10000, bytes: 128 * 1024 * 1024, duration: Duration::from_secs(10), cancelled: Arc::new(AtomicBool::new(false)) },
    );
    match r {
        Ok(r) => format!("ACCEPT latest={} restored={}", r.latest().sequence, r.restored()),
        Err(e) => format!("REFUSE {e:?}"),
    }
}
#[test]
fn generated_empty_original_probes() {
    let dir = PathBuf::from(std::env::var("KAN_REVIEW_GENERATED").expect("KAN_REVIEW_GENERATED"));
    for v in generated() {
        let name = v["name"].as_str().unwrap();
        let path = dir.join(format!("{name}.sqlite"));
        let before = std::fs::read(&path).unwrap();
        println!("PROBE {name} pure_replay => {}", pure(&v));
        probe(&format!("{name} physical"), &path, &v, budget());
        println!("PROBE {name} source-unchanged={}", std::fs::read(&path).unwrap() == before);
    }
}
#[test]
fn oversized_rss_probe() {
    // Run alone under /usr/bin/time -l with KAN_REVIEW_RSS_FILE prepared outside.
    let Some(p) = std::env::var_os("KAN_REVIEW_RSS_FILE") else { return };
    let v = corpus().into_iter().find(|v| v["name"] == std::env::var("KAN_REVIEW_RSS_CASE").unwrap()).unwrap();
    probe("RSS", Path::new(&p), &v, budget());
}
