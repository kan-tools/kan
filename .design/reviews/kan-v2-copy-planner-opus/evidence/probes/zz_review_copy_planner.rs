#![cfg(feature = "v2-storage")]
//! Reviewer probes for the copy-plan codec and read-only source planner (Scope A).
//! Synthetic fixtures only. Each probe prints a RESULT line; assertions are the verdicts.
use kan::{
    evidence_copy_plan::{Plan, Target},
    evidence_service::{hex, Command, Grant, Output, Request, Service, SignedRequest},
    evidence_store::{copy_upgrade::PlannedCopy, Ledger, RecoveryReader},
    sign::Identity,
};
use std::{io::Write, path::Path, time::Instant};

fn identity(n: u8) -> Identity {
    let mut f = tempfile::NamedTempFile::new().unwrap();
    f.write_all(&[n; 32]).unwrap();
    Identity::load_existing(f.path()).unwrap()
}
fn target() -> Target {
    Target {
        scope: [1; 32],
        issuer: identity(8).did().to_string(),
    }
}
fn service(root: &Path, issuer: u8, writers: &[u8]) -> Service {
    let ledger = if root.join("archive.sqlite").exists() {
        Ledger::open(root).unwrap()
    } else {
        Ledger::create(root).unwrap()
    };
    Service::new(
        ledger,
        [1; 32],
        identity(issuer),
        writers
            .iter()
            .map(|w| Grant {
                principal: identity(*w).did().to_string(),
                append: true,
                inventory: false,
            })
            .collect(),
    )
    .unwrap()
}
fn request(issuer: &str, writer: &Identity, id: [u8; 16], position: u64, previous: Option<String>, payload: &[u8]) -> Vec<u8> {
    SignedRequest::sign(
        Request {
            version: 1,
            scope: hex(&[1; 32]),
            audience: issuer.into(),
            principal: writer.did().to_string(),
            expires: None,
            command: Command::Append {
                id: hex(&id),
                position,
                previous,
                ciphertext: hex(payload),
            },
        },
        writer,
    )
    .unwrap()
    .bytes()
    .unwrap()
}
fn admit(s: &mut Service, bytes: &[u8]) -> String {
    let reply = s.dispatch(bytes, 100).unwrap();
    match &reply.verify(bytes, &s.issuer()).unwrap().result {
        Ok(Output::Committed { record, .. }) => {
            let raw: Vec<u8> = (0..record.manifest.len() / 2)
                .map(|i| u8::from_str_radix(&record.manifest[2 * i..2 * i + 2], 16).unwrap())
                .collect();
            let kan::evidence::Decoded::Known(m) = kan::evidence::decode(&raw).unwrap() else {
                panic!()
            };
            m.cid().to_string()
        }
        other => panic!("not committed: {other:?}"),
    }
}
fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}
/// Authoritative media under the declared read-source boundary: main database and
/// any NON-EMPTY WAL. Empty WAL / SHM are coordination files and reported separately.
fn authoritative(root: &Path) -> Vec<(String, Vec<u8>)> {
    files(root)
        .into_iter()
        .filter(|(n, b)| !(n.ends_with("-wal") && b.is_empty()))
        .collect()
}
fn names(root: &Path) -> Vec<(String, u64)> {
    let mut v: Vec<_> = std::fs::read_dir(root).unwrap().map(|e| { let e = e.unwrap(); (e.file_name().to_string_lossy().into_owned(), e.metadata().unwrap().len()) }).collect();
    v.sort();
    v
}
fn files(root: &Path) -> Vec<(String, Vec<u8>)> {
    let mut out: Vec<_> = std::fs::read_dir(root)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| !p.to_string_lossy().ends_with("-shm"))
        .map(|p| (p.file_name().unwrap().to_string_lossy().into_owned(), std::fs::read(&p).unwrap()))
        .collect();
    out.sort();
    out
}
fn chmod600(p: &Path) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600)).unwrap();
}

/// RA1: hostile/noncanonical plans from an independent encoder are refused; labels printed.
#[test]
fn ra1_noncanonical_and_hostile_plans() {
    let path = std::env::var("REVIEW_PLANS").expect("REVIEW_PLANS");
    let vectors: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let mut bad = Vec::new();
    for v in vectors.as_array().unwrap() {
        let name = v["name"].as_str().unwrap();
        let result = Plan::decode(&unhex(v["hex"].as_str().unwrap()));
        let shown = match &result {
            Ok(p) => format!("ACCEPT archive={}", hex(&p.archive_id())),
            Err(e) => format!("REFUSE {e}"),
        };
        println!("RA1 {name}: {shown}");
        match v["expect"].as_str().unwrap() {
            "accept" if result.is_err() => bad.push(name.to_string()),
            "refuse" if result.is_ok() => bad.push(name.to_string()),
            _ => {}
        }
    }
    assert!(bad.is_empty(), "RA1 unexpected outcomes: {bad:?}");
}

/// RA2: the author's 33 negative vectors — print each failure reason to judge specificity.
#[test]
fn ra2_author_negative_vector_reasons() {
    let fx: serde_json::Value =
        serde_json::from_str(include_str!("../.design/fixtures/copy-plan-v1.json")).unwrap();
    for v in fx["negative"].as_array().unwrap() {
        let e = Plan::decode(&unhex(v["hex"].as_str().unwrap())).unwrap_err();
        println!("RA2 {}: {e}", v["name"].as_str().unwrap());
    }
}

/// RA3: multi-writer, multi-chain, many staged objects; Rust digest vs two Python oracles.
#[test]
fn ra3_digest_matches_independent_oracles_on_richer_fixture() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("a");
    let mut s = service(&root, 7, &[5, 6]);
    let issuer = s.issuer();
    let (w5, w6) = (identity(5), identity(6));
    let (mut prev5, mut prev6) = (None, None);
    for i in 0..4u8 {
        prev5 = Some(admit(&mut s, &request(&issuer, &w5, [10 + i; 16], i as u64, prev5.clone(), &[i; 7])));
        prev6 = Some(admit(&mut s, &request(&issuer, &w6, [40 + i; 16], i as u64, prev6.clone(), &vec![i; 300 + i as usize])));
    }
    drop(s);
    let mut ledger = Ledger::open(&root).unwrap();
    for i in 0..25u16 {
        ledger.stage(format!("staged object {i:03} {}", "x".repeat(i as usize * 13)).as_bytes()).unwrap();
    }
    drop(ledger);
    let db = root.join("archive.sqlite");
    let planned = PlannedCopy::open(&db, target(), issuer, [9; 32]).unwrap();
    let rust = hex(&planned.plan().source().digest);
    drop(planned);
    let mine = std::process::Command::new("python3")
        .args(["-I", &std::env::var("REVIEW_ORACLE").unwrap()])
        .arg(&db)
        .output()
        .unwrap();
    let theirs = std::process::Command::new("python3")
        .args(["-I", "-B", concat!(env!("CARGO_MANIFEST_DIR"), "/.design/tools/copy_source_digest.py")])
        .arg(&db)
        .output()
        .unwrap();
    let mine = String::from_utf8(mine.stdout).unwrap().trim().to_string();
    let theirs = String::from_utf8(theirs.stdout).unwrap().trim().to_string();
    println!("RA3 rust={rust} reviewer={mine} author={theirs} commits=8 objects=33");
    assert_eq!(rust, mine);
    assert_eq!(rust, theirs);
}

/// RA4: mixed receipt issuers (record 2 admitted under a different issuer) refuse for either H.
#[test]
fn ra4_mixed_historical_issuers_refuse() {
    let dir = tempfile::tempdir().unwrap();
    let a = dir.path().join("a");
    let b = dir.path().join("b");
    let mut sa = service(&a, 7, &[6]);
    let ha = sa.issuer();
    admit(&mut sa, &request(&ha, &identity(6), [1; 16], 0, None, b"a"));
    drop(sa);
    let mut sb = service(&b, 9, &[5]);
    let hb = sb.issuer();
    admit(&mut sb, &request(&hb, &identity(5), [2; 16], 0, None, b"b"));
    drop(sb);
    let rb = RecoveryReader::open(&b.join("archive.sqlite")).unwrap();
    let rec = rb.record(1).unwrap();
    let kan::evidence::Decoded::Known(_) = kan::evidence::decode(rec.manifest.bytes()).unwrap() else { panic!() };
    let req_cid = {
        let ipld = rec.manifest.body();
        let atproto_dasl::Ipld::List(es) = &ipld["entries"] else { panic!() };
        let atproto_dasl::Ipld::Map(e) = &es[0] else { panic!() };
        let atproto_dasl::Ipld::Link(c) = &e["ciphertext"] else { panic!() };
        c.clone()
    };
    let req = rb.read_object(&req_cid).unwrap();
    drop(rb);
    let mut la = Ledger::open(&a).unwrap();
    la.stage(&req).unwrap();
    la.commit(rec.manifest.bytes(), rec.receipt.bytes()).unwrap();
    assert_eq!(la.verify().unwrap().commits, 2, "raw structure valid");
    drop(la);
    let db = a.join("archive.sqlite");
    for h in [&ha, &hb] {
        let r = PlannedCopy::open(&db, target(), h.clone(), [9; 32]);
        println!("RA4 H={} -> {:?}", &h[..20], r.as_ref().err().map(|e| e.to_string()));
        assert!(r.is_err());
    }
}

/// RA5: unsupported schema/profile variants refuse and leave db/WAL bytes unchanged.
#[test]
fn ra5_unsupported_schema_and_profiles_refuse_without_writes() {
    let cases = [
        ("extra-index", "CREATE INDEX zz ON commits(writer);"),
        ("extra-trigger", "CREATE TRIGGER zz AFTER INSERT ON objects BEGIN SELECT 1; END;"),
        ("extra-view", "CREATE VIEW zz AS SELECT 1;"),
        ("extra-table", "CREATE TABLE zz(x);"),
        ("user-version-2", "PRAGMA user_version=2;"),
        ("user-version-3", "PRAGMA user_version=3;"),
        ("application-id", "PRAGMA application_id=7;"),
    ];
    for (name, sql) in cases {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("a");
        let mut s = service(&root, 7, &[6]);
        let h = s.issuer();
        admit(&mut s, &request(&h, &identity(6), [1; 16], 0, None, b"a"));
        drop(s);
        let db = root.join("archive.sqlite");
        let c = rusqlite::Connection::open(&db).unwrap();
        c.execute_batch(sql).unwrap();
        c.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);").unwrap();
        drop(c);
        let (before, listing) = (authoritative(&root), names(&root));
        let r = PlannedCopy::open(&db, target(), h, [9; 32]);
        println!("RA5 {name}: {:?}", r.as_ref().err().map(|e| e.to_string()));
        assert!(r.is_err(), "{name} accepted");
        drop(r);
        println!("RA5 {name} media before={listing:?} after={:?}", names(&root));
        assert_eq!(authoritative(&root), before, "{name} changed authoritative source media");
    }
    // A profile-2 attested archive is not a recipe-1 source.
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("p2");
    let binding = kan::evidence_store::attested::Binding {
        archive: [3; 32],
        scope: [1; 32],
        issuer: identity(8).did().to_string(),
    };
    drop(kan::evidence_store::attested::Archive::create(&root, binding).unwrap());
    let r = PlannedCopy::open(&root.join("archive.sqlite"), target(), identity(8).did().to_string(), [9; 32]);
    println!("RA5 profile-2-source: {:?}", r.as_ref().err().map(|e| e.to_string()));
    assert!(r.is_err());
}

/// RA6: failure handling: corrupt/oversized/missing objects, permissions, symlinks, bad owner input.
#[test]
fn ra6_failure_handling_is_closed_and_labelled() {
    let setup = || {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("a");
        let mut s = service(&root, 7, &[6]);
        let h = s.issuer();
        admit(&mut s, &request(&h, &identity(6), [1; 16], 0, None, b"a"));
        drop(s);
        (dir, root, h)
    };
    let mutate = |root: &Path, sql: &str| {
        let c = rusqlite::Connection::open(root.join("archive.sqlite")).unwrap();
        c.execute_batch(sql).unwrap();
        drop(c);
    };
    let mut outcomes = Vec::new();
    for (name, sql) in [
        ("flip-object-byte", "UPDATE objects SET bytes=CAST(x'00' || substr(bytes,2) AS BLOB) WHERE cid IN (SELECT ciphertext FROM bindings);"),
        ("delete-request-object", "PRAGMA foreign_keys=OFF; DELETE FROM objects WHERE cid IN (SELECT ciphertext FROM bindings);"),
        ("oversized-staged-5MiB", "PRAGMA ignore_check_constraints=ON; INSERT INTO objects VALUES('bafkreizzzz', zeroblob(5242880));"),
        ("oversized-staged-9MiB", "PRAGMA ignore_check_constraints=ON; INSERT INTO objects VALUES('bafkreizzzy', zeroblob(9437184));"),
        ("bad-cid-staged", "INSERT INTO objects VALUES('not-a-cid', x'01');"),
        ("gap-sequence", "UPDATE commits SET sequence=2 WHERE sequence=1;"),
    ] {
        let (_d, root, h) = setup();
        mutate(&root, sql);
        let t = Instant::now();
        let r = std::panic::catch_unwind(|| PlannedCopy::open(&root.join("archive.sqlite"), target(), h.clone(), [9; 32]).map(|_| ()));
        let shown = match &r {
            Ok(Ok(())) => "ACCEPT".to_string(),
            Ok(Err(e)) => format!("REFUSE {e}"),
            Err(_) => "PANIC".to_string(),
        };
        println!("RA6 {name}: {shown} in {:?}", t.elapsed());
        outcomes.push((name, shown));
    }
    // Permissions and symlink.
    let (_d, root, h) = setup();
    let db = root.join("archive.sqlite");
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&db, std::fs::Permissions::from_mode(0o640)).unwrap();
        let r = PlannedCopy::open(&db, target(), h.clone(), [9; 32]);
        println!("RA6 group-readable: {:?}", r.as_ref().err().map(|e| e.to_string()));
        outcomes.push(("group-readable", if r.is_ok() { "ACCEPT".into() } else { "REFUSE".into() }));
        chmod600(&db);
        let link = root.join("link.sqlite");
        std::os::unix::fs::symlink(&db, &link).unwrap();
        let r = PlannedCopy::open(&link, target(), h.clone(), [9; 32]);
        println!("RA6 symlink: {:?}", r.as_ref().err().map(|e| e.to_string()));
        outcomes.push(("symlink", if r.is_ok() { "ACCEPT".into() } else { "REFUSE".into() }));
    }
    // Invalid owner configuration refuses before touching (even nonexistent) media.
    let r = PlannedCopy::open(&root.join("missing.sqlite"), Target { scope: [1; 32], issuer: identity(6).did().to_string() + "x" }, h.clone(), [9; 32]);
    println!("RA6 bad-current-issuer-on-missing-path: {:?}", r.as_ref().err().map(|e| e.to_string()));
    assert!(!root.join("missing.sqlite").exists());
    for (name, shown) in outcomes {
        assert!(shown.starts_with("REFUSE"), "{name}: {shown}");
    }
}

/// RA7: a held planner pins its snapshot across a concurrent stage+commit in another
/// connection; a RESERVED writer's uncommitted rows are invisible; confirm on a byte
/// backup of the source succeeds (content-addressed recipe, not a file identity).
#[test]
fn ra7_pinning_reserved_writer_and_backup_substitution() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("a");
    let mut s = service(&root, 7, &[6]);
    let h = s.issuer();
    admit(&mut s, &request(&h, &identity(6), [1; 16], 0, None, b"a"));
    let db = root.join("archive.sqlite");
    // RESERVED writer with an uncommitted staged row while planning.
    let w = rusqlite::Connection::open(&db).unwrap();
    w.execute_batch("BEGIN IMMEDIATE; INSERT INTO objects VALUES('bafkreiuncommitted', x'01');").unwrap();
    let t = Instant::now();
    let held = PlannedCopy::open(&db, target(), h.clone(), [9; 32]).unwrap();
    println!("RA7 planned beside RESERVED writer in {:?}", t.elapsed());
    w.execute_batch("ROLLBACK;").unwrap();
    drop(w);
    let plan = held.plan().clone();
    // Later admission while held.
    admit(&mut s, &request(&h, &identity(6), [2; 16], 1, Some(plan.source().tip.clone().unwrap().to_string()), b"b"));
    assert_eq!(held.snapshot().unwrap().through, 1);
    drop(held);
    assert!(PlannedCopy::confirm(&db, &plan, &plan.archive_id()).is_err());
    drop(s);
    // Backup equivalence: a byte backup of the ORIGINAL frontier confirms.
    let dir2 = tempfile::tempdir().unwrap();
    let root2 = dir2.path().join("b");
    let mut s2 = service(&root2, 7, &[6]);
    admit(&mut s2, &request(&h, &identity(6), [1; 16], 0, None, b"a"));
    drop(s2);
    let p2 = PlannedCopy::open(&root2.join("archive.sqlite"), target(), h.clone(), [9; 32]).unwrap();
    let plan2 = p2.plan().clone();
    let backup = dir2.path().join("backup.sqlite");
    Ledger::open(&root2).unwrap().backup(&backup).unwrap();
    drop(p2);
    let confirmed = PlannedCopy::confirm(&backup, &plan2, &plan2.archive_id());
    println!("RA7 backup confirms same recipe: {}", confirmed.is_ok());
    assert!(confirmed.is_ok());
    // Two independently admitted archives with identical content (same keys, same
    // receipt time) are indistinguishable sources: same recipe.
    println!("RA7 independent identical archive digest equal: {}", plan2.source().digest == plan.source().digest);
}

/// RA8: wall-clock cost of open/confirm as history grows (debug build, warm cache).
#[test]
fn ra8_audit_cost_scaling() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("a");
    let writers: Vec<u8> = (20..36).collect();
    let mut s = service(&root, 7, &writers);
    let h = s.issuer();
    let ids: Vec<Identity> = writers.iter().map(|w| identity(*w)).collect();
    let db = root.join("archive.sqlite");
    let mut n = 0u32;
    let mut prev: Vec<Option<String>> = vec![None; 16];
    for milestone in [100u32, 200, 400, 800] {
        while n < milestone {
            let k = (n % 16) as usize;
            let mut id = [0u8; 16];
            id[..4].copy_from_slice(&n.to_be_bytes());
            let position = (n / 16) as u64;
            prev[k] = Some(admit(&mut s, &request(&h, &ids[k], id, position, prev[k].clone(), &vec![(n % 251) as u8; 2048])));
            n += 1;
        }
        let t = Instant::now();
        let p = PlannedCopy::open(&db, target(), h.clone(), [9; 32]).unwrap();
        let open = t.elapsed();
        let plan = p.plan().clone();
        drop(p);
        let t = Instant::now();
        drop(PlannedCopy::confirm(&db, &plan, &plan.archive_id()).unwrap());
        println!("RA8 records={milestone} open={open:?} confirm={:?}", t.elapsed());
    }
}

/// RA9: the owner pin is checked by confirm even when the source is unchanged.
#[test]
fn ra9_confirm_requires_owner_pin_on_unchanged_source() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("a");
    let mut s = service(&root, 7, &[6]);
    let h = s.issuer();
    admit(&mut s, &request(&h, &identity(6), [1; 16], 0, None, b"a"));
    drop(s);
    let db = root.join("archive.sqlite");
    let plan = PlannedCopy::open(&db, target(), h.clone(), [9; 32]).unwrap().plan().clone();
    assert!(PlannedCopy::confirm(&db, &plan, &plan.archive_id()).is_ok());
    let mut wrong = plan.archive_id();
    wrong[31] ^= 1;
    let r = PlannedCopy::confirm(&db, &plan, &wrong);
    println!("RA9 wrong pin, unchanged source: {:?}", r.as_ref().err().map(|e| e.to_string()));
    assert!(r.is_err());
    // A sibling plan (fresh nonce) over the same source is a different archive.
    let sibling = PlannedCopy::open(&db, target(), h, [10; 32]).unwrap().plan().clone();
    assert!(PlannedCopy::confirm(&db, &sibling, &plan.archive_id()).is_err());
}
