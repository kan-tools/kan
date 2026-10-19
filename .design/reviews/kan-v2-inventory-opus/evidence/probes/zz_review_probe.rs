// TEMPORARY independent-review probe. Copied into tests/ only while running;
// removed afterwards. Prints observations ("PROBE ...") rather than asserting
// the reviewer's expectations, so every probe runs and is judged from the log.
#![cfg(feature = "v2-storage")]
use kan::{
    evidence_copy_plan::Target,
    evidence_service::{self as service, Command, Grant, Request, Service, SignedRequest},
    evidence_store::{
        self as store, attested, copied,
        copy_upgrade::{read_plan_for_copy, retain_plan, PlannedCopy},
        inventory::{self, Availability, Budget, Inventory, PageBudget, Profile, Source},
        Ledger, RecoveryReader,
    },
    sign::Identity,
};
use std::{
    io::Write,
    path::{Path, PathBuf},
    sync::{atomic::AtomicBool, Arc},
    time::{Duration, Instant},
};

fn identity(n: u8) -> Identity {
    let mut f = tempfile::NamedTempFile::new().unwrap();
    f.write_all(&[n; 32]).unwrap();
    Identity::load_existing(f.path()).unwrap()
}
fn grant() -> Grant {
    Grant {
        principal: identity(6).did().to_string(),
        append: true,
        inventory: true,
    }
}
fn request(n: u8, audience: u8, previous: Option<String>) -> Vec<u8> {
    SignedRequest::sign(
        Request {
            version: 1,
            scope: service::hex(&[1; 32]),
            principal: identity(6).did().to_string(),
            audience: identity(audience).did().to_string(),
            expires: None,
            command: Command::Append {
                id: service::hex(&[n + 1; 16]),
                position: n as u64,
                previous,
                ciphertext: service::hex(b"synthetic encrypted capture"),
            },
        },
        &identity(6),
    )
    .unwrap()
    .bytes()
    .unwrap()
}
fn legacy(parent: &Path, records: u8) -> (PathBuf, Vec<Vec<u8>>) {
    let root = parent.join("legacy");
    let mut a = Service::new(
        Ledger::create(&root).unwrap(),
        [1; 32],
        identity(7),
        vec![grant()],
    )
    .unwrap();
    let mut previous = None;
    let mut requests = Vec::new();
    for n in 0..records {
        let bytes = request(n, 7, previous);
        assert!(a.dispatch(&bytes, 100 + n as u64).unwrap().reply.result.is_ok());
        previous = Some(service::append_manifest(&bytes).unwrap().cid().to_string());
        requests.push(bytes);
    }
    (root.join("archive.sqlite"), requests)
}
fn planned(db: &Path) -> PlannedCopy {
    PlannedCopy::open(
        db,
        Target {
            scope: [1; 32],
            issuer: identity(8).did().to_string(),
        },
        identity(7).did().to_string(),
        [9; 32],
    )
    .unwrap()
}
fn admitted(parent: &Path) -> (PathBuf, attested::Binding, Vec<Vec<u8>>) {
    let root = parent.join("archive");
    let binding = attested::Binding {
        archive: [2; 32],
        scope: [1; 32],
        issuer: identity(8).did().to_string(),
    };
    let mut a = attested::Archive::create(&root, binding.clone()).unwrap();
    let mut previous = None;
    let mut requests = Vec::new();
    for n in 0..3 {
        let bytes = request(n, 8, previous);
        let r = a.admit(&bytes, &identity(8), &grant(), 100 + n as u64).unwrap();
        previous = Some(r.record.manifest.cid().to_string());
        requests.push(bytes);
    }
    (root, binding, requests)
}
fn budget() -> Budget {
    Budget {
        items: 100,
        metadata_bytes: 4 * 1024 * 1024,
        duration: Duration::from_secs(10),
        cancelled: Arc::new(AtomicBool::new(false)),
    }
}
fn page_budget() -> PageBudget {
    PageBudget {
        rows: 40,
        record_bytes: 4 * 1024 * 1024,
        payload_bytes: 16 * 1024 * 1024,
    }
}
fn read_opt(p: &Path) -> Option<Vec<u8>> {
    std::fs::read(p).ok()
}
fn private(p: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
}

// ---------------- Scope A ----------------

/// Every APFS alias found by the filesystem brute force, plus mixed-case/base aliases,
/// through the real retain_plan and read_plan_for_copy entry points.
#[test]
fn probe_a1_all_observed_fs_aliases_refused_by_real_entry_points() {
    let t = tempfile::tempdir().unwrap();
    let (db, _) = legacy(t.path(), 2);
    let src = planned(&db);
    let safe = t.path().join("safe.cbor");
    retain_plan(&safe, &src).unwrap();
    let plan_bytes = std::fs::read(&safe).unwrap();
    let pin = src.plan().archive_id();
    let root = t.path().join("copy");
    let mut a = copied::Archive::create(
        &root,
        &src,
        attested::Binding {
            archive: pin,
            scope: [1; 32],
            issuer: identity(8).did().to_string(),
        },
    )
    .unwrap();
    drop(a.verify());
    drop(a);
    let names = [
        "archive.sqlite-Shm", "archive.sqlite-ſhm", "archive.sqlite-sHm", "archive.sqlite-shM",
        "archive.sqlite-ſHM", "archive.sqlite-Wal", "archive.sqlite-WAL", "archive.sqlite-Journal",
        "archive.sqlite-JOURNAL", "ARCHIVE.SQLITE-shm", "Archive.SQLite-ſhm", "ARCHIVE.SQLITE",
        "archive.sqlite-shm", "archive.sqlite-wal", "archive.sqlite-journal", "archive.sqlite",
    ];
    let source_before = std::fs::read(&db).unwrap();
    for name in names {
        let s = db.with_file_name(name);
        let existed = s.exists();
        let r = retain_plan(&s, &src);
        println!("PROBE A1 retain_plan source-dir {name:?} existed={existed} -> {:?}", r.as_ref().err().map(|e| e.to_string()));
        assert!(r.is_err(), "retain_plan accepted {name}");
        // destination family: place plan bytes at the alias (if creatable) and read it.
        let d = root.join(name);
        let pre = d.exists();
        if !pre {
            std::fs::write(&d, &plan_bytes).unwrap();
            private(&d);
        }
        let before = std::fs::read(&d).unwrap();
        let r = read_plan_for_copy(&d, &db, &root, &pin);
        println!("PROBE A1 read_plan_for_copy dest-dir {name:?} preexisting={pre} -> {:?}", r.as_ref().err().map(|e| e.to_string()));
        assert!(r.is_err(), "read_plan_for_copy accepted {name}");
        assert_eq!(std::fs::read(&d).unwrap(), before);
        if !pre {
            std::fs::remove_file(&d).unwrap();
        }
    }
    assert_eq!(std::fs::read(&db).unwrap(), source_before);
    // Legitimate path still works, including a name that merely contains '-shm'.
    for ok in ["plan-shm.cbor", "archive.sqlite-shmx", "archive.sqlite.shm", "plan-ſ.cbor"] {
        let p = t.path().join(ok);
        let r = retain_plan(&p, &src);
        println!("PROBE A1 legitimate {ok:?} -> {:?}", r.as_ref().err().map(|e| e.to_string()));
    }
    // A plan literally named like a sidecar of an unrelated, absent database is allowed?
    let unrelated = t.path().join("notes.db-ſhm");
    println!("PROBE A1 unrelated absent-base sidecar-shaped name -> {:?}", retain_plan(&unrelated, &src).err().map(|e| e.to_string()));
}

/// Recovery/backup interfaces use the same helper: refuse Unicode/base aliases and
/// leave source bytes unchanged.
#[test]
fn probe_a2_backup_and_rebuild_refuse_aliases() {
    let t = tempfile::tempdir().unwrap();
    let (db, _) = legacy(t.path(), 2);
    let dir = db.parent().unwrap().to_path_buf();
    let link = t.path().join("linkdir");
    #[cfg(unix)]
    std::os::unix::fs::symlink(&dir, &link).unwrap();
    let ledger = Ledger::open(&dir).unwrap();
    let before = std::fs::read(&db).unwrap();
    for dest in [
        dir.join("archive.sqlite-ſhm"),
        dir.join("archive.sqlite-WAL"),
        dir.join("ARCHIVE.SQLITE"),
        link.join("archive.sqlite-journal"),
        link.join("Archive.sqlite-ſhm"),
    ] {
        let r = ledger.backup(&dest);
        println!("PROBE A2 Ledger::backup {:?} -> {:?}", dest.file_name().unwrap(), r.as_ref().err().map(|e| e.to_string()));
        assert!(r.is_err());
    }
    drop(ledger);
    let reader = RecoveryReader::open(&db).unwrap();
    for dest in [dir.join("archive.sqlite-ſhm"), link.join("ARCHIVE.sqlite-Wal")] {
        let r = reader.rebuild(&dest);
        println!("PROBE A2 RecoveryReader::rebuild {:?} -> {:?}", dest.file_name().unwrap(), r.as_ref().err().map(|e| e.to_string()));
        assert!(r.is_err());
    }
    drop(reader);
    // Positive control: an unrelated backup path succeeds.
    let ledger = Ledger::open(&dir).unwrap();
    let ok = t.path().join("backup.sqlite");
    println!("PROBE A2 positive backup -> ok={}", ledger.backup(&ok).is_ok());
    drop(ledger);
    assert_eq!(std::fs::read(&db).unwrap(), before);
}

/// CLI copy-plan opens the source before checking its output plan path. If an owner
/// file already sits at a Unicode alias of the source's SQLite sidecar, does the
/// refusal happen before SQLite consumes it?
#[test]
fn probe_a3_cli_copy_plan_existing_alias_output_is_preserved() {
    for (label, name) in [
        ("control-existing-ordinary", "existing-plan.cbor"),
        ("shm-unicode", "archive.sqlite-ſhm"),
        ("shm-case", "archive.sqlite-SHM"),
        ("wal-case", "archive.sqlite-WAL"),
        ("journal-case", "archive.sqlite-JOURNAL"),
    ] {
        let t = tempfile::tempdir().unwrap();
        let (db, _) = legacy(t.path(), 2);
        // Owner's previously retained plan, then copied to the probe path.
        let src = planned(&db);
        let safe = t.path().join("safe.cbor");
        retain_plan(&safe, &src).unwrap();
        drop(src);
        let target = if label.starts_with("control") {
            t.path().join(name)
        } else {
            db.with_file_name(name)
        };
        std::fs::copy(&safe, &target).unwrap();
        private(&target);
        let original = std::fs::read(&target).unwrap();
        let db_before = std::fs::read(&db).unwrap();
        let o = std::process::Command::new(env!("CARGO_BIN_EXE_kan-v2"))
            .args([
                "copy-plan",
                db.to_str().unwrap(),
                target.to_str().unwrap(),
                "--scope",
                &service::hex(&[1; 32]),
                "--issuer",
                identity(8).did().as_str(),
                "--historical-issuer",
                identity(7).did().as_str(),
                "--nonce",
                &service::hex(&[9; 32]),
            ])
            .output()
            .unwrap();
        let after = read_opt(&target);
        println!(
            "PROBE A3 {label}: exit_ok={} stderr={:?} target_preserved={} target_len_after={:?} db_unchanged={}",
            o.status.success(),
            String::from_utf8_lossy(&o.stderr).trim(),
            after.as_deref() == Some(&original[..]),
            after.as_ref().map(|b| b.len()),
            std::fs::read(&db).unwrap() == db_before
        );
    }
}

// ---------------- Scope B ----------------

/// A single payload whose SQLite storage class flipped from BLOB to TEXT (one bit in
/// the record header) with the declared length: per-row Corrupt, or whole-page refusal?
#[test]
fn probe_b1_text_typed_payload_classification() {
    for (label, sql_value) in [
        ("text-same-length", "same"),
        ("text-other-length", "short"),
        ("integer", "int"),
    ] {
        let t = tempfile::tempdir().unwrap();
        let (root, binding, requests) = admitted(t.path());
        let db = root.join("archive.sqlite");
        let id = store::ciphertext_cid(&requests[1]).to_string();
        let c = rusqlite::Connection::open(&db).unwrap();
        match sql_value {
            "same" => c
                .execute(
                    "UPDATE objects SET bytes=? WHERE cid=?",
                    rusqlite::params!["a".repeat(requests[1].len()), id],
                )
                .unwrap(),
            "short" => c
                .execute("UPDATE objects SET bytes='abc' WHERE cid=?", [&id])
                .unwrap(),
            _ => c
                .execute("UPDATE objects SET bytes=12345 WHERE cid=?", [&id])
                .unwrap(),
        };
        let ty: String = c
            .query_row("SELECT typeof(bytes) FROM objects WHERE cid=?", [&id], |r| r.get(0))
            .unwrap();
        drop(c);
        let a = Inventory::open(&db, Profile::Admitted, binding.clone(), budget()).unwrap();
        let p = a.page(None, page_budget(), budget());
        match p {
            Ok(p) => println!(
                "PROBE B1 {label} (typeof={ty}): page ok, states={:?}",
                p.records.iter().map(|r| (r.record.sequence, r.availability)).collect::<Vec<_>>()
            ),
            Err(e) => println!("PROBE B1 {label} (typeof={ty}): WHOLE PAGE REFUSED: {e}"),
        }
    }
}

/// One unrelated damaged object row (oversized key) — with the linear NOT INDEXED scan,
/// does it refuse every page, including rows whose payloads are healthy?
#[test]
fn probe_b2_unrelated_object_row_damage_blast_radius() {
    let t = tempfile::tempdir().unwrap();
    let (root, binding, _) = admitted(t.path());
    let db = root.join("archive.sqlite");
    let c = rusqlite::Connection::open(&db).unwrap();
    c.execute_batch("PRAGMA foreign_keys=OFF").unwrap();
    // Sorts after real CIDs ("bafk..."), so it is not on any healthy row's key path.
    c.execute(
        "INSERT INTO objects VALUES('zz'||hex(zeroblob(200000)), x'01')",
        [],
    )
    .unwrap();
    drop(c);
    let a = Inventory::open(&db, Profile::Admitted, binding.clone(), budget());
    match a {
        Err(e) => println!("PROBE B2 startup refused: {e}"),
        Ok(a) => {
            match a.page(None, page_budget(), budget()) {
                Ok(p) => println!("PROBE B2 page ok: {:?}", p.records.iter().map(|r| r.availability).collect::<Vec<_>>()),
                Err(e) => println!("PROBE B2 WHOLE PAGE REFUSED by unrelated object row: {e}"),
            }
        }
    }
}

/// Production page path: VM cancellation interrupts a long payload scan
/// (not only the in-memory unit test), plus disclosed linear-scan latency.
#[test]
fn probe_b3_page_scan_latency_and_production_cancellation() {
    let t = tempfile::tempdir().unwrap();
    let (root, binding, _) = admitted(t.path());
    let db = root.join("archive.sqlite");
    let c = rusqlite::Connection::open(&db).unwrap();
    c.execute_batch("PRAGMA foreign_keys=OFF").unwrap();
    // 400k staged-orphan-sized rows sorting before real CIDs.
    c.execute_batch(
        "WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<400000)
         INSERT INTO objects SELECT 'a'||printf('%08d',x), x'01' FROM n;",
    )
    .unwrap();
    drop(c);
    let a = Inventory::open(&db, Profile::Admitted, binding.clone(), budget()).unwrap();
    let start = Instant::now();
    let p = a.page(None, page_budget(), budget()).unwrap();
    println!(
        "PROBE B3 3-row page over 400k objects: {:?}, states={:?}",
        start.elapsed(),
        p.records.iter().map(|r| r.availability).collect::<Vec<_>>()
    );
    let b = budget();
    let flag = b.cancelled.clone();
    let start = Instant::now();
    let th = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(5));
        flag.store(true, std::sync::atomic::Ordering::Relaxed);
    });
    let r = a.page(None, page_budget(), b);
    th.join().unwrap();
    println!(
        "PROBE B3 cancel after 5ms: elapsed={:?} result={:?}",
        start.elapsed(),
        r.as_ref().err().map(|e| e.to_string())
    );
    let mut b = budget();
    b.duration = Duration::from_millis(15);
    let start = Instant::now();
    let r = a.page(None, page_budget(), b);
    println!(
        "PROBE B3 15ms deadline: elapsed={:?} result={:?}",
        start.elapsed(),
        r.as_ref().err().map(|e| e.to_string())
    );
    // The handle remains usable after interrupted pages.
    println!("PROBE B3 reuse after interrupt ok={}", a.page(None, page_budget(), budget()).is_ok());
}

/// Profile-3 admitted suffix rows: page + fresh source positive, and selection replay
/// against a later, extended snapshot.
#[test]
fn probe_b4_profile3_admitted_suffix_and_snapshot_isolation() {
    let t = tempfile::tempdir().unwrap();
    let (db, requests) = legacy(t.path(), 2);
    let src = planned(&db);
    let binding = attested::Binding {
        archive: src.plan().archive_id(),
        scope: [1; 32],
        issuer: identity(8).did().to_string(),
    };
    let root = t.path().join("copy");
    let mut a = copied::Archive::create(&root, &src, binding.clone()).unwrap();
    assert!(a
        .copy_batch(&src, &identity(8), 1000, copied::Budget { objects: 100, records: 100, bytes: 1 << 24 })
        .unwrap()
        .status
        .source_copy_complete);
    let prev = service::append_manifest(&requests[1]).unwrap().cid().to_string();
    a.admit(&request(2, 8, Some(prev.clone())), &identity(8), &grant(), 300).unwrap();
    drop(a);
    let path = root.join("archive.sqlite");
    let inv = Inventory::open(&path, Profile::Copied, binding.clone(), budget()).unwrap();
    println!("PROBE B4 frontier={} recipe_metadata_match={:?}", inv.frontier().through, inv.recipe_metadata_match());
    let p = inv.page(None, page_budget(), budget()).unwrap();
    for r in &p.records {
        let s = inventory::source(&path, Profile::Copied, binding.clone(), &r.selection, service::MAX_REQUEST, budget());
        println!(
            "PROBE B4 seq={} purpose={:?} avail={:?} source={}",
            r.record.sequence,
            r.proof.purpose(),
            r.availability,
            match s {
                Ok(Source::Available { writer, .. }) => format!("Available writer={}", writer == identity(6).did().to_string()),
                Ok(Source::Unavailable(x)) => format!("Unavailable({x:?})"),
                Err(e) => format!("ERR {e}"),
            }
        );
    }
    // Writer appends while the pinned inventory is open.
    let tip = p.records[0].record.manifest.cid().to_string();
    let mut w = copied::Archive::open(&root, binding.clone());
    match &mut w {
        Ok(w) => println!(
            "PROBE B4 concurrent admit while inventory pinned -> ok={}",
            w.admit(&request(3, 8, Some(tip)), &identity(8), &grant(), 400).is_ok()
        ),
        Err(e) => println!("PROBE B4 writer open while inventory pinned -> {e}"),
    }
    drop(w);
    let again = inv.page(None, page_budget(), budget()).unwrap();
    println!("PROBE B4 pinned snapshot still through={} rows={}", inv.frontier().through, again.records.len());
    let inv2 = Inventory::open(&path, Profile::Copied, binding.clone(), budget()).unwrap();
    println!(
        "PROBE B4 new snapshot through={}; old cursor on new snapshot refused={}; old selection on fresh source={}",
        inv2.frontier().through,
        p.next.as_ref().map(|c| inv2.page(Some(c), page_budget(), budget()).is_err()).unwrap_or(true),
        inventory::source(&path, Profile::Copied, binding.clone(), &p.records[0].selection, service::MAX_REQUEST, budget()).is_ok()
    );
    let _ = Availability::Available;
}

/// B1 realism: flip ONE bit in the on-disk record header (BLOB serial type 2N+12 ->
/// TEXT 2N+13) of one payload row. Payloads are JSON signed requests (ASCII), so the
/// TEXT character length equals the declared byte length.
#[test]
fn probe_b5_single_bit_serial_type_flip_on_disk() {
    let t = tempfile::tempdir().unwrap();
    let (root, binding, requests) = admitted(t.path());
    let db = root.join("archive.sqlite");
    let id = store::ciphertext_cid(&requests[1]).to_string();
    let c = rusqlite::Connection::open(&db).unwrap();
    c.execute_batch("PRAGMA journal_mode=DELETE; VACUUM;").unwrap();
    drop(c);
    let mut file = std::fs::read(&db).unwrap();
    let n = requests[1].len() as u64;
    let serial = 2 * n + 12;
    let mut varint = Vec::new();
    // SQLite big-endian varint (values here < 2^14).
    assert!(serial < 16384);
    if serial >= 128 {
        varint.push(0x80 | (serial >> 7) as u8);
    }
    varint.push((serial & 0x7f) as u8);
    let mut needle = varint.clone();
    // header: [hdr size][cid serial][bytes serial] then cid text
    let cid_serial = 2 * id.len() as u64 + 13;
    assert!(cid_serial < 16384);
    let mut pattern = Vec::new();
    if cid_serial >= 128 {
        pattern.push(0x80 | (cid_serial >> 7) as u8);
    }
    pattern.push((cid_serial & 0x7f) as u8);
    pattern.extend(&needle);
    pattern.extend(id.as_bytes());
    let hits: Vec<usize> = file
        .windows(pattern.len())
        .enumerate()
        .filter(|(_, w)| *w == &pattern[..])
        .map(|(i, _)| i)
        .collect();
    println!("PROBE B5 header pattern hits={}", hits.len());
    assert_eq!(hits.len(), 1);
    // last byte of the bytes-serial varint (after the cid-serial varint)
    let at = hits[0] + (pattern.len() - id.len()) - 1;
    assert_eq!(file[at], *varint.last().unwrap());
    file[at] ^= 1;
    needle.clear();
    std::fs::write(&db, &file).unwrap();
    let c = rusqlite::Connection::open(&db).unwrap();
    let ty: String = c
        .query_row("SELECT typeof(bytes) FROM objects WHERE cid=?", [&id], |r| r.get(0))
        .unwrap();
    drop(c);
    let inv = Inventory::open(&db, Profile::Admitted, binding.clone(), budget());
    match inv {
        Err(e) => println!("PROBE B5 (typeof={ty}) startup refused: {e}"),
        Ok(inv) => {
            for limit in [page_budget(), PageBudget { rows: 1, ..page_budget() }] {
                match inv.page(None, limit, budget()) {
                    Ok(p) => println!("PROBE B5 (typeof={ty}) rows={} page ok {:?}", limit.rows, p.records.iter().map(|r| r.availability).collect::<Vec<_>>()),
                    Err(e) => println!("PROBE B5 (typeof={ty}) rows={} WHOLE PAGE REFUSED: {e}", limit.rows),
                }
            }
            // Browse past the damaged row: page 1 (row 3) then cursor.
            let first = inv.page(None, PageBudget { rows: 1, ..page_budget() }, budget()).unwrap();
            let sel = first.records[0].selection.clone();
            println!(
                "PROBE B5 cursor past damaged row 2 -> {:?}",
                inv.page(first.next.as_ref(), page_budget(), budget()).err().map(|e| e.to_string())
            );
            let _ = sel;
            // Fresh source of the damaged row cannot be selected (no selection is
            // obtainable); healthy row 3 still sources.
            println!(
                "PROBE B5 healthy tip source ok={}",
                matches!(inventory::source(&db, Profile::Admitted, binding.clone(), &first.records[0].selection, service::MAX_REQUEST, budget()), Ok(Source::Available { .. }))
            );
        }
    }
}
