#![cfg(feature = "v2-storage")]
//! Reviewer probe (temporary). Scope B per-case attribution.
#![allow(unused_imports, dead_code)]
use kan::{
    evidence::{self, Decoded},
    evidence_copy_plan::Target,
    evidence_service::{hex, Command, Grant, Output, Request, Service, SignedRequest},
    evidence_store::{copy_upgrade::PlannedCopy, Ledger, RecoveryReader},
    sign::Identity,
};
use std::{io::Write, path::Path};
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
fn service(root: &Path) -> Service {
    Service::new(
        Ledger::create(root).unwrap(),
        [1; 32],
        identity(7),
        vec![Grant {
            principal: identity(6).did().to_string(),
            append: true,
            inventory: false,
        }],
    )
    .unwrap()
}
fn append(s: &mut Service, n: u8) {
    let writer = identity(6);
    let bytes = SignedRequest::sign(
        Request {
            version: 1,
            scope: hex(&[1; 32]),
            audience: identity(7).did().to_string(),
            principal: writer.did().to_string(),
            expires: None,
            command: Command::Append {
                id: hex(&[n; 16]),
                position: 0,
                previous: None,
                ciphertext: hex(b"opaque fixture"),
            },
        },
        &writer,
    )
    .unwrap()
    .bytes()
    .unwrap();
    assert!(matches!(
        s.dispatch(&bytes, 100)
            .unwrap()
            .verify(&bytes, &s.issuer())
            .unwrap()
            .result,
        Ok(Output::Committed { .. })
    ));
}

fn reason<T>(r: Result<T, kan::evidence_store::Error>) -> String {
    match r { Ok(_) => "ACCEPTED".into(), Err(e) => e.to_string() }
}
#[test]
fn pb1_schema_cases_print_exact_reasons() {
    let mut accepted = Vec::new();
    for sql in [
        "CREATE INDEX extra ON commits(writer)",
        "CREATE TRIGGER extra AFTER INSERT ON objects BEGIN SELECT 1; END",
        "CREATE VIEW extra AS SELECT 1",
        "CREATE TABLE extra(x)",
        "PRAGMA user_version=2",
        "PRAGMA user_version=3",
        "PRAGMA application_id=7",
    ] {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("archive");
        let mut s = service(&root);
        append(&mut s, 1);
        let issuer = s.issuer();
        drop(s);
        let db = root.join("archive.sqlite");
        let c = rusqlite::Connection::open(&db).unwrap();
        c.execute_batch(sql).unwrap();
        c.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)").unwrap();
        drop(c);
        let r = reason(PlannedCopy::open(&db, target(), issuer, [9; 32]));
        println!("PB1 {sql:70} -> {r}");
        if r == "ACCEPTED" { accepted.push(sql); }
    }
    println!("PB1 accepted={accepted:?}");
    assert!(accepted.is_empty());
}
#[test]
fn pb2_owner_pin_reasons_and_object_count() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("archive");
    let mut s = service(&root);
    append(&mut s, 1);
    let issuer = s.issuer();
    drop(s);
    let db = root.join("archive.sqlite");
    let planned = PlannedCopy::open(&db, target(), issuer.clone(), [9; 32]).unwrap();
    let plan = planned.plan();
    let mut wrong = plan.archive_id();
    wrong[31] ^= 1;
    println!("PB2 right={}", reason(PlannedCopy::confirm(&db, plan, &plan.archive_id()).map(|_| ())));
    println!("PB2 wrong-pin={}", reason(PlannedCopy::confirm(&db, plan, &wrong).map(|_| ())));
    let sibling = PlannedCopy::open(&db, target(), issuer, [10; 32]).unwrap();
    println!("PB2 sibling-with-other-pin={}", reason(PlannedCopy::confirm(&db, sibling.plan(), &plan.archive_id()).map(|_| ())));
    println!("PB2 sibling-own-pin={}", reason(PlannedCopy::confirm(&db, sibling.plan(), &sibling.plan().archive_id()).map(|_| ())));
    // Object count of the oracle fixture shape.
    let mut ledger = Ledger::open(&root).unwrap();
    ledger.stage(b"uncommitted object preserved separately").unwrap();
    for n in 1..=25 { ledger.stage(&vec![n as u8; n * 13]).unwrap(); }
    drop(ledger);
    let c = rusqlite::Connection::open(&db).unwrap();
    let n: i64 = c.query_row("SELECT count(*) FROM objects", [], |r| r.get(0)).unwrap();
    let mut st = c.prepare("SELECT cid FROM objects").unwrap();
    let cids: Vec<String> = st.query_map([], |r| r.get(0)).unwrap().map(Result::unwrap).collect();
    let mut sorted = cids.clone(); sorted.sort();
    let ascii = cids.iter().all(|c| c.is_ascii());
    println!("PB2 objects={n} all_ascii={ascii} unsorted_scan_differs_from_sorted={}", cids != sorted);
}
