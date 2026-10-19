#![cfg(feature = "v2-storage")]
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
#[test]
fn source_plan_is_pinned_and_reconfirmation_detects_later_admission() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("archive");
    let mut s = service(&root);
    append(&mut s, 1);
    let db = root.join("archive.sqlite");
    let planned = PlannedCopy::open(&db, target(), s.issuer(), [9; 32]).unwrap();
    let plan = planned.plan().clone();
    assert_eq!(plan.source().through, 1);
    // A different writer starts a new independent chain so the second admission is valid.
    drop(s);
    let other = identity(5);
    let mut s = Service::new(
        Ledger::open(&root).unwrap(),
        [1; 32],
        identity(7),
        vec![Grant {
            principal: other.did().to_string(),
            append: true,
            inventory: false,
        }],
    )
    .unwrap();
    let bytes = SignedRequest::sign(
        Request {
            version: 1,
            scope: hex(&[1; 32]),
            audience: s.issuer(),
            principal: other.did().to_string(),
            expires: None,
            command: Command::Append {
                id: hex(&[2; 16]),
                position: 0,
                previous: None,
                ciphertext: hex(b"later"),
            },
        },
        &other,
    )
    .unwrap()
    .bytes()
    .unwrap();
    assert!(s
        .dispatch(&bytes, 100)
        .unwrap()
        .verify(&bytes, &s.issuer())
        .unwrap()
        .result
        .is_ok());
    assert_eq!(planned.snapshot().unwrap().through, 1);
    assert!(PlannedCopy::confirm(&db, &plan, &plan.archive_id()).is_err());
    assert!(PlannedCopy::confirm(&db, &plan, &[0; 32]).is_err());
}
// Isolate owner pin enforcement from source-change refusal (review RA9).
#[test]
fn unchanged_source_confirmation_still_requires_the_external_owner_pin() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("archive");
    let mut s = service(&root);
    append(&mut s, 1);
    let issuer = s.issuer();
    drop(s);
    let db = root.join("archive.sqlite");
    let planned = PlannedCopy::open(&db, target(), issuer.clone(), [9; 32]).unwrap();
    let plan = planned.plan();
    assert!(PlannedCopy::confirm(&db, plan, &plan.archive_id()).is_ok());
    let mut wrong = plan.archive_id();
    wrong[31] ^= 1;
    assert!(PlannedCopy::confirm(&db, plan, &wrong).is_err());
    let sibling = PlannedCopy::open(&db, target(), issuer, [10; 32]).unwrap();
    assert!(PlannedCopy::confirm(&db, sibling.plan(), &plan.archive_id()).is_err());
}

// A source that passes its raw content audit can still have an unsupported
// schema. These cases preserve the distinct schema check (review RA5).
#[test]
fn source_planning_refuses_extra_schema_and_wrong_profiles_without_rewriting() {
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
        let before = std::fs::read(&db).unwrap();
        let error = PlannedCopy::open(&db, target(), issuer, [9; 32])
            .err()
            .expect("foreign schema/profile accepted");
        let expected = if sql.starts_with("PRAGMA") {
            "invalid input: unknown database profile"
        } else {
            "invalid input: unsupported writable archive schema"
        };
        assert_eq!(error.to_string(), expected, "{sql}");
        assert_eq!(std::fs::read(&db).unwrap(), before, "source changed: {sql}");
    }
}
#[test]
fn same_frontier_with_a_changed_unsigned_receipt_fails_exact_plan_confirmation() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("archive");
    let mut s = service(&root);
    append(&mut s, 1);
    let issuer = s.issuer();
    drop(s);
    let db = root.join("archive.sqlite");
    let original = PlannedCopy::open(&db, target(), issuer.clone(), [9; 32]).unwrap();
    let plan = original.plan().clone();
    drop(original);
    let c = rusqlite::Connection::open(&db).unwrap();
    let raw: Vec<u8> = c
        .query_row("SELECT receipt FROM commits WHERE sequence=1", [], |r| {
            r.get(0)
        })
        .unwrap();
    let Decoded::Known(receipt) = evidence::decode(&raw).unwrap() else {
        panic!()
    };
    let mut body = receipt.body().clone();
    body.insert("issuedAt".into(), atproto_dasl::Ipld::Integer(100001));
    let value = atproto_dasl::Ipld::Map(
        [
            ("v".into(), atproto_dasl::Ipld::Integer(1)),
            ("kind".into(), atproto_dasl::Ipld::String("receipt".into())),
            ("body".into(), atproto_dasl::Ipld::Map(body)),
        ]
        .into_iter()
        .collect(),
    );
    let Decoded::Known(changed_receipt) = evidence::encode(&value).unwrap() else {
        panic!()
    };
    c.execute(
        "UPDATE commits SET receipt=? WHERE sequence=1",
        [changed_receipt.bytes()],
    )
    .unwrap();
    drop(c);
    let changed = PlannedCopy::open(&db, target(), issuer, [9; 32]).unwrap();
    assert_eq!(changed.snapshot().unwrap().through, plan.source().through);
    assert_eq!(changed.snapshot().unwrap().tip, plan.source().tip);
    assert_ne!(changed.plan().source().digest, plan.source().digest);
    assert!(PlannedCopy::confirm(&db, &plan, &plan.archive_id()).is_err());
}
#[test]
fn plans_require_explicit_scope_historical_issuer_and_all_source_payloads() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("archive");
    let mut s = service(&root);
    let db = root.join("archive.sqlite");
    let empty = PlannedCopy::open(&db, target(), s.issuer(), [9; 32]).unwrap();
    assert_eq!(empty.plan().source().through, 0);
    drop(empty);
    append(&mut s, 1);
    let issuer = s.issuer();
    drop(s);
    assert!(PlannedCopy::open(&db, target(), identity(8).did().to_string(), [9; 32]).is_err());
    let mut foreign = target();
    foreign.scope = [2; 32];
    assert!(PlannedCopy::open(&db, foreign, issuer.clone(), [9; 32]).is_err());
    let c = rusqlite::Connection::open(&db).unwrap();
    c.execute_batch("PRAGMA foreign_keys=OFF; DELETE FROM objects;")
        .unwrap();
    drop(c);
    assert!(PlannedCopy::open(&db, target(), issuer, [9; 32]).is_err());
}

#[test]
fn staged_but_uncommitted_objects_are_part_of_the_source_commitment() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("archive");
    let s = service(&root);
    let issuer = s.issuer();
    drop(s);
    let db = root.join("archive.sqlite");
    let planned = PlannedCopy::open(&db, target(), issuer.clone(), [9; 32]).unwrap();
    let empty = planned.plan().clone();
    drop(planned);
    let mut ledger = Ledger::open(&root).unwrap();
    ledger.stage(b"retained staged ground truth").unwrap();
    drop(ledger);
    let staged = PlannedCopy::open(&db, target(), issuer, [9; 32]).unwrap();
    assert_eq!(staged.snapshot().unwrap().through, 0);
    assert_ne!(staged.plan().source().digest, empty.source().digest);
    assert!(PlannedCopy::confirm(&db, &empty, &empty.archive_id()).is_err());
}

#[test]
fn source_fingerprint_matches_an_independent_python_byte_oracle() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("archive");
    let mut s = service(&root);
    append(&mut s, 1);
    let issuer = s.issuer();
    drop(s);
    let mut ledger = Ledger::open(&root).unwrap();
    ledger
        .stage(b"uncommitted object preserved separately")
        .unwrap();
    for n in 1..=25 {
        ledger.stage(&vec![n as u8; n * 13]).unwrap();
    }
    drop(ledger);
    let db = root.join("archive.sqlite");
    let source = PlannedCopy::open(&db, target(), issuer, [9; 32]).unwrap();
    let output = std::process::Command::new("python3")
        .arg("-B")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/.design/tools/copy_source_digest.py"
        ))
        .arg(&db)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8(output.stdout).unwrap().trim(),
        hex(&source.plan().source().digest)
    );
}

#[test]
fn planning_and_confirmation_preserve_database_and_retained_wal_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("archive");
    let mut s = service(&root);
    append(&mut s, 1);
    let db = root.join("archive.sqlite");
    let wal = root.join("archive.sqlite-wal");
    let before = (std::fs::read(&db).unwrap(), std::fs::read(&wal).unwrap());
    assert!(!before.1.is_empty(), "fixture needs retained WAL frames");
    let planned = PlannedCopy::open(&db, target(), s.issuer(), [9; 32]).unwrap();
    let plan = planned.plan().clone();
    drop(planned);
    let confirmed = PlannedCopy::confirm(&db, &plan, &plan.archive_id()).unwrap();
    assert_eq!(confirmed.plan().bytes(), plan.bytes());
    drop(confirmed);
    assert_eq!(std::fs::read(&db).unwrap(), before.0);
    assert_eq!(std::fs::read(&wal).unwrap(), before.1);
    // Keep the writer open until after the checks: its own close can checkpoint.
    drop(s);
}

#[test]
fn derived_damage_requires_separate_recovery_and_preserves_the_exact_recipe() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("archive");
    let mut s = service(&root);
    append(&mut s, 1);
    let issuer = s.issuer();
    drop(s);
    let db = root.join("archive.sqlite");
    let planned = PlannedCopy::open(&db, target(), issuer.clone(), [9; 32]).unwrap();
    let plan = planned.plan().clone();
    drop(planned);
    let c = rusqlite::Connection::open(&db).unwrap();
    c.execute_batch("PRAGMA foreign_keys=OFF; DELETE FROM bindings;")
        .unwrap();
    drop(c);
    let damaged = std::fs::read(&db).unwrap();
    assert!(PlannedCopy::open(&db, target(), issuer, [9; 32]).is_err());
    assert_eq!(std::fs::read(&db).unwrap(), damaged);
    let rebuilt = dir.path().join("recovered.sqlite");
    RecoveryReader::open(&db)
        .unwrap()
        .rebuild(&rebuilt)
        .unwrap();
    let restored = PlannedCopy::confirm(&rebuilt, &plan, &plan.archive_id()).unwrap();
    assert_eq!(restored.plan().bytes(), plan.bytes());
    assert_eq!(std::fs::read(&db).unwrap(), damaged);
}

#[test]
fn structurally_healthy_raw_archives_cannot_bypass_request_authentication() {
    use atproto_dasl::Ipld;
    fn record(kind: &str, body: std::collections::BTreeMap<String, Ipld>) -> evidence::Record {
        let value = Ipld::Map(
            [
                ("v".into(), Ipld::Integer(1)),
                ("kind".into(), Ipld::String(kind.into())),
                ("body".into(), Ipld::Map(body)),
            ]
            .into_iter()
            .collect(),
        );
        let Decoded::Known(value) = evidence::encode(&value).unwrap() else {
            panic!()
        };
        value
    }
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("original");
    let mut s = service(&root);
    append(&mut s, 1);
    let issuer = s.issuer();
    drop(s);
    let source = RecoveryReader::open(&root.join("archive.sqlite")).unwrap();
    let original = source.record(1).unwrap();
    let Ipld::List(entries) = &original.manifest.body()["entries"] else {
        panic!()
    };
    let Ipld::Map(entry) = &entries[0] else {
        panic!()
    };
    let Ipld::Link(id) = &entry["ciphertext"] else {
        panic!()
    };
    let original_request = source.read_object(id).unwrap();
    for attack in ["invalid-signature", "different-slot"] {
        let mut bytes = original_request.clone();
        if attack == "invalid-signature" {
            let mut request: SignedRequest = serde_json::from_slice(&bytes).unwrap();
            request.signature = "00".repeat(64);
            bytes = request.bytes().unwrap();
        }
        let mut body = original.manifest.body().clone();
        let Ipld::List(entries) = body.get_mut("entries").unwrap() else {
            panic!()
        };
        let Ipld::Map(entry) = &mut entries[0] else {
            panic!()
        };
        entry.insert(
            "ciphertext".into(),
            Ipld::Link(kan::evidence_store::ciphertext_cid(&bytes)),
        );
        entry.insert("length".into(), Ipld::Integer(bytes.len() as i128));
        if attack == "different-slot" {
            entry.insert("slot".into(), Ipld::Bytes(vec![0; 32]));
        }
        let manifest = record("manifest", body);
        let mut body = original.receipt.body().clone();
        body.insert("manifest".into(), Ipld::Link(manifest.cid().clone()));
        let receipt = record("receipt", body);
        let target_root = dir.path().join(attack);
        let mut ledger = Ledger::create(&target_root).unwrap();
        ledger.stage(&bytes).unwrap();
        ledger.commit(manifest.bytes(), receipt.bytes()).unwrap();
        assert_eq!(
            ledger.verify().unwrap().commits,
            1,
            "raw structure is valid"
        );
        drop(ledger);
        assert!(
            PlannedCopy::open(
                &target_root.join("archive.sqlite"),
                target(),
                issuer.clone(),
                [9; 32]
            )
            .is_err(),
            "planner must authenticate source requests and exact manifests: {attack}"
        );
    }
}
