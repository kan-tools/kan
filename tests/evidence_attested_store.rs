#![cfg(feature = "v2-storage")]
use kan::{
    evidence_attestation::{self as proof, Context, Frontier, Purpose},
    evidence_service::{hex, Command as Operation, Failure, Grant, Request, SignedRequest},
    evidence_store::{
        attested::{Archive, Binding},
        Boundary, Ledger, RecoveryReader,
    },
    sign::Identity,
};
use std::{io::Write, path::Path, process::Command};
fn identity(byte: u8) -> Identity {
    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(&[byte; 32]).unwrap();
    Identity::load_existing(file.path()).unwrap()
}
fn binding() -> Binding {
    Binding {
        archive: [8; 32],
        scope: [9; 32],
        issuer: identity(7).did().to_string(),
    }
}
fn grant() -> Grant {
    Grant {
        principal: identity(6).did().to_string(),
        append: true,
        inventory: false,
    }
}
fn request(position: u64, previous: Option<String>) -> Vec<u8> {
    let writer = identity(6);
    SignedRequest::sign(
        Request {
            version: 1,
            scope: hex(&binding().scope),
            audience: binding().issuer,
            principal: writer.did().to_string(),
            expires: None,
            command: Operation::Append {
                id: hex(&[position as u8; 16]),
                position,
                previous,
                ciphertext: hex(b"opaque bytes"),
            },
        },
        &writer,
    )
    .unwrap()
    .bytes()
    .unwrap()
}
fn connection(root: &Path) -> rusqlite::Connection {
    rusqlite::Connection::open(root.join("archive.sqlite")).unwrap()
}

#[test]
fn atomic_admission_retry_and_legacy_refusal() {
    let temp = tempfile::tempdir().unwrap();
    let mut archive = Archive::create(temp.path(), binding()).unwrap();
    let first = archive
        .admit(&request(0, None), &identity(7), &grant(), 100)
        .unwrap();
    assert_eq!(first.attestation.purpose(), Purpose::Admitted);
    assert_eq!(first.attestation.frontier(), &archive.verify().unwrap());
    let second = archive
        .admit(
            &request(1, Some(first.record.manifest.cid().to_string())),
            &identity(7),
            &grant(),
            99,
        )
        .unwrap();
    assert_eq!(second.attestation.previous(), first.attestation.frontier());
    drop(archive);
    assert!(Ledger::open(temp.path()).is_err());
    assert!(Ledger::resume_initialization(temp.path()).is_err());
    assert!(RecoveryReader::open(temp.path()).is_err());
    let mut archive = Archive::open(temp.path(), binding()).unwrap();
    let retry = archive
        .admit(&request(0, None), &identity(7), &grant(), 999)
        .unwrap();
    assert!(retry.record.duplicate);
    assert_eq!(retry.record.receipt.bytes(), first.record.receipt.bytes());
    assert_eq!(retry.attestation.bytes(), first.attestation.bytes());
    assert_eq!(archive.verify().unwrap(), *second.attestation.frontier());
}

#[test]
fn authorization_precedes_storage_and_retries() {
    let temp = tempfile::tempdir().unwrap();
    let mut archive = Archive::create(temp.path(), binding()).unwrap();
    for g in [
        Grant {
            append: false,
            ..grant()
        },
        Grant {
            principal: identity(5).did().to_string(),
            ..grant()
        },
    ] {
        assert_eq!(
            archive
                .admit(&request(0, None), &identity(7), &g, 100)
                .unwrap_err(),
            Failure::AccessLimited
        );
    }
    assert_eq!(
        archive
            .admit(&request(0, None), &identity(5), &grant(), 100)
            .unwrap_err(),
        Failure::AccessLimited
    );
    let conn = connection(temp.path());
    assert_eq!(
        conn.query_row("SELECT count(*) FROM objects", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        0
    );
    archive
        .admit(&request(0, None), &identity(7), &grant(), 100)
        .unwrap();
    conn.execute("DELETE FROM attestations", []).unwrap();
    assert_eq!(
        archive
            .admit(
                &request(0, None),
                &identity(7),
                &Grant {
                    append: false,
                    ..grant()
                },
                100
            )
            .unwrap_err(),
        Failure::AccessLimited
    );
    assert!(archive
        .admit(&request(0, None), &identity(7), &grant(), 100)
        .is_err());
}

#[test]
fn proof_mutations_and_payload_loss_refuse_writable_open() {
    for mutation in [
        "missing",
        "statement",
        "archive",
        "receipt",
        "extra",
        "payload",
        "schema",
    ] {
        let temp = tempfile::tempdir().unwrap();
        let mut archive = Archive::create(temp.path(), binding()).unwrap();
        let row = archive
            .admit(&request(0, None), &identity(7), &grant(), 100)
            .unwrap();
        drop(archive);
        let conn = connection(temp.path());
        conn.execute_batch("PRAGMA foreign_keys=OFF").unwrap();
        match mutation {
            "missing" => {
                conn.execute("DELETE FROM attestations", []).unwrap();
            }
            "statement" => {
                let mut bytes = row.attestation.bytes().to_vec();
                let last = bytes.len() - 1;
                bytes[last] ^= 1;
                conn.execute("UPDATE attestations SET envelope=?", [bytes])
                    .unwrap();
            }
            "archive" => {
                conn.execute("UPDATE archive_identity SET archive=?", [[4u8; 32]])
                    .unwrap();
            }
            "receipt" => {
                conn.execute("UPDATE commits SET receipt=manifest", [])
                    .unwrap();
            }
            "extra" => {
                conn.execute(
                    "INSERT INTO attestations VALUES(2,?)",
                    [row.attestation.bytes()],
                )
                .unwrap();
            }
            "payload" => {
                conn.execute("DELETE FROM objects", []).unwrap();
            }
            "schema" => {
                conn.execute_batch("CREATE TRIGGER omit_proof AFTER INSERT ON attestations BEGIN DELETE FROM attestations; END").unwrap();
            }
            _ => unreachable!(),
        }
        drop(conn);
        assert!(
            Archive::open(temp.path(), binding()).is_err(),
            "accepted {mutation}"
        );
    }
}

#[test]
fn owner_binding_is_not_selected_by_database() {
    let temp = tempfile::tempdir().unwrap();
    drop(Archive::create(temp.path(), binding()).unwrap());
    for b in [
        Binding {
            archive: [1; 32],
            ..binding()
        },
        Binding {
            scope: [1; 32],
            ..binding()
        },
        Binding {
            issuer: identity(4).did().to_string(),
            ..binding()
        },
    ] {
        assert!(Archive::open(temp.path(), b).is_err());
    }
    assert!(Archive::create(
        &temp.path().join("bad"),
        Binding {
            issuer: "did:key:z".into(),
            ..binding()
        }
    )
    .is_err());
    assert!(!temp.path().join("bad").exists());
}

#[test]
fn proof_crash_worker() {
    let Ok(root) = std::env::var("KAN_PROOF_CRASH_ROOT") else {
        return;
    };
    let phase = std::env::var("KAN_PROOF_CRASH_PHASE").unwrap();
    let mut archive = Archive::open(Path::new(&root), binding()).unwrap();
    archive
        .admit_observed(
            &request(0, None),
            &identity(7),
            &grant(),
            100,
            &mut |boundary| {
                if format!("{boundary:?}") == phase {
                    std::process::exit(91);
                }
            },
        )
        .unwrap();
    panic!("fault boundary not reached");
}
#[test]
fn process_death_keeps_both_metadata_and_proof_or_neither() {
    for phase in [
        "ObjectInserted",
        "ObjectDurable",
        "ManifestInserted",
        "BindingsInserted",
        "AttestationSigned",
        "AttestationInserted",
        "BeforeCommit",
        "AfterCommit",
    ] {
        let temp = tempfile::tempdir().unwrap();
        drop(Archive::create(temp.path(), binding()).unwrap());
        let result = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "proof_crash_worker", "--nocapture"])
            .env("KAN_PROOF_CRASH_ROOT", temp.path())
            .env("KAN_PROOF_CRASH_PHASE", phase)
            .output()
            .unwrap();
        assert_eq!(
            result.status.code(),
            Some(91),
            "{phase}: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        let mut archive = Archive::open(temp.path(), binding()).unwrap();
        let count = u64::from(phase == "AfterCommit");
        assert_eq!(archive.verify().unwrap().through, count, "{phase}");
        let conn = connection(temp.path());
        assert_eq!(
            conn.query_row("SELECT count(*) FROM commits", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            count as i64
        );
        assert_eq!(
            conn.query_row("SELECT count(*) FROM attestations", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            count as i64
        );
        let original: Option<Vec<u8>> = if count == 1 {
            Some(
                conn.query_row("SELECT envelope FROM attestations", [], |r| r.get(0))
                    .unwrap(),
            )
        } else {
            None
        };
        let retry = archive
            .admit(&request(0, None), &identity(7), &grant(), 101)
            .unwrap();
        assert_eq!(retry.record.duplicate, count == 1);
        if let Some(original) = original {
            assert_eq!(retry.attestation.bytes(), original);
        }
        assert_eq!(archive.verify().unwrap().through, 1);
    }
}

#[test]
fn same_height_proof_fork_between_audit_and_commit_is_rejected() {
    let temp = tempfile::tempdir().unwrap();
    let mut archive = Archive::create(temp.path(), binding()).unwrap();
    let first = archive
        .admit(&request(0, None), &identity(7), &grant(), 100)
        .unwrap();
    let config = binding();
    let fork = proof::issue(
        &identity(7),
        &Context {
            issuer: &config.issuer,
            archive: config.archive,
            scope: config.scope,
        },
        &first.record.manifest,
        &first.record.receipt,
        &Frontier::default(),
        Purpose::Admitted,
        123,
    )
    .unwrap();
    let mut replaced = false;
    let result = archive.admit_observed(
        &request(1, Some(first.record.manifest.cid().to_string())),
        &identity(7),
        &grant(),
        101,
        &mut |boundary| {
            if boundary == Boundary::ObjectDurable && !replaced {
                replaced = true;
                connection(temp.path())
                    .execute(
                        "UPDATE attestations SET envelope=? WHERE sequence=1",
                        [fork.bytes()],
                    )
                    .unwrap();
            }
        },
    );
    assert!(replaced);
    assert_eq!(result.unwrap_err(), Failure::Conflict);
    assert_eq!(
        connection(temp.path())
            .query_row("SELECT count(*) FROM commits", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        1
    );
}

#[test]
fn database_columns_match_independent_surface_catalog() {
    let temp = tempfile::tempdir().unwrap();
    drop(Archive::create(temp.path(), binding()).unwrap());
    let conn = connection(temp.path());
    let mut actual = std::collections::BTreeSet::new();
    let mut tables = conn
        .prepare("SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%'")
        .unwrap();
    for table in tables.query_map([], |r| r.get::<_, String>(0)).unwrap() {
        let table = table.unwrap();
        let prefix = if ["archive_identity", "attestations"].contains(&table.as_str()) {
            "evidence-proof-sqlite"
        } else {
            "evidence-sqlite"
        };
        let mut columns = conn
            .prepare(&format!("PRAGMA table_info({table})"))
            .unwrap();
        for column in columns.query_map([], |r| r.get::<_, String>(1)).unwrap() {
            actual.insert((format!("{prefix}:{table}"), column.unwrap()));
        }
        if prefix == "evidence-proof-sqlite" {
            let mut indexes=conn.prepare("SELECT name,sql FROM sqlite_schema WHERE type='index' AND tbl_name=? ORDER BY name").unwrap();
            for index in indexes
                .query_map([&table], |r| {
                    Ok((r.get::<_, String>(0)?, r.get::<_, Option<String>>(1)?))
                })
                .unwrap()
            {
                let (name, definition) = index.unwrap();
                actual.insert((
                    format!("{prefix}:{table}"),
                    format!("index:{name}:{}", definition.unwrap_or_default()),
                ));
            }
        }
    }
    let expected = include_str!("fixtures/read-write-surface.tsv")
        .lines()
        .filter_map(|l| {
            let c: Vec<_> = l.split('\t').collect();
            (c.len() > 5
                && (c[4].starts_with("evidence-proof-sqlite:")
                    || c[4].starts_with("evidence-sqlite:")))
            .then(|| (c[4].to_owned(), c[5].to_owned()))
        })
        .collect();
    assert_eq!(actual, expected);
}

#[test]
fn purpose_order_is_a_store_invariant_not_just_a_signature_check() {
    let temp = tempfile::tempdir().unwrap();
    let mut archive = Archive::create(temp.path(), binding()).unwrap();
    let first = archive
        .admit(&request(0, None), &identity(7), &grant(), 100)
        .unwrap();
    let second = archive
        .admit(
            &request(1, Some(first.record.manifest.cid().to_string())),
            &identity(7),
            &grant(),
            101,
        )
        .unwrap();
    let config = binding();
    let ctx = Context {
        issuer: &config.issuer,
        archive: config.archive,
        scope: config.scope,
    };
    let invalid_order = proof::issue(
        &identity(7),
        &ctx,
        &second.record.manifest,
        &second.record.receipt,
        first.attestation.frontier(),
        Purpose::RetainedVerified,
        102,
    )
    .unwrap();
    connection(temp.path())
        .execute(
            "UPDATE attestations SET envelope=? WHERE sequence=2",
            [invalid_order.bytes()],
        )
        .unwrap();
    // Profile 2 now refuses any retained row; this is the admitted-only gate,
    // not a specific test of historical-purpose ordering under profile 3.
    assert_eq!(
        archive.verify().unwrap_err().to_string(),
        "corrupt evidence: retained-verified prefix requires copy profile"
    );
    // Even a correctly signed retained prefix followed by admitted rows cannot
    // establish copy completeness without the profile-3 recipe.
    let prefix = proof::issue(
        &identity(7),
        &ctx,
        &first.record.manifest,
        &first.record.receipt,
        &Frontier::default(),
        Purpose::RetainedVerified,
        200,
    )
    .unwrap();
    let tail = proof::issue(
        &identity(7),
        &ctx,
        &second.record.manifest,
        &second.record.receipt,
        prefix.frontier(),
        Purpose::Admitted,
        100,
    )
    .unwrap();
    let conn = connection(temp.path());
    conn.execute(
        "UPDATE attestations SET envelope=? WHERE sequence=1",
        [prefix.bytes()],
    )
    .unwrap();
    conn.execute(
        "UPDATE attestations SET envelope=? WHERE sequence=2",
        [tail.bytes()],
    )
    .unwrap();
    assert_eq!(
        archive.verify().unwrap_err().to_string(),
        "corrupt evidence: retained-verified prefix requires copy profile"
    );
    assert_eq!(
        archive
            .backup(&temp.path().join("refused-backup.sqlite"))
            .unwrap_err()
            .to_string(),
        "corrupt evidence: retained-verified prefix requires copy profile"
    );
    assert_eq!(
        archive
            .admit(&request(0, None), &identity(7), &grant(), 300)
            .unwrap_err(),
        Failure::Corrupt,
        "ordinary Append must refuse a plan-less imported prefix"
    );
}

#[test]
fn unproven_raw_append_between_audit_and_commit_conflicts() {
    let temp = tempfile::tempdir().unwrap();
    let donor = tempfile::tempdir().unwrap();
    let mut archive = Archive::create(temp.path(), binding()).unwrap();
    let mut other = Archive::create(donor.path(), binding()).unwrap();
    let first = archive
        .admit(&request(0, None), &identity(7), &grant(), 100)
        .unwrap();
    other
        .admit(&request(0, None), &identity(7), &grant(), 100)
        .unwrap();
    let second = request(1, Some(first.record.manifest.cid().to_string()));
    other.admit(&second, &identity(7), &grant(), 101).unwrap();
    drop(other);
    let mut inserted = false;
    let result = archive.admit_observed(&second, &identity(7), &grant(), 101, &mut |boundary| {
        if boundary == Boundary::ObjectDurable && !inserted {
            inserted = true;
            let conn = connection(temp.path());
            conn.execute(
                "ATTACH DATABASE ? AS donor",
                [donor.path().join("archive.sqlite").to_str().unwrap()],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO commits SELECT * FROM donor.commits WHERE sequence=2",
                [],
            )
            .unwrap();
        }
    });
    assert!(inserted);
    assert_eq!(result.unwrap_err(), Failure::Conflict);
    assert_eq!(
        connection(temp.path())
            .query_row("SELECT count(*) FROM attestations", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        1
    );
    assert!(archive.verify().is_err());
}
