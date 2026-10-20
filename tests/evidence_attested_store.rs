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

#[cfg(feature = "v2-crypto")]
#[tokio::test]
async fn queued_capture_reaches_profile_two_over_http_and_reads_through_proof_reader() {
    use kan::{
        evidence_crypto as crypto, evidence_delivery as delivery, evidence_http as http,
        evidence_proof_service as wire, evidence_reader::proof as reader,
        evidence_service::AdmittingService, evidence_spool::Spool,
    };
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("archive");
    std::fs::create_dir(&root).unwrap();
    let archive = Archive::create(&root, binding()).unwrap();
    let service = AdmittingService::new(archive, identity(7), vec![grant()]).unwrap();
    let listener = http::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let endpoint = format!("http://{}/v1/rpc", listener.local_addr().unwrap());
    let ingest = tokio::spawn(http::serve_admitted(listener, service));
    let mut spool = Spool::create(
        &temp.path().join("spool.sqlite"),
        &hex(&binding().scope),
        identity(6).did().as_str(),
        &binding().issuer,
        8 * 1024 * 1024,
    )
    .unwrap();
    let private = [71; 32];
    let queued = delivery::queue(
        &mut spool,
        &identity(6),
        &crypto::public_key(&private).unwrap(),
        &[19; 16],
        b"A retained message through real profile-2 ingress",
    )
    .unwrap();
    let retained = spool.head().unwrap().unwrap();
    let committed = delivery::deliver_one(&mut spool, &endpoint)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(queued.manifest, committed.manifest);
    assert!(spool.head().unwrap().is_none());
    let reply = http::send(&endpoint, &binding().issuer, &retained)
        .await
        .unwrap();
    let kan::evidence_service::Output::Committed { duplicate, .. } = reply.reply.result.unwrap()
    else {
        panic!("append reply")
    };
    assert!(duplicate);
    let pin = wire::Binding {
        profile: wire::Profile::Admitted,
        archive: hex(&binding().archive),
        scope: hex(&binding().scope),
        issuer: binding().issuer,
    };
    let service = wire::Service::new(
        root.join("archive.sqlite"),
        pin.clone(),
        identity(7),
        vec![Grant {
            principal: identity(5).did().to_string(),
            append: false,
            inventory: true,
        }],
        kan::evidence_store::inventory::Budget {
            items: 100,
            metadata_bytes: 1024 * 1024,
            duration: std::time::Duration::from_secs(5),
            cancelled: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        },
    )
    .unwrap();
    let listener = http::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let endpoint_read = format!("http://{}/v2/read", listener.local_addr().unwrap());
    let reads = tokio::spawn(http::serve_proof(listener, service));
    let reader = reader::Reader::new(
        identity(5),
        reader::Access {
            binding: pin,
            endpoint: endpoint_read,
            private_key: private,
        },
    )
    .unwrap();
    let snapshot = reader.snapshot().await.unwrap();
    let page = reader.page(&snapshot, None, 1).await.unwrap();
    assert_eq!(page.records[0].purpose, "admitted");
    let reader::Source::Available { plaintext, .. } = reader
        .source(&snapshot, &page.records[0].selection)
        .await
        .unwrap()
    else {
        panic!("retained source")
    };
    assert_eq!(
        plaintext,
        b"A retained message through real profile-2 ingress"
    );
    let forbidden = SignedRequest::sign(
        Request {
            version: 1,
            scope: hex(&binding().scope),
            principal: identity(5).did().to_string(),
            audience: binding().issuer,
            expires: None,
            command: Operation::Append {
                id: hex(&[28; 16]),
                position: 0,
                previous: None,
                ciphertext: hex(b"denied"),
            },
        },
        &identity(5),
    )
    .unwrap()
    .bytes()
    .unwrap();
    assert_eq!(
        http::send(&endpoint, &binding().issuer, &forbidden)
            .await
            .unwrap()
            .reply
            .result
            .unwrap_err(),
        Failure::AccessLimited
    );
    reads.abort();
    ingest.abort();
    let _ = reads.await;
    let _ = ingest.await;
    assert_eq!(
        Archive::open(&root, binding())
            .unwrap()
            .verify()
            .unwrap()
            .through,
        1
    );
}

#[test]
fn signed_erasure_preserves_proofs_blocks_replay_and_survives_recovery() {
    use kan::evidence_store::{erasure::Record as Erasure, inventory};
    let temp = tempfile::tempdir().unwrap();
    let mut archive = Archive::create(temp.path(), binding()).unwrap();
    let first = request(0, None);
    let a = archive.admit(&first, &identity(7), &grant(), 100).unwrap();
    let second = request(1, Some(a.record.manifest.cid().to_string()));
    let b = archive.admit(&second, &identity(7), &grant(), 101).unwrap();
    let before = archive.verify().unwrap();
    let old = tempfile::tempdir().unwrap();
    archive.backup(&old.path().join("archive.sqlite")).unwrap();
    let plan = archive.preview_erasure(&[1], hex(&[3; 32]), 102).unwrap();
    assert!(Erasure::sign(plan.clone(), &identity(8)).is_err());
    let record = Erasure::sign(plan, &identity(7)).unwrap();
    let mut wrong = record.clone();
    wrong.plan.targets[0].length += 1;
    assert!(archive.apply_erasure(wrong).is_err());
    assert_eq!(archive.verify().unwrap(), before);
    let history = archive.apply_erasure(record.clone()).unwrap();
    assert_eq!(archive.apply_erasure(record).unwrap().tip, history.tip);
    assert_eq!(
        archive.verify().unwrap(),
        before,
        "erasure must not rewrite ledger or proof tips"
    );
    assert_eq!(
        connection(temp.path())
            .query_row(
                "SELECT bytes FROM objects WHERE cid=?",
                [kan::evidence_store::ciphertext_cid(&first).to_string()],
                |r| r.get::<_, Vec<u8>>(0)
            )
            .unwrap(),
        vec![0]
    );
    assert_eq!(
        archive
            .admit(&first, &identity(7), &grant(), 103)
            .unwrap_err(),
        Failure::AccessLimited
    );
    assert!(
        archive
            .admit(&second, &identity(7), &grant(), 103)
            .unwrap()
            .record
            .duplicate
    );
    let third = request(2, Some(b.record.manifest.cid().to_string()));
    archive.admit(&third, &identity(7), &grant(), 104).unwrap();
    let budget = inventory::Budget {
        items: 100,
        metadata_bytes: 1024 * 1024,
        duration: std::time::Duration::from_secs(10),
        cancelled: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
    };
    let path = temp.path().join("archive.sqlite");
    let inv = inventory::Inventory::open(
        &path,
        inventory::Profile::Admitted,
        binding(),
        budget.clone(),
    )
    .unwrap();
    let page = inv
        .page(
            None,
            inventory::PageBudget {
                rows: 10,
                record_bytes: 1024 * 1024,
                payload_bytes: 10 * kan::evidence_service::MAX_REQUEST,
            },
            budget.clone(),
        )
        .unwrap();
    let erased = page
        .records
        .iter()
        .find(|r| r.record.sequence == 1)
        .unwrap();
    assert_eq!(erased.availability, inventory::Availability::Erased);
    assert!(matches!(
        inventory::source(
            &path,
            inventory::Profile::Admitted,
            binding(),
            &erased.selection,
            kan::evidence_service::MAX_REQUEST,
            budget
        )
        .unwrap(),
        inventory::Source::Unavailable(inventory::Availability::Erased)
    ));
    drop(inv);
    let rebuilt = tempfile::tempdir().unwrap();
    kan::evidence_store::attested::Recovery::open(&path, binding())
        .unwrap()
        .rebuild(&rebuilt.path().join("archive.sqlite"))
        .unwrap();
    let recovered = Archive::open(rebuilt.path(), binding()).unwrap();
    assert_eq!(recovered.erasure_history().unwrap().tip, history.tip);
    assert_eq!(recovered.verify().unwrap(), archive.verify().unwrap());
    let mut restored = Archive::open(old.path(), binding()).unwrap();
    assert!(restored
        .reconcile_erasure(&history, &hex(&[9; 32]))
        .is_err());
    restored
        .reconcile_erasure(&history, history.tip.as_ref().unwrap())
        .unwrap();
    assert_eq!(restored.verify().unwrap(), before);
    assert_eq!(
        restored
            .admit(&first, &identity(7), &grant(), 105)
            .unwrap_err(),
        Failure::AccessLimited
    );
    assert!(restored.reclaim_erased_pages().unwrap());
    // A raw payload replacement cannot be hidden by authorization: verification
    // detects cleanup regression and source reads still refuse the erased bytes.
    connection(temp.path())
        .execute(
            "UPDATE objects SET bytes=? WHERE cid=?",
            rusqlite::params![
                first,
                kan::evidence_store::ciphertext_cid(&request(0, None)).to_string()
            ],
        )
        .unwrap();
    assert!(archive.verify().is_err());
}

#[test]
fn erasure_refuses_stale_plans_and_forged_history_and_carries_future_restore_fences() {
    use kan::evidence_store::erasure::Record as Erasure;
    let temp = tempfile::tempdir().unwrap();
    let mut archive = Archive::create(temp.path(), binding()).unwrap();
    let first = request(0, None);
    let a = archive.admit(&first, &identity(7), &grant(), 100).unwrap();
    let old = tempfile::tempdir().unwrap();
    archive.backup(&old.path().join("archive.sqlite")).unwrap();
    let stale = archive.preview_erasure(&[1], hex(&[1; 32]), 101).unwrap();
    let second = request(1, Some(a.record.manifest.cid().to_string()));
    archive.admit(&second, &identity(7), &grant(), 102).unwrap();
    assert!(archive
        .apply_erasure(Erasure::sign(stale, &identity(7)).unwrap())
        .is_err());
    let plan = archive
        .preview_erasure(&[1, 2], hex(&[2; 32]), 103)
        .unwrap();
    let package = archive
        .apply_erasure(Erasure::sign(plan, &identity(7)).unwrap())
        .unwrap();
    let mut restored = Archive::open(old.path(), binding()).unwrap();
    restored
        .reconcile_erasure(&package, package.tip.as_ref().unwrap())
        .unwrap();
    assert_eq!(restored.verify().unwrap().through, 1);
    assert_eq!(
        restored
            .admit(&second, &identity(7), &grant(), 104)
            .unwrap_err(),
        Failure::AccessLimited,
        "a later erased object is fenced even when absent in the old backup"
    );
    let unrelated = SignedRequest::sign(
        Request {
            version: 1,
            scope: hex(&binding().scope),
            audience: binding().issuer,
            principal: identity(6).did().to_string(),
            expires: None,
            command: Operation::Append {
                id: hex(&[77; 16]),
                position: 1,
                previous: Some(a.record.manifest.cid().to_string()),
                ciphertext: hex(b"new bytes"),
            },
        },
        &identity(6),
    )
    .unwrap()
    .bytes()
    .unwrap();
    assert_eq!(
        restored
            .admit(&unrelated, &identity(7), &grant(), 105)
            .unwrap_err(),
        Failure::Conflict
    );
    assert_eq!(restored.verify().unwrap().through, 1);
    connection(temp.path())
        .execute(
            "UPDATE erasures SET body=replace(CAST(body AS TEXT),'signature','forgery')",
            [],
        )
        .unwrap();
    assert!(archive.verify().is_err());
}

#[cfg(feature = "v2-crypto")]
#[test]
fn capture_erasure_scans_the_complete_archive_and_refuses_active_or_unknown_membership() {
    use kan::{
        evidence_capture::{Event, Header, Observer, Outcome},
        evidence_crypto as crypto,
        evidence_store::erasure::{Capture, Record as Erasure},
    };
    let dir = tempfile::tempdir().unwrap();
    let mut archive = Archive::create(dir.path(), binding()).unwrap();
    let key = [18; 32];
    let public = crypto::public_key(&key).unwrap();
    let mut previous = None;
    for (position, attempt, ordinal, event) in [
        (
            0,
            20,
            0,
            Event::Started {
                method: "POST".into(),
                route: "test".into(),
            },
        ),
        (
            1,
            21,
            0,
            Event::Started {
                method: "POST".into(),
                route: "test".into(),
            },
        ),
        (
            2,
            20,
            1,
            Event::Terminal {
                outcome: Outcome::Completed,
            },
        ),
    ] {
        let header = Header {
            version: 2,
            attempt: hex(&[attempt; 32]),
            observer: Observer::Gateway,
            ordinal,
            observed_at_unix_micros: Some(100),
            elapsed_micros: 0,
            unconfirmed_before: 0,
            event,
        };
        let h = serde_json::to_vec(&header).unwrap();
        let mut frame = b"KANC2".to_vec();
        frame.extend_from_slice(&(h.len() as u32).to_be_bytes());
        frame.extend_from_slice(&h);
        let sealed = crypto::seal(&public, &binding().scope, &frame).unwrap();
        let bytes = SignedRequest::sign(
            Request {
                version: 1,
                scope: hex(&binding().scope),
                audience: binding().issuer,
                principal: identity(6).did().to_string(),
                expires: None,
                command: Operation::Append {
                    id: hex(&[position as u8; 16]),
                    position,
                    previous,
                    ciphertext: hex(&sealed),
                },
            },
            &identity(6),
        )
        .unwrap()
        .bytes()
        .unwrap();
        previous = Some(
            archive
                .admit(&bytes, &identity(7), &grant(), 100)
                .unwrap()
                .record
                .manifest
                .cid()
                .to_string(),
        );
    }
    let selected = Capture {
        writer: identity(6).did().to_string(),
        observer: "gateway".into(),
        attempt: hex(&[20; 32]),
    };
    let preview = archive
        .preview_capture_erasure(selected.clone(), &[key], hex(&[1; 32]), 101)
        .unwrap();
    assert_eq!(
        preview
            .plan
            .targets
            .iter()
            .map(|t| t.sequence)
            .collect::<Vec<_>>(),
        vec![1, 3]
    );
    assert!(!preview.recording_gap);
    let active = Capture {
        attempt: hex(&[21; 32]),
        ..selected.clone()
    };
    assert!(archive
        .preview_capture_erasure(active, &[key], hex(&[2; 32]), 101)
        .is_err());
    assert!(archive
        .preview_capture_erasure(selected, &[[19; 32]], hex(&[2; 32]), 101)
        .is_err());
    archive
        .apply_erasure(Erasure::sign(preview.plan, &identity(7)).unwrap())
        .unwrap();
    assert_eq!(archive.verify().unwrap().through, 3);
    assert_eq!(
        archive.erasure_history().unwrap().records[0]
            .plan
            .targets
            .len(),
        2
    );
}

#[test]
fn independent_owner_erasure_custody_gates_live_services_and_older_restores() {
    use kan::{
        evidence_erasure_history as custody, evidence_proof_service as wire,
        evidence_service::AdmittingService,
        evidence_store::{erasure, inventory},
    };
    let root = tempfile::tempdir().unwrap();
    let older = tempfile::tempdir().unwrap();
    let history_dir = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(history_dir.path(), std::fs::Permissions::from_mode(0o700))
            .unwrap();
    }
    let owner = identity(4); // deliberately not the storage issuer
    let wire_binding = wire::Binding {
        profile: wire::Profile::Admitted,
        archive: hex(&binding().archive),
        scope: hex(&binding().scope),
        issuer: binding().issuer,
    };
    let mut history = custody::Access {
        directory: history_dir.path().to_path_buf(),
        binding: wire_binding.clone(),
        owner: owner.did().to_string(),
        minimum: None,
    };
    history.initialize().unwrap();
    assert!(history.current().is_err());
    let genesis = history.preview(None, hex(&[1; 32])).unwrap();
    assert!(custody::Record::sign(genesis.clone(), &identity(7)).is_err());
    let genesis = custody::Record::sign(genesis, &owner).unwrap();
    let genesis_id = genesis.id().unwrap();
    history.append(genesis).unwrap();
    history.minimum = Some(genesis_id);
    assert!(
        history.preview(None, hex(&[2; 32])).is_err(),
        "no second empty genesis"
    );

    let mut archive = Archive::create(root.path(), binding()).unwrap();
    let first = request(0, None);
    archive.admit(&first, &identity(7), &grant(), 100).unwrap();
    archive
        .backup(&older.path().join("archive.sqlite"))
        .unwrap();
    let plan = archive.preview_erasure(&[1], hex(&[3; 32]), 101).unwrap();
    let erasure = erasure::Record::sign(plan, &identity(7)).unwrap();
    let read_grant = Grant {
        inventory: true,
        ..grant()
    };
    let make_reader = |root: &Path| {
        wire::Service::new(
            root.join("archive.sqlite"),
            wire_binding.clone(),
            identity(7),
            vec![read_grant.clone()],
            inventory::Budget {
                items: 100,
                metadata_bytes: 1024 * 1024,
                duration: std::time::Duration::from_secs(10),
                cancelled: Default::default(),
            },
        )
        .unwrap()
    };
    let reader = make_reader(root.path())
        .with_erasure_history(history.clone())
        .unwrap();
    let mut ingest = AdmittingService::new(
        Archive::open(root.path(), binding()).unwrap(),
        identity(7),
        vec![grant()],
    )
    .unwrap()
    .with_erasure_history(history.clone())
    .unwrap();
    let query = wire::SignedRequest::sign(
        wire::Request {
            version: 2,
            binding: wire_binding.clone(),
            principal: identity(6).did().to_string(),
            expires: 200,
            command: wire::Command::Snapshot,
        },
        &identity(6),
    )
    .unwrap()
    .bytes()
    .unwrap();
    assert!(reader.dispatch(&query, 101).unwrap().reply.result.is_ok());
    assert!(ingest.dispatch(&first, 101).unwrap().reply.result.is_ok());
    let change = history
        .preview(Some(erasure.clone()), hex(&[4; 32]))
        .unwrap();
    let authorized = custody::Record::sign(change, &owner).unwrap();
    // Publication cannot pass a read or admission already holding the custody lease.
    let held = history.current().unwrap();
    assert_eq!(
        history.append(authorized.clone()).unwrap_err(),
        Failure::Unavailable
    );
    drop(held);
    history.append(authorized.clone()).unwrap();
    history.append(authorized.clone()).unwrap(); // lost acknowledgement retry
                                                 // Crash boundary: owner intent is durable before archive mutation. Live services stop.
    assert!(matches!(
        reader.dispatch(&query, 102),
        Err(Failure::AccessLimited)
    ));
    assert!(matches!(
        ingest.dispatch(&first, 102),
        Err(Failure::AccessLimited)
    ));
    assert!(make_reader(older.path())
        .with_erasure_history(history.clone())
        .is_err());
    let current = history.current().unwrap();
    let package = current.package().unwrap();
    archive
        .reconcile_erasure(&package, package.tip.as_ref().unwrap())
        .unwrap();
    assert!(reader.dispatch(&query, 103).unwrap().reply.result.is_ok());
    assert_eq!(
        ingest
            .dispatch(&first, 103)
            .unwrap()
            .reply
            .result
            .unwrap_err(),
        Failure::AccessLimited
    );
    // Reconciliation of the old checkpoint is necessary before enrollment succeeds.
    let reconciled = history.reconcile_archive(older.path()).unwrap();
    assert_eq!(reconciled["state"], "storage-history-reconciled");
    assert_eq!(reconciled["activation"], "not-performed");
    assert!(make_reader(older.path())
        .with_erasure_history(history.clone())
        .is_ok());
    drop(current);
    // A separately retained new pin catches deletion of the latest custody record.
    history.minimum = Some(authorized.id().unwrap());
    let path = history.directory.join(format!(
        "erasure-{:020}-{}.json",
        1,
        authorized.id().unwrap()
    ));
    let bytes = std::fs::read(&path).unwrap();
    std::fs::remove_file(&path).unwrap();
    assert!(history.current().is_err());
    // Restoring a canonical but forged owner signature must not authorize service startup.
    let mut forged: custody::Record = serde_json::from_slice(&bytes).unwrap();
    forged.signature = hex(&[0; 64]);
    std::fs::write(&path, serde_json::to_vec(&forged).unwrap()).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    assert!(history.current().is_err());
    assert!(reader.dispatch(&query, 104).is_err());
}
