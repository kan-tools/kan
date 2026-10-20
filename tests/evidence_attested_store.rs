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
    let mut observe = |boundary| {
        if format!("{boundary:?}") == phase {
            std::process::exit(91);
        }
    };
    if std::env::var_os("KAN_PROOF_INDEXED").is_some() {
        archive
            .admit_indexed_observed(
                &request(0, None),
                &identity(7),
                &grant(),
                100,
                None,
                &mut observe,
            )
            .unwrap();
    } else {
        archive
            .admit_observed(&request(0, None), &identity(7), &grant(), 100, &mut observe)
            .unwrap();
    }
    panic!("fault boundary not reached");
}
#[test]
fn process_death_keeps_both_metadata_and_proof_or_neither() {
    for indexed in [false, true] {
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
            let archive = Archive::create(temp.path(), binding()).unwrap();
            archive.rebuild_serving_index(&identity(7)).unwrap();
            drop(archive);
            let mut command = Command::new(std::env::current_exe().unwrap());
            if indexed {
                command.env("KAN_PROOF_INDEXED", "1");
            }
            let result = command
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
            let pin = archive.verify().unwrap();
            assert_eq!(pin.through, 1);
            let indexed = kan::evidence_store::serving::read_metadata(
                &temp.path().join("archive.sqlite"),
                binding(),
                &pin,
                None,
                1,
            )
            .unwrap();
            assert_eq!(indexed.proof.bytes(), retry.attestation.bytes());
        }
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
    let mut checkpoint = None;
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
        if position == 1 {
            let selected = Capture {
                writer: identity(6).did().to_string(),
                observer: "gateway".into(),
                attempt: hex(&[20; 32]),
            };
            let page = archive
                .scan_capture_erasure(selected, &[key], None, 1, 1024 * 1024)
                .unwrap();
            assert!(!page.complete());
            assert!(archive
                .finish_capture_erasure(page.clone(), hex(&[1; 32]), 101)
                .is_err());
            checkpoint = Some(serde_json::to_vec(&page).unwrap());
        }
    }
    let selected = Capture {
        writer: identity(6).did().to_string(),
        observer: "gateway".into(),
        attempt: hex(&[20; 32]),
    };
    drop(archive);
    let mut archive = Archive::open(dir.path(), binding()).unwrap();
    let page = archive
        .scan_capture_erasure(
            selected.clone(),
            &[key],
            Some(serde_json::from_slice(&checkpoint.unwrap()).unwrap()),
            1,
            1024 * 1024,
        )
        .unwrap();
    assert_eq!(
        page.progress()["through"],
        "3",
        "newly appended records extend the pinned scan"
    );
    assert_eq!(page.progress()["scanned_through"], "2");
    let changed = Capture {
        attempt: hex(&[21; 32]),
        ..selected.clone()
    };
    assert!(archive
        .scan_capture_erasure(changed, &[key], Some(page.clone()), 1, 1024 * 1024)
        .is_err());
    let page = archive
        .scan_capture_erasure(selected.clone(), &[key], Some(page), 1, 1024 * 1024)
        .unwrap();
    assert!(page.complete());
    let members = page.member_delta(0);
    let small = page.checkpoint();
    assert_eq!(small.member_count(), 0);
    let restored = small.restore_members(members).unwrap();
    let complete = archive.finish_capture_selection(restored.clone()).unwrap();
    assert_eq!(complete.sequences, vec![1, 3]);
    assert_eq!(complete.through, 3);
    let paged = archive
        .finish_capture_erasure(restored, hex(&[1; 32]), 101)
        .unwrap();
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
    assert_eq!(paged.plan, preview.plan);
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
    // Lost acknowledgement retry.
    history.append(authorized.clone()).unwrap();
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

#[test]
#[cfg(feature = "v2-service")]
fn erasure_custody_cli_initializes_pinned_genesis_and_reconciles_without_activation() {
    use kan::{evidence_erasure_history as custody, evidence_proof_service as wire};
    let directory = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let mut key = tempfile::NamedTempFile::new().unwrap();
    key.write_all(&[4; 32]).unwrap();
    let history = custody::Access {
        directory: directory.path().to_path_buf(),
        binding: wire::Binding {
            profile: wire::Profile::Admitted,
            archive: hex(&binding().archive),
            scope: hex(&binding().scope),
            issuer: binding().issuer,
        },
        owner: identity(4).did().to_string(),
        minimum: None,
    };
    let mut config = tempfile::NamedTempFile::new().unwrap();
    config
        .write_all(&serde_json::to_vec(&history).unwrap())
        .unwrap();
    let initialized = Command::new(env!("CARGO_BIN_EXE_kan-v2"))
        .arg("init-erasure-history")
        .arg(config.path())
        .arg("--signing-key")
        .arg(key.path())
        .output()
        .unwrap();
    assert!(
        initialized.status.success(),
        "{}",
        String::from_utf8_lossy(&initialized.stderr)
    );
    let output: serde_json::Value = serde_json::from_slice(&initialized.stdout).unwrap();
    let pinned: custody::Access = serde_json::from_value(output["config"].clone()).unwrap();
    assert!(pinned.minimum.is_some());
    assert!(pinned
        .current()
        .unwrap()
        .package()
        .unwrap()
        .records
        .is_empty());
    let retry = Command::new(env!("CARGO_BIN_EXE_kan-v2"))
        .arg("init-erasure-history")
        .arg(config.path())
        .arg("--signing-key")
        .arg(key.path())
        .output()
        .unwrap();
    assert!(
        retry.status.success(),
        "{}",
        String::from_utf8_lossy(&retry.stderr)
    );
    let retried: serde_json::Value = serde_json::from_slice(&retry.stdout).unwrap();
    assert_eq!(retried["config"]["minimum"], output["config"]["minimum"]);
    std::fs::write(config.path(), serde_json::to_vec(&pinned).unwrap()).unwrap();
    let root = tempfile::tempdir().unwrap();
    let archive = Archive::create(root.path(), binding()).unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_kan-v2"))
        .arg("reconcile-erasure")
        .arg(root.path())
        .arg("--erasure-history")
        .arg(config.path())
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let result: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(result["state"], "storage-history-reconciled");
    assert_eq!(result["activation"], "not-performed");
    assert_eq!(result["managed_cleanup"], "pending-coordination");
    assert_eq!(archive.verify().unwrap().through, 0);
}

#[test]
fn initial_erased_admission_preserves_chain_without_staging_payload_and_retires_sender() {
    use kan::{
        evidence_erasure_history as custody, evidence_spool::Spool, evidence_store::erasure,
    };
    let root = tempfile::tempdir().unwrap();
    let history_root = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(history_root.path(), std::fs::Permissions::from_mode(0o700))
            .unwrap();
    }
    let queue_root = tempfile::tempdir().unwrap();
    let mut history:custody::Access=serde_json::from_value(serde_json::json!({"directory":history_root.path(),"binding":{"profile":"admitted","archive":hex(&binding().archive),"scope":hex(&binding().scope),"issuer":binding().issuer},"owner":identity(5).did().as_str()})).unwrap();
    history.initialize().unwrap();
    let genesis =
        custody::Record::sign(history.preview(None, hex(&[1; 32])).unwrap(), &identity(5)).unwrap();
    let pin = genesis.id().unwrap();
    history.append(genesis).unwrap();
    history.minimum = Some(pin);
    let mut archive = Archive::create(root.path(), binding()).unwrap();
    let raw = request(0, None);
    let next = request(
        1,
        Some(
            kan::evidence_service::append_manifest(&raw)
                .unwrap()
                .cid()
                .to_string(),
        ),
    );
    let mut spool = Spool::create(
        &queue_root.path().join("queue.sqlite"),
        &hex(&binding().scope),
        identity(6).did().as_str(),
        &binding().issuer,
        1024 * 1024,
    )
    .unwrap();
    spool.enqueue(&raw).unwrap();
    spool.enqueue(&next).unwrap();
    let plan = archive
        .preview_erased_admission(&raw, hex(&[2; 32]), 100)
        .unwrap();
    assert!(plan.initial_erasure.as_ref().unwrap().previous.is_none());
    let erasure = erasure::Record::sign(plan, &identity(7)).unwrap();
    let owner = custody::Record::sign(
        history
            .preview(Some(erasure.clone()), hex(&[3; 32]))
            .unwrap(),
        &identity(5),
    )
    .unwrap();
    history.append(owner).unwrap();
    assert!(
        spool.reconcile_erasure(&history).is_err(),
        "prospective intent is not a committed admission"
    );
    assert_eq!(spool.head().unwrap(), Some(raw.clone()));
    let admitted = archive
        .admit_erased(&raw, &identity(7), &grant(), &erasure)
        .unwrap();
    assert_eq!(admitted.record.sequence, 1);
    assert_eq!(admitted.attestation.purpose(), Purpose::Admitted);
    assert_eq!(
        connection(root.path())
            .query_row("SELECT bytes FROM objects", [], |r| r.get::<_, Vec<u8>>(0))
            .unwrap(),
        vec![0]
    );
    assert_eq!(
        archive.erasure_history().unwrap().records[0].id().unwrap(),
        erasure.id().unwrap()
    );
    let again = archive
        .admit_erased(&raw, &identity(7), &grant(), &erasure)
        .unwrap();
    assert!(again.record.duplicate);
    assert_eq!(again.attestation.bytes(), admitted.attestation.bytes());
    assert!(
        archive.admit(&raw, &identity(7), &grant(), 101).is_err(),
        "ordinary replay cannot stage erased bytes"
    );
    assert!(
        spool.reconcile_erasure(&history).is_err(),
        "retirement still needs post-commit evidence"
    );
    let mut completion = kan::evidence_service::AdmittingService::new(
        Archive::open(root.path(), binding()).unwrap(),
        identity(7),
        vec![grant()],
    )
    .unwrap();
    let reply = completion.admit_erased(&raw, &erasure, &history).unwrap();
    // A valid completion for identical bytes/issuer/scope/sequence in another
    // archive must not complete this archive's cancellation.
    let elsewhere = tempfile::tempdir().unwrap();
    let other_custody = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(other_custody.path(), std::fs::Permissions::from_mode(0o700))
            .unwrap();
    }
    let mut other_binding = binding();
    other_binding.archive = [99; 32];
    let mut other_history = history.clone();
    other_history.directory = other_custody.path().to_path_buf();
    other_history.binding.archive = hex(&other_binding.archive);
    other_history.minimum = None;
    other_history.initialize().unwrap();
    let genesis = custody::Record::sign(
        other_history.preview(None, hex(&[4; 32])).unwrap(),
        &identity(5),
    )
    .unwrap();
    let pin = genesis.id().unwrap();
    other_history.append(genesis).unwrap();
    other_history.minimum = Some(pin);
    let other_archive = Archive::create(elsewhere.path(), other_binding).unwrap();
    let other_erasure = erasure::Record::sign(
        other_archive
            .preview_erased_admission(&raw, hex(&[5; 32]), 100)
            .unwrap(),
        &identity(7),
    )
    .unwrap();
    other_history
        .append(
            custody::Record::sign(
                other_history
                    .preview(Some(other_erasure.clone()), hex(&[6; 32]))
                    .unwrap(),
                &identity(5),
            )
            .unwrap(),
        )
        .unwrap();
    let mut other =
        kan::evidence_service::AdmittingService::new(other_archive, identity(7), vec![grant()])
            .unwrap();
    let foreign = other
        .admit_erased(&raw, &other_erasure, &other_history)
        .unwrap();
    assert!(spool
        .reconcile_erasure_with_admissions(&history, &[foreign])
        .is_err());
    assert_eq!(spool.head().unwrap(), Some(raw.clone()));
    let mut forged = reply.clone();
    forged.signature = hex(&[0; 64]);
    assert!(spool
        .reconcile_erasure_with_admissions(&history, &[forged])
        .is_err());
    assert_eq!(spool.head().unwrap(), Some(raw.clone()));
    assert_eq!(
        spool
            .reconcile_erasure_with_admissions(&history, &[reply])
            .unwrap()["retired_operations"],
        1
    );
    assert_eq!(spool.head().unwrap(), Some(next.clone()));
    drop(spool);
    let reopened = Spool::open(&queue_root.path().join("queue.sqlite")).unwrap();
    assert_eq!(reopened.head().unwrap(), Some(next.clone()));
    drop(reopened);
    archive.admit(&next, &identity(7), &grant(), 101).unwrap();
    assert_eq!(archive.verify().unwrap().through, 2);
    let backup = root.path().join("backup.sqlite");
    let report = archive.backup(&backup).unwrap();
    assert_eq!(report.erased_objects, 1);
    assert_eq!(report.bytes, next.len() as u64);
    let disk = std::fs::read(&backup).unwrap();
    assert!(!disk.windows(raw.len()).any(|b| b == raw));
    let recovered = tempfile::tempdir().unwrap();
    kan::evidence_store::attested::Recovery::open(&backup, binding())
        .unwrap()
        .rebuild(&recovered.path().join("archive.sqlite"))
        .unwrap();
    assert_eq!(
        Archive::open(recovered.path(), binding())
            .unwrap()
            .verify()
            .unwrap(),
        archive.verify().unwrap()
    );
    let queue = rusqlite::Connection::open(queue_root.path().join("queue.sqlite")).unwrap();
    let body: Vec<u8> = queue
        .query_row(
            "SELECT manifest FROM erased_operations WHERE position=0",
            [],
            |r| r.get(0),
        )
        .unwrap();
    let mut forged: serde_json::Value = serde_json::from_slice(&body).unwrap();
    forged["signature"] = serde_json::json!(hex(&[0; 64]));
    queue
        .execute(
            "UPDATE erased_operations SET manifest=? WHERE position=0",
            [serde_json::to_vec(&forged).unwrap()],
        )
        .unwrap();
    drop(queue);
    assert!(
        Spool::open(&queue_root.path().join("queue.sqlite")).is_err(),
        "restart audits the retained post-commit proof"
    );
}

#[test]
fn initial_erasure_is_atomic_and_resumes_with_ahead_custody() {
    use kan::evidence_store::erasure;
    let root = tempfile::tempdir().unwrap();
    let mut archive = Archive::create(root.path(), binding()).unwrap();
    let raw = request(0, None);
    let erasure = erasure::Record::sign(
        archive
            .preview_erased_admission(&raw, hex(&[2; 32]), 100)
            .unwrap(),
        &identity(7),
    )
    .unwrap();
    let failed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        archive
            .admit_erased_observed(&raw, &identity(7), &grant(), &erasure, &mut |b| {
                if b == Boundary::BeforeCommit {
                    panic!("synthetic precommit interruption");
                }
            })
            .unwrap();
    }));
    assert!(failed.is_err());
    assert_eq!(archive.verify().unwrap().through, 0);
    for table in ["objects", "commits", "attestations"] {
        assert_eq!(
            connection(root.path())
                .query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            0
        );
    }
    assert!(archive.erasure_history().unwrap().records.is_empty());
    let package = erasure::Package {
        version: 1,
        tip: Some(erasure.id().unwrap()),
        records: vec![erasure.clone()],
    };
    archive
        .reconcile_erasure(&package, package.tip.as_ref().unwrap())
        .unwrap();
    assert!(
        archive.admit(&raw, &identity(7), &grant(), 100).is_err(),
        "current custody blocks ordinary staging before metadata recovery"
    );
    archive
        .admit_erased(&raw, &identity(7), &grant(), &erasure)
        .unwrap();
    assert_eq!(archive.verify().unwrap().through, 1);
    assert_eq!(archive.erasure_history().unwrap().records.len(), 1);
}

#[test]
fn initial_erasure_refuses_wrong_request_stale_tip_and_false_initial_disposition() {
    use kan::evidence_store::erasure;
    let root = tempfile::tempdir().unwrap();
    let mut archive = Archive::create(root.path(), binding()).unwrap();
    let raw = request(0, None);
    let erasure = erasure::Record::sign(
        archive
            .preview_erased_admission(&raw, hex(&[2; 32]), 100)
            .unwrap(),
        &identity(7),
    )
    .unwrap();
    assert!(archive
        .admit_erased(
            &request(
                1,
                Some(
                    kan::evidence_service::append_manifest(&raw)
                        .unwrap()
                        .cid()
                        .to_string()
                )
            ),
            &identity(7),
            &grant(),
            &erasure
        )
        .is_err());
    assert!(archive
        .admit_erased(&raw, &identity(5), &grant(), &erasure)
        .is_err());
    let mut denied = grant();
    denied.append = false;
    assert!(archive
        .admit_erased(&raw, &identity(7), &denied, &erasure)
        .is_err());
    assert_eq!(archive.verify().unwrap().through, 0);
    archive.admit(&raw, &identity(7), &grant(), 100).unwrap();
    assert!(
        archive
            .admit_erased(&raw, &identity(7), &grant(), &erasure)
            .is_err(),
        "ordinary retained admission cannot be relabeled initially erased"
    );
    assert!(archive.apply_erasure(erasure).is_err());
    assert_eq!(
        connection(root.path())
            .query_row("SELECT bytes FROM objects", [], |r| r.get::<_, Vec<u8>>(0))
            .unwrap(),
        raw
    );
    let next = request(
        1,
        Some(
            kan::evidence_service::append_manifest(&raw)
                .unwrap()
                .cid()
                .to_string(),
        ),
    );
    let mut plan = archive
        .preview_erased_admission(&next, hex(&[3; 32]), 101)
        .unwrap();
    plan.initial_erasure.as_mut().unwrap().previous =
        Some(kan::evidence_store::ciphertext_cid(b"wrong parent").to_string());
    let wrong = erasure::Record::sign(plan, &identity(7)).unwrap();
    assert!(archive
        .admit_erased(&next, &identity(7), &grant(), &wrong)
        .is_err());
    assert_eq!(archive.verify().unwrap().through, 1);
}

#[test]
fn serving_index_authenticates_selected_metadata_and_repairs_only_after_full_audit() {
    use kan::evidence_store::serving::read_metadata;
    let temp = tempfile::tempdir().unwrap();
    let mut archive = Archive::create(temp.path(), binding()).unwrap();
    let first = archive
        .admit(&request(0, None), &identity(7), &grant(), 100)
        .unwrap();
    let path = temp.path().join("archive.sqlite");
    assert!(read_metadata(&path, binding(), first.attestation.frontier(), None, 1).is_err());
    archive.rebuild_serving_index(&identity(7)).unwrap();
    let second = archive
        .admit(
            &request(1, Some(first.record.manifest.cid().to_string())),
            &identity(7),
            &grant(),
            101,
        )
        .unwrap();
    let pin = second.attestation.frontier();
    drop(archive);
    let archive = Archive::open(temp.path(), binding()).unwrap();
    let selected = read_metadata(&path, binding(), pin, None, 1).unwrap();
    assert_eq!(
        selected.record.manifest.bytes(),
        first.record.manifest.bytes()
    );
    assert_eq!(selected.proof.bytes(), first.attestation.bytes());
    assert!(read_metadata(&path, binding(), first.attestation.frontier(), None, 1).is_err());
    assert!(read_metadata(
        &path,
        Binding {
            archive: [99; 32],
            ..binding()
        },
        pin,
        None,
        1
    )
    .is_err());
    let conn = connection(temp.path());
    conn.execute("UPDATE serving_nodes SET body=zeroblob(length(body))", [])
        .unwrap();
    assert!(read_metadata(&path, binding(), pin, None, 1).is_err());
    archive.rebuild_serving_index(&identity(7)).unwrap();
    assert!(read_metadata(&path, binding(), pin, None, 1).is_ok());
    // The bounded path makes no whole-corpus health claim: unrelated metadata
    // corruption is found by the explicit full audit, not a selected read.
    let receipt: Vec<u8> = conn
        .query_row("SELECT receipt FROM commits WHERE sequence=2", [], |r| {
            r.get(0)
        })
        .unwrap();
    conn.execute("UPDATE commits SET receipt=x'00' WHERE sequence=2", [])
        .unwrap();
    assert!(read_metadata(&path, binding(), pin, None, 1).is_ok());
    assert!(read_metadata(&path, binding(), pin, None, 2).is_err());
    let before: Vec<u8> = conn
        .query_row("SELECT body FROM serving_checkpoint", [], |r| r.get(0))
        .unwrap();
    assert!(archive.rebuild_serving_index(&identity(7)).is_err());
    let after: Vec<u8> = conn
        .query_row("SELECT body FROM serving_checkpoint", [], |r| r.get(0))
        .unwrap();
    assert_eq!(before, after);
    conn.execute("UPDATE commits SET receipt=? WHERE sequence=2", [receipt])
        .unwrap();
    // Captured bytes are deliberately outside the metadata-only claim.
    conn.execute("UPDATE objects SET bytes=x'00'", []).unwrap();
    assert!(read_metadata(&path, binding(), pin, None, 1).is_ok());
    assert!(archive.verify().is_err());
    assert!(archive.rebuild_serving_index(&identity(7)).is_err());
}

#[test]
fn serving_checkpoint_rejects_tampering_rollback_and_changed_custody() {
    use kan::evidence_store::{erasure::Record, serving::read_metadata};
    let temp = tempfile::tempdir().unwrap();
    let mut archive = Archive::create(temp.path(), binding()).unwrap();
    let first = archive
        .admit(&request(0, None), &identity(7), &grant(), 100)
        .unwrap();
    let old = archive
        .rebuild_serving_index(&identity(7))
        .unwrap()
        .bytes()
        .unwrap();
    let path = temp.path().join("archive.sqlite");
    let conn = connection(temp.path());
    let mut changed: serde_json::Value = serde_json::from_slice(&old).unwrap();
    changed["statement"]["root"] = serde_json::Value::String(hex(&[0; 32]));
    conn.execute(
        "UPDATE serving_checkpoint SET body=?",
        [serde_json::to_vec(&changed).unwrap()],
    )
    .unwrap();
    assert!(read_metadata(&path, binding(), first.attestation.frontier(), None, 1).is_err());
    archive.rebuild_serving_index(&identity(7)).unwrap();
    let second = archive
        .admit(
            &request(1, Some(first.record.manifest.cid().to_string())),
            &identity(7),
            &grant(),
            101,
        )
        .unwrap();
    conn.execute("UPDATE serving_checkpoint SET body=?", [&old])
        .unwrap();
    assert!(read_metadata(&path, binding(), second.attestation.frontier(), None, 1).is_err());
    archive.rebuild_serving_index(&identity(7)).unwrap();
    let plan = archive.preview_erasure(&[1], hex(&[31; 32]), 102).unwrap();
    let custody = archive
        .apply_erasure(Record::sign(plan, &identity(7)).unwrap())
        .unwrap();
    assert!(read_metadata(
        &path,
        binding(),
        second.attestation.frontier(),
        custody.tip.as_deref(),
        1
    )
    .is_err());
    archive.rebuild_serving_index(&identity(7)).unwrap();
    let selected = read_metadata(
        &path,
        binding(),
        second.attestation.frontier(),
        custody.tip.as_deref(),
        1,
    )
    .unwrap();
    assert_eq!(selected.proof.bytes(), first.attestation.bytes());
    assert!(read_metadata(&path, binding(), second.attestation.frontier(), None, 1).is_err());
}

#[test]
fn indexed_admission_preserves_retries_and_does_not_scan_unselected_history() {
    let temp = tempfile::tempdir().unwrap();
    let mut archive = Archive::create(temp.path(), binding()).unwrap();
    assert!(Archive::open_indexed(temp.path(), binding(), None).is_err());
    archive.rebuild_serving_index(&identity(7)).unwrap();
    let first_bytes = request(0, None);
    let first = archive
        .admit_indexed(&first_bytes, &identity(7), &grant(), 100, None)
        .unwrap();
    let second = archive
        .admit_indexed(
            &request(1, Some(first.record.manifest.cid().to_string())),
            &identity(7),
            &grant(),
            101,
            None,
        )
        .unwrap();
    let retry = archive
        .admit_indexed(&first_bytes, &identity(7), &grant(), 999, None)
        .unwrap();
    assert!(retry.record.duplicate);
    assert_eq!(retry.attestation.bytes(), first.attestation.bytes());
    let conn = connection(temp.path());
    let receipt: Vec<u8> = conn
        .query_row("SELECT receipt FROM commits WHERE sequence=1", [], |r| {
            r.get(0)
        })
        .unwrap();
    // This is unselected historical damage, not permission to accept a changed
    // writer frontier. Full verify still fails; indexed open/append stay bounded.
    conn.execute("UPDATE commits SET receipt=x'00' WHERE sequence=1", [])
        .unwrap();
    drop(archive);
    assert!(Archive::open(temp.path(), binding()).is_err());
    let mut indexed = Archive::open_indexed(temp.path(), binding(), None).unwrap();
    let third = indexed
        .admit_indexed(
            &request(2, Some(second.record.manifest.cid().to_string())),
            &identity(7),
            &grant(),
            102,
            None,
        )
        .unwrap();
    assert_eq!(third.record.sequence, 3);
    assert!(indexed
        .admit_indexed(&first_bytes, &identity(7), &grant(), 103, None)
        .is_err());
    conn.execute("UPDATE commits SET receipt=? WHERE sequence=1", [receipt])
        .unwrap();
    assert_eq!(indexed.verify().unwrap(), *third.attestation.frontier());
}

#[test]
fn indexed_admission_rejects_poisoned_writer_lookup_and_erased_request_replay() {
    use kan::evidence_store::erasure::Record;
    let temp = tempfile::tempdir().unwrap();
    let mut archive = Archive::create(temp.path(), binding()).unwrap();
    archive.rebuild_serving_index(&identity(7)).unwrap();
    let first_bytes = request(0, None);
    let first = archive
        .admit_indexed(&first_bytes, &identity(7), &grant(), 100, None)
        .unwrap();
    let second = archive
        .admit_indexed(
            &request(1, Some(first.record.manifest.cid().to_string())),
            &identity(7),
            &grant(),
            101,
            None,
        )
        .unwrap();
    let conn = connection(temp.path());
    // A forged SQL head would allow a second position=1 append without the
    // authenticated writer-head check. Give it a fresh operation identifier.
    conn.execute("UPDATE commits SET position=-1 WHERE sequence=2", [])
        .unwrap();
    let mut fork =
        SignedRequest::decode(&request(1, Some(first.record.manifest.cid().to_string())))
            .unwrap()
            .request;
    if let Operation::Append { id, .. } = &mut fork.command {
        *id = hex(&[88; 16]);
    }
    let fork = SignedRequest::sign(fork, &identity(6))
        .unwrap()
        .bytes()
        .unwrap();
    assert_eq!(
        archive
            .admit_indexed(&fork, &identity(7), &grant(), 102, None)
            .unwrap_err(),
        Failure::Conflict
    );
    assert_eq!(
        conn.query_row("SELECT count(*) FROM commits", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        2
    );
    conn.execute("UPDATE commits SET position=1 WHERE sequence=2", [])
        .unwrap();
    let erased = Record::sign(
        archive.preview_erasure(&[1], hex(&[44; 32]), 103).unwrap(),
        &identity(7),
    )
    .unwrap();
    let custody = archive.apply_erasure(erased).unwrap();
    assert!(Archive::open_indexed(temp.path(), binding(), custody.tip.as_deref()).is_err());
    archive.rebuild_serving_index(&identity(7)).unwrap();
    assert!(Archive::open_indexed(temp.path(), binding(), None).is_err());
    let mut archive =
        Archive::open_indexed(temp.path(), binding(), custody.tip.as_deref()).unwrap();
    assert_eq!(
        archive
            .admit_indexed(
                &first_bytes,
                &identity(7),
                &grant(),
                104,
                custody.tip.as_deref()
            )
            .unwrap_err(),
        Failure::AccessLimited
    );
    let third = archive
        .admit_indexed(
            &request(2, Some(second.record.manifest.cid().to_string())),
            &identity(7),
            &grant(),
            104,
            custody.tip.as_deref(),
        )
        .unwrap();
    assert_eq!(third.record.sequence, 3);
    assert_eq!(archive.verify().unwrap(), *third.attestation.frontier());
}
