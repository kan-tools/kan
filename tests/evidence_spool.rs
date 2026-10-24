#![cfg(feature = "v2-storage")]
use kan::{
    evidence_service::{self as service, Command, Grant, Request, Service, SignedRequest},
    evidence_spool::{Enqueue, Error, Spool},
    evidence_store::Ledger,
    sign::Identity,
};
fn append(
    writer: &Identity,
    audience: &str,
    scope: u8,
    id: u8,
    position: u64,
    previous: Option<String>,
) -> Vec<u8> {
    SignedRequest::sign(
        Request {
            version: 1,
            scope: service::hex(&[scope; 32]),
            audience: audience.into(),
            principal: writer.did().to_string(),
            expires: None,
            command: Command::Append {
                id: service::hex(&[id; 16]),
                position,
                previous,
                ciphertext: service::hex(b"synthetic opaque payload"),
            },
        },
        writer,
    )
    .unwrap()
    .bytes()
    .unwrap()
}
fn create(path: &std::path::Path, writer: &Identity, server: &Identity, budget: u64) -> Spool {
    Spool::create(
        path,
        &service::hex(&[1; 32]),
        writer.did().as_str(),
        server.did().as_str(),
        budget,
    )
    .unwrap()
}
#[test]
fn exact_bytes_restart_capacity_and_proven_remote_acknowledgment() {
    let t = tempfile::tempdir().unwrap();
    let path = t.path().join("spool.sqlite");
    let writer = Identity::generate();
    let server = Identity::generate();
    let audience = server.did().to_string();
    let first = append(&writer, &audience, 1, 1, 0, None);
    let mut spool = create(&path, &writer, &server, first.len() as u64);
    assert_eq!(spool.enqueue(&first).unwrap(), Enqueue::Queued);
    assert_eq!(spool.enqueue(&first).unwrap(), Enqueue::AlreadyPending);
    let frontier = spool.frontier().unwrap();
    let second = append(
        &writer,
        &audience,
        1,
        2,
        frontier.next,
        frontier.previous.clone(),
    );
    assert!(matches!(spool.enqueue(&second), Err(Error::Full)));
    assert_eq!(spool.frontier().unwrap(), frontier);
    drop(spool);
    let mut spool = Spool::open(&path).unwrap();
    assert_eq!(spool.head().unwrap().unwrap(), first);
    let conn = rusqlite::Connection::open(&path).unwrap();
    let independently_read: Vec<u8> = conn
        .query_row("SELECT request FROM pending", [], |r| r.get(0))
        .unwrap();
    assert_eq!(independently_read, first);
    drop(conn);
    let mut service = Service::new(
        Ledger::create(&t.path().join("remote")).unwrap(),
        [1; 32],
        server,
        vec![Grant {
            principal: writer.did().to_string(),
            append: true,
            inventory: false,
        }],
    )
    .unwrap();
    let lost = service.dispatch(&first, 1000).unwrap();
    let retry = service
        .dispatch(&spool.head().unwrap().unwrap(), 2000)
        .unwrap();
    let service::Output::Committed { record: old, .. } = lost.reply.result.clone().unwrap() else {
        panic!()
    };
    let service::Output::Committed {
        record: new,
        duplicate: true,
    } = retry.reply.result.clone().unwrap()
    else {
        panic!()
    };
    assert_eq!(old, new);
    let mut forged = retry.clone();
    forged.signature = service::hex(&[0; 64]);
    assert!(spool.acknowledge(&forged.bytes().unwrap()).is_err());
    assert_eq!(spool.head().unwrap().unwrap(), first);
    spool.acknowledge(&retry.bytes().unwrap()).unwrap();
    assert!(spool.head().unwrap().is_none());
    assert_eq!(spool.pending_bytes().unwrap(), 0);
    drop(spool);
    let spool = Spool::open(&path).unwrap();
    assert_eq!(spool.frontier().unwrap(), frontier);
}
#[test]
fn wrong_binding_fork_and_reordered_ack_never_advance() {
    let t = tempfile::tempdir().unwrap();
    let path = t.path().join("spool.sqlite");
    let writer = Identity::generate();
    let server = Identity::generate();
    let outsider = Identity::generate();
    let audience = server.did().to_string();
    let mut spool = create(&path, &writer, &server, 100000);
    for raw in [
        append(&writer, &audience, 2, 1, 0, None),
        append(&outsider, &audience, 1, 1, 0, None),
        append(&writer, outsider.did().as_str(), 1, 1, 0, None),
    ] {
        assert!(spool.enqueue(&raw).is_err());
    }
    let first = append(&writer, &audience, 1, 1, 0, None);
    spool.enqueue(&first).unwrap();
    let mut other = Spool::open(&path).unwrap();
    assert!(matches!(
        other.enqueue(&append(&writer, &audience, 1, 2, 0, None)),
        Err(Error::Conflict)
    ));
    let f = spool.frontier().unwrap();
    let second = append(&writer, &audience, 1, 2, f.next, f.previous);
    spool.enqueue(&second).unwrap();
    let mut service = Service::new(
        Ledger::create(&t.path().join("remote")).unwrap(),
        [1; 32],
        server,
        vec![Grant {
            principal: writer.did().to_string(),
            append: true,
            inventory: false,
        }],
    )
    .unwrap();
    let failure = service.dispatch(&second, 1000).unwrap();
    assert!(spool.acknowledge(&failure.bytes().unwrap()).is_err());
    let first_ack = service.dispatch(&first, 1000).unwrap();
    let second_ack = service.dispatch(&second, 1000).unwrap();
    assert!(spool.acknowledge(&second_ack.bytes().unwrap()).is_err());
    assert_eq!(spool.head().unwrap().unwrap(), first);
    spool.acknowledge(&first_ack.bytes().unwrap()).unwrap();
    spool.acknowledge(&second_ack.bytes().unwrap()).unwrap();
    assert!(spool.head().unwrap().is_none());
    drop(spool);
    assert_eq!(Spool::open(&path).unwrap().frontier().unwrap().next, 2);
}
#[test]
fn foreign_schema_and_queue_damage_fail_closed() {
    let t = tempfile::tempdir().unwrap();
    let writer = Identity::generate();
    let server = Identity::generate();
    for damage in ["schema", "signature", "frontier", "ack"] {
        let path = t.path().join(damage);
        let mut spool = create(&path, &writer, &server, 100000);
        spool
            .enqueue(&append(&writer, server.did().as_str(), 1, 1, 0, None))
            .unwrap();
        drop(spool);
        let conn = rusqlite::Connection::open(&path).unwrap();
        match damage {
            "schema" => conn.execute_batch("CREATE TABLE foreign_data(x)").unwrap(),
            "signature" => {
                conn.execute("UPDATE pending SET request=?", [b"invalid".as_slice()])
                    .unwrap();
            }
            "frontier" => {
                conn.execute("UPDATE state SET next=8", []).unwrap();
            }
            _ => {
                conn.execute("UPDATE state SET acknowledged_reply=x'00'", [])
                    .unwrap();
            }
        }
        drop(conn);
        assert!(Spool::open(&path).is_err());
        assert!(Spool::create(
            &path,
            &service::hex(&[1; 32]),
            writer.did().as_str(),
            server.did().as_str(),
            100000
        )
        .is_err());
    }
}
#[test]
fn concurrent_producers_serialize_one_frontier() {
    let t = tempfile::tempdir().unwrap();
    let path = t.path().join("spool.sqlite");
    let writer = Identity::generate();
    let server = Identity::generate();
    drop(create(&path, &writer, &server, 100000));
    let gate = std::sync::Arc::new(std::sync::Barrier::new(2));
    let mut jobs = vec![];
    for id in [1, 2] {
        let path = path.clone();
        let gate = gate.clone();
        let raw = append(&writer, server.did().as_str(), 1, id, 0, None);
        jobs.push(std::thread::spawn(move || {
            let mut s = Spool::open(&path).unwrap();
            gate.wait();
            s.enqueue(&raw)
        }));
    }
    let outcomes: Vec<_> = jobs.into_iter().map(|j| j.join().unwrap()).collect();
    assert_eq!(
        outcomes
            .iter()
            .filter(|r| matches!(r, Ok(Enqueue::Queued)))
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|r| matches!(r, Err(Error::Conflict)))
            .count(),
        1
    );
    assert_eq!(Spool::open(&path).unwrap().frontier().unwrap().next, 1);
}

#[test]
fn crash_worker() {
    let Some(path) = std::env::var_os("KAN_SPOOL_CRASH_PATH") else {
        return;
    };
    let raw = std::fs::read(std::env::var_os("KAN_SPOOL_CRASH_INPUT").unwrap()).unwrap();
    let mut spool = Spool::open(std::path::Path::new(&path)).unwrap();
    let boundary = std::env::var("KAN_SPOOL_CRASH_BOUNDARY").unwrap();
    let mut observe = |b| {
        if format!("{b:?}") == boundary {
            std::process::exit(77);
        }
    };
    if std::env::var("KAN_SPOOL_CRASH_OP").unwrap() == "enqueue" {
        spool.enqueue_observed(&raw, &mut observe).unwrap();
    } else {
        spool.acknowledge_observed(&raw, &mut observe).unwrap();
    }
    panic!("boundary was not reached");
}
#[test]
fn abrupt_exit_before_and_after_publish_preserves_atomic_state() {
    for operation in ["enqueue", "acknowledge"] {
        for boundary in ["BeforeCommit", "AfterCommit"] {
            let t = tempfile::tempdir().unwrap();
            let path = t.path().join("spool.sqlite");
            let writer = Identity::generate();
            let server = Identity::generate();
            let raw = append(&writer, server.did().as_str(), 1, 1, 0, None);
            let mut spool = create(&path, &writer, &server, 100000);
            let input = if operation == "acknowledge" {
                spool.enqueue(&raw).unwrap();
                let mut service = Service::new(
                    Ledger::create(&t.path().join("remote")).unwrap(),
                    [1; 32],
                    server,
                    vec![Grant {
                        principal: writer.did().to_string(),
                        append: true,
                        inventory: false,
                    }],
                )
                .unwrap();
                service.dispatch(&raw, 1000).unwrap().bytes().unwrap()
            } else {
                raw.clone()
            };
            drop(spool);
            let input_path = t.path().join("input");
            std::fs::write(&input_path, input).unwrap();
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "crash_worker"])
                .env("KAN_SPOOL_CRASH_PATH", &path)
                .env("KAN_SPOOL_CRASH_INPUT", input_path)
                .env("KAN_SPOOL_CRASH_OP", operation)
                .env("KAN_SPOOL_CRASH_BOUNDARY", boundary)
                .output()
                .unwrap();
            assert_eq!(
                status.status.code(),
                Some(77),
                "{}",
                String::from_utf8_lossy(&status.stderr)
            );
            let spool = Spool::open(&path).unwrap();
            let pending = (operation == "enqueue") == (boundary == "AfterCommit");
            assert_eq!(spool.head().unwrap().is_some(), pending);
            if pending {
                assert_eq!(spool.head().unwrap().unwrap(), raw);
            }
            let next = if operation == "enqueue" && boundary == "BeforeCommit" {
                0
            } else {
                1
            };
            assert_eq!(spool.frontier().unwrap().next, next);
        }
    }
}

#[cfg(feature = "v2-crypto")]
#[test]
fn encrypted_spool_has_no_plaintext_canary() {
    let t = tempfile::tempdir().unwrap();
    let path = t.path().join("spool.sqlite");
    let writer = Identity::generate();
    let server = Identity::generate();
    let canary = b"PLAINTEXT-ONLY-AT-THE-CAPTURE-BOUNDARY-2026-SPOOL";
    let ciphertext = kan::evidence_crypto::seal(
        &kan::evidence_crypto::public_key(&[67; 32]).unwrap(),
        &[1; 32],
        canary,
    )
    .unwrap();
    let raw = SignedRequest::sign(
        Request {
            version: 1,
            scope: service::hex(&[1; 32]),
            audience: server.did().to_string(),
            principal: writer.did().to_string(),
            expires: None,
            command: Command::Append {
                id: service::hex(&[1; 16]),
                position: 0,
                previous: None,
                ciphertext: service::hex(&ciphertext),
            },
        },
        &writer,
    )
    .unwrap()
    .bytes()
    .unwrap();
    let mut spool = create(&path, &writer, &server, 100000);
    spool.enqueue(&raw).unwrap();
    for item in std::fs::read_dir(t.path()).unwrap() {
        let bytes = std::fs::read(item.unwrap().path()).unwrap();
        assert!(!bytes.windows(canary.len()).any(|w| w == canary));
    }
    drop(spool);
    assert_eq!(Spool::open(&path).unwrap().head().unwrap().unwrap(), raw);
}

#[test]
fn acknowledged_operation_ids_cannot_be_reused() {
    let t = tempfile::tempdir().unwrap();
    let path = t.path().join("spool.sqlite");
    let writer = Identity::generate();
    let server = Identity::generate();
    let audience = server.did().to_string();
    let mut spool = create(&path, &writer, &server, 100000);
    let mut service = Service::new(
        Ledger::create(&t.path().join("remote")).unwrap(),
        [1; 32],
        server,
        vec![Grant {
            principal: writer.did().to_string(),
            append: true,
            inventory: false,
        }],
    )
    .unwrap();
    let mut first = vec![];
    for id in [1, 2] {
        let f = spool.frontier().unwrap();
        let raw = append(&writer, &audience, 1, id, f.next, f.previous);
        if id == 1 {
            first = raw.clone();
        }
        assert_eq!(spool.enqueue(&raw).unwrap(), Enqueue::Queued);
        spool
            .acknowledge(&service.dispatch(&raw, 1000).unwrap().bytes().unwrap())
            .unwrap();
    }
    let f = spool.frontier().unwrap();
    let reused = append(&writer, &audience, 1, 1, f.next, f.previous.clone());
    assert!(matches!(spool.enqueue(&reused), Err(Error::Conflict)));
    assert_eq!(spool.enqueue(&first).unwrap(), Enqueue::AlreadyAcknowledged);
    assert_eq!(spool.frontier().unwrap(), f);
    assert!(spool.head().unwrap().is_none());
    drop(spool);
    let mut spool = Spool::open(&path).unwrap();
    assert!(matches!(spool.enqueue(&reused), Err(Error::Conflict)));
    assert_eq!(spool.enqueue(&first).unwrap(), Enqueue::AlreadyAcknowledged);
    let next = append(&writer, &audience, 1, 3, f.next, f.previous);
    assert_eq!(spool.enqueue(&next).unwrap(), Enqueue::Queued);
    assert_eq!(spool.enqueue(&next).unwrap(), Enqueue::AlreadyPending);
    assert_eq!(spool.enqueue(&first).unwrap(), Enqueue::AlreadyAcknowledged);
    assert_eq!(spool.head().unwrap().unwrap(), next);
}

#[test]
fn operation_registry_damage_and_empty_route_damage_refuse_reopen() {
    let t = tempfile::tempdir().unwrap();
    let writer = Identity::generate();
    let server = Identity::generate();
    for damage in ["registry", "route", "old-profile"] {
        let path = t.path().join(damage);
        let mut spool = create(&path, &writer, &server, 100000);
        if damage == "registry" {
            spool
                .enqueue(&append(&writer, server.did().as_str(), 1, 1, 0, None))
                .unwrap();
        }
        drop(spool);
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch(match damage {
            "registry" => "DELETE FROM operations",
            "route" => "UPDATE state SET scope='invalid'",
            _ => "PRAGMA user_version=1",
        })
        .unwrap();
        drop(conn);
        assert!(Spool::open(&path).is_err());
    }
}

#[test]
fn actual_writer_lock_reports_storage_unavailable_without_advancing() {
    let t = tempfile::tempdir().unwrap();
    let path = t.path().join("spool.sqlite");
    let writer = Identity::generate();
    let server = Identity::generate();
    let mut spool = create(&path, &writer, &server, 100000);
    let lock = rusqlite::Connection::open(&path).unwrap();
    lock.execute_batch("BEGIN IMMEDIATE").unwrap();
    assert!(matches!(
        spool.enqueue(&append(&writer, server.did().as_str(), 1, 1, 0, None)),
        Err(Error::Unavailable)
    ));
    lock.execute_batch("ROLLBACK").unwrap();
    assert_eq!(spool.frontier().unwrap().next, 0);
}

#[cfg(feature = "v2-crypto")]
#[test]
fn generated_encrypted_requests_reserve_frontier_before_preparation() {
    use std::sync::{Arc, Barrier};
    let dir = tempfile::tempdir().unwrap();
    let writer = Identity::generate();
    let key = dir.path().join("key");
    writer.save(&key).unwrap();
    let path = dir.path().join("spool");
    let scope = [17; 32];
    let private = [73; 32];
    drop(
        Spool::create(
            &path,
            &service::hex(&scope),
            writer.did().as_str(),
            Identity::generate().did().as_str(),
            64 << 20,
        )
        .unwrap(),
    );
    let barrier = Arc::new(Barrier::new(2));
    let mut jobs = Vec::new();
    for producer in 0..2u8 {
        let (path, key, barrier) = (path.clone(), key.clone(), barrier.clone());
        jobs.push(std::thread::spawn(move || {
            let writer = Identity::load_existing(&key).unwrap();
            let mut spool = Spool::open(&path).unwrap();
            let recipient = kan::evidence_crypto::public_key(&private).unwrap();
            let mut results = Vec::new();
            for n in 0..40u8 {
                let mut id = [99; 16];
                id[0] = producer;
                id[1] = n;
                let body = format!("producer {producer} frame {n}");
                barrier.wait();
                results.push(
                    kan::evidence_delivery::queue(
                        &mut spool,
                        &writer,
                        &recipient,
                        &id,
                        body.as_bytes(),
                    )
                    .map(|_| ())
                    .map_err(|e| e.to_string()),
                );
                barrier.wait();
            }
            results
        }));
    }
    for job in jobs {
        let results = job.join().unwrap();
        assert!(results.iter().all(Result::is_ok), "{results:?}");
    }
    let raw = rusqlite::Connection::open(&path).unwrap();
    let mut query = raw
        .prepare("SELECT position,request FROM pending ORDER BY position")
        .unwrap();
    let rows = query
        .query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, Vec<u8>>(1)?)))
        .unwrap();
    let mut plaintext = std::collections::BTreeSet::new();
    let mut count = 0;
    for row in rows {
        let (position, bytes) = row.unwrap();
        assert_eq!(position, count);
        count += 1;
        plaintext.insert(
            String::from_utf8(
                kan::evidence_delivery::decrypt_request(
                    &bytes,
                    &private,
                    &scope,
                    writer.did().as_str(),
                )
                .unwrap(),
            )
            .unwrap(),
        );
    }
    assert_eq!(count, 80);
    assert_eq!(plaintext.len(), 80);
    for p in 0..2 {
        for n in 0..40 {
            assert!(plaintext.contains(&format!("producer {p} frame {n}")));
        }
    }
    assert_eq!(Spool::open(&path).unwrap().status().unwrap().pending, 80);
}

fn erasure_identity(n: u8) -> Identity {
    use std::io::Write;
    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(&[n; 32]).unwrap();
    Identity::load_existing(file.path()).unwrap()
}
fn erasure_custody(
    root: &std::path::Path,
    binding: &kan::evidence_store::attested::Binding,
) -> kan::evidence_erasure_history::Access {
    use kan::evidence_erasure_history::{Access, Record};
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let mut access:Access=serde_json::from_value(serde_json::json!({"directory":root,"binding":{"profile":"admitted","archive":service::hex(&binding.archive),"scope":service::hex(&binding.scope),"issuer":binding.issuer},"owner":erasure_identity(9).did().as_str()})).unwrap();
    access.initialize().unwrap();
    let genesis = Record::sign(
        access.preview(None, "1".repeat(64)).unwrap(),
        &erasure_identity(9),
    )
    .unwrap();
    let id = genesis.id().unwrap();
    access.append(genesis).unwrap();
    access.minimum = Some(id);
    access
}
fn authorize_erasure(
    root: &std::path::Path,
    binding: &kan::evidence_store::attested::Binding,
    access: &kan::evidence_erasure_history::Access,
    sequences: &[u64],
) {
    let mut archive = kan::evidence_store::attested::Archive::open(root, binding.clone()).unwrap();
    let plan = archive
        .preview_erasure(sequences, "2".repeat(64), 2000)
        .unwrap();
    let record = kan::evidence_store::erasure::Record::sign(plan, &erasure_identity(8)).unwrap();
    let owner = kan::evidence_erasure_history::Record::sign(
        access
            .preview(Some(record.clone()), "3".repeat(64))
            .unwrap(),
        &erasure_identity(9),
    )
    .unwrap();
    access.append(owner).unwrap();
    archive.apply_erasure(record).unwrap();
}
#[test]
fn erased_spool_ack_and_lost_ack_head_keep_authenticated_cursor_and_unrelated_delivery() {
    use kan::evidence_store::attested::{Archive, Binding};
    let local = tempfile::tempdir().unwrap();
    let custody = tempfile::tempdir().unwrap();
    let root = local.path().join("archive");
    let path = local.path().join("spool.sqlite");
    let writer = erasure_identity(6);
    let issuer = erasure_identity(8);
    let binding = Binding {
        archive: [21; 32],
        scope: [1; 32],
        issuer: issuer.did().to_string(),
    };
    let access = erasure_custody(custody.path(), &binding);
    let mut remote = service::AdmittingService::new(
        Archive::create(&root, binding.clone()).unwrap(),
        issuer,
        vec![Grant {
            principal: writer.did().to_string(),
            append: true,
            inventory: false,
        }],
    )
    .unwrap()
    .with_erasure_history(access.clone())
    .unwrap();
    let mut spool = create(&path, &writer, &erasure_identity(8), 1024 * 1024);
    let mut requests = Vec::new();
    let mut replies = Vec::new();
    for n in 0..4 {
        let next = spool.frontier().unwrap();
        let raw = append(&writer, &binding.issuer, 1, n as u8, n, next.previous);
        spool.enqueue(&raw).unwrap();
        if n < 3 {
            let reply = remote.dispatch(&raw, 1000 + n).unwrap().bytes().unwrap();
            if n < 2 {
                spool.acknowledge(&reply).unwrap();
            }
            replies.push(reply);
        }
        requests.push(raw);
    }
    let expected = spool.frontier().unwrap();
    let mut already_open = Spool::open(&path).unwrap();
    authorize_erasure(&root, &binding, &access, &[1, 2, 3]);
    let done = spool.reconcile_erasure(&access).unwrap();
    assert_eq!(done["retired_operations"], 3);
    assert_eq!(spool.frontier().unwrap(), expected);
    assert_eq!(spool.head().unwrap(), Some(requests[3].clone()));
    assert_eq!(already_open.head().unwrap(), Some(requests[3].clone()));
    assert!(
        already_open.acknowledge(&replies[2]).is_err(),
        "late ACK must not release the new head"
    );
    for n in 0..3 {
        assert!(
            spool
                .operation(&service::hex(&[n; 16]))
                .unwrap()
                .unwrap()
                .erased
        );
        assert!(matches!(
            already_open.enqueue(&requests[n as usize]),
            Err(Error::Erased)
        ));
    }
    let db = rusqlite::Connection::open(&path).unwrap();
    let ack: (Option<Vec<u8>>, Option<Vec<u8>>) = db
        .query_row(
            "SELECT acknowledged_request,acknowledged_reply FROM state",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(ack, (None, None));
    assert_eq!(
        db.query_row("SELECT count(*) FROM erasure_authorizations", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        1,
        "large signed authorization retained once"
    );
    assert_eq!(
        db.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        3
    );
    let response = remote
        .dispatch(&requests[3], 2001)
        .unwrap()
        .bytes()
        .unwrap();
    spool.acknowledge(&response).unwrap();
    assert_eq!(spool.status().unwrap().pending, 0);
    assert_eq!(
        spool.reconcile_erasure(&access).unwrap()["retired_operations"],
        0
    );
    drop(spool);
    drop(already_open);
    drop(db);
    let spool = Spool::open(&path).unwrap();
    assert!(spool.head().unwrap().is_none());
    assert_eq!(spool.frontier().unwrap(), expected);
    assert!(spool.reclaim_erased_pages().unwrap());
    drop(spool);
    let file = std::fs::read(&path).unwrap();
    for raw in &requests[..3] {
        assert!(!file.windows(raw.len()).any(|p| p == raw));
    }
    // A minimal proof cannot be replaced with fabricated cursor metadata.
    let db = rusqlite::Connection::open(&path).unwrap();
    db.execute(
        "UPDATE erased_operations SET manifest=x'00' WHERE position=2",
        [],
    )
    .unwrap();
    drop(db);
    assert!(Spool::open(&path).is_err());
}
#[test]
fn spool_erasure_refuses_nonprefix_removal_then_retires_after_unrelated_ack() {
    use kan::evidence_store::attested::{Archive, Binding};
    let local = tempfile::tempdir().unwrap();
    let custody = tempfile::tempdir().unwrap();
    let root = local.path().join("archive");
    let path = local.path().join("spool.sqlite");
    let writer = erasure_identity(6);
    let binding = Binding {
        archive: [22; 32],
        scope: [1; 32],
        issuer: erasure_identity(8).did().to_string(),
    };
    let access = erasure_custody(custody.path(), &binding);
    let mut remote = service::AdmittingService::new(
        Archive::create(&root, binding.clone()).unwrap(),
        erasure_identity(8),
        vec![Grant {
            principal: writer.did().to_string(),
            append: true,
            inventory: false,
        }],
    )
    .unwrap();
    let mut spool = create(&path, &writer, &erasure_identity(8), 1024 * 1024);
    let mut replies = Vec::new();
    let mut requests = Vec::new();
    for n in 0..2 {
        let next = spool.frontier().unwrap();
        let raw = append(&writer, &binding.issuer, 1, n as u8, n, next.previous);
        spool.enqueue(&raw).unwrap();
        replies.push(remote.dispatch(&raw, 1000).unwrap().bytes().unwrap());
        requests.push(raw);
    }
    authorize_erasure(&root, &binding, &access, &[2]);
    assert!(matches!(
        spool.reconcile_erasure(&access),
        Err(Error::Conflict)
    ));
    assert_eq!(spool.head().unwrap(), Some(requests[0].clone()));
    assert_eq!(spool.status().unwrap().pending, 2);
    assert!(
        !spool
            .operation(&service::hex(&[1; 16]))
            .unwrap()
            .unwrap()
            .erased
    );
    spool.acknowledge(&replies[0]).unwrap();
    spool.reconcile_erasure(&access).unwrap();
    assert!(spool.head().unwrap().is_none());
    assert_eq!(
        spool.enqueue(&requests[0]).unwrap(),
        Enqueue::AlreadyAcknowledged
    );
    assert!(matches!(spool.enqueue(&requests[1]), Err(Error::Erased)));
    drop(spool);
    let mut spool = Spool::open(&path).unwrap();
    assert_eq!(spool.status().unwrap().pending, 0);
    let mut foreign = access.clone();
    foreign.owner = erasure_identity(10).did().to_string();
    assert!(spool.reconcile_erasure(&foreign).is_err());
}

#[test]
fn spool_erasure_makes_prefix_progress_without_skipping_unaffected_requests() {
    use kan::evidence_store::attested::{Archive, Binding};
    let local = tempfile::tempdir().unwrap();
    let custody = tempfile::tempdir().unwrap();
    let root = local.path().join("archive");
    let path = local.path().join("spool.sqlite");
    let writer = erasure_identity(6);
    let binding = Binding {
        archive: [23; 32],
        scope: [1; 32],
        issuer: erasure_identity(8).did().to_string(),
    };
    let access = erasure_custody(custody.path(), &binding);
    let mut remote = service::AdmittingService::new(
        Archive::create(&root, binding.clone()).unwrap(),
        erasure_identity(8),
        vec![Grant {
            principal: writer.did().to_string(),
            append: true,
            inventory: false,
        }],
    )
    .unwrap();
    let mut spool = create(&path, &writer, &erasure_identity(8), 1024 * 1024);
    let mut replies = Vec::new();
    let mut requests = Vec::new();
    for n in 0..3 {
        let next = spool.frontier().unwrap();
        let raw = append(&writer, &binding.issuer, 1, n as u8, n, next.previous);
        spool.enqueue(&raw).unwrap();
        replies.push(remote.dispatch(&raw, 1000).unwrap().bytes().unwrap());
        requests.push(raw);
    }
    authorize_erasure(&root, &binding, &access, &[1, 3]);
    let first = spool.reconcile_erasure(&access).unwrap();
    assert_eq!(first["state"], "partial-admitted-erasure");
    assert_eq!(first["retired_operations"], 1);
    assert_eq!(first["deferred_pending_operations"], 1);
    assert_eq!(spool.head().unwrap(), Some(requests[1].clone()));
    assert_eq!(spool.status().unwrap().pending, 2);
    spool.acknowledge(&replies[1]).unwrap();
    let second = spool.reconcile_erasure(&access).unwrap();
    assert_eq!(second["state"], "admitted-erasure-reconciled");
    assert_eq!(second["retired_operations"], 1);
    assert!(spool.head().unwrap().is_none());
    drop(spool);
    assert!(Spool::open(&path).unwrap().head().unwrap().is_none());
    #[cfg(feature = "v2-service")]
    {
        let config = local.path().join("custody.json");
        std::fs::write(&config, serde_json::to_vec(&access).unwrap()).unwrap();
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_kan-v2"))
            .args(["reconcile-spool-erasure"])
            .arg(&path)
            .arg("--erasure-history")
            .arg(config)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(report["retired_operations"], 0);
        assert_eq!(report["page_reclamation"], "completed");
    }
}

#[test]
fn managed_spool_fences_current_erasure_across_live_handles_and_old_restore() {
    use kan::evidence_store::attested::{Archive, Binding};
    let local = tempfile::tempdir().unwrap();
    let custody = tempfile::tempdir().unwrap();
    let root = local.path().join("archive");
    let path = local.path().join("spool.sqlite");
    let restored = local.path().join("restored.sqlite");
    let writer = erasure_identity(6);
    let binding = Binding {
        archive: [24; 32],
        scope: [1; 32],
        issuer: erasure_identity(8).did().to_string(),
    };
    let access = erasure_custody(custody.path(), &binding);
    let mut remote = service::AdmittingService::new(
        Archive::create(&root, binding.clone()).unwrap(),
        erasure_identity(8),
        vec![Grant {
            principal: writer.did().to_string(),
            append: true,
            inventory: false,
        }],
    )
    .unwrap();
    let mut spool = create(&path, &writer, &erasure_identity(8), 1024 * 1024);
    let mut requests = Vec::new();
    let mut replies = Vec::new();
    for n in 0..2 {
        let raw = append(
            &writer,
            &binding.issuer,
            1,
            n as u8,
            n,
            spool.frontier().unwrap().previous,
        );
        spool.enqueue(&raw).unwrap();
        replies.push(remote.dispatch(&raw, 1000).unwrap().bytes().unwrap());
        requests.push(raw);
    }
    drop(spool);
    std::fs::copy(&path, &restored).unwrap();
    let mut live = Spool::open(&path)
        .unwrap()
        .with_erasure_history(access.clone())
        .unwrap();
    authorize_erasure(&root, &binding, &access, &[2]);
    {
        let mut queue = Spool::open(&restored)
            .unwrap()
            .with_erasure_history(access.clone())
            .unwrap();
        assert_eq!(
            queue.head().unwrap(),
            Some(requests[0].clone()),
            "unaffected predecessor stays deliverable"
        );
        assert!(
            queue
                .operation(&service::hex(&[1; 16]))
                .unwrap()
                .unwrap()
                .erased
        );
        assert!(matches!(queue.enqueue(&requests[1]), Err(Error::Erased)));
        queue.acknowledge(&replies[0]).unwrap();
        assert!(
            matches!(queue.head(), Err(Error::Erased)),
            "profile-2 backup cannot export erased bytes"
        );
        assert!(matches!(queue.acknowledge(&replies[1]), Err(Error::Erased)));
        #[cfg(feature = "v2-crypto")]
        assert!(
            tokio::runtime::Runtime::new()
                .unwrap()
                .block_on(kan::evidence_delivery::deliver_one(
                    &mut queue,
                    "not-an-endpoint"
                ))
                .unwrap()
                .is_none(),
            "retirement precedes any network activity"
        );
    }
    live.acknowledge(&replies[0]).unwrap();
    assert!(
        matches!(live.head(), Err(Error::Erased)),
        "live enrollment refreshes owner history"
    );
    #[cfg(feature = "v2-service")]
    {
        let config = local.path().join("custody.json");
        std::fs::write(&config, serde_json::to_vec(&access).unwrap()).unwrap();
        let out = std::process::Command::new(env!("CARGO_BIN_EXE_kan-v2"))
            .arg("spool-head")
            .arg(&path)
            .arg("--erasure-history")
            .arg(config)
            .output()
            .unwrap();
        assert!(!out.status.success());
        assert!(out.stdout.is_empty(), "managed CLI emits no erased request");
    }
    let history_path = custody.path().to_path_buf();
    let unavailable = local.path().join("unavailable-history");
    std::fs::rename(&history_path, &unavailable).unwrap();
    assert!(
        live.head().is_err(),
        "missing independent custody fails closed"
    );
    assert!(live.enqueue(&requests[0]).is_err());
    std::fs::rename(unavailable, history_path).unwrap();
    let mut wrong = access.clone();
    wrong.binding.scope = "ff".repeat(32);
    assert!(Spool::open(&path)
        .unwrap()
        .with_erasure_history(wrong)
        .is_err());
}

#[cfg(feature = "v2-crypto")]
#[tokio::test]
async fn managed_delivery_holds_owner_custody_until_network_ack() {
    use kan::{
        evidence_erasure_history::Record,
        evidence_store::attested::{Archive, Binding},
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let local = tempfile::tempdir().unwrap();
    let custody = tempfile::tempdir().unwrap();
    let root = local.path().join("archive");
    let path = local.path().join("spool.sqlite");
    let writer = erasure_identity(6);
    let issuer = erasure_identity(8);
    let binding = Binding {
        archive: [25; 32],
        scope: [1; 32],
        issuer: issuer.did().to_string(),
    };
    let access = erasure_custody(custody.path(), &binding);
    let mut remote = service::AdmittingService::new(
        Archive::create(&root, binding.clone()).unwrap(),
        issuer,
        vec![Grant {
            principal: writer.did().to_string(),
            append: true,
            inventory: false,
        }],
    )
    .unwrap();
    let raw = append(&writer, &binding.issuer, 1, 0, 0, None);
    let reply = remote.dispatch(&raw, 1000).unwrap().bytes().unwrap();
    let mut spool = create(&path, &writer, &erasure_identity(8), 1024 * 1024)
        .with_erasure_history(access.clone())
        .unwrap();
    spool.enqueue(&raw).unwrap();
    let mut archive = Archive::open(&root, binding).unwrap();
    let erasure = kan::evidence_store::erasure::Record::sign(
        archive.preview_erasure(&[1], "4".repeat(64), 2000).unwrap(),
        &erasure_identity(8),
    )
    .unwrap();
    let authorization = Record::sign(
        access
            .preview(Some(erasure.clone()), "5".repeat(64))
            .unwrap(),
        &erasure_identity(9),
    )
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}/v1/rpc", listener.local_addr().unwrap());
    let server = async {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut received = Vec::new();
        loop {
            let mut buf = [0; 4096];
            let n = socket.read(&mut buf).await.unwrap();
            assert!(n > 0);
            received.extend_from_slice(&buf[..n]);
            assert!(received.len() <= raw.len() + 65536);
            if received
                .windows(4)
                .position(|b| b == b"\r\n\r\n")
                .is_some_and(|header| received.len() >= header + 4 + raw.len())
            {
                break;
            }
        }
        assert!(
            access.append(authorization.clone()).is_err(),
            "owner publication must not race an in-flight old request"
        );
        socket.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",reply.len()).as_bytes()).await.unwrap();
        socket.write_all(&reply).await.unwrap();
    };
    let (_, delivered) = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        tokio::join!(
            server,
            kan::evidence_delivery::deliver_one(&mut spool, &endpoint)
        )
    })
    .await
    .unwrap();
    assert!(delivered.unwrap().is_some());
    access.append(authorization).unwrap();
    archive.apply_erasure(erasure).unwrap();
    assert!(kan::evidence_delivery::deliver_one(&mut spool, "unused")
        .await
        .unwrap()
        .is_none());
    assert!(
        spool
            .operation(&service::hex(&[0; 16]))
            .unwrap()
            .unwrap()
            .erased
    );
    assert!(Spool::open(&path).unwrap().head().unwrap().is_none());
}
