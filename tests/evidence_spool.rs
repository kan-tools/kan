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
