#![cfg(feature = "v2-storage")]
use kan::{
    evidence::{self, Decoded},
    evidence_service::{
        hex, unhex, Command, Failure, Grant, Output, Request, Service, SignedRequest, MAX_PAYLOAD,
    },
    evidence_store::Ledger,
    sign::Identity,
};

fn service_identity() -> Identity {
    use std::io::Write;
    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(&[7; 32]).unwrap();
    Identity::load_existing(file.path()).unwrap()
}

fn request(identity: &Identity, scope: u8, command: Command, expires: Option<u64>) -> Vec<u8> {
    SignedRequest::sign(
        Request {
            version: 1,
            scope: hex(&[scope; 32]),
            audience: service_identity().did().to_string(),
            principal: identity.did().to_string(),
            expires,
            command,
        },
        identity,
    )
    .unwrap()
    .bytes()
    .unwrap()
}
fn append(identity: &Identity, id: u8, position: u64, previous: Option<String>) -> Vec<u8> {
    request(
        identity,
        1,
        Command::Append {
            id: hex(&[id; 16]),
            position,
            previous,
            ciphertext: hex(b"opaque fixture"),
        },
        None,
    )
}
fn grant(identity: &Identity, append: bool, inventory: bool) -> Grant {
    Grant {
        principal: identity.did().to_string(),
        append,
        inventory,
    }
}
fn result(service: &mut Service, request: &[u8]) -> Result<Output, Failure> {
    let reply = service.dispatch(request, 1000).unwrap();
    reply
        .verify(request, &service.issuer())
        .unwrap()
        .result
        .clone()
}
fn cid(manifest: &str) -> String {
    let Decoded::Known(record) = evidence::decode(&unhex(manifest, 65536).unwrap()).unwrap() else {
        panic!()
    };
    record.cid().to_string()
}

#[test]
fn independent_capabilities_deny_other_scopes_and_unadmitted_writers() {
    let t = tempfile::tempdir().unwrap();
    let writer = Identity::generate();
    let reader = Identity::generate();
    let outsider = Identity::generate();
    let mut service = Service::new(
        Ledger::create(&t.path().join("archive")).unwrap(),
        [1; 32],
        service_identity(),
        vec![grant(&writer, true, false), grant(&reader, false, true)],
    )
    .unwrap();
    assert!(matches!(
        result(&mut service, &append(&writer, 1, 0, None)),
        Ok(Output::Committed { .. })
    ));
    for (identity, scope, command) in [
        (&writer, 1, Command::Read { sequence: 1 }),
        (&writer, 1, Command::Read { sequence: 99 }),
        (&reader, 2, Command::Read { sequence: 1 }),
        (&outsider, 1, Command::Snapshot),
    ] {
        assert_eq!(
            result(&mut service, &request(identity, scope, command, Some(1100))),
            Err(Failure::AccessLimited)
        );
    }
    assert_eq!(
        result(&mut service, &append(&reader, 2, 0, None)),
        Err(Failure::AccessLimited)
    );
    assert_eq!(
        result(&mut service, &append(&outsider, 2, 0, None)),
        Err(Failure::AccessLimited)
    );
    assert!(matches!(
        result(
            &mut service,
            &request(&reader, 1, Command::Read { sequence: 1 }, Some(1100))
        ),
        Ok(Output::Evidence { .. })
    ));
    assert_eq!(
        result(
            &mut service,
            &request(&reader, 1, Command::Read { sequence: 2 }, Some(1100))
        ),
        Err(Failure::Missing)
    );
}

#[test]
fn retained_signed_bytes_retry_conflict_restart_and_revoked_writer() {
    let t = tempfile::tempdir().unwrap();
    let root = t.path().join("archive");
    let writer = Identity::generate();
    let reader = Identity::generate();
    let original = append(&writer, 1, 0, None);
    let oracle_input = t.path().join("request.json");
    std::fs::write(&oracle_input, &original).unwrap();
    let oracle = std::process::Command::new("python3")
        .arg("scripts/verify_service_request.py")
        .arg(&oracle_input)
        .output()
        .unwrap();
    assert!(
        oracle.status.success(),
        "{}",
        String::from_utf8_lossy(&oracle.stderr)
    );
    let mut tampered: serde_json::Value = serde_json::from_slice(&original).unwrap();
    tampered["request"]["scope"] = serde_json::json!(hex(&[2; 32]));
    // Retain the declared struct order, so this fails cryptographic verification,
    // not only the oracle's canonical-envelope check.
    let tampered: SignedRequest = serde_json::from_value(tampered).unwrap();
    std::fs::write(&oracle_input, tampered.bytes().unwrap()).unwrap();
    let oracle = std::process::Command::new("python3")
        .arg("scripts/verify_service_request.py")
        .arg(&oracle_input)
        .output()
        .unwrap();
    assert!(!oracle.status.success());
    assert!(String::from_utf8_lossy(&oracle.stderr).contains("signature verification failed"));

    let mut service = Service::new(
        Ledger::create(&root).unwrap(),
        [1; 32],
        service_identity(),
        vec![grant(&writer, true, true)],
    )
    .unwrap();
    let Output::Committed {
        record: first,
        duplicate: false,
    } = result(&mut service, &original).unwrap()
    else {
        panic!()
    };
    let Output::Committed {
        record: retry,
        duplicate: true,
    } = result(&mut service, &original).unwrap()
    else {
        panic!()
    };
    assert_eq!(first, retry);
    let changed = request(
        &writer,
        1,
        Command::Append {
            id: hex(&[1; 16]),
            position: 0,
            previous: None,
            ciphertext: hex(b"changed"),
        },
        None,
    );
    assert_eq!(result(&mut service, &changed), Err(Failure::Conflict));
    assert_eq!(
        result(&mut service, &append(&writer, 2, 0, None)),
        Err(Failure::Conflict)
    );
    let next = append(&writer, 2, 1, Some(cid(&first.manifest)));
    assert!(matches!(
        result(&mut service, &next),
        Ok(Output::Committed { .. })
    ));
    drop(service);
    // Reopening with new current grants preserves signed historical authorship.
    let mut service = Service::new(
        Ledger::open(&root).unwrap(),
        [1; 32],
        service_identity(),
        vec![grant(&reader, false, true)],
    )
    .unwrap();
    assert_eq!(result(&mut service, &original), Err(Failure::AccessLimited));
    let Output::Evidence {
        record,
        signed_request,
    } = result(
        &mut service,
        &request(&reader, 1, Command::Read { sequence: 1 }, Some(1100)),
    )
    .unwrap()
    else {
        panic!()
    };
    assert_eq!(record, first);
    assert_eq!(unhex(&signed_request, 4 * 1024 * 1024).unwrap(), original);
    assert_eq!(
        SignedRequest::decode(&original).unwrap().request.principal,
        writer.did().to_string()
    );
    let Output::Snapshot { through, tip } = result(
        &mut service,
        &request(&reader, 1, Command::Snapshot, Some(1100)),
    )
    .unwrap() else {
        panic!()
    };
    assert_eq!(through, 2);
    let Output::Page { records, complete } = result(
        &mut service,
        &request(
            &reader,
            1,
            Command::Page {
                through,
                tip,
                after: 0,
                limit: 1,
            },
            Some(1100),
        ),
    )
    .unwrap() else {
        panic!()
    };
    assert_eq!(records, vec![first]);
    assert!(!complete);
    drop(service);
    let ledger = Ledger::open(&root).unwrap();
    assert_eq!(ledger.verify().unwrap().commits, 2);
    ledger.backup(&t.path().join("backup.sqlite")).unwrap();
    let output = std::process::Command::new("python3")
        .arg("scripts/verify_evidence_store.py")
        .arg(t.path().join("backup.sqlite"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["commits"], 2);
}

#[test]
fn signatures_canonical_bounds_expiry_and_reply_binding() {
    let t = tempfile::tempdir().unwrap();
    let writer = Identity::generate();
    let mut service = Service::new(
        Ledger::create(&t.path().join("archive")).unwrap(),
        [1; 32],
        service_identity(),
        vec![grant(&writer, true, true)],
    )
    .unwrap();
    let raw = append(&writer, 1, 0, None);
    let mut elsewhere: SignedRequest = serde_json::from_slice(&raw).unwrap();
    elsewhere.request.audience = Identity::generate().did().to_string();
    let elsewhere = SignedRequest::sign(elsewhere.request, &writer)
        .unwrap()
        .bytes()
        .unwrap();
    assert_eq!(
        result(&mut service, &elsewhere),
        Err(Failure::AccessLimited)
    );

    let mut changed: SignedRequest = serde_json::from_slice(&raw).unwrap();
    let Command::Append { ciphertext, .. } = &mut changed.request.command else {
        panic!()
    };
    *ciphertext = hex(b"forged payload under an otherwise authorized request");
    assert_eq!(
        result(&mut service, &changed.bytes().unwrap()),
        Err(Failure::AccessLimited)
    );
    let mut noncanonical = raw.clone();
    noncanonical.push(b' ');
    assert_eq!(result(&mut service, &noncanonical), Err(Failure::Invalid));
    let duplicate = String::from_utf8(raw.clone()).unwrap().replacen(
        "\"version\":1",
        "\"version\":1,\"version\":1",
        1,
    );
    assert_eq!(
        result(&mut service, duplicate.as_bytes()),
        Err(Failure::Invalid)
    );
    let unknown = String::from_utf8(raw.clone()).unwrap().replacen(
        "\"version\":1",
        "\"unknown\":1,\"version\":1",
        1,
    );
    assert_eq!(
        result(&mut service, unknown.as_bytes()),
        Err(Failure::Invalid)
    );
    for expires in [999, 1301] {
        assert_eq!(
            result(
                &mut service,
                &request(&writer, 1, Command::Snapshot, Some(expires))
            ),
            Err(Failure::AccessLimited)
        );
    }
    let reply = service.dispatch(&raw, 1000).unwrap();
    assert!(reply.verify(&raw, &service.issuer()).is_ok());
    assert!(reply.verify(&raw, writer.did().as_str()).is_err());
    assert!(reply.verify(b"another request", &service.issuer()).is_err());
    let mut changed = reply.clone();
    changed.reply.result = Err(Failure::Missing);
    assert!(changed.verify(&raw, &service.issuer()).is_err());
    let oversized = Request {
        version: 1,
        scope: hex(&[1; 32]),
        audience: service_identity().did().to_string(),
        principal: writer.did().to_string(),
        expires: None,
        command: Command::Append {
            id: hex(&[2; 16]),
            position: 0,
            previous: None,
            ciphertext: hex(&vec![0; MAX_PAYLOAD + 1]),
        },
    };
    assert!(SignedRequest::sign(oversized, &writer).is_err());
    let badpage = Request {
        version: 1,
        scope: hex(&[1; 32]),
        audience: service_identity().did().to_string(),
        principal: writer.did().to_string(),
        expires: Some(1100),
        command: Command::Page {
            through: 0,
            tip: None,
            after: 0,
            limit: 129,
        },
    };
    assert!(SignedRequest::sign(badpage, &writer).is_err());
}

#[test]
fn startup_rejects_wrong_scope_and_foreign_payload_preserves_source() {
    let t = tempfile::tempdir().unwrap();
    let root = t.path().join("archive");
    let writer = Identity::generate();
    let mut service = Service::new(
        Ledger::create(&root).unwrap(),
        [1; 32],
        service_identity(),
        vec![grant(&writer, true, false)],
    )
    .unwrap();
    result(&mut service, &append(&writer, 1, 0, None)).unwrap();
    drop(service);
    assert!(Service::new(
        Ledger::open(&root).unwrap(),
        [2; 32],
        service_identity(),
        vec![]
    )
    .is_err());
    assert_eq!(Ledger::open(&root).unwrap().verify().unwrap().commits, 1);
    // A structurally valid bare ledger is not automatically a service partition.
    let vectors: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/evidence-v1/vectors.json")).unwrap();
    let fixture = |name: &str| {
        vectors["positive"]
            .as_array()
            .unwrap()
            .iter()
            .find(|v| v["name"] == name)
            .unwrap()["hex"]
            .as_str()
            .unwrap()
            .to_owned()
    };
    let rawroot = t.path().join("raw");
    let mut ledger = Ledger::create(&rawroot).unwrap();
    ledger.stage(b"synthetic opaque ciphertext\x00").unwrap();
    ledger
        .commit(
            &unhex(&fixture("manifest"), 65536).unwrap(),
            &unhex(&fixture("receipt"), 65536).unwrap(),
        )
        .unwrap();
    assert!(Service::new(ledger, [1; 32], Identity::generate(), vec![]).is_err());
    assert_eq!(Ledger::open(&rawroot).unwrap().verify().unwrap().commits, 1);
}
