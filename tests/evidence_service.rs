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
    let Decoded::Known(receipt) = evidence::decode(&unhex(&first.receipt, 65536).unwrap()).unwrap()
    else {
        panic!()
    };
    assert_eq!(
        receipt.body()["issuedAt"],
        atproto_dasl::Ipld::Integer(1_000_000)
    );
    drop(service);
    let mut service = Service::new(
        Ledger::open(&root).unwrap(),
        [1; 32],
        service_identity(),
        vec![grant(&writer, true, true)],
    )
    .unwrap();
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
    let db = rusqlite::Connection::open(t.path().join("backup.sqlite")).unwrap();
    let mut statement = db.prepare("SELECT bytes FROM objects").unwrap();
    let rows = statement.query_map([], |r| r.get::<_, Vec<u8>>(0)).unwrap();
    let mut verified = 0;
    for row in rows {
        std::fs::write(&oracle_input, row.unwrap()).unwrap();
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
        verified += 1;
    }
    assert!(verified >= 2);
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

#[test]
fn competing_service_scopes_cannot_mix_or_disclose_records() {
    let t = tempfile::tempdir().unwrap();
    let root = t.path().join("archive");
    let writer = Identity::generate();
    let mut first = Service::new(
        Ledger::create(&root).unwrap(),
        [1; 32],
        service_identity(),
        vec![grant(&writer, true, true)],
    )
    .unwrap();
    let mut second = Service::new(
        Ledger::open(&root).unwrap(),
        [2; 32],
        service_identity(),
        vec![grant(&writer, true, true)],
    )
    .unwrap();
    result(&mut first, &append(&writer, 1, 0, None)).unwrap();
    let second_append = request(
        &writer,
        2,
        Command::Append {
            id: hex(&[2; 16]),
            position: 0,
            previous: None,
            ciphertext: hex(b"opaque"),
        },
        None,
    );
    assert_eq!(result(&mut second, &second_append), Err(Failure::Corrupt));
    assert_eq!(
        result(
            &mut second,
            &request(&writer, 2, Command::Snapshot, Some(1100))
        ),
        Err(Failure::Corrupt)
    );
    let Output::Snapshot { through, tip } = result(
        &mut first,
        &request(&writer, 1, Command::Snapshot, Some(1100)),
    )
    .unwrap() else {
        panic!()
    };
    assert_eq!(
        result(
            &mut second,
            &request(
                &writer,
                2,
                Command::Page {
                    through,
                    tip,
                    after: 0,
                    limit: 128
                },
                Some(1100)
            )
        ),
        Err(Failure::Corrupt)
    );
    assert_eq!(Ledger::open(&root).unwrap().verify().unwrap().commits, 1);
}

#[test]
fn high_s_signature_cannot_change_retry_identity() {
    // P-256 group order minus low S gives the alternative valid ECDSA signature.
    let writer = Identity::generate();
    let mut signed = SignedRequest::decode(&append(&writer, 1, 0, None)).unwrap();
    let mut sig = unhex(&signed.signature, 64).unwrap();
    let order = unhex(
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
        32,
    )
    .unwrap();
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let value = i16::from(order[i]) - i16::from(sig[32 + i]) - borrow;
        sig[32 + i] = value as u8;
        borrow = i16::from(value < 0);
    }
    signed.signature = hex(&sig);
    assert!(matches!(
        SignedRequest::decode(&signed.bytes().unwrap()),
        Err(Failure::AccessLimited)
    ));
}

#[test]
fn retained_signature_and_receipt_issuer_are_verified_independently_of_structure() {
    use atproto_dasl::Ipld;
    use sha2::{Digest, Sha256};
    fn record(kind: &str, body: std::collections::BTreeMap<String, Ipld>) -> evidence::Record {
        let envelope = Ipld::Map(
            [
                ("v".into(), Ipld::Integer(1)),
                ("kind".into(), Ipld::String(kind.into())),
                ("body".into(), Ipld::Map(body)),
            ]
            .into(),
        );
        let Decoded::Known(record) = evidence::encode(&envelope).unwrap() else {
            panic!()
        };
        record
    }
    let t = tempfile::tempdir().unwrap();
    let writer = Identity::generate();
    let original = append(&writer, 1, 0, None);
    let mut service = Service::new(
        Ledger::create(&t.path().join("valid")).unwrap(),
        [1; 32],
        service_identity(),
        vec![grant(&writer, true, true)],
    )
    .unwrap();
    let Output::Committed { record: view, .. } = result(&mut service, &original).unwrap() else {
        panic!()
    };
    let Decoded::Known(manifest) =
        evidence::decode(&unhex(&view.manifest, 65536).unwrap()).unwrap()
    else {
        panic!()
    };
    let Decoded::Known(receipt) = evidence::decode(&unhex(&view.receipt, 65536).unwrap()).unwrap()
    else {
        panic!()
    };
    for flaw in ["signature", "issuer", "manifest"] {
        let root = t.path().join(flaw);
        let mut bytes = original.clone();
        let mut mb = manifest.body().clone();
        let mut rb = receipt.body().clone();
        if flaw == "signature" {
            let mut signed: SignedRequest = serde_json::from_slice(&bytes).unwrap();
            signed.signature = hex(&[0; 64]);
            bytes = signed.bytes().unwrap();
            let Ipld::List(entries) = mb.get_mut("entries").unwrap() else {
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
        } else if flaw == "issuer" {
            rb.insert("issuer".into(), mb["writer"].clone());
        } else {
            let Ipld::List(entries) = mb.get_mut("entries").unwrap() else {
                panic!()
            };
            let Ipld::Map(entry) = &mut entries[0] else {
                panic!()
            };
            entry.insert("slot".into(), Ipld::Bytes(vec![99; 32]));
        }
        let manifest = record("manifest", mb);
        rb.insert("manifest".into(), Ipld::Link(manifest.cid().clone()));
        let receipt = record("receipt", rb);
        let mut ledger = Ledger::create(&root).unwrap();
        ledger.stage(&bytes).unwrap();
        ledger.commit(manifest.bytes(), receipt.bytes()).unwrap();
        assert_eq!(ledger.verify().unwrap().commits, 1);
        let before = t.path().join(format!("{flaw}-before.sqlite"));
        ledger.backup(&before).unwrap();
        assert!(matches!(
            Service::new(ledger, [1; 32], service_identity(), vec![]),
            Err(Failure::Corrupt)
        ));
        let after = t.path().join(format!("{flaw}-after.sqlite"));
        Ledger::open(&root).unwrap().backup(&after).unwrap();
        assert_eq!(
            Sha256::digest(std::fs::read(before).unwrap()),
            Sha256::digest(std::fs::read(after).unwrap())
        );
    }
}

// A valid raw-ledger record with the service's scope but no signed request.
fn append_foreign_format(ledger: &mut Ledger) {
    use atproto_dasl::Ipld;
    let vectors: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/evidence-v1/vectors.json")).unwrap();
    let decode = |name: &str| -> Ipld {
        let item = vectors["positive"]
            .as_array()
            .unwrap()
            .iter()
            .find(|v| v["name"] == name)
            .unwrap();
        atproto_dasl::from_reader(&unhex(item["hex"].as_str().unwrap(), 65536).unwrap()[..])
            .unwrap()
    };
    let encode = |value: &Ipld| {
        let Decoded::Known(record) = evidence::encode(value).unwrap() else {
            panic!()
        };
        record
    };
    let mut m = decode("manifest");
    let Ipld::Map(root) = &mut m else { panic!() };
    let Ipld::Map(body) = root.get_mut("body").unwrap() else {
        panic!()
    };
    body.insert("scopeToken".into(), Ipld::Bytes(vec![1; 32]));
    let manifest = encode(&m);
    let mut r = decode("receipt");
    let Ipld::Map(root) = &mut r else { panic!() };
    let Ipld::Map(body) = root.get_mut("body").unwrap() else {
        panic!()
    };
    body.insert("scopeToken".into(), Ipld::Bytes(vec![1; 32]));
    body.insert("manifest".into(), Ipld::Link(manifest.cid().clone()));
    ledger.stage(b"synthetic opaque ciphertext\x00").unwrap();
    ledger.commit(manifest.bytes(), encode(&r).bytes()).unwrap();
}

#[test]
fn invalid_raw_suffix_cannot_hide_behind_valid_tip_or_exact_retry() {
    let t = tempfile::tempdir().unwrap();
    let root = t.path().join("archive");
    let writer = Identity::generate();
    let mut service = Service::new(
        Ledger::create(&root).unwrap(),
        [1; 32],
        service_identity(),
        vec![grant(&writer, true, true)],
    )
    .unwrap();
    let first = append(&writer, 1, 0, None);
    let Output::Committed {
        record: first_record,
        ..
    } = result(&mut service, &first).unwrap()
    else {
        panic!()
    };
    let mut raw = Ledger::open(&root).unwrap();
    append_foreign_format(&mut raw);

    // Produce an authentic service record independently, then append it through
    // the raw API after the invalid record. A tip-only audit would accept this.
    let other = Identity::generate();
    let trailing = append(&other, 2, 0, None);
    let mut producer = Service::new(
        Ledger::create(&t.path().join("producer")).unwrap(),
        [1; 32],
        service_identity(),
        vec![grant(&other, true, false)],
    )
    .unwrap();
    let Output::Committed { record, .. } = result(&mut producer, &trailing).unwrap() else {
        panic!()
    };
    raw.stage(&trailing).unwrap();
    raw.commit(
        &unhex(&record.manifest, 65536).unwrap(),
        &unhex(&record.receipt, 65536).unwrap(),
    )
    .unwrap();
    let snapshot = raw.snapshot().unwrap();
    assert_eq!(snapshot.through, 3);
    let retained = || {
        raw.page(&snapshot, 0, 128)
            .unwrap()
            .iter()
            .map(|r| (r.manifest.bytes().to_vec(), r.receipt.bytes().to_vec()))
            .collect::<Vec<_>>()
    };
    let before = retained();
    for command in [
        Command::Snapshot,
        Command::Read { sequence: 3 },
        Command::Page {
            through: 3,
            tip: snapshot.tip.as_ref().map(ToString::to_string),
            after: 2,
            limit: 1,
        },
    ] {
        assert_eq!(
            result(&mut service, &request(&writer, 1, command, Some(1100))),
            Err(Failure::Corrupt)
        );
    }
    assert_eq!(result(&mut service, &first), Err(Failure::Corrupt));
    assert_eq!(
        result(
            &mut service,
            &append(&writer, 9, 1, Some(cid(&first_record.manifest)))
        ),
        Err(Failure::Corrupt)
    );
    assert_eq!(
        result(
            &mut service,
            &request(&other, 1, Command::Snapshot, Some(1100))
        ),
        Err(Failure::AccessLimited)
    );
    assert_eq!(retained(), before);
    assert_eq!(raw.verify().unwrap().commits, 3);
    assert!(matches!(
        Service::new(raw, [1; 32], service_identity(), vec![]),
        Err(Failure::Corrupt)
    ));
}

#[test]
fn multiple_instances_audit_paginated_suffixes_and_preserve_retries() {
    let t = tempfile::tempdir().unwrap();
    let writer = Identity::generate();
    let reader = Identity::generate();
    let root = t.path().join("archive");
    let mut first = Service::new(
        Ledger::create(&root).unwrap(),
        [1; 32],
        service_identity(),
        vec![grant(&writer, true, true)],
    )
    .unwrap();
    // This instance has no grant for the historical writer. History remains valid.
    let mut second = Service::new(
        Ledger::open(&root).unwrap(),
        [1; 32],
        service_identity(),
        vec![grant(&reader, true, true)],
    )
    .unwrap();
    let mut previous = None;
    let mut original = None;
    for i in 0..130u8 {
        let bytes = append(&writer, i, u64::from(i), previous);
        let Output::Committed {
            record,
            duplicate: false,
        } = result(&mut first, &bytes).unwrap()
        else {
            panic!()
        };
        previous = Some(cid(&record.manifest));
        if i == 0 {
            original = Some((bytes, record));
        }
    }
    assert_eq!(
        result(
            &mut second,
            &request(&reader, 1, Command::Snapshot, Some(1100))
        )
        .unwrap(),
        Output::Snapshot {
            through: 130,
            tip: previous
        }
    );
    result(&mut second, &append(&reader, 200, 0, None)).unwrap();
    let (bytes, expected) = original.unwrap();
    assert_eq!(
        result(&mut first, &bytes).unwrap(),
        Output::Committed {
            record: expected,
            duplicate: true
        }
    );
    let output = result(
        &mut first,
        &request(&writer, 1, Command::Snapshot, Some(1100)),
    )
    .unwrap();
    assert!(matches!(output, Output::Snapshot { through: 131, .. }));
    assert_eq!(Ledger::open(&root).unwrap().verify().unwrap().commits, 131);
}

#[test]
fn missing_committed_object_is_corrupt_on_read_and_startup() {
    let t = tempfile::tempdir().unwrap();
    let root = t.path().join("archive");
    let writer = Identity::generate();
    let mut service = Service::new(
        Ledger::create(&root).unwrap(),
        [1; 32],
        service_identity(),
        vec![grant(&writer, true, true)],
    )
    .unwrap();
    result(&mut service, &append(&writer, 1, 0, None)).unwrap();
    // Open before owner corruption so Service::new itself must detect the
    // missing reference rather than relying on Ledger::open verification.
    let existing = Ledger::open(&root).unwrap();
    let db = rusqlite::Connection::open(root.join("archive.sqlite")).unwrap();
    db.execute_batch("PRAGMA foreign_keys=OFF; DELETE FROM objects;")
        .unwrap();
    assert_eq!(
        result(
            &mut service,
            &request(&writer, 1, Command::Read { sequence: 1 }, Some(1100))
        ),
        Err(Failure::Corrupt)
    );
    assert_eq!(
        result(
            &mut service,
            &request(&writer, 1, Command::Snapshot, Some(1100))
        ),
        Err(Failure::Corrupt)
    );
    assert!(matches!(
        Service::new(existing, [1; 32], service_identity(), vec![]),
        Err(Failure::Corrupt)
    ));
}

#[test]
fn audit_pin_guards_detect_retreat_replacement_and_sequence_holes() {
    // Defense-in-depth against fixture owner-SQL damage; this does not claim
    // detection of arbitrary rewrites elsewhere in an already audited prefix.
    for damage in ["gap", "prior-pin", "retreat", "same-height"] {
        let t = tempfile::tempdir().unwrap();
        let root = t.path().join("archive");
        let writer = Identity::generate();
        let grants = vec![grant(&writer, true, true)];
        let mut service = Service::new(
            Ledger::create(&root).unwrap(),
            [1; 32],
            service_identity(),
            grants.clone(),
        )
        .unwrap();
        let Output::Committed { record: first, .. } =
            result(&mut service, &append(&writer, 1, 0, None)).unwrap()
        else {
            panic!()
        };
        let mut peer = Service::new(
            Ledger::open(&root).unwrap(),
            [1; 32],
            service_identity(),
            grants,
        )
        .unwrap();
        result(
            &mut peer,
            &append(&writer, 2, 1, Some(cid(&first.manifest))),
        )
        .unwrap();
        let db = rusqlite::Connection::open(root.join("archive.sqlite")).unwrap();
        db.execute_batch("PRAGMA foreign_keys=OFF;").unwrap();
        match damage {
            "gap" => {
                db.execute("UPDATE commits SET sequence=3 WHERE sequence=2", [])
                    .unwrap();
            }
            "prior-pin" | "same-height" => {
                if damage == "same-height" {
                    db.execute("DELETE FROM commits WHERE sequence=2", [])
                        .unwrap();
                }
                db.execute(
                    "UPDATE commits SET cid=? WHERE sequence=1",
                    [cid(&first.receipt)],
                )
                .unwrap();
            }
            "retreat" => {
                db.execute("DELETE FROM commits", []).unwrap();
            }
            _ => unreachable!(),
        }
        assert_eq!(
            result(
                &mut service,
                &request(&writer, 1, Command::Snapshot, Some(1100))
            ),
            Err(Failure::Corrupt),
            "{damage}"
        );
    }
}
