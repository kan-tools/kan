use super::*;
use kan::evidence_proof_service as wire;

fn binding(f: &Fixture) -> wire::Binding {
    wire::Binding {
        profile: match f.profile {
            Profile::Admitted => wire::Profile::Admitted,
            Profile::Copied => wire::Profile::Copied,
        },
        archive: service::hex(&f.binding.archive),
        scope: service::hex(&f.binding.scope),
        issuer: f.binding.issuer.clone(),
    }
}
fn reader(f: &Fixture) -> wire::Service {
    wire::Service::new(f.db(), binding(f), identity(8), vec![grant()], budget()).unwrap()
}
fn signed(f: &Fixture, command: wire::Command) -> wire::SignedRequest {
    wire::SignedRequest::sign(
        wire::Request {
            version: 2,
            binding: binding(f),
            principal: identity(6).did().to_string(),
            expires: 1600,
            command,
        },
        &identity(6),
    )
    .unwrap()
}
fn call(f: &Fixture, r: &wire::Service, command: wire::Command) -> wire::Output {
    let bytes = signed(f, command).bytes().unwrap();
    let reply = r.dispatch(&bytes, 1500).unwrap();
    let reply =
        wire::SignedReply::decode(&reply.bytes().unwrap(), &bytes, &f.binding.issuer).unwrap();
    reply.reply.result.unwrap()
}
fn snapshot(f: &Fixture, r: &wire::Service) -> wire::Coordinate {
    let wire::Output::Snapshot {
        frontier,
        plan,
        recipe_metadata_match,
    } = call(f, r, wire::Command::Snapshot)
    else {
        panic!("snapshot shape")
    };
    if f.profile == Profile::Copied {
        let plan = kan::evidence_copy_plan::Plan::decode(
            &service::unhex(plan.as_ref().unwrap(), 4096).unwrap(),
        )
        .unwrap();
        assert_eq!(plan.archive_id(), f.binding.archive);
        assert_eq!(plan.source().historical_issuer, identity(7).did().as_str());
        assert_eq!(recipe_metadata_match, Some(true));
    } else {
        assert!(plan.is_none());
        assert!(recipe_metadata_match.is_none());
    }
    frontier
}
fn verify_rows(
    f: &Fixture,
    start: &wire::Coordinate,
    rows: &[wire::RecordView],
) -> kan::evidence_attestation::Frontier {
    let mut expected = start.frontier(&binding(f)).unwrap();
    for row in rows {
        assert_eq!(row.sequence, expected.through.to_string());
        let decode = |s: &str| {
            let kan::evidence::Decoded::Known(r) =
                kan::evidence::decode(&service::unhex(s, kan::evidence::MAX_RECORD_BYTES).unwrap())
                    .unwrap()
            else {
                panic!("known metadata")
            };
            r
        };
        let proof = kan::evidence_attestation::verify_at(
            &service::unhex(&row.proof, kan::evidence_attestation::MAX_ENVELOPE_BYTES).unwrap(),
            &kan::evidence_attestation::Context {
                issuer: &f.binding.issuer,
                archive: f.binding.archive,
                scope: f.binding.scope,
            },
            &decode(&row.manifest),
            &decode(&row.receipt),
            &expected,
        )
        .unwrap();
        expected = proof.previous().clone();
    }
    expected
}

#[test]
fn proof_wire_capabilities_and_exact_descending_pages_cover_both_profiles() {
    for profile in [Profile::Admitted, Profile::Copied] {
        let dir = tempfile::tempdir().unwrap();
        let f = fixture(dir.path(), profile);
        let r = reader(&f);
        let wire::Output::Capabilities {
            protocol,
            operations,
        } = call(&f, &r, wire::Command::Capabilities)
        else {
            panic!("capabilities")
        };
        assert_eq!(protocol, wire::PROTOCOL);
        assert_eq!(operations, ["capabilities", "snapshot", "page", "read"]);
        let pin = snapshot(&f, &r);
        let wire::Output::Page { records, next } = call(
            &f,
            &r,
            wire::Command::Page {
                pin: pin.clone(),
                next: pin.clone(),
                limit: 2,
            },
        ) else {
            panic!("page")
        };
        assert_eq!(records.len(), 2);
        assert!(records
            .iter()
            .all(|r| r.availability == wire::Availability::Available));
        let expected = verify_rows(&f, &pin, &records);
        assert_eq!(
            next.as_ref().unwrap().frontier(&binding(&f)).unwrap(),
            expected
        );
        let wire::Output::Page { records, next } = call(
            &f,
            &r,
            wire::Command::Page {
                pin,
                next: next.clone().unwrap(),
                limit: 2,
            },
        ) else {
            panic!("page")
        };
        assert_eq!(records.len(), 1);
        assert_eq!(
            verify_rows(&f, &wire::Coordinate::from_frontier(&expected), &records).through,
            0
        );
        assert!(next.is_none());
    }
}

#[test]
fn proof_wire_source_samples_loss_freshly_and_preserves_historical_writer() {
    for profile in [Profile::Admitted, Profile::Copied] {
        let dir = tempfile::tempdir().unwrap();
        let f = fixture(dir.path(), profile);
        let r = reader(&f);
        let pin = snapshot(&f, &r);
        let command = wire::Command::Read {
            pin: pin.clone(),
            selected: pin.clone(),
        };
        let wire::Output::Evidence {
            record,
            source:
                wire::Source::Available {
                    signed_request,
                    writer,
                },
        } = call(&f, &r, command.clone())
        else {
            panic!("available")
        };
        assert_eq!(writer, identity(6).did().as_str());
        assert_eq!(
            service::unhex(&signed_request, service::MAX_REQUEST).unwrap(),
            f.requests[2]
        );
        assert_eq!(record.availability, wire::Availability::Available);
        verify_rows(&f, &pin, &[record]);
        f.remove(2);
        let wire::Output::Evidence {
            record,
            source: wire::Source::Missing,
        } = call(&f, &r, command.clone())
        else {
            panic!("fresh missing")
        };
        assert_eq!(record.availability, wire::Availability::Missing);
        drop(r);
        let restarted = reader(&f);
        let wire::Output::Page { records, .. } = call(
            &f,
            &restarted,
            wire::Command::Page {
                pin: pin.clone(),
                next: pin.clone(),
                limit: 3,
            },
        ) else {
            panic!("lost tip stays browsable")
        };
        assert_eq!(records[0].availability, wire::Availability::Missing);
        assert_eq!(records[1].availability, wire::Availability::Available);
        f.edit(&format!(
            "UPDATE objects SET bytes=x'00' WHERE cid='{}'",
            f.id(1)
        ));
        let selected = wire::Coordinate::from_frontier(&verify_rows(&f, &pin, &records[..1]));
        let wire::Output::Evidence {
            record,
            source: wire::Source::Corrupt,
        } = call(&f, &restarted, wire::Command::Read { pin, selected })
        else {
            panic!("fresh corrupt")
        };
        assert_eq!(record.availability, wire::Availability::Corrupt);
    }
}

#[test]
fn proof_wire_denies_current_grants_expiry_and_foreign_binding_before_metadata() {
    let dir = tempfile::tempdir().unwrap();
    let f = fixture(dir.path(), Profile::Admitted);
    let mut r = reader(&f);
    let bytes = signed(&f, wire::Command::Snapshot).bytes().unwrap();
    r.replace_grants(vec![]).unwrap();
    f.edit("UPDATE attestations SET envelope=x'00' WHERE sequence=3");
    assert!(matches!(
        r.dispatch(&bytes, 1500).unwrap().reply.result,
        Err(service::Failure::AccessLimited)
    ));
    r.replace_grants(vec![grant()]).unwrap();
    for now in [1200, 1601] {
        assert!(matches!(
            r.dispatch(&bytes, now).unwrap().reply.result,
            Err(service::Failure::AccessLimited)
        ));
    }
    let mut req = signed(&f, wire::Command::Snapshot).request;
    req.binding.archive = service::hex(&[99; 32]);
    let foreign = wire::SignedRequest::sign(req, &identity(6))
        .unwrap()
        .bytes()
        .unwrap();
    assert!(matches!(
        r.dispatch(&foreign, 1500).unwrap().reply.result,
        Err(service::Failure::AccessLimited)
    ));
    let mut denied = grant();
    denied.inventory = false;
    denied.append = true;
    r.replace_grants(vec![denied]).unwrap();
    assert!(matches!(
        r.dispatch(&bytes, 1500).unwrap().reply.result,
        Err(service::Failure::AccessLimited)
    ));
    r.replace_grants(vec![grant()]).unwrap();
    assert!(matches!(
        r.dispatch(&bytes, 1500).unwrap().reply.result,
        Err(service::Failure::Corrupt)
    ));
}

#[test]
fn proof_wire_signatures_canonical_shapes_and_request_binding_are_enforced() {
    let dir = tempfile::tempdir().unwrap();
    let f = fixture(dir.path(), Profile::Admitted);
    let r = reader(&f);
    let signed = signed(&f, wire::Command::Snapshot);
    let bytes = signed.bytes().unwrap();
    assert!(wire::SignedRequest::decode(&bytes).is_ok());
    let mut padded = bytes.clone();
    padded.push(b' ');
    assert!(wire::SignedRequest::decode(&padded).is_err());
    let mut altered = signed.clone();
    altered.request.expires += 1;
    assert!(wire::SignedRequest::decode(&altered.bytes().unwrap()).is_err());
    let mut altered = signed.clone();
    altered.signature = "00".repeat(64);
    assert!(wire::SignedRequest::decode(&altered.bytes().unwrap()).is_err());
    let mut invalid = signed.request.clone();
    invalid.version = 1;
    assert!(wire::SignedRequest::sign(invalid, &identity(6)).is_err());
    assert!(wire::SignedRequest::sign(signed.request.clone(), &identity(7)).is_err());
    assert!(r.dispatch(&vec![0; wire::MAX_REQUEST + 1], 1500).is_err());
    let reply = r.dispatch(&bytes, 1500).unwrap();
    let encoded = reply.bytes().unwrap();
    assert!(wire::SignedReply::decode(&encoded, &bytes, &f.binding.issuer).is_ok());
    assert!(wire::SignedReply::decode(&encoded, b"another request", &f.binding.issuer).is_err());
    assert!(wire::SignedReply::decode(&encoded, &bytes, identity(7).did().as_str()).is_err());
    let mut altered = reply.clone();
    altered.reply.result = Err(service::Failure::Missing);
    assert!(altered.verify(&bytes, &f.binding.issuer).is_err());
    let mut padded = encoded;
    padded.push(b' ');
    assert!(wire::SignedReply::decode(&padded, &bytes, &f.binding.issuer).is_err());
}

#[test]
fn proof_wire_coordinates_are_canonical_and_cannot_escape_the_selected_pin() {
    let dir = tempfile::tempdir().unwrap();
    let f = fixture(dir.path(), Profile::Admitted);
    let r = reader(&f);
    let pin = snapshot(&f, &r);
    for text in [
        "",
        "03",
        "+3",
        " 3",
        "3 ",
        "3.0",
        "3e0",
        "-1",
        "9007199254740992",
    ] {
        let mut altered = pin.clone();
        altered.through = text.into();
        assert!(altered.frontier(&binding(&f)).is_err(), "{text:?}");
    }
    let mut altered = pin.clone();
    altered.through = "0".into();
    assert!(altered.frontier(&binding(&f)).is_err());
    let wire::Output::Page { records, .. } = call(
        &f,
        &r,
        wire::Command::Page {
            pin: pin.clone(),
            next: pin.clone(),
            limit: 1,
        },
    ) else {
        panic!("page")
    };
    let old = wire::Coordinate::from_frontier(&verify_rows(&f, &pin, &records));
    let req = wire::Request {
        command: wire::Command::Page {
            pin: old,
            next: pin.clone(),
            limit: 1,
        },
        ..signed(&f, wire::Command::Snapshot).request
    };
    assert!(wire::SignedRequest::sign(req, &identity(6)).is_err());
    let mut fork = pin.clone();
    fork.attestation = Some(
        kan::cid::content_cid(&atproto_dasl::Ipld::String("fork".into()))
            .unwrap()
            .to_string(),
    );
    let bytes = signed(
        &f,
        wire::Command::Page {
            pin: fork.clone(),
            next: fork,
            limit: 1,
        },
    )
    .bytes()
    .unwrap();
    assert!(matches!(
        r.dispatch(&bytes, 1500).unwrap().reply.result,
        Err(service::Failure::Corrupt)
    ));
}

#[test]
fn proof_wire_old_pin_excludes_new_capture_and_rejects_corrupt_current_metadata() {
    for profile in [Profile::Admitted, Profile::Copied] {
        let dir = tempfile::tempdir().unwrap();
        let f = fixture(dir.path(), profile);
        let r = reader(&f);
        let pin = snapshot(&f, &r);
        let bytes = request(3, 8, pin.manifest.clone());
        match profile {
            Profile::Admitted => {
                attested::Archive::open(&f.root, f.binding.clone())
                    .unwrap()
                    .admit(&bytes, &identity(8), &grant(), 2000)
                    .unwrap();
            }
            Profile::Copied => {
                copied::Archive::open(&f.root, f.binding.clone())
                    .unwrap()
                    .admit(&bytes, &identity(8), &grant(), 2000)
                    .unwrap();
            }
        }
        assert_eq!(snapshot(&f, &r).through, "4");
        let command = wire::Command::Page {
            pin: pin.clone(),
            next: pin,
            limit: 40,
        };
        let wire::Output::Page { records, next } = call(&f, &r, command.clone()) else {
            panic!("old page")
        };
        assert_eq!(
            records
                .iter()
                .map(|r| r.sequence.as_str())
                .collect::<Vec<_>>(),
            ["3", "2", "1"]
        );
        assert!(next.is_none());
        f.edit("UPDATE attestations SET envelope=x'00' WHERE sequence=4");
        assert!(matches!(
            r.dispatch(&signed(&f, command).bytes().unwrap(), 1500)
                .unwrap()
                .reply
                .result,
            Err(service::Failure::Corrupt)
        ));
    }
}

#[test]
fn proof_wire_owner_configuration_and_work_limits_fail_closed() {
    let dir = tempfile::tempdir().unwrap();
    let f = fixture(dir.path(), Profile::Admitted);
    assert!(wire::Service::new(f.db(), binding(&f), identity(7), vec![grant()], budget()).is_err());
    assert!(wire::Service::new(
        f.db(),
        binding(&f),
        identity(8),
        vec![grant(), grant()],
        budget()
    )
    .is_err());
    let mut limited = budget();
    limited.items = 1;
    assert!(wire::Service::new(f.db(), binding(&f), identity(8), vec![grant()], limited).is_err());
    let r = reader(&f);
    let pin = snapshot(&f, &r);
    for limit in [0, wire::PAGE_LIMIT + 1] {
        let req = wire::Request {
            command: wire::Command::Page {
                pin: pin.clone(),
                next: pin.clone(),
                limit,
            },
            ..signed(&f, wire::Command::Snapshot).request
        };
        assert!(wire::SignedRequest::sign(req, &identity(6)).is_err());
    }
}
