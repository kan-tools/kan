#![cfg(feature = "v2-storage")]
use atproto_dasl::{Cid, Ipld};
use kan::{
    evidence::{self, Decoded, Record},
    evidence_attestation::{self as proof, Frontier, Purpose},
    evidence_copy_plan::{Plan, Source, Target},
    evidence_recovery_member::{
        self as member, Availability, Budget, Input, Membership, Object, Row,
    },
    evidence_recovery_observation::Context,
    evidence_service::{self as service, Command, Request, SignedRequest},
    evidence_store::ciphertext_cid,
    sign::Identity,
};
use sha2::{Digest, Sha256};
use std::{
    sync::{atomic::AtomicBool, Arc},
    time::Duration,
};
fn identity(n: u8) -> Identity {
    let f = tempfile::NamedTempFile::new().unwrap();
    let mut s = [0; 32];
    s[31] = n;
    std::fs::write(f.path(), s).unwrap();
    Identity::load_existing(f.path()).unwrap()
}
fn budget() -> Budget {
    Budget {
        items: 100,
        input_bytes: 20 * 1024 * 1024,
        duration: Duration::from_secs(10),
        cancelled: Arc::new(AtomicBool::new(false)),
    }
}
fn map<const N: usize>(a: [(&str, Ipld); N]) -> Ipld {
    Ipld::Map(a.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
}
fn author(did: &str) -> Ipld {
    map([
        ("principal", Ipld::String(did.into())),
        (
            "verificationMethod",
            Ipld::String(format!("{did}#{}", &did[8..])),
        ),
        (
            "identityVersion",
            map([
                ("kind", Ipld::String("static".into())),
                ("value", Ipld::Null),
            ]),
        ),
    ])
}
fn receipt(m: &Record, issuer: &str) -> Record {
    let b = m.body();
    let Decoded::Known(r) = evidence::encode(&map([
        ("v", Ipld::Integer(1)),
        ("kind", Ipld::String("receipt".into())),
        (
            "body",
            map([
                ("issuer", author(issuer)),
                ("manifest", Ipld::Link(m.cid().clone())),
                ("scopeToken", b["scopeToken"].clone()),
                ("operation", b["operation"].clone()),
                ("position", b["position"].clone()),
                ("durability", Ipld::String("remote-durable".into())),
                ("issuedAt", Ipld::Integer(1)),
            ]),
        ),
    ]))
    .unwrap() else {
        panic!()
    };
    r
}
struct Fixture {
    context: Context,
    plan: Option<Vec<u8>>,
    records: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)>,
    objects: Vec<(Cid, Vec<u8>)>,
    membership: Vec<(Cid, u64)>,
}
fn frame(h: &mut Sha256, b: &[u8]) {
    h.update((b.len() as u64).to_be_bytes());
    h.update(b)
}
impl Fixture {
    fn new(profile: u8, n: usize) -> Self {
        let issuer = identity(3);
        let historical = identity(4);
        let writer = identity(5);
        let audience = if profile == 3 {
            historical.did().to_string()
        } else {
            issuer.did().to_string()
        };
        let mut s = Self {
            context: Context {
                bundle: [1; 32],
                profile,
                archive: [2; 32],
                scope: [3; 32],
                issuer: issuer.did().to_string(),
                observer: identity(6).did().to_string(),
            },
            plan: None,
            records: Vec::new(),
            objects: Vec::new(),
            membership: Vec::new(),
        };
        let mut previous = None;
        for i in 0..n {
            let bytes = SignedRequest::sign(
                Request {
                    version: 1,
                    scope: service::hex(&s.context.scope),
                    principal: writer.did().to_string(),
                    audience: audience.clone(),
                    expires: None,
                    command: Command::Append {
                        id: service::hex(&[i as u8 + 1; 16]),
                        position: i as u64,
                        previous: previous.clone(),
                        ciphertext: service::hex(b"synthetic ciphertext"),
                    },
                },
                &writer,
            )
            .unwrap()
            .bytes()
            .unwrap();
            let m = service::append_manifest(&bytes).unwrap();
            let r = receipt(&m, &audience);
            previous = Some(m.cid().to_string());
            s.records
                .push((m.bytes().to_vec(), r.bytes().to_vec(), Vec::new()));
            s.objects.push((ciphertext_cid(&bytes), bytes));
        }
        s.objects.sort_by_key(|o| o.0.to_string());
        if profile == 3 {
            s.membership = s
                .objects
                .iter()
                .map(|(c, b)| (c.clone(), b.len() as u64))
                .collect();
            let mut h = Sha256::new();
            h.update(b"tools.kan.archive.copy-source.v1\0");
            frame(&mut h, b"commits");
            h.update((n as u64).to_be_bytes());
            for (i, (m, r, _)) in s.records.iter().enumerate() {
                let Decoded::Known(rec) = evidence::decode(m).unwrap() else {
                    panic!()
                };
                let Ipld::List(es) = &rec.body()["entries"] else {
                    panic!()
                };
                let Ipld::Map(e) = &es[0] else { panic!() };
                let Ipld::Link(c) = &e["ciphertext"] else {
                    panic!()
                };
                h.update((i as u64 + 1).to_be_bytes());
                frame(&mut h, m);
                frame(&mut h, r);
                frame(&mut h, &c.to_bytes());
            }
            frame(&mut h, b"objects");
            h.update((s.membership.len() as u64).to_be_bytes());
            for (c, n) in &s.membership {
                frame(&mut h, &c.to_bytes());
                h.update(n.to_be_bytes())
            }
            let plan = Plan::new(
                Source {
                    through: n as u64,
                    tip: previous.map(|x| x.parse().unwrap()),
                    digest: h.finalize().into(),
                    historical_issuer: audience,
                },
                Target {
                    scope: s.context.scope,
                    issuer: s.context.issuer.clone(),
                },
                [8; 32],
            )
            .unwrap();
            s.context.archive = plan.archive_id();
            s.plan = Some(plan.bytes().to_vec());
        }
        s.resign();
        s
    }
    fn resign(&mut self) {
        let mut previous = Frontier::default();
        for (i, (m, r, p)) in self.records.iter_mut().enumerate() {
            let Decoded::Known(m) = evidence::decode(m).unwrap() else {
                panic!()
            };
            let Decoded::Known(r) = evidence::decode(r).unwrap() else {
                panic!()
            };
            let v = proof::issue(
                &identity(3),
                &proof::Context {
                    issuer: &self.context.issuer,
                    archive: self.context.archive,
                    scope: self.context.scope,
                },
                &m,
                &r,
                &previous,
                if self.context.profile == 3 {
                    Purpose::RetainedVerified
                } else {
                    Purpose::Admitted
                },
                i as u64,
            )
            .unwrap();
            *p = v.bytes().to_vec();
            previous = v.frontier().clone();
        }
    }
    fn check(&self, b: Budget) -> Result<member::Member, member::Error> {
        let rows: Vec<_> = self
            .records
            .iter()
            .enumerate()
            .map(|(i, (m, r, p))| Row {
                sequence: i as u64 + 1,
                manifest: m,
                receipt: r,
                proof: p,
            })
            .collect();
        let objects: Vec<_> = self
            .objects
            .iter()
            .map(|(cid, bytes)| Object { cid, bytes })
            .collect();
        let membership: Vec<_> = self
            .membership
            .iter()
            .map(|(cid, length)| Membership {
                cid,
                length: *length,
            })
            .collect();
        member::verify(
            Input {
                context: &self.context,
                plan: self.plan.as_deref(),
                membership: &membership,
                records: &rows,
                objects: &objects,
            },
            b,
        )
    }
}
#[test]
fn both_profiles_verify_real_writer_requests_and_empty_members() {
    for profile in [2, 3] {
        for n in [0, 3] {
            let f = Fixture::new(profile, n);
            let m = f.check(budget()).unwrap();
            assert_eq!(m.frontier().through, n as u64);
            assert_eq!(m.verified_requests(), n as u64);
            assert!(m.recipe_metadata_complete());
            assert!(m.losses().is_empty());
            assert_eq!(m.context(), &f.context);
        }
    }
}
#[test]
fn missing_corrupt_empty_and_orphan_bytes_have_exact_distinct_loss_and_commitment() {
    for profile in [2, 3] {
        let mut f = Fixture::new(profile, 3);
        let healthy = *f.check(budget()).unwrap().commitment();
        let lost = f.objects.remove(0).0;
        f.objects[0].1.clear();
        let bad = f.objects[0].0.clone();
        let orphan = ciphertext_cid(b"original orphan");
        f.objects.push((orphan.clone(), b"broken".to_vec()));
        f.objects.sort_by_key(|o| o.0.to_string());
        let m = f.check(budget()).unwrap();
        assert_ne!(m.commitment(), &healthy);
        assert_eq!(m.verified_requests(), 1);
        assert_eq!(m.losses().len(), 3);
        let loss = m.losses();
        assert!(loss[0].occurrence.unwrap() < loss[1].occurrence.unwrap());
        assert!(loss[..2].iter().any(|l| l.cid == lost
            && l.state == Availability::Missing
            && l.expected_length.is_some()));
        assert!(loss[..2]
            .iter()
            .any(|l| l.cid == bad && l.state == Availability::Corrupt));
        assert_eq!(
            loss[2],
            member::Loss {
                occurrence: None,
                cid: orphan,
                expected_length: None,
                state: Availability::Corrupt,
                basis: member::Basis::OriginalObject,
            }
        );
    }
}
#[test]
fn profile3_partial_metadata_does_not_claim_completion_or_accept_extra_objects() {
    let mut f = Fixture::new(3, 3);
    f.records.truncate(1);
    let m = f.check(budget()).unwrap();
    assert!(!m.recipe_metadata_complete());
    let c = ciphertext_cid(b"extra");
    f.objects.push((c, b"extra".to_vec()));
    f.objects.sort_by_key(|o| o.0.to_string());
    assert_eq!(
        f.check(budget()).err(),
        Some(member::Error::Invalid("untracked object in partial copy"))
    );
}
#[test]
fn owner_pins_proofs_missing_membership_and_conflicting_lengths_refuse() {
    let mut f = Fixture::new(2, 1);
    f.context.archive[0] ^= 1;
    assert_eq!(
        f.check(budget()).err(),
        Some(member::Error::Invalid("issuer proof"))
    );
    let mut f = Fixture::new(3, 2);
    f.membership.clear();
    assert_eq!(
        f.check(budget()).err(),
        Some(member::Error::Invalid(
            "retained reference absent from membership"
        ))
    );
    let mut f = Fixture::new(3, 2);
    f.membership[0].1 += 1;
    assert_eq!(
        f.check(budget()).err(),
        Some(member::Error::Invalid("conflicting expected lengths"))
    );
    let mut f = Fixture::new(2, 1);
    f.records[0].2[0] ^= 1;
    assert!(f.check(budget()).is_err());
}
#[test]
fn bounded_acquisition_order_and_cancellation_refuse() {
    let f = Fixture::new(2, 3);
    let mut b = budget();
    b.items = 2;
    assert_eq!(f.check(b).err(), Some(member::Error::Budget));
    let mut b = budget();
    b.input_bytes = 10;
    assert_eq!(f.check(b).err(), Some(member::Error::Budget));
    let b = budget();
    b.cancelled
        .store(true, std::sync::atomic::Ordering::Relaxed);
    assert_eq!(f.check(b).err(), Some(member::Error::Cancelled));
    let mut f = f;
    f.objects.reverse();
    assert_eq!(
        f.check(budget()).err(),
        Some(member::Error::Invalid("CID order or duplicate"))
    );
}
#[test]
fn issuer_resigning_cannot_hide_invalid_writer_chain() {
    let mut f = Fixture::new(2, 2);
    let Decoded::Known(m) = evidence::decode(&f.records[1].0).unwrap() else {
        panic!()
    };
    let mut b = m.body().clone();
    b.insert(
        "previous".into(),
        Ipld::Link(ciphertext_cid(b"wrong codec")),
    );
    assert!(evidence::encode(&map([
        ("v", Ipld::Integer(1)),
        ("kind", Ipld::String("manifest".into())),
        ("body", Ipld::Map(b.clone()))
    ]))
    .is_err());
    b.insert("previous".into(), Ipld::Null);
    b.insert("position".into(), Ipld::Integer(0));
    let Decoded::Known(m) = evidence::encode(&map([
        ("v", Ipld::Integer(1)),
        ("kind", Ipld::String("manifest".into())),
        ("body", Ipld::Map(b)),
    ]))
    .unwrap() else {
        panic!()
    };
    f.records[1].0 = m.bytes().to_vec();
    f.records[1].1 = receipt(&m, &f.context.issuer).bytes().to_vec();
    f.resign();
    assert_eq!(
        f.check(budget()).err(),
        Some(member::Error::Invalid("writer predecessor"))
    );
}

fn replace_manifest(
    f: &mut Fixture,
    index: usize,
    mutate: impl FnOnce(&mut std::collections::BTreeMap<String, Ipld>),
) {
    let Decoded::Known(m) = evidence::decode(&f.records[index].0).unwrap() else {
        panic!()
    };
    let mut b = m.body().clone();
    mutate(&mut b);
    let Decoded::Known(m) = evidence::encode(&map([
        ("v", Ipld::Integer(1)),
        ("kind", Ipld::String("manifest".into())),
        ("body", Ipld::Map(b)),
    ]))
    .unwrap() else {
        panic!()
    };
    f.records[index].0 = m.bytes().to_vec();
    f.records[index].1 = receipt(&m, &f.context.issuer).bytes().to_vec();
    f.resign();
}
#[test]
fn hash_valid_but_unsigned_bytes_are_not_treated_as_recoverable_loss() {
    let mut f = Fixture::new(2, 1);
    let bytes = b"not a signed request".to_vec();
    let cid = ciphertext_cid(&bytes);
    replace_manifest(&mut f, 0, |b| {
        let Ipld::List(es) = b.get_mut("entries").unwrap() else {
            panic!()
        };
        let Ipld::Map(e) = &mut es[0] else { panic!() };
        e.insert("ciphertext".into(), Ipld::Link(cid.clone()));
        e.insert("length".into(), Ipld::Integer(bytes.len() as i128));
    });
    f.objects = vec![(cid, bytes)];
    assert_eq!(
        f.check(budget()).err(),
        Some(member::Error::Invalid("retained writer request"))
    );
    f.objects.clear();
    let m = f.check(budget()).unwrap();
    assert_eq!(m.verified_requests(), 0);
    assert_eq!(m.losses()[0].state, Availability::Missing);
}
#[test]
fn shared_missing_service_request_cid_refuses_before_restoration() {
    let mut f = Fixture::new(2, 2);
    let Decoded::Known(first) = evidence::decode(&f.records[0].0).unwrap() else {
        panic!()
    };
    let Ipld::List(es) = &first.body()["entries"] else {
        panic!()
    };
    let Ipld::Map(e) = &es[0] else { panic!() };
    let c = e["ciphertext"].clone();
    let len = e["length"].clone();
    replace_manifest(&mut f, 1, |b| {
        let Ipld::List(es) = b.get_mut("entries").unwrap() else {
            panic!()
        };
        let Ipld::Map(e) = &mut es[0] else { panic!() };
        e.insert("ciphertext".into(), c);
        e.insert("length".into(), len);
    });
    f.objects.clear();
    assert_eq!(
        f.check(budget()).err(),
        Some(member::Error::Invalid("reused service request CID"))
    );
}
#[test]
fn expected_oversized_length_refuses_without_a_physical_object() {
    let mut f = Fixture::new(2, 1);
    replace_manifest(&mut f, 0, |b| {
        let Ipld::List(es) = b.get_mut("entries").unwrap() else {
            panic!()
        };
        let Ipld::Map(e) = &mut es[0] else { panic!() };
        e.insert("length".into(), Ipld::Integer(4 * 1024 * 1024 + 1));
    });
    f.objects.clear();
    assert_eq!(
        f.check(budget()).err(),
        Some(member::Error::Invalid("forensic-recovery-required"))
    );
}
#[test]
fn copy_plan_cannot_relabel_a_different_complete_source_digest() {
    let mut f = Fixture::new(3, 2);
    let p = Plan::decode(f.plan.as_ref().unwrap()).unwrap();
    let mut source = p.source().clone();
    source.digest[0] ^= 1;
    let p = Plan::new(source, p.target().clone(), *p.nonce()).unwrap();
    f.context.archive = p.archive_id();
    f.plan = Some(p.bytes().to_vec());
    f.resign();
    assert_eq!(
        f.check(budget()).err(),
        Some(member::Error::Invalid("source metadata digest"))
    );
}

#[test]
fn independently_constructed_python_members_match_commitments_losses_and_refusals() {
    let vectors: serde_json::Value =
        serde_json::from_str(include_str!("../.design/fixtures/recovery-member-v1.json")).unwrap();
    let raw = |v: &serde_json::Value| service::unhex(v.as_str().unwrap(), 4 * 1024 * 1024).unwrap();
    for case in vectors["cases"].as_array().unwrap() {
        let c = &case["context"];
        let f = Fixture {
            context: Context {
                bundle: raw(&c["bundle"]).try_into().unwrap(),
                profile: c["profile"].as_u64().unwrap() as u8,
                archive: raw(&c["archive"]).try_into().unwrap(),
                scope: raw(&c["scope"]).try_into().unwrap(),
                issuer: c["issuer"].as_str().unwrap().into(),
                observer: c["observer"].as_str().unwrap().into(),
            },
            plan: (!case["plan"].is_null()).then(|| raw(&case["plan"])),
            records: case["records"]
                .as_array()
                .unwrap()
                .iter()
                .map(|r| (raw(&r[1]), raw(&r[2]), raw(&r[3])))
                .collect(),
            objects: case["objects"]
                .as_array()
                .unwrap()
                .iter()
                .map(|o| (o[0].as_str().unwrap().parse().unwrap(), raw(&o[1])))
                .collect(),
            membership: case["membership"]
                .as_array()
                .unwrap()
                .iter()
                .map(|m| {
                    (
                        m[0].as_str().unwrap().parse().unwrap(),
                        m[1].as_u64().unwrap(),
                    )
                })
                .collect(),
        };
        // Preserve explicit external row coordinates, including the hostile reorder.
        let rows: Vec<_> = case["records"]
            .as_array()
            .unwrap()
            .iter()
            .zip(&f.records)
            .map(|(r, (m, receipt, p))| Row {
                sequence: r[0].as_u64().unwrap(),
                manifest: m,
                receipt,
                proof: p,
            })
            .collect();
        let objects: Vec<_> = f
            .objects
            .iter()
            .map(|(cid, bytes)| Object { cid, bytes })
            .collect();
        let membership: Vec<_> = f
            .membership
            .iter()
            .map(|(cid, n)| Membership { cid, length: *n })
            .collect();
        let result = member::verify(
            Input {
                context: &f.context,
                plan: f.plan.as_deref(),
                records: &rows,
                objects: &objects,
                membership: &membership,
            },
            budget(),
        );
        if let Some(reason) = case.get("error") {
            let error = result.err().expect("hostile member must refuse");
            let member::Error::Invalid(actual) = error else {
                panic!("wrong refusal: {error}")
            };
            assert_eq!(actual, reason.as_str().unwrap(), "{}", case["name"]);
            continue;
        }
        let result = result.unwrap_or_else(|e| panic!("{}: {e}", case["name"]));
        let expected = &case["expected"];
        assert_eq!(
            service::hex(result.commitment()),
            expected["member"],
            "{}",
            case["name"]
        );
        assert_eq!(
            result.frontier().through,
            expected["through"].as_u64().unwrap()
        );
        assert_eq!(
            result.verified_requests(),
            expected["verifiedRequests"].as_u64().unwrap()
        );
        assert_eq!(
            result.recipe_metadata_complete(),
            expected["recipeMetadataComplete"].as_bool().unwrap()
        );
        let losses:Vec<_>=result.losses().iter().map(|l|serde_json::json!({"occurrence":l.occurrence,"cid":l.cid.to_string(),"expectedLength":l.expected_length,"basis":format!("{:?}",l.basis),"state":match l.state {Availability::Missing=>"missing",Availability::Corrupt=>"corrupt",Availability::Available=>panic!("loss cannot be available")}})).collect();
        assert_eq!(
            serde_json::json!(losses),
            expected["losses"],
            "{}",
            case["name"]
        );
    }
}

#[test]
fn shared_cid_lengths_and_duplicate_operations_refuse_even_when_all_bytes_missing() {
    // In a partial copy the source digest cannot mask a missing length check.
    let mut partial = Fixture::new(3, 2);
    partial.records.truncate(1);
    let Decoded::Known(first) = evidence::decode(&partial.records[0].0).unwrap() else {
        panic!()
    };
    let Ipld::List(entries) = &first.body()["entries"] else {
        panic!()
    };
    let Ipld::Map(entry) = &entries[0] else {
        panic!()
    };
    let Ipld::Link(cid) = &entry["ciphertext"] else {
        panic!()
    };
    partial
        .membership
        .iter_mut()
        .find(|(c, _)| c == cid)
        .unwrap()
        .1 += 1;
    partial.objects.clear();
    assert_eq!(
        partial.check(budget()).err(),
        Some(member::Error::Invalid("conflicting expected lengths"))
    );
    let mut f = Fixture::new(2, 2);
    let Decoded::Known(first) = evidence::decode(&f.records[0].0).unwrap() else {
        panic!()
    };
    let op = first.body()["operation"].clone();
    let entries = first.body()["entries"].clone();
    replace_manifest(&mut f, 1, |b| {
        b.insert("operation".into(), op);
        b.insert("entries".into(), entries);
    });
    f.objects.clear();
    assert_eq!(
        f.check(budget()).err(),
        Some(member::Error::Invalid("duplicate operation"))
    );
    let mut f = Fixture::new(2, 2);
    let Decoded::Known(first) = evidence::decode(&f.records[0].0).unwrap() else {
        panic!()
    };
    let Ipld::List(es) = &first.body()["entries"] else {
        panic!()
    };
    let Ipld::Map(first) = &es[0] else { panic!() };
    let cid = first["ciphertext"].clone();
    let Ipld::Integer(len) = first["length"] else {
        panic!()
    };
    replace_manifest(&mut f, 1, |b| {
        let Ipld::List(es) = b.get_mut("entries").unwrap() else {
            panic!()
        };
        let Ipld::Map(e) = &mut es[0] else { panic!() };
        e.insert("ciphertext".into(), cid);
        e.insert("length".into(), Ipld::Integer(len + 1));
    });
    f.objects.clear();
    assert_eq!(
        f.check(budget()).err(),
        Some(member::Error::Invalid("conflicting expected lengths"))
    );
}
#[test]
fn complete_copy_accepts_new_admitted_suffix_without_rewriting_original_recipe() {
    let mut f = Fixture::new(3, 2);
    let prefix = f.check(budget()).unwrap();
    let writer = identity(5);
    let issuer = identity(3);
    let bytes = SignedRequest::sign(
        Request {
            version: 1,
            scope: service::hex(&f.context.scope),
            audience: f.context.issuer.clone(),
            principal: writer.did().to_string(),
            expires: None,
            command: Command::Append {
                id: service::hex(&[9; 16]),
                position: 2,
                previous: prefix.frontier().manifest.as_ref().map(ToString::to_string),
                ciphertext: service::hex(b"new capture"),
            },
        },
        &writer,
    )
    .unwrap()
    .bytes()
    .unwrap();
    let m = service::append_manifest(&bytes).unwrap();
    let r = receipt(&m, &f.context.issuer);
    let p = proof::issue(
        &issuer,
        &proof::Context {
            issuer: &f.context.issuer,
            archive: f.context.archive,
            scope: f.context.scope,
        },
        &m,
        &r,
        prefix.frontier(),
        Purpose::Admitted,
        5,
    )
    .unwrap();
    f.records
        .push((m.bytes().to_vec(), r.bytes().to_vec(), p.bytes().to_vec()));
    f.objects.push((ciphertext_cid(&bytes), bytes));
    f.objects.sort_by_key(|o| o.0.to_string());
    let member = f.check(budget()).unwrap();
    assert_eq!(member.verified_requests(), 3);
    assert!(member.recipe_metadata_complete());
    assert!(member.losses().is_empty());
}

#[test]
fn time_and_physical_object_bounds_refuse() {
    let f = Fixture::new(2, 3);
    let mut b = budget();
    b.duration = Duration::from_nanos(1);
    assert_eq!(f.check(b).err(), Some(member::Error::Budget));
    let mut f = Fixture::new(2, 0);
    f.objects
        .push((ciphertext_cid(b"key"), vec![7; 4 * 1024 * 1024 + 1]));
    assert_eq!(
        f.check(budget()).err(),
        Some(member::Error::Invalid("forensic-recovery-required"))
    );
}

#[test]
fn issuer_resigning_does_not_make_wrong_service_slot_valid_when_payload_is_missing() {
    let mut f = Fixture::new(2, 1);
    replace_manifest(&mut f, 0, |b| {
        let Ipld::List(es) = b.get_mut("entries").unwrap() else {
            panic!()
        };
        let Ipld::Map(e) = &mut es[0] else { panic!() };
        e.insert("slot".into(), Ipld::Bytes(vec![0; 32]));
    });
    f.objects.clear();
    assert_eq!(
        f.check(budget()).err(),
        Some(member::Error::Invalid("service slot"))
    );
}

#[test]
fn valid_json_with_bad_writer_signature_and_resigned_manifest_substitution_refuse() {
    let mut f = Fixture::new(2, 1);
    let mut request: SignedRequest = serde_json::from_slice(&f.objects[0].1).unwrap();
    let mut signature = service::unhex(&request.signature, 64).unwrap();
    signature[7] ^= 1;
    request.signature = service::hex(&signature);
    let bytes = request.bytes().unwrap();
    let cid = ciphertext_cid(&bytes);
    replace_manifest(&mut f, 0, |b| {
        let Ipld::List(es) = b.get_mut("entries").unwrap() else {
            panic!()
        };
        let Ipld::Map(e) = &mut es[0] else { panic!() };
        e.insert("ciphertext".into(), Ipld::Link(cid.clone()));
        e.insert("length".into(), Ipld::Integer(bytes.len() as i128));
    });
    f.objects = vec![(cid, bytes)];
    assert_eq!(
        f.check(budget()).err(),
        Some(member::Error::Invalid("retained writer request"))
    );
    let mut f = Fixture::new(2, 1);
    replace_manifest(&mut f, 0, |b| {
        b.insert("writer".into(), author(&identity(8).did().to_string()));
    });
    assert_eq!(
        f.check(budget()).err(),
        Some(member::Error::Invalid("retained writer request"))
    );
}
