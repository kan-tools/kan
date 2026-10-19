#![cfg(feature = "v2-storage")]
//! Promoted deterministic Opus probes from frozen 5e54513; original files retained
//! in .design/reviews/kan-v2-recovery-member-opus/evidence/probes/.
//! RP02/03/14 expectations now pin the explicitly corrected contracts; Loss
//! assertions also pin the added basis. Timing probes remain raw review evidence.
use atproto_dasl::{Cid, Ipld};
use kan::{
    evidence::{self, Decoded, Record},
    evidence_attestation::{self as proof, Frontier, Purpose},
    evidence_copy_plan::{Plan, Source, Target},
    evidence_recovery_member::{
        self as member, Availability, Basis, Budget, Input, Loss, Membership, Object, Row,
    },
    evidence_recovery_observation::Context,
    evidence_service::{self as service, Command, Request, SignedRequest},
    evidence_store::ciphertext_cid,
    sign::Identity,
};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

fn identity(n: u8) -> Identity {
    let f = tempfile::NamedTempFile::new().unwrap();
    let mut s = [0; 32];
    s[31] = n;
    std::fs::write(f.path(), s).unwrap();
    Identity::load_existing(f.path()).unwrap()
}
fn did(n: u8) -> String {
    identity(n).did().to_string()
}
fn budget() -> Budget {
    Budget {
        items: 1000,
        input_bytes: 512 * 1024 * 1024,
        duration: Duration::from_secs(600),
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
fn record(kind: &str, body: Ipld) -> Result<Record, String> {
    match evidence::encode(&map([
        ("v", Ipld::Integer(1)),
        ("kind", Ipld::String(kind.into())),
        ("body", body),
    ])) {
        Ok(Decoded::Known(r)) => Ok(r),
        Ok(_) => Err("not known".into()),
        Err(e) => Err(e.to_string()),
    }
}
fn receipt(m: &Record, issuer: &str) -> Record {
    let b = m.body();
    record(
        "receipt",
        map([
            ("issuer", author(issuer)),
            ("manifest", Ipld::Link(m.cid().clone())),
            ("scopeToken", b["scopeToken"].clone()),
            ("operation", b["operation"].clone()),
            ("position", b["position"].clone()),
            ("durability", Ipld::String("remote-durable".into())),
            ("issuedAt", Ipld::Integer(1)),
        ]),
    )
    .unwrap()
}
fn decode(bytes: &[u8]) -> Record {
    let Decoded::Known(r) = evidence::decode(bytes).unwrap() else {
        panic!()
    };
    r
}
fn entry_cid(manifest: &[u8]) -> (Cid, u64) {
    let m = decode(manifest);
    let Ipld::List(es) = &m.body()["entries"] else {
        panic!()
    };
    let Ipld::Map(e) = &es[0] else { panic!() };
    let Ipld::Link(c) = &e["ciphertext"] else {
        panic!()
    };
    let Ipld::Integer(n) = e["length"] else {
        panic!()
    };
    (c.clone(), n as u64)
}
fn frame(h: &mut Sha256, b: &[u8]) {
    h.update((b.len() as u64).to_be_bytes());
    h.update(b)
}

#[derive(Clone)]
struct F {
    context: Context,
    plan: Option<Vec<u8>>,
    records: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)>,
    requests: Vec<Vec<u8>>,
    objects: Vec<(Cid, Vec<u8>)>,
    membership: Vec<(Cid, u64)>,
}
struct Opts {
    profile: u8,
    n: usize,
    /// Profile 3: requests/receipts addressed to the CURRENT issuer instead of historical.
    current_receipts: bool,
    /// Extra staged membership keys (bytes), included in the source digest.
    staged: Vec<Vec<u8>>,
    /// Override plan tip with this record index's manifest CID.
    tip_index: Option<usize>,
    target_scope: Option<[u8; 32]>,
    target_issuer: Option<String>,
}
impl Default for Opts {
    fn default() -> Self {
        Opts {
            profile: 2,
            n: 2,
            current_receipts: false,
            staged: vec![],
            tip_index: None,
            target_scope: None,
            target_issuer: None,
        }
    }
}
fn source_digest(
    records: &[(Vec<u8>, Vec<u8>, Vec<u8>)],
    through: u64,
    members: &[(Cid, u64)],
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"tools.kan.archive.copy-source.v1\0");
    frame(&mut h, b"commits");
    h.update(through.to_be_bytes());
    for (i, (m, r, _)) in records.iter().enumerate().take(through as usize) {
        let (c, _) = entry_cid(m);
        h.update((i as u64 + 1).to_be_bytes());
        frame(&mut h, m);
        frame(&mut h, r);
        frame(&mut h, &c.to_bytes());
    }
    frame(&mut h, b"objects");
    h.update((members.len() as u64).to_be_bytes());
    for (c, n) in members {
        frame(&mut h, &c.to_bytes());
        h.update(n.to_be_bytes())
    }
    h.finalize().into()
}
fn sign_request(
    writer: &Identity,
    scope: &[u8; 32],
    audience: &str,
    id: [u8; 16],
    position: u64,
    previous: Option<String>,
    payload: &[u8],
) -> Vec<u8> {
    SignedRequest::sign(
        Request {
            version: 1,
            scope: service::hex(scope),
            principal: writer.did().to_string(),
            audience: audience.into(),
            expires: None,
            command: Command::Append {
                id: service::hex(&id),
                position,
                previous,
                ciphertext: service::hex(payload),
            },
        },
        writer,
    )
    .unwrap()
    .bytes()
    .unwrap()
}
fn build(o: Opts) -> F {
    let issuer = did(3);
    let historical = did(4);
    let writer = identity(5);
    let audience = if o.profile == 3 && !o.current_receipts {
        historical.clone()
    } else {
        issuer.clone()
    };
    let scope = [3u8; 32];
    let mut f = F {
        context: Context {
            bundle: [1; 32],
            profile: o.profile,
            archive: [2; 32],
            scope,
            issuer: issuer.clone(),
            observer: did(6),
        },
        plan: None,
        records: vec![],
        requests: vec![],
        objects: vec![],
        membership: vec![],
    };
    let mut previous: Option<String> = None;
    for i in 0..o.n {
        let bytes = sign_request(
            &writer,
            &scope,
            &audience,
            [0x40 + i as u8; 16],
            i as u64,
            previous.clone(),
            format!("reviewer payload {i}").as_bytes(),
        );
        let m = service::append_manifest(&bytes).unwrap();
        let r = receipt(&m, &audience);
        previous = Some(m.cid().to_string());
        f.records
            .push((m.bytes().to_vec(), r.bytes().to_vec(), vec![]));
        f.objects.push((ciphertext_cid(&bytes), bytes.clone()));
        f.requests.push(bytes);
    }
    for s in &o.staged {
        f.objects.push((ciphertext_cid(s), s.clone()));
    }
    f.objects.sort_by_key(|x| x.0.to_string());
    if o.profile == 3 {
        f.membership = f
            .objects
            .iter()
            .map(|(c, b)| (c.clone(), b.len() as u64))
            .collect();
        let tip = match o.tip_index {
            Some(i) => Some(decode(&f.records[i].0).cid().clone()),
            None => previous.map(|x| x.parse().unwrap()),
        };
        let plan = Plan::new(
            Source {
                through: o.n as u64,
                tip,
                digest: source_digest(&f.records, o.n as u64, &f.membership),
                historical_issuer: historical,
            },
            Target {
                scope: o.target_scope.unwrap_or(scope),
                issuer: o.target_issuer.unwrap_or(issuer),
            },
            [8; 32],
        )
        .unwrap();
        f.context.archive = plan.archive_id();
        f.plan = Some(plan.bytes().to_vec());
    }
    let profile = o.profile;
    resign(&mut f, |_| {
        if profile == 3 {
            Purpose::RetainedVerified
        } else {
            Purpose::Admitted
        }
    });
    f
}
fn resign(f: &mut F, purpose: impl Fn(usize) -> Purpose) {
    let mut previous = Frontier::default();
    let ctx = f.context.clone();
    for (i, (m, r, p)) in f.records.iter_mut().enumerate() {
        let v = proof::issue(
            &identity(3),
            &proof::Context {
                issuer: &ctx.issuer,
                archive: ctx.archive,
                scope: ctx.scope,
            },
            &decode(m),
            &decode(r),
            &previous,
            purpose(i),
            i as u64,
        )
        .unwrap();
        *p = v.bytes().to_vec();
        previous = v.frontier().clone();
    }
}
fn replace_manifest(
    f: &mut F,
    index: usize,
    issuer: &str,
    mutate: impl FnOnce(&mut BTreeMap<String, Ipld>),
) -> Result<(), String> {
    let mut b = decode(&f.records[index].0).body().clone();
    mutate(&mut b);
    let m = record("manifest", Ipld::Map(b))?;
    f.records[index].0 = m.bytes().to_vec();
    f.records[index].1 = receipt(&m, issuer).bytes().to_vec();
    Ok(())
}
fn run(f: &F, b: Budget) -> Result<member::Member, member::Error> {
    let rows: Vec<_> = f
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
    let objects: Vec<_> = f
        .objects
        .iter()
        .map(|(cid, bytes)| Object { cid, bytes })
        .collect();
    let membership: Vec<_> = f
        .membership
        .iter()
        .map(|(cid, length)| Membership {
            cid,
            length: *length,
        })
        .collect();
    member::verify(
        Input {
            context: &f.context,
            plan: f.plan.as_deref(),
            membership: &membership,
            records: &rows,
            objects: &objects,
        },
        b,
    )
}
fn show(name: &str, r: &Result<member::Member, member::Error>) {
    match r {
        Ok(m) => eprintln!(
            "RP {name}: ACCEPT through={} verified={} complete={} losses={:?}",
            m.frontier().through,
            m.verified_requests(),
            m.recipe_metadata_complete(),
            m.losses()
        ),
        Err(e) => eprintln!("RP {name}: REFUSE {e:?}"),
    }
}
fn invalid(r: &Result<member::Member, member::Error>) -> Option<&'static str> {
    match r {
        Err(member::Error::Invalid(s)) => Some(s),
        _ => None,
    }
}

/// Complete-copy staged membership losses retain authenticated length and basis.
#[test]
fn rp01_staged_membership_key_null_coordinate() {
    let staged = b"reviewer staged object".to_vec();
    let sc = ciphertext_cid(&staged);
    let base = build(Opts {
        profile: 3,
        n: 2,
        staged: vec![staged.clone()],
        ..Default::default()
    });
    let r = run(&base, budget());
    show("rp01-intact", &r);
    let m = r.unwrap();
    assert!(m.recipe_metadata_complete());
    assert!(m.losses().is_empty());
    assert_eq!(m.verified_requests(), 2);

    let mut f = base.clone();
    f.objects.retain(|o| o.0 != sc);
    let r = run(&f, budget());
    show("rp01-staged-missing", &r);
    assert_eq!(
        r.unwrap().losses(),
        &[Loss {
            occurrence: None,
            cid: sc.clone(),
            expected_length: Some(staged.len() as u64),
            state: Availability::Missing,
            basis: Basis::VerifiedCopyRecipe
        }]
    );

    let mut f = base.clone();
    for o in &mut f.objects {
        if o.0 == sc {
            o.1 = b"tampered".to_vec();
        }
    }
    let r = run(&f, budget());
    show("rp01-staged-corrupt", &r);
    assert_eq!(
        r.unwrap().losses(),
        &[Loss {
            occurrence: None,
            cid: sc.clone(),
            expected_length: Some(staged.len() as u64),
            state: Availability::Corrupt,
            basis: Basis::VerifiedCopyRecipe
        }]
    );

    // Combined ordering: occurrence losses first by sequence, then null coordinates.
    let mut f = base.clone();
    let (c2, n2) = entry_cid(&f.records[1].0);
    let (c1, n1) = entry_cid(&f.records[0].0);
    f.objects.retain(|o| o.0 != sc && o.0 != c2);
    for o in &mut f.objects {
        if o.0 == c1 {
            o.1.clear();
        }
    }
    let r = run(&f, budget());
    show("rp01-combined-order", &r);
    assert_eq!(
        r.unwrap().losses(),
        &[
            Loss {
                occurrence: Some(1),
                cid: c1,
                expected_length: Some(n1),
                state: Availability::Corrupt,
                basis: Basis::IssuerMetadata
            },
            Loss {
                occurrence: Some(2),
                cid: c2,
                expected_length: Some(n2),
                state: Availability::Missing,
                basis: Basis::IssuerMetadata
            },
            Loss {
                occurrence: None,
                cid: sc,
                expected_length: Some(staged.len() as u64),
                state: Availability::Missing,
                basis: Basis::VerifiedCopyRecipe
            },
        ]
    );
}

/// Incomplete-copy membership claims remain explicitly unverified and carry no authenticated length.
#[test]
fn rp02_partial_profile3_membership_is_labeled_unverified() {
    let staged = b"reviewer staged object".to_vec();
    let full = build(Opts {
        profile: 3,
        n: 3,
        staged: vec![staged.clone()],
        ..Default::default()
    });
    let fabricated = ciphertext_cid(b"never in the source");
    let add_fabricated = |f: &mut F| {
        f.membership.push((fabricated.clone(), 77));
        f.membership.sort_by_key(|m| m.0.to_string());
    };
    // Complete copy: fabricated membership is caught by the plan's source digest.
    let mut f = full.clone();
    add_fabricated(&mut f);
    let r = run(&f, budget());
    show("rp02-complete-fabricated", &r);
    assert_eq!(invalid(&r), Some("source metadata digest"));
    // Partial copy (1 of 3 records): fabricated key accepted and reported as a loss.
    let mut partial = full.clone();
    partial.records.truncate(1);
    let r = run(&partial, budget());
    show("rp02-partial-honest", &r);
    let honest = r.unwrap();
    assert!(!honest.recipe_metadata_complete());
    assert!(honest.losses().is_empty());
    let mut f = partial.clone();
    add_fabricated(&mut f);
    let r = run(&f, budget());
    show("rp02-partial-fabricated", &r);
    let m = r.unwrap();
    assert!(!m.recipe_metadata_complete());
    assert_eq!(
        m.losses(),
        &[Loss {
            occurrence: None,
            cid: fabricated.clone(),
            expected_length: None,
            state: Availability::Missing,
            basis: Basis::UnverifiedMembership
        }]
    );
    // Removing an unreferenced row is undetectable while the source recipe is incomplete.
    let sc = ciphertext_cid(&staged);
    let mut f = partial.clone();
    f.membership.retain(|m| m.0 != sc);
    f.objects.retain(|o| o.0 != sc);
    let r = run(&f, budget());
    show("rp02-partial-drop-staged", &r);
    assert!(r.unwrap().losses().is_empty());
    // An unauthenticated length must not reclassify hash-valid bytes as corrupt.
    let mut f = partial.clone();
    for m in &mut f.membership {
        if m.0 == sc {
            m.1 += 1;
        }
    }
    let r = run(&f, budget());
    show("rp02-partial-relength-staged", &r);
    assert!(r.unwrap().losses().is_empty());
}

/// Distinct service occurrences cannot share a request CID, with or without bytes.
#[test]
fn rp03_shared_request_cid_refuses_with_or_without_bytes() {
    let mut f = build(Opts {
        profile: 2,
        n: 2,
        ..Default::default()
    });
    let (c, n) = entry_cid(&f.records[0].0);
    let issuer = f.context.issuer.clone();
    replace_manifest(&mut f, 1, &issuer, |b| {
        let Ipld::List(es) = b.get_mut("entries").unwrap() else {
            panic!()
        };
        let Ipld::Map(e) = &mut es[0] else { panic!() };
        e.insert("ciphertext".into(), Ipld::Link(c.clone()));
        e.insert("length".into(), Ipld::Integer(n as i128));
    })
    .unwrap();
    resign(&mut f, |_| Purpose::Admitted);
    let genuine = f.requests[0].clone();
    f.objects.clear();
    let r = run(&f, budget());
    show("rp03-shared-missing", &r);
    assert_eq!(invalid(&r), Some("reused service request CID"));
    f.objects = vec![(c.clone(), genuine)];
    let r = run(&f, budget());
    show("rp03-shared-restored-genuine-bytes", &r);
    assert_eq!(invalid(&r), Some("reused service request CID"));
}

/// Retained receipts must use the plan historical issuer.
#[test]
fn rp04_retained_receipts_from_wrong_issuer_refuse() {
    let f = build(Opts {
        profile: 3,
        n: 2,
        current_receipts: true,
        ..Default::default()
    });
    let r = run(&f, budget());
    show("rp04-current-issuer-receipts", &r);
    assert_eq!(invalid(&r), Some("historical receipt issuer"));
    let mut g = f.clone();
    g.objects.clear();
    let r = run(&g, budget());
    show("rp04-current-issuer-receipts-bytes-missing", &r);
    assert_eq!(invalid(&r), Some("historical receipt issuer"));
}

/// The verified recipe must also match the declared source tip.
#[test]
fn rp05_source_tip_mismatch_refuses() {
    let f = build(Opts {
        profile: 3,
        n: 3,
        tip_index: Some(0),
        ..Default::default()
    });
    let r = run(&f, budget());
    show("rp05-wrong-tip", &r);
    assert_eq!(invalid(&r), Some("source tip"));
}

/// The plan target scope and issuer must match independent owner pins.
#[test]
fn rp06_plan_target_scope_and_issuer_binding() {
    let f = build(Opts {
        profile: 3,
        n: 1,
        target_scope: Some([9; 32]),
        ..Default::default()
    });
    let r = run(&f, budget());
    show("rp06-target-scope", &r);
    assert_eq!(invalid(&r), Some("plan binding"));
    let f = build(Opts {
        profile: 3,
        n: 1,
        target_issuer: Some(did(7)),
        ..Default::default()
    });
    let r = run(&f, budget());
    show("rp06-target-issuer", &r);
    assert_eq!(invalid(&r), Some("plan binding"));
}

/// Issuer-proof purpose must match the retained/admitted range.
#[test]
fn rp07_proof_purpose_per_range() {
    let mut f = build(Opts {
        profile: 3,
        n: 2,
        current_receipts: true,
        ..Default::default()
    });
    resign(&mut f, |_| Purpose::Admitted);
    let r = run(&f, budget());
    show("rp07-admitted-in-retained-range", &r);
    assert_eq!(invalid(&r), Some("proof purpose"));
    let mut f = build(Opts {
        profile: 3,
        n: 2,
        current_receipts: true,
        ..Default::default()
    });
    resign(&mut f, |i| {
        if i == 0 {
            Purpose::RetainedVerified
        } else {
            Purpose::Admitted
        }
    });
    let r = run(&f, budget());
    show("rp07-mixed-in-retained-range", &r);
    // Row 1 is retained-verified over current-issuer receipts, so the historical-issuer
    // rule may fire first; diagnostic precedence is explicitly not a contract.
    assert!(matches!(
        invalid(&r),
        Some("proof purpose") | Some("historical receipt issuer")
    ));
}

/// Membership ordering, CID codec and profile/plan presence must be valid.
#[test]
fn rp08_membership_order_duplicates_and_codec() {
    let base = build(Opts {
        profile: 3,
        n: 3,
        ..Default::default()
    });
    let mut f = base.clone();
    f.membership.reverse();
    let r = run(&f, budget());
    show("rp08-membership-reversed", &r);
    assert_eq!(invalid(&r), Some("CID order or duplicate"));
    let mut f = base.clone();
    let d = f.membership[0].clone();
    f.membership.insert(0, d);
    let r = run(&f, budget());
    show("rp08-membership-duplicate", &r);
    assert_eq!(invalid(&r), Some("CID order or duplicate"));
    let mut f = base.clone();
    let cbor = decode(&f.records[0].0).cid().clone();
    f.membership.insert(0, (cbor, 10));
    let r = run(&f, budget());
    show("rp08-membership-dagcbor-cid", &r);
    assert_eq!(invalid(&r), Some("raw CID"));
    // Profile shape mismatches.
    let mut f = build(Opts {
        profile: 2,
        n: 1,
        ..Default::default()
    });
    f.membership = vec![(ciphertext_cid(b"x"), 1)];
    let r = run(&f, budget());
    show("rp08-profile2-membership", &r);
    assert!(r.is_err());
    let mut f = build(Opts {
        profile: 3,
        n: 1,
        ..Default::default()
    });
    f.plan = None;
    let r = run(&f, budget());
    show("rp08-profile3-no-plan", &r);
    assert_eq!(invalid(&r), Some("profile plan"));
}

/// Unsupported writer identity forms refuse even without payload bytes.
#[test]
fn rp09_non_static_writer_refuses_without_bytes() {
    let writer = did(5);
    let variants: Vec<(&str, Ipld)> = vec![
        (
            "event-version",
            map([
                ("principal", Ipld::String(writer.clone())),
                (
                    "verificationMethod",
                    Ipld::String(format!("{writer}#{}", &writer[8..])),
                ),
                (
                    "identityVersion",
                    map([
                        ("kind", Ipld::String("event".into())),
                        ("value", Ipld::Link(ciphertext_cid(b"e"))),
                    ]),
                ),
            ]),
        ),
        (
            "versionid",
            map([
                ("principal", Ipld::String(writer.clone())),
                (
                    "verificationMethod",
                    Ipld::String(format!("{writer}#{}", &writer[8..])),
                ),
                (
                    "identityVersion",
                    map([
                        ("kind", Ipld::String("versionId".into())),
                        ("value", Ipld::String("v1".into())),
                    ]),
                ),
            ]),
        ),
        (
            "other-fragment",
            map([
                ("principal", Ipld::String(writer.clone())),
                (
                    "verificationMethod",
                    Ipld::String(format!("{writer}#key-1")),
                ),
                (
                    "identityVersion",
                    map([
                        ("kind", Ipld::String("static".into())),
                        ("value", Ipld::Null),
                    ]),
                ),
            ]),
        ),
        (
            "did-web-documentcid",
            map([
                ("principal", Ipld::String("did:web:example.com".into())),
                (
                    "verificationMethod",
                    Ipld::String("did:web:example.com#key-1".into()),
                ),
                (
                    "identityVersion",
                    map([
                        ("kind", Ipld::String("documentCid".into())),
                        ("value", Ipld::Link(ciphertext_cid(b"doc"))),
                    ]),
                ),
            ]),
        ),
        (
            "did-web-static",
            map([
                ("principal", Ipld::String("did:web:example.com".into())),
                (
                    "verificationMethod",
                    Ipld::String("did:web:example.com#key-1".into()),
                ),
                (
                    "identityVersion",
                    map([
                        ("kind", Ipld::String("static".into())),
                        ("value", Ipld::Null),
                    ]),
                ),
            ]),
        ),
        (
            "did-plc-versionid",
            map([
                (
                    "principal",
                    Ipld::String("did:plc:ewvi7nxzyoun6zhxrhs64oiz".into()),
                ),
                (
                    "verificationMethod",
                    Ipld::String("did:plc:ewvi7nxzyoun6zhxrhs64oiz#atproto".into()),
                ),
                (
                    "identityVersion",
                    map([
                        ("kind", Ipld::String("versionId".into())),
                        ("value", Ipld::String("bafyreib".into())),
                    ]),
                ),
            ]),
        ),
    ];
    let mut reached = 0;
    for (name, w) in variants {
        let mut f = build(Opts {
            profile: 2,
            n: 1,
            ..Default::default()
        });
        let issuer = f.context.issuer.clone();
        if let Err(e) = replace_manifest(&mut f, 0, &issuer, |b| {
            b.insert("writer".into(), w);
        }) {
            eprintln!("RP rp09-{name}: schema-refused {e}");
            continue;
        }
        resign(&mut f, |_| Purpose::Admitted);
        f.objects.clear();
        let r = run(&f, budget());
        show(&format!("rp09-{name}"), &r);
        assert!(
            matches!(invalid(&r), Some("static writer") | Some("writer")),
            "{name}"
        );
        reached += 1;
    }
    assert!(reached > 0, "no non-static variant passed record schema");
}

/// Pre-cancellation prevents later semantic work on a broken proof.
#[test]
fn rp10a_precancelled_refuses_before_semantic_work() {
    let mut f = build(Opts {
        profile: 2,
        n: 2,
        ..Default::default()
    });
    f.records[1].2[10] ^= 1;
    let b = budget();
    b.cancelled.store(true, Ordering::Relaxed);
    let r = run(&f, b);
    show("rp10a-precancelled-with-later-fault", &r);
    assert_eq!(r.err(), Some(member::Error::Cancelled));
}

/// Input count and byte budgets include their exact acceptance edge.
#[test]
fn rp11_caps_before_work() {
    let mut f = build(Opts {
        profile: 2,
        n: 0,
        ..Default::default()
    });
    let bytes = vec![1u8; 4 * 1024 * 1024];
    f.objects.push((ciphertext_cid(&bytes), bytes));
    let mut b = budget();
    b.items = 0;
    let r = run(&f, b);
    show("rp11-items-0", &r);
    assert_eq!(r.err(), Some(member::Error::Budget));
    let mut b = budget();
    b.input_bytes = 4 * 1024 * 1024 - 1;
    let r = run(&f, b);
    show("rp11-input-below-object", &r);
    assert_eq!(r.err(), Some(member::Error::Budget));
    let mut b = budget();
    b.input_bytes = 4 * 1024 * 1024;
    let r = run(&f, b);
    show("rp11-input-exact-object", &r);
    assert!(r.is_ok());
}

/// Owner pins remain independent of the signed member.
#[test]
fn rp12_cross_scope_issuer_and_observer() {
    let mut f = build(Opts {
        profile: 2,
        n: 1,
        ..Default::default()
    });
    f.context.scope = [9; 32];
    let r = run(&f, budget());
    show("rp12-wrong-owner-scope", &r);
    assert_eq!(invalid(&r), Some("issuer proof"));
    let mut f = build(Opts {
        profile: 2,
        n: 1,
        ..Default::default()
    });
    f.context.issuer = did(7);
    let r = run(&f, budget());
    show("rp12-wrong-owner-issuer", &r);
    assert_eq!(invalid(&r), Some("issuer proof"));
    let mut f = build(Opts {
        profile: 2,
        n: 1,
        ..Default::default()
    });
    f.context.observer = f.context.observer.to_uppercase();
    let r = run(&f, budget());
    show("rp12-noncanonical-observer", &r);
    assert!(r.is_err());
    // Same-key observer/issuer is wire-valid by recorded decision.
    let mut f = build(Opts {
        profile: 2,
        n: 1,
        ..Default::default()
    });
    f.context.observer = f.context.issuer.clone();
    let r = run(&f, budget());
    show("rp12-same-key-observer", &r);
    assert!(r.is_ok());
}

/// Typed CIDs cannot preserve a noncanonical physical spelling.
#[test]
fn rp13_noncanonical_spelling_is_invisible_to_typed_api() {
    let c = ciphertext_cid(b"spelling");
    let canonical = c.to_string();
    let upper = canonical.to_uppercase();
    let parsed: Result<Cid, _> = upper.parse();
    match parsed {
        Ok(p) => {
            eprintln!(
                "RP rp13: uppercase spelling parses; to_string()==canonical: {}",
                p.to_string() == canonical
            );
            assert_eq!(p, c);
        }
        Err(e) => eprintln!("RP rp13: uppercase spelling refused by Cid parser: {e}"),
    }
}

/// Authentic bytes with false metadata refuse; empty request CIDs are impossible.
#[test]
fn rp14_hash_valid_bytes_with_false_signed_length() {
    let mut f = build(Opts {
        profile: 2,
        n: 1,
        ..Default::default()
    });
    let (c, n) = entry_cid(&f.records[0].0);
    let issuer = f.context.issuer.clone();
    replace_manifest(&mut f, 0, &issuer, |b| {
        let Ipld::List(es) = b.get_mut("entries").unwrap() else {
            panic!()
        };
        let Ipld::Map(e) = &mut es[0] else { panic!() };
        e.insert("length".into(), Ipld::Integer(n as i128 + 1));
    })
    .unwrap();
    resign(&mut f, |_| Purpose::Admitted);
    // f.objects still holds the GENUINE request bytes, whose raw CID is exactly `c`.
    assert_eq!(ciphertext_cid(&f.objects[0].1), c);
    let r = run(&f, budget());
    show("rp14a-genuine-bytes-false-length", &r);
    assert_eq!(
        invalid(&r),
        Some("hash-valid bytes contradict authenticated length")
    );
    // Same request, honest length, bytes present: verifies (control for the fixture).
    let g = build(Opts {
        profile: 2,
        n: 1,
        ..Default::default()
    });
    let r = run(&g, budget());
    show("rp14a-control-honest-length", &r);
    assert_eq!(r.unwrap().verified_requests(), 1);

    // Empty-bytes CID referenced with signed length 1; the empty object is present.
    let mut f = build(Opts {
        profile: 2,
        n: 1,
        ..Default::default()
    });
    let empty = ciphertext_cid(b"");
    replace_manifest(&mut f, 0, &issuer, |b| {
        let Ipld::List(es) = b.get_mut("entries").unwrap() else {
            panic!()
        };
        let Ipld::Map(e) = &mut es[0] else { panic!() };
        e.insert("ciphertext".into(), Ipld::Link(empty.clone()));
        e.insert("length".into(), Ipld::Integer(1));
    })
    .unwrap();
    resign(&mut f, |_| Purpose::Admitted);
    f.objects = vec![(empty.clone(), vec![])];
    let r = run(&f, budget());
    show("rp14b-empty-cid-signed-length-1", &r);
    assert_eq!(invalid(&r), Some("empty service request CID"));
}

/// An empty orphan remains raw corrupt evidence, not a valid object.
#[test]
fn rp15_empty_orphan_with_empty_cid_is_corrupt() {
    let mut f = build(Opts {
        profile: 2,
        n: 0,
        ..Default::default()
    });
    let empty = ciphertext_cid(b"");
    f.objects = vec![(empty.clone(), vec![])];
    let r = run(&f, budget());
    show("rp15-empty-orphan-empty-cid", &r);
    assert_eq!(
        r.unwrap().losses(),
        &[Loss {
            occurrence: None,
            cid: empty,
            expected_length: None,
            state: Availability::Corrupt,
            basis: Basis::OriginalObject
        }]
    );
}

/// A retained reference in a partial copy still needs a membership row.
#[test]
fn rp16_partial_retained_reference_outside_membership_refuses() {
    let mut f = build(Opts {
        profile: 3,
        n: 3,
        ..Default::default()
    });
    f.records.truncate(2);
    let (c, _) = entry_cid(&f.records[0].0);
    f.membership.retain(|m| m.0 != c);
    f.objects.retain(|o| o.0 != c);
    let r = run(&f, budget());
    show("rp16-partial-retained-ref-not-member", &r);
    assert_eq!(
        invalid(&r),
        Some("retained reference absent from membership")
    );
}

/// A broken writer predecessor refuses even when every payload is missing.
#[test]
fn rp17_writer_predecessor_without_bytes() {
    let mut f = build(Opts {
        profile: 2,
        n: 2,
        ..Default::default()
    });
    let issuer = f.context.issuer.clone();
    replace_manifest(&mut f, 1, &issuer, |b| {
        b.insert("previous".into(), Ipld::Null);
        b.insert("position".into(), Ipld::Integer(0));
    })
    .unwrap();
    resign(&mut f, |_| Purpose::Admitted);
    f.objects.clear();
    let r = run(&f, budget());
    show("rp17-writer-chain-missing-bytes", &r);
    assert_eq!(invalid(&r), Some("writer predecessor"));
}

// Author follow-through for A-F1/A-F5: deliberately independent of request parsing.
#[test]
fn completed_copy_cannot_mislabel_hash_valid_orphan_with_false_length() {
    let mut f = build(Opts {
        profile: 3,
        n: 0,
        staged: vec![b"known orphan bytes".to_vec()],
        ..Default::default()
    });
    f.membership[0].1 += 1;
    let old = Plan::decode(f.plan.as_ref().unwrap()).unwrap();
    let mut source = old.source().clone();
    source.digest = source_digest(&f.records, 0, &f.membership);
    let plan = Plan::new(source, old.target().clone(), *old.nonce()).unwrap();
    f.context.archive = plan.archive_id();
    f.plan = Some(plan.bytes().to_vec());
    assert_eq!(
        invalid(&run(&f, budget())),
        Some("hash-valid bytes contradict authenticated length")
    );
}
#[test]
fn membership_bytes_are_charged_at_the_exact_input_boundary() {
    let f = build(Opts {
        profile: 3,
        n: 0,
        staged: vec![b"budgeted membership".to_vec()],
        ..Default::default()
    });
    let total = f.plan.as_ref().unwrap().len()
        + 44 * f.membership.len()
        + f.objects.iter().map(|o| o.1.len()).sum::<usize>();
    let mut b = budget();
    b.input_bytes = total as u64;
    run(&f, b.clone()).unwrap();
    b.input_bytes -= 1;
    assert_eq!(run(&f, b).err(), Some(member::Error::Budget));
}
#[test]
fn orphan_hash_mismatch_is_reported_without_rewriting_its_bytes() {
    let mut f = build(Opts {
        profile: 2,
        n: 0,
        ..Default::default()
    });
    let cid = ciphertext_cid(b"original intended bytes");
    f.objects = vec![(cid.clone(), b"wrong retained bytes".to_vec())];
    let m = run(&f, budget()).unwrap();
    assert_eq!(
        m.losses(),
        &[Loss {
            occurrence: None,
            cid,
            expected_length: None,
            state: Availability::Corrupt,
            basis: Basis::OriginalObject
        }]
    );
}

// Promoted from the b11cbf4 independent correction review.
#[test]
fn cp01_request_length_edges_without_bytes() {
    for (n, want) in [
        (MAXREQ, None),
        (MAXREQ + 1, Some("service request length")),
        (MIB4, Some("service request length")),
        (MIB4 + 1, Some("forensic-recovery-required")),
    ] {
        let mut f = build(Opts {
            profile: 2,
            n: 1,
            ..Default::default()
        });
        let (c, _) = entry_cid(&f.records[0].0);
        set_len(&mut f, 0, n);
        f.objects.clear();
        let r = run(&f, budget());
        show(&format!("cp01-len-{n}"), &r);
        match want {
            None => assert_eq!(
                r.unwrap().losses(),
                &[loss(
                    Some(1),
                    &c,
                    Some(n),
                    Availability::Missing,
                    Basis::IssuerMetadata
                )]
            ),
            Some(w) => assert_eq!(invalid(&r), Some(w)),
        }
    }
}

// Promoted from the b11cbf4 independent correction review.
#[test]
fn cp11_basis_deterministic() {
    let full = build(Opts {
        profile: 3,
        n: 3,
        ..Default::default()
    });
    let mut p = full.clone();
    p.records.truncate(2);
    p.objects.clear();
    let a = run(&p, budget()).unwrap();
    let b = run(&p, budget()).unwrap();
    show("cp11", &Ok::<_, member::Error>(run(&p, budget()).unwrap()));
    assert_eq!(a.losses(), b.losses());
    assert_eq!(a.commitment(), b.commitment());
    let bases: Vec<_> = a
        .losses()
        .iter()
        .map(|l| (l.occurrence, l.basis, l.expected_length.is_some()))
        .collect();
    assert_eq!(
        bases,
        vec![
            (Some(1), Basis::IssuerMetadata, true),
            (Some(2), Basis::IssuerMetadata, true),
            (None, Basis::UnverifiedMembership, false)
        ]
    );
}

#[test]
fn empty_service_request_cid_refuses_without_an_original() {
    let mut f = build(Opts {
        profile: 2,
        n: 1,
        ..Default::default()
    });
    let issuer = f.context.issuer.clone();
    replace_manifest(&mut f, 0, &issuer, |body| {
        let Ipld::List(entries) = body.get_mut("entries").unwrap() else {
            panic!()
        };
        let Ipld::Map(entry) = &mut entries[0] else {
            panic!()
        };
        entry.insert("ciphertext".into(), Ipld::Link(ciphertext_cid(b"")));
        entry.insert("length".into(), Ipld::Integer(1));
    })
    .unwrap();
    resign(&mut f, |_| Purpose::Admitted);
    f.objects.clear();
    assert_eq!(
        invalid(&run(&f, budget())),
        Some("empty service request CID")
    );
}

// Helpers promoted with CP01 and CP11.
const MAXREQ: u64 = service::MAX_REQUEST as u64;
const MIB4: u64 = 4 * 1024 * 1024;
fn set_len(f: &mut F, i: usize, n: u64) {
    let issuer = f.context.issuer.clone();
    replace_manifest(f, i, &issuer, |b| {
        let Ipld::List(es) = b.get_mut("entries").unwrap() else {
            panic!()
        };
        let Ipld::Map(e) = &mut es[0] else { panic!() };
        e.insert("length".into(), Ipld::Integer(n as i128));
    })
    .unwrap();
    resign(f, |_| Purpose::Admitted);
}
fn loss(occ: Option<u64>, cid: &Cid, n: Option<u64>, s: Availability, b: Basis) -> Loss {
    Loss {
        occurrence: occ,
        cid: cid.clone(),
        expected_length: n,
        state: s,
        basis: b,
    }
}
