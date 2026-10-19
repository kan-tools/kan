#![cfg(feature = "v2-storage")]
//! Independent reviewer probes for src/evidence_recovery_member.rs at frozen 5e54513.
//! Canonical copy lives in review-evidence/probes/; a temporary copy is placed in
//! tests/ only while probes/controls run, then removed.
//! Every probe prints a RP-line so the raw log records what was observed.
use atproto_dasl::{Cid, Ipld};
use kan::{
    evidence::{self, Decoded, Record},
    evidence_attestation::{self as proof, Frontier, Purpose},
    evidence_copy_plan::{Plan, Source, Target},
    evidence_recovery_member::{
        self as member, Availability, Budget, Input, Loss, Membership, Object, Row,
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
    time::{Duration, Instant},
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
fn source_digest(records: &[(Vec<u8>, Vec<u8>, Vec<u8>)], through: u64, members: &[(Cid, u64)]) -> [u8; 32] {
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
fn sign_request(writer: &Identity, scope: &[u8; 32], audience: &str, id: [u8; 16], position: u64, previous: Option<String>, payload: &[u8]) -> Vec<u8> {
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
        let bytes = sign_request(&writer, &scope, &audience, [0x40 + i as u8; 16], i as u64, previous.clone(), format!("reviewer payload {i}").as_bytes());
        let m = service::append_manifest(&bytes).unwrap();
        let r = receipt(&m, &audience);
        previous = Some(m.cid().to_string());
        f.records.push((m.bytes().to_vec(), r.bytes().to_vec(), vec![]));
        f.objects.push((ciphertext_cid(&bytes), bytes.clone()));
        f.requests.push(bytes);
    }
    for s in &o.staged {
        f.objects.push((ciphertext_cid(s), s.clone()));
    }
    f.objects.sort_by_key(|x| x.0.to_string());
    if o.profile == 3 {
        f.membership = f.objects.iter().map(|(c, b)| (c.clone(), b.len() as u64)).collect();
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
    resign(&mut f, |_| if profile == 3 { Purpose::RetainedVerified } else { Purpose::Admitted });
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
fn replace_manifest(f: &mut F, index: usize, issuer: &str, mutate: impl FnOnce(&mut BTreeMap<String, Ipld>)) -> Result<(), String> {
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
        .map(|(i, (m, r, p))| Row { sequence: i as u64 + 1, manifest: m, receipt: r, proof: p })
        .collect();
    let objects: Vec<_> = f.objects.iter().map(|(cid, bytes)| Object { cid, bytes }).collect();
    let membership: Vec<_> = f.membership.iter().map(|(cid, length)| Membership { cid, length: *length }).collect();
    member::verify(
        Input { context: &f.context, plan: f.plan.as_deref(), membership: &membership, records: &rows, objects: &objects },
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

/// RP01: an unreferenced staged membership key in a COMPLETE profile-3 copy gets exactly
/// one null-occurrence coordinate carrying its authenticated membership length.
#[test]
fn rp01_staged_membership_key_null_coordinate() {
    let staged = b"reviewer staged object".to_vec();
    let sc = ciphertext_cid(&staged);
    let base = build(Opts { profile: 3, n: 2, staged: vec![staged.clone()], ..Default::default() });
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
        &[Loss { occurrence: None, cid: sc.clone(), expected_length: Some(staged.len() as u64), state: Availability::Missing }]
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
        &[Loss { occurrence: None, cid: sc.clone(), expected_length: Some(staged.len() as u64), state: Availability::Corrupt }]
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
            Loss { occurrence: Some(1), cid: c1, expected_length: Some(n1), state: Availability::Corrupt },
            Loss { occurrence: Some(2), cid: c2, expected_length: Some(n2), state: Availability::Missing },
            Loss { occurrence: None, cid: sc, expected_length: Some(staged.len() as u64), state: Availability::Missing },
        ]
    );
}

/// RP02: in a PARTIAL profile-3 copy the membership list is not bound by any digest.
/// Characterisation: fabricated/omitted unreferenced membership is accepted and drives the
/// reported null-coordinate loss vector; the same edits refuse in a complete copy.
#[test]
fn rp02_partial_profile3_membership_is_unauthenticated() {
    let staged = b"reviewer staged object".to_vec();
    let full = build(Opts { profile: 3, n: 3, staged: vec![staged.clone()], ..Default::default() });
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
        &[Loss { occurrence: None, cid: fabricated.clone(), expected_length: Some(77), state: Availability::Missing }]
    );
    // Partial copy: dropping an unreferenced staged member (and its row) is accepted silently.
    let sc = ciphertext_cid(&staged);
    let mut f = partial.clone();
    f.membership.retain(|m| m.0 != sc);
    f.objects.retain(|o| o.0 != sc);
    let r = run(&f, budget());
    show("rp02-partial-drop-staged", &r);
    assert!(r.unwrap().losses().is_empty());
    // Partial copy: altering an unreferenced member's length turns valid bytes into "corrupt".
    let mut f = partial.clone();
    for m in &mut f.membership {
        if m.0 == sc {
            m.1 += 1;
        }
    }
    let r = run(&f, budget());
    show("rp02-partial-relength-staged", &r);
    assert_eq!(r.unwrap().losses()[0].state, Availability::Corrupt);
}

/// RP03: two occurrences sharing one request CID. With bytes missing the member is accepted
/// with two "missing" losses; supplying the genuine bytes then REFUSES. No bytes can ever
/// satisfy both occurrences (request bytes fix one operation), so the losses are unrepairable.
#[test]
fn rp03_shared_request_cid_is_unsatisfiable_but_accepted_when_missing() {
    let mut f = build(Opts { profile: 2, n: 2, ..Default::default() });
    let (c, n) = entry_cid(&f.records[0].0);
    let issuer = f.context.issuer.clone();
    replace_manifest(&mut f, 1, &issuer, |b| {
        let Ipld::List(es) = b.get_mut("entries").unwrap() else { panic!() };
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
    assert_eq!(r.unwrap().losses().len(), 2);
    f.objects = vec![(c.clone(), genuine)];
    let r = run(&f, budget());
    show("rp03-shared-restored-genuine-bytes", &r);
    assert_eq!(invalid(&r), Some("retained writer request"));
}

/// RP04: profile-3 retained receipts must come from the plan's historical issuer.
#[test]
fn rp04_retained_receipts_from_wrong_issuer_refuse() {
    let f = build(Opts { profile: 3, n: 2, current_receipts: true, ..Default::default() });
    let r = run(&f, budget());
    show("rp04-current-issuer-receipts", &r);
    assert_eq!(invalid(&r), Some("historical receipt issuer"));
    let mut g = f.clone();
    g.objects.clear();
    let r = run(&g, budget());
    show("rp04-current-issuer-receipts-bytes-missing", &r);
    assert_eq!(invalid(&r), Some("historical receipt issuer"));
}

/// RP05: plan tip must equal the manifest at sourceThrough even when the digest matches.
#[test]
fn rp05_source_tip_mismatch_refuses() {
    let f = build(Opts { profile: 3, n: 3, tip_index: Some(0), ..Default::default() });
    let r = run(&f, budget());
    show("rp05-wrong-tip", &r);
    assert_eq!(invalid(&r), Some("source tip"));
}

/// RP06: plan target scope / issuer must equal the owner context (archive alone is not enough).
#[test]
fn rp06_plan_target_scope_and_issuer_binding() {
    let f = build(Opts { profile: 3, n: 1, target_scope: Some([9; 32]), ..Default::default() });
    let r = run(&f, budget());
    show("rp06-target-scope", &r);
    assert_eq!(invalid(&r), Some("plan binding"));
    let f = build(Opts { profile: 3, n: 1, target_issuer: Some(did(7)), ..Default::default() });
    let r = run(&f, budget());
    show("rp06-target-issuer", &r);
    assert_eq!(invalid(&r), Some("plan binding"));
}

/// RP07: purpose must be retained-verified inside the plan prefix and admitted after it.
/// (Attempt 1 used historical-issuer receipts; proof::issue itself refuses `admitted`
/// there, so receipts are re-addressed to the current issuer to reach the member check.)
#[test]
fn rp07_proof_purpose_per_range() {
    let mut f = build(Opts { profile: 3, n: 2, current_receipts: true, ..Default::default() });
    resign(&mut f, |_| Purpose::Admitted);
    let r = run(&f, budget());
    show("rp07-admitted-in-retained-range", &r);
    assert_eq!(invalid(&r), Some("proof purpose"));
    let mut f = build(Opts { profile: 3, n: 2, current_receipts: true, ..Default::default() });
    resign(&mut f, |i| if i == 0 { Purpose::RetainedVerified } else { Purpose::Admitted });
    let r = run(&f, budget());
    show("rp07-mixed-in-retained-range", &r);
    // Row 1 is retained-verified over current-issuer receipts, so the historical-issuer
    // rule may fire first; diagnostic precedence is explicitly not a contract.
    assert!(matches!(invalid(&r), Some("proof purpose") | Some("historical receipt issuer")));
}

/// RP08: membership must be strictly canonical-text ordered, unique and raw/SHA-256.
#[test]
fn rp08_membership_order_duplicates_and_codec() {
    let base = build(Opts { profile: 3, n: 3, ..Default::default() });
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
    let mut f = build(Opts { profile: 2, n: 1, ..Default::default() });
    f.membership = vec![(ciphertext_cid(b"x"), 1)];
    let r = run(&f, budget());
    show("rp08-profile2-membership", &r);
    assert!(r.is_err());
    let mut f = build(Opts { profile: 3, n: 1, ..Default::default() });
    f.plan = None;
    let r = run(&f, budget());
    show("rp08-profile3-no-plan", &r);
    assert_eq!(invalid(&r), Some("profile plan"));
}

/// RP09: a non-static writer form with bytes MISSING (so writer signature never runs)
/// must still refuse on static-writer shape. Variants that the record schema itself
/// refuses are logged as schema-refused.
#[test]
fn rp09_non_static_writer_refuses_without_bytes() {
    let writer = did(5);
    let variants: Vec<(&str, Ipld)> = vec![
        (
            "event-version",
            map([
                ("principal", Ipld::String(writer.clone())),
                ("verificationMethod", Ipld::String(format!("{writer}#{}", &writer[8..]))),
                ("identityVersion", map([("kind", Ipld::String("event".into())), ("value", Ipld::Link(ciphertext_cid(b"e")))])),
            ]),
        ),
        (
            "versionid",
            map([
                ("principal", Ipld::String(writer.clone())),
                ("verificationMethod", Ipld::String(format!("{writer}#{}", &writer[8..]))),
                ("identityVersion", map([("kind", Ipld::String("versionId".into())), ("value", Ipld::String("v1".into()))])),
            ]),
        ),
        (
            "other-fragment",
            map([
                ("principal", Ipld::String(writer.clone())),
                ("verificationMethod", Ipld::String(format!("{writer}#key-1"))),
                ("identityVersion", map([("kind", Ipld::String("static".into())), ("value", Ipld::Null)])),
            ]),
        ),
        (
            "did-web-documentcid",
            map([
                ("principal", Ipld::String("did:web:example.com".into())),
                ("verificationMethod", Ipld::String("did:web:example.com#key-1".into())),
                ("identityVersion", map([("kind", Ipld::String("documentCid".into())), ("value", Ipld::Link(ciphertext_cid(b"doc")))])),
            ]),
        ),
        (
            "did-web-static",
            map([
                ("principal", Ipld::String("did:web:example.com".into())),
                ("verificationMethod", Ipld::String("did:web:example.com#key-1".into())),
                ("identityVersion", map([("kind", Ipld::String("static".into())), ("value", Ipld::Null)])),
            ]),
        ),
        (
            "did-plc-versionid",
            map([
                ("principal", Ipld::String("did:plc:ewvi7nxzyoun6zhxrhs64oiz".into())),
                ("verificationMethod", Ipld::String("did:plc:ewvi7nxzyoun6zhxrhs64oiz#atproto".into())),
                ("identityVersion", map([("kind", Ipld::String("versionId".into())), ("value", Ipld::String("bafyreib".into()))])),
            ]),
        ),
    ];
    let mut reached = 0;
    for (name, w) in variants {
        let mut f = build(Opts { profile: 2, n: 1, ..Default::default() });
        let issuer = f.context.issuer.clone();
        match replace_manifest(&mut f, 0, &issuer, |b| {
            b.insert("writer".into(), w);
        }) {
            Err(e) => {
                eprintln!("RP rp09-{name}: schema-refused {e}");
                continue;
            }
            Ok(()) => {}
        }
        resign(&mut f, |_| Purpose::Admitted);
        f.objects.clear();
        let r = run(&f, budget());
        show(&format!("rp09-{name}"), &r);
        assert!(matches!(invalid(&r), Some("static writer") | Some("writer")), "{name}");
        reached += 1;
    }
    assert!(reached > 0, "no non-static variant passed record schema");
}

/// RP10a: a pre-cancelled invocation reports Cancelled before semantic work. With the
/// member-stage cancellation poll removed the verifier instead runs to the first semantic
/// fault (here a broken issuer proof) — i.e. it performed work after cancellation.
#[test]
fn rp10a_precancelled_refuses_before_semantic_work() {
    let mut f = build(Opts { profile: 2, n: 2, ..Default::default() });
    f.records[1].2[10] ^= 1;
    let b = budget();
    b.cancelled.store(true, Ordering::Relaxed);
    let r = run(&f, b);
    show("rp10a-precancelled-with-later-fault", &r);
    assert_eq!(r.err(), Some(member::Error::Cancelled));
}

/// RP10b (timing-based): cancellation raised mid-way through member-stage hashing of
/// 16 x 4 MiB valid orphans returns promptly, not after the member stage completes.
#[test]
fn rp10b_midflight_cancellation_is_prompt() {
    let mut f = build(Opts { profile: 2, n: 0, ..Default::default() });
    for i in 0..16u8 {
        let bytes = vec![i; 4 * 1024 * 1024];
        f.objects.push((ciphertext_cid(&bytes), bytes));
    }
    f.objects.sort_by_key(|o| o.0.to_string());
    let t = Instant::now();
    let m = run(&f, budget()).unwrap();
    let total = t.elapsed();
    assert!(m.losses().is_empty());
    // Member stage hashes every byte once; framing hashes them again: ~half each.
    let member_stage = total / 2;
    assert!(member_stage >= Duration::from_millis(150), "probe not discriminating: total {total:?}");
    let b = budget();
    let flag = b.cancelled.clone();
    let delay = member_stage / 5;
    let setter = std::thread::spawn(move || {
        std::thread::sleep(delay);
        flag.store(true, Ordering::Relaxed);
        Instant::now()
    });
    let r = run(&f, b);
    let returned = Instant::now();
    let set_at = setter.join().unwrap();
    let latency = returned.saturating_duration_since(set_at);
    eprintln!("RP rp10b: total={total:?} member_stage~{member_stage:?} cancel_after={delay:?} latency={latency:?} result={:?}", r.as_ref().err());
    assert_eq!(r.err(), Some(member::Error::Cancelled));
    assert!(latency < member_stage / 10, "cancellation latency {latency:?} vs member stage {member_stage:?}");
}

/// RP10c (timing-based): elapsed-time budget expiring inside member-stage hashing.
#[test]
fn rp10c_deadline_inside_member_stage_is_prompt() {
    let mut f = build(Opts { profile: 2, n: 0, ..Default::default() });
    for i in 0..16u8 {
        let bytes = vec![i.wrapping_add(100); 4 * 1024 * 1024];
        f.objects.push((ciphertext_cid(&bytes), bytes));
    }
    f.objects.sort_by_key(|o| o.0.to_string());
    let t = Instant::now();
    run(&f, budget()).unwrap();
    let total = t.elapsed();
    let mut b = budget();
    b.duration = total / 10;
    let t = Instant::now();
    let r = run(&f, b);
    let took = t.elapsed();
    eprintln!("RP rp10c: total={total:?} duration={:?} took={took:?} result={:?}", total / 10, r.as_ref().err());
    assert_eq!(r.err(), Some(member::Error::Budget));
    assert!(took < total / 10 + total / 20, "deadline overshoot {took:?}");
}

/// RP11: item and input-byte caps refuse before any hashing (pre-allocation ordering):
/// a 0-item budget refuses even an empty-record member with one huge object.
#[test]
fn rp11_caps_before_work() {
    let mut f = build(Opts { profile: 2, n: 0, ..Default::default() });
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

/// RP12: cross-scope/issuer owner context and observer DID validation.
#[test]
fn rp12_cross_scope_issuer_and_observer() {
    let mut f = build(Opts { profile: 2, n: 1, ..Default::default() });
    f.context.scope = [9; 32];
    let r = run(&f, budget());
    show("rp12-wrong-owner-scope", &r);
    assert_eq!(invalid(&r), Some("issuer proof"));
    let mut f = build(Opts { profile: 2, n: 1, ..Default::default() });
    f.context.issuer = did(7);
    let r = run(&f, budget());
    show("rp12-wrong-owner-issuer", &r);
    assert_eq!(invalid(&r), Some("issuer proof"));
    let mut f = build(Opts { profile: 2, n: 1, ..Default::default() });
    f.context.observer = f.context.observer.to_uppercase();
    let r = run(&f, budget());
    show("rp12-noncanonical-observer", &r);
    assert!(r.is_err());
    // Same-key observer/issuer is wire-valid by recorded decision.
    let mut f = build(Opts { profile: 2, n: 1, ..Default::default() });
    f.context.observer = f.context.issuer.clone();
    let r = run(&f, budget());
    show("rp12-same-key-observer", &r);
    assert!(r.is_ok());
}

/// RP13: a canonical-text CID parsed from a NON-canonical spelling is indistinguishable at
/// this typed API: the verifier cannot detect it; the physical reader must refuse first.
#[test]
fn rp13_noncanonical_spelling_is_invisible_to_typed_api() {
    let c = ciphertext_cid(b"spelling");
    let canonical = c.to_string();
    let upper = canonical.to_uppercase();
    let parsed: Result<Cid, _> = upper.parse();
    match parsed {
        Ok(p) => {
            eprintln!("RP rp13: uppercase spelling parses; to_string()==canonical: {}", p.to_string() == canonical);
            assert_eq!(p, c);
        }
        Err(e) => eprintln!("RP rp13: uppercase spelling refused by Cid parser: {e}"),
    }
}

/// RP10d (timing-based, finer): pins per-chunk (not per-object) polling inside member-stage
/// hashing. Several trials cancel at different offsets inside 4 MiB objects; the worst
/// observed latency must stay far below one 4 MiB hash.
#[test]
fn rp10d_cancellation_latency_is_below_one_object_hash() {
    let mut f = build(Opts { profile: 2, n: 0, ..Default::default() });
    for i in 0..4u8 {
        let bytes = vec![i.wrapping_add(200); 4 * 1024 * 1024];
        f.objects.push((ciphertext_cid(&bytes), bytes));
    }
    f.objects.sort_by_key(|o| o.0.to_string());
    let one = vec![9u8; 4 * 1024 * 1024];
    let t = Instant::now();
    let _ = Sha256::digest(&one);
    let per_object = t.elapsed();
    assert!(per_object >= Duration::from_millis(40), "probe not discriminating: 4 MiB hash {per_object:?}");
    let mut worst = Duration::ZERO;
    for k in 1..=6u32 {
        let b = budget();
        let flag = b.cancelled.clone();
        let delay = per_object * k / 4 + per_object / 7;
        let setter = std::thread::spawn(move || {
            std::thread::sleep(delay);
            flag.store(true, Ordering::Relaxed);
            Instant::now()
        });
        let r = run(&f, b);
        let returned = Instant::now();
        let set_at = setter.join().unwrap();
        let latency = returned.saturating_duration_since(set_at);
        eprintln!("RP rp10d trial {k}: delay={delay:?} latency={latency:?} result={:?}", r.as_ref().err());
        assert_eq!(r.err(), Some(member::Error::Cancelled));
        worst = worst.max(latency);
    }
    eprintln!("RP rp10d: 4MiB-hash={per_object:?} worst-latency={worst:?}");
    assert!(worst < per_object / 4, "worst latency {worst:?} vs one-object hash {per_object:?}");
}
