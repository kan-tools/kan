#![cfg(feature = "v2-storage")]
//! Reviewer probes, part 2 (false-but-signed length metadata), frozen 5e54513.
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


/// RP14 (characterisation): issuer-signed metadata whose expected length disagrees with
/// HASH-VALID original bytes. Codec :166 says wrong length => corrupt entry; the checkpoint
/// text (codec :406-408) says a hash-valid request failing exact manifest binding is invalid
/// member evidence, not a repairable loss. Record which one the implementation follows.
#[test]
fn rp14_hash_valid_bytes_with_false_signed_length() {
    let mut f = build(Opts { profile: 2, n: 1, ..Default::default() });
    let (c, n) = entry_cid(&f.records[0].0);
    let issuer = f.context.issuer.clone();
    replace_manifest(&mut f, 0, &issuer, |b| {
        let Ipld::List(es) = b.get_mut("entries").unwrap() else { panic!() };
        let Ipld::Map(e) = &mut es[0] else { panic!() };
        e.insert("length".into(), Ipld::Integer(n as i128 + 1));
    })
    .unwrap();
    resign(&mut f, |_| Purpose::Admitted);
    // f.objects still holds the GENUINE request bytes, whose raw CID is exactly `c`.
    assert_eq!(ciphertext_cid(&f.objects[0].1), c);
    let r = run(&f, budget());
    show("rp14a-genuine-bytes-false-length", &r);
    let m = r.expect("observed: accepted");
    assert_eq!(m.verified_requests(), 0);
    assert_eq!(
        m.losses(),
        &[Loss { occurrence: Some(1), cid: c.clone(), expected_length: Some(n + 1), state: Availability::Corrupt }]
    );
    // Same request, honest length, bytes present: verifies (control for the fixture).
    let g = build(Opts { profile: 2, n: 1, ..Default::default() });
    let r = run(&g, budget());
    show("rp14a-control-honest-length", &r);
    assert_eq!(r.unwrap().verified_requests(), 1);

    // Empty-bytes CID referenced with signed length 1; the empty object is present.
    let mut f = build(Opts { profile: 2, n: 1, ..Default::default() });
    let empty = ciphertext_cid(b"");
    replace_manifest(&mut f, 0, &issuer, |b| {
        let Ipld::List(es) = b.get_mut("entries").unwrap() else { panic!() };
        let Ipld::Map(e) = &mut es[0] else { panic!() };
        e.insert("ciphertext".into(), Ipld::Link(empty.clone()));
        e.insert("length".into(), Ipld::Integer(1));
    })
    .unwrap();
    resign(&mut f, |_| Purpose::Admitted);
    f.objects = vec![(empty.clone(), vec![])];
    let r = run(&f, budget());
    show("rp14b-empty-cid-signed-length-1", &r);
    assert_eq!(r.unwrap().losses()[0].state, Availability::Corrupt);
}

/// RP15: an empty orphan whose key IS the empty-bytes CID (hash-valid, no expected length)
/// must still be a corrupt null coordinate: every valid KNB1 object length is positive.
#[test]
fn rp15_empty_orphan_with_empty_cid_is_corrupt() {
    let mut f = build(Opts { profile: 2, n: 0, ..Default::default() });
    let empty = ciphertext_cid(b"");
    f.objects = vec![(empty.clone(), vec![])];
    let r = run(&f, budget());
    show("rp15-empty-orphan-empty-cid", &r);
    assert_eq!(
        r.unwrap().losses(),
        &[Loss { occurrence: None, cid: empty, expected_length: None, state: Availability::Corrupt }]
    );
}

/// RP16: PARTIAL copy, a retained reference absent from membership with bytes missing.
/// (The author test uses a complete copy, where the source digest refuses anyway.)
#[test]
fn rp16_partial_retained_reference_outside_membership_refuses() {
    let mut f = build(Opts { profile: 3, n: 3, ..Default::default() });
    f.records.truncate(2);
    let (c, _) = entry_cid(&f.records[0].0);
    f.membership.retain(|m| m.0 != c);
    f.objects.retain(|o| o.0 != c);
    let r = run(&f, budget());
    show("rp16-partial-retained-ref-not-member", &r);
    assert_eq!(invalid(&r), Some("retained reference absent from membership"));
}

/// RP17: a broken per-writer chain (second request claims genesis) with bytes MISSING, so
/// writer-signature verification cannot catch it.
#[test]
fn rp17_writer_predecessor_without_bytes() {
    let mut f = build(Opts { profile: 2, n: 2, ..Default::default() });
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
