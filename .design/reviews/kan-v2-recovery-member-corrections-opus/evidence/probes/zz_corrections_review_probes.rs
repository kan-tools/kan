#![cfg(feature = "v2-storage")]
//! REVIEWER PROBES (independent correction review of b11cbf4). Helpers copied verbatim
//! from tests/evidence_recovery_member_review_regressions.rs:6-378. Temporary file.
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

// ---------------------------------------------------------------- reviewer probes
const MAXREQ: u64 = service::MAX_REQUEST as u64;
const MIB4: u64 = 4 * 1024 * 1024;
fn set_len(f: &mut F, i: usize, n: u64) {
    let issuer = f.context.issuer.clone();
    replace_manifest(f, i, &issuer, |b| {
        let Ipld::List(es) = b.get_mut("entries").unwrap() else { panic!() };
        let Ipld::Map(e) = &mut es[0] else { panic!() };
        e.insert("length".into(), Ipld::Integer(n as i128));
    })
    .unwrap();
    resign(f, |_| Purpose::Admitted);
}
fn loss(occ: Option<u64>, cid: &Cid, n: Option<u64>, s: Availability, b: Basis) -> Loss {
    Loss { occurrence: occ, cid: cid.clone(), expected_length: n, state: s, basis: b }
}

/// CP01: referenced service-request length edges with bytes MISSING.
#[test]
fn cp01_request_length_edges_without_bytes() {
    for (n, want) in [
        (MAXREQ, None),
        (MAXREQ + 1, Some("service request length")),
        (MIB4, Some("service request length")),
        (MIB4 + 1, Some("forensic-recovery-required")),
    ] {
        let mut f = build(Opts { profile: 2, n: 1, ..Default::default() });
        let (c, _) = entry_cid(&f.records[0].0);
        set_len(&mut f, 0, n);
        f.objects.clear();
        let r = run(&f, budget());
        show(&format!("cp01-len-{n}"), &r);
        match want {
            None => assert_eq!(
                r.unwrap().losses(),
                &[loss(Some(1), &c, Some(n), Availability::Missing, Basis::IssuerMetadata)]
            ),
            Some(w) => assert_eq!(invalid(&r), Some(w)),
        }
    }
}

/// CP02: MAX_REQUEST applies only to referenced service requests, not to staged
/// membership-only originals in a complete copy (up to 4 MiB).
#[test]
fn cp02_staged_object_above_request_bound_is_not_a_request() {
    let big = vec![7u8; (MAXREQ + 10) as usize];
    let sc = ciphertext_cid(&big);
    let f = build(Opts { profile: 3, n: 1, staged: vec![big.clone()], ..Default::default() });
    let r = run(&f, budget());
    show("cp02-big-staged-present", &r);
    let m = r.unwrap();
    assert!(m.recipe_metadata_complete());
    assert!(m.losses().is_empty());
    let mut g = f.clone();
    g.objects.retain(|o| o.0 != sc);
    let r = run(&g, budget());
    show("cp02-big-staged-missing", &r);
    assert_eq!(
        r.unwrap().losses(),
        &[loss(None, &sc, Some(big.len() as u64), Availability::Missing, Basis::VerifiedCopyRecipe)]
    );
}

/// CP03 (characterisation): the empty-bytes CID referenced with signed length 1 and the
/// empty row ABSENT. Only the empty string hashes to that CID, so the coordinate is as
/// unsatisfiable as A-F3's shared CID, yet nothing refuses it without bytes.
#[test]
fn cp03_empty_cid_positive_length_without_bytes() {
    let mut f = build(Opts { profile: 2, n: 1, ..Default::default() });
    let empty = ciphertext_cid(b"");
    let issuer = f.context.issuer.clone();
    replace_manifest(&mut f, 0, &issuer, |b| {
        let Ipld::List(es) = b.get_mut("entries").unwrap() else { panic!() };
        let Ipld::Map(e) = &mut es[0] else { panic!() };
        e.insert("ciphertext".into(), Ipld::Link(empty.clone()));
        e.insert("length".into(), Ipld::Integer(1));
    })
    .unwrap();
    resign(&mut f, |_| Purpose::Admitted);
    f.objects.clear();
    let r = run(&f, budget());
    show("cp03-empty-cid-len1-missing", &r);
    eprintln!("CP03 outcome: {:?}", r.as_ref().map(|m| m.losses().to_vec()).map_err(|e| e.clone()));
}

/// CP04: partial copy, membership-only coordinates: hash-invalid bytes are Corrupt with
/// no authenticated length; an empty-CID membership row with an empty original is Corrupt
/// (partial) but REFUSES in a complete copy (authenticated length >= 1 contradicts).
#[test]
fn cp04_partial_membership_only_corrupt_and_empty() {
    let full = build(Opts { profile: 3, n: 3, ..Default::default() });
    let (c3, _) = entry_cid(&full.records[2].0);
    let mut p = full.clone();
    p.records.truncate(1);
    for o in &mut p.objects {
        if o.0 == c3 {
            o.1 = b"tampered".to_vec();
        }
    }
    let r = run(&p, budget());
    show("cp04-partial-corrupt-member-only", &r);
    assert_eq!(
        r.unwrap().losses(),
        &[loss(None, &c3, None, Availability::Corrupt, Basis::UnverifiedMembership)]
    );
    // Empty-CID membership row, length 5, empty bytes present.
    let empty = ciphertext_cid(b"");
    let mut p = full.clone();
    p.records.truncate(1);
    p.membership.push((empty.clone(), 5));
    p.membership.sort_by_key(|m| m.0.to_string());
    p.objects.push((empty.clone(), vec![]));
    p.objects.sort_by_key(|o| o.0.to_string());
    let r = run(&p, budget());
    show("cp04-partial-empty-cid-row", &r);
    assert_eq!(
        r.unwrap().losses(),
        &[loss(None, &empty, None, Availability::Corrupt, Basis::UnverifiedMembership)]
    );
    // Same empty-CID row in a COMPLETE copy, with a re-issued correct digest.
    let mut c = full.clone();
    c.membership.push((empty.clone(), 5));
    c.membership.sort_by_key(|m| m.0.to_string());
    c.objects.push((empty.clone(), vec![]));
    c.objects.sort_by_key(|o| o.0.to_string());
    let old = Plan::decode(c.plan.as_ref().unwrap()).unwrap();
    let mut source = old.source().clone();
    source.digest = source_digest(&c.records, 3, &c.membership);
    let plan = Plan::new(source, old.target().clone(), *old.nonce()).unwrap();
    c.context.archive = plan.archive_id();
    c.plan = Some(plan.bytes().to_vec());
    resign(&mut c, |_| Purpose::RetainedVerified);
    let r = run(&c, budget());
    show("cp04-complete-empty-cid-row", &r);
    assert_eq!(invalid(&r), Some("hash-valid bytes contradict authenticated length"));
}

/// CP05 (characterisation): unverified partial-copy rows that are locally out of bounds
/// still refuse the whole member (fail closed), they are not silently dropped.
#[test]
fn cp05_partial_out_of_bound_rows_refuse() {
    let full = build(Opts { profile: 3, n: 3, ..Default::default() });
    for n in [0u64, MIB4 + 1] {
        let mut p = full.clone();
        p.records.truncate(1);
        p.membership.push((ciphertext_cid(b"fabricated out of bound"), n));
        p.membership.sort_by_key(|m| m.0.to_string());
        let r = run(&p, budget());
        show(&format!("cp05-partial-row-{n}"), &r);
        assert_eq!(invalid(&r), Some("forensic-recovery-required"));
    }
}

/// CP06: M1 retains claimed partial-copy lengths verbatim: changing only an unverified
/// length changes the commitment, while the loss projection is unchanged.
#[test]
fn cp06_m1_retains_unverified_lengths() {
    let full = build(Opts { profile: 3, n: 3, ..Default::default() });
    let (c3, _) = entry_cid(&full.records[2].0);
    let mut p = full.clone();
    p.records.truncate(1);
    p.objects.retain(|o| o.0 != c3);
    let a = run(&p, budget()).unwrap();
    let mut q = p.clone();
    for m in &mut q.membership {
        if m.0 == c3 {
            m.1 += 9;
        }
    }
    let b = run(&q, budget()).unwrap();
    eprintln!("CP06 losses a={:?} b={:?}", a.losses(), b.losses());
    assert_eq!(a.losses(), b.losses());
    assert_eq!(
        a.losses(),
        &[loss(None, &c3, None, Availability::Missing, Basis::UnverifiedMembership)]
    );
    assert_ne!(a.commitment(), b.commitment(), "M1 must retain exact claimed rows");
}

/// CP07: complete copy, membership-only key: same-length tampered bytes and wrong-length
/// garbage are both Corrupt (not hash-valid), with the authenticated length.
#[test]
fn cp07_complete_membership_only_corrupt_variants() {
    let staged = b"reviewer staged bytes".to_vec();
    let sc = ciphertext_cid(&staged);
    let f = build(Opts { profile: 3, n: 1, staged: vec![staged.clone()], ..Default::default() });
    for (name, bytes) in [
        ("same-length", vec![b'x'; staged.len()]),
        ("other-length", b"short".to_vec()),
        ("empty", vec![]),
    ] {
        let mut g = f.clone();
        for o in &mut g.objects {
            if o.0 == sc {
                o.1 = bytes.clone();
            }
        }
        let r = run(&g, budget());
        show(&format!("cp07-{name}"), &r);
        assert_eq!(
            r.unwrap().losses(),
            &[loss(None, &sc, Some(staged.len() as u64), Availability::Corrupt, Basis::VerifiedCopyRecipe)]
        );
    }
}

/// CP08: referenced request with hash-INVALID bytes of the correct length is Corrupt
/// (IssuerMetadata); the A-F1 refusal is limited to hash-valid bytes.
#[test]
fn cp08_referenced_hash_invalid_is_corrupt() {
    let mut f = build(Opts { profile: 2, n: 1, ..Default::default() });
    let (c, n) = entry_cid(&f.records[0].0);
    f.objects[0].1 = vec![b'z'; n as usize];
    let r = run(&f, budget());
    show("cp08-ref-hash-invalid", &r);
    assert_eq!(
        r.unwrap().losses(),
        &[loss(Some(1), &c, Some(n), Availability::Corrupt, Basis::IssuerMetadata)]
    );
}

/// CP09: shared request CID: three occurrences, and a shared CID with different signed
/// lengths (diagnostic precedence only; both must refuse).
#[test]
fn cp09_shared_request_variants() {
    let mut f = build(Opts { profile: 2, n: 3, ..Default::default() });
    let (c, n) = entry_cid(&f.records[0].0);
    let issuer = f.context.issuer.clone();
    for i in [2usize] {
        replace_manifest(&mut f, i, &issuer, |b| {
            let Ipld::List(es) = b.get_mut("entries").unwrap() else { panic!() };
            let Ipld::Map(e) = &mut es[0] else { panic!() };
            e.insert("ciphertext".into(), Ipld::Link(c.clone()));
            e.insert("length".into(), Ipld::Integer(n as i128));
        })
        .unwrap();
    }
    resign(&mut f, |_| Purpose::Admitted);
    f.objects.clear();
    let r = run(&f, budget());
    show("cp09-non-adjacent-shared", &r);
    assert_eq!(invalid(&r), Some("reused service request CID"));
    let mut g = build(Opts { profile: 2, n: 2, ..Default::default() });
    replace_manifest(&mut g, 1, &issuer, |b| {
        let Ipld::List(es) = b.get_mut("entries").unwrap() else { panic!() };
        let Ipld::Map(e) = &mut es[0] else { panic!() };
        e.insert("ciphertext".into(), Ipld::Link(c.clone()));
        e.insert("length".into(), Ipld::Integer(n as i128 + 1));
    })
    .unwrap();
    resign(&mut g, |_| Purpose::Admitted);
    g.objects.clear();
    let r = run(&g, budget());
    show("cp09-shared-different-length", &r);
    assert!(r.is_err());
}

/// CP10: profile-3 COMPLETE copy: shared CID between two retained occurrences with the
/// digest recomputed so only the A-F3 guard can refuse.
#[test]
fn cp10_profile3_complete_shared_request_refuses() {
    let mut f = build(Opts { profile: 3, n: 2, ..Default::default() });
    let (c, n) = entry_cid(&f.records[0].0);
    let (c2, _) = entry_cid(&f.records[1].0);
    let historical = did(4);
    replace_manifest(&mut f, 1, &historical, |b| {
        let Ipld::List(es) = b.get_mut("entries").unwrap() else { panic!() };
        let Ipld::Map(e) = &mut es[0] else { panic!() };
        e.insert("ciphertext".into(), Ipld::Link(c.clone()));
        e.insert("length".into(), Ipld::Integer(n as i128));
    })
    .unwrap();
    f.membership.retain(|m| m.0 != c2);
    f.objects.clear();
    let old = Plan::decode(f.plan.as_ref().unwrap()).unwrap();
    let mut source = old.source().clone();
    source.digest = source_digest(&f.records, 2, &f.membership);
    source.tip = Some(decode(&f.records[1].0).cid().clone());
    let plan = Plan::new(source, old.target().clone(), *old.nonce()).unwrap();
    f.context.archive = plan.archive_id();
    f.plan = Some(plan.bytes().to_vec());
    resign(&mut f, |_| Purpose::RetainedVerified);
    let r = run(&f, budget());
    show("cp10-p3-complete-shared", &r);
    assert_eq!(invalid(&r), Some("reused service request CID"));
}

/// CP11: basis is a pure function of the member: repeated verification of the same
/// partial input yields identical losses and commitment.
#[test]
fn cp11_basis_deterministic() {
    let full = build(Opts { profile: 3, n: 3, ..Default::default() });
    let mut p = full.clone();
    p.records.truncate(2);
    p.objects.clear();
    let a = run(&p, budget()).unwrap();
    let b = run(&p, budget()).unwrap();
    show("cp11", &Ok::<_, member::Error>(run(&p, budget()).unwrap()));
    assert_eq!(a.losses(), b.losses());
    assert_eq!(a.commitment(), b.commitment());
    let bases: Vec<_> = a.losses().iter().map(|l| (l.occurrence, l.basis, l.expected_length.is_some())).collect();
    assert_eq!(
        bases,
        vec![
            (Some(1), Basis::IssuerMetadata, true),
            (Some(2), Basis::IssuerMetadata, true),
            (None, Basis::UnverifiedMembership, false)
        ]
    );
}

/// CP12: partial copy, a membership row that claims the length of the REFERENCED key
/// differently refuses (unverified rows that contradict issuer metadata are not repaired).
#[test]
fn cp12_partial_row_contradicting_issuer_length_refuses_with_bytes() {
    let full = build(Opts { profile: 3, n: 3, ..Default::default() });
    let (c1, _) = entry_cid(&full.records[0].0);
    let mut p = full.clone();
    p.records.truncate(1);
    for m in &mut p.membership {
        if m.0 == c1 {
            m.1 += 1;
        }
    }
    let r = run(&p, budget());
    show("cp12-partial-referenced-row-relength-bytes-present", &r);
    assert_eq!(invalid(&r), Some("conflicting expected lengths"));
}
