//! Reviewer probe (temporary copy under tests/; canonical copy in review-evidence/probes).
//! Synthetic public test scalar only. Env REVIEW_DIFFERENTIAL = differential.json path.
#![cfg(feature = "v2-storage")]
use std::panic::{catch_unwind, AssertUnwindSafe};

use atproto_dasl::Ipld;
use kan::{
    evidence::{self, Decoded, Record},
    evidence_attestation::{self as proof, Frontier, Purpose},
    evidence_service::unhex,
    sign::Identity,
};
use serde_json::Value;

fn fixture() -> Value {
    serde_json::from_str(include_str!("../.design/fixtures/service-attestation-v1.json")).unwrap()
}
fn raw(value: &Value) -> Vec<u8> {
    unhex(value.as_str().unwrap(), 65536).unwrap()
}
fn ipld(v: &Value) -> Ipld {
    match v {
        Value::Null => Ipld::Null,
        Value::Bool(b) => Ipld::Bool(*b),
        Value::Number(n) => Ipld::Integer(n.as_u64().unwrap() as i128),
        Value::String(s) => Ipld::String(s.clone()),
        Value::Array(a) => Ipld::List(a.iter().map(ipld).collect()),
        Value::Object(m) if m.len() == 1 && m.contains_key("$bytes") => Ipld::Bytes(raw(&m["$bytes"])),
        Value::Object(m) if m.len() == 1 && m.contains_key("$link") => {
            Ipld::Link(m["$link"].as_str().unwrap().parse().unwrap())
        }
        Value::Object(m) => Ipld::Map(m.iter().map(|(k, v)| (k.clone(), ipld(v))).collect()),
    }
}
fn decode_record(bytes: &[u8]) -> Record {
    let Decoded::Known(r) = evidence::decode(bytes).unwrap() else { panic!("known") };
    r
}
fn signer(scalar: u8) -> Identity {
    let f = tempfile::NamedTempFile::new().unwrap();
    let mut s = [0; 32];
    s[31] = scalar;
    std::fs::write(f.path(), s).unwrap();
    Identity::load_existing(f.path()).unwrap()
}
fn ctx<'a>(issuer: &'a str, f: &Value) -> proof::Context<'a> {
    proof::Context {
        issuer,
        archive: raw(&f["archiveHex"]).try_into().unwrap(),
        scope: raw(&f["scopeHex"]).try_into().unwrap(),
    }
}
fn label(r: Result<proof::Verified, evidence::Error>) -> String {
    match r {
        Ok(_) => "ACCEPT".into(),
        Err(evidence::Error::Schema(l)) => l,
        Err(e) => format!("OTHER:{e}"),
    }
}
struct Rows {
    envelopes: Vec<Vec<u8>>,
    manifests: Vec<Vec<u8>>,
    receipts: Vec<Vec<u8>>,
    verified: Vec<proof::Verified>,
}
fn rows(f: &Value) -> Rows {
    let issuer = f["pinnedIssuer"].as_str().unwrap();
    let (mut envelopes, mut manifests, mut receipts, mut verified) = (vec![], vec![], vec![], vec![]);
    let mut previous = Frontier::default();
    for row in f["positive"].as_array().unwrap() {
        let (e, m, r) = (raw(&row["envelopeHex"]), raw(&row["manifestHex"]), raw(&row["receiptHex"]));
        let v = proof::verify_encoded(&e, &ctx(issuer, f), &m, &r, &previous).unwrap();
        previous = v.frontier().clone();
        envelopes.push(e);
        manifests.push(m);
        receipts.push(r);
        verified.push(v);
    }
    Rows { envelopes, manifests, receipts, verified }
}

#[test]
fn review_differential_against_python_oracle() {
    let Ok(path) = std::env::var("REVIEW_DIFFERENTIAL") else {
        panic!("REVIEW_DIFFERENTIAL not set")
    };
    let cases: Vec<Value> = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let f = fixture();
    let base = rows(&f);
    let mut laxer = Vec::new();
    for case in &cases {
        let i = case["base"].as_u64().unwrap() as usize;
        let issuer = case.get("pinnedIssuer").unwrap_or(&f["pinnedIssuer"]).as_str().unwrap();
        let previous = if i == 0 { Frontier::default() } else { base.verified[i - 1].frontier().clone() };
        let env = raw(&case["envelopeHex"]);
        let m = case.get("manifestHex").map(raw).unwrap_or_else(|| base.manifests[i].clone());
        let r = case.get("receiptHex").map(raw).unwrap_or_else(|| base.receipts[i].clone());
        let c = ctx(issuer, &f);
        let got = catch_unwind(AssertUnwindSafe(|| label(proof::verify_encoded(&env, &c, &m, &r, &previous))))
            .unwrap_or_else(|_| "RUST-PANIC".into());
        let py = case["python"].as_str().unwrap();
        let mark = if got == py { "same" } else { "DIFF" };
        println!("{mark} {:48} python={py:22} rust={got}", case["name"].as_str().unwrap());
        assert_ne!(got, "RUST-PANIC", "{}", case["name"]);
        if got == "ACCEPT" && py != "ACCEPT" {
            laxer.push(case["name"].as_str().unwrap().to_string());
        }
    }
    assert!(laxer.is_empty(), "Rust accepted what the oracle rejected: {laxer:?}");
}

/// Source-schema rejections the oracle does not enforce; Rust must.
#[test]
fn review_rust_rejects_schema_invalid_sources_oracle_accepts() {
    let Ok(path) = std::env::var("REVIEW_DIFFERENTIAL") else { panic!("unset") };
    let cases: Vec<Value> = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let f = fixture();
    let base = rows(&f);
    for (name, want) in [
        ("rv-receipt-web-bogus-version", "receipt-canonical"),
        ("manifest-empty-entries", "manifest-canonical"),
        ("manifest-bad-writer", "manifest-canonical"),
    ] {
        let case = cases.iter().find(|c| c["name"] == name).unwrap();
        let i = case["base"].as_u64().unwrap() as usize;
        let previous = if i == 0 { Frontier::default() } else { base.verified[i - 1].frontier().clone() };
        let got = label(proof::verify_encoded(
            &raw(&case["envelopeHex"]),
            &ctx(f["pinnedIssuer"].as_str().unwrap(), &f),
            &raw(&case["manifestHex"]),
            &raw(&case["receiptHex"]),
            &previous,
        ));
        assert_eq!(got, want, "{name}");
    }
}

#[test]
fn review_verify_at_labels_fork_height_and_genesis() {
    let f = fixture();
    let b = rows(&f);
    let issuer = f["pinnedIssuer"].as_str().unwrap();
    let c = ctx(issuer, &f);
    let (m0, r0) = (decode_record(&b.manifests[0]), decode_record(&b.receipts[0]));
    let (m1, r1) = (decode_record(&b.manifests[1]), decode_record(&b.receipts[1]));
    // Descend from row 2: its signed predecessor names the exact row-1 statement.
    let top = proof::verify_at(&b.envelopes[1], &c, &m1, &r1, b.verified[1].frontier()).unwrap();
    assert_eq!(top.previous(), b.verified[0].frontier());
    // Fork: a validly signed alternate row 1 (same manifest/receipt, other time).
    let fork = proof::issue(&signer(1), &c, &m0, &r0, &Frontier::default(), Purpose::Admitted,
        b.verified[0].issued_at() + 7).unwrap();
    assert_eq!(label(proof::verify_at(fork.bytes(), &c, &m0, &r0, top.previous())), "pinned-frontier");
    // Fork accepted by plain verify from genesis: verify alone is not a pin.
    assert_eq!(label(proof::verify(fork.bytes(), &c, &m0, &r0, &Frontier::default())), "ACCEPT");
    // Wrong height and splice.
    assert_eq!(label(proof::verify_at(&b.envelopes[0], &c, &m0, &r0, b.verified[1].frontier())), "pinned-frontier");
    assert_eq!(label(proof::verify_at(&b.envelopes[1], &c, &m1, &r1, b.verified[0].frontier())), "pinned-frontier");
    // Past genesis.
    assert_eq!(label(proof::verify_at(&b.envelopes[0], &c, &m0, &r0, &Frontier::default())), "row-after-genesis");
    // Pinned row but foreign configured archive/issuer in the expected frontier.
    let mut foreign = b.verified[1].frontier().clone();
    foreign.archive = Some([7; 32]);
    assert_eq!(label(proof::verify_at(&b.envelopes[1], &c, &m1, &r1, &foreign)), "pinned-frontier");
    // Framing label parity between verify and verify_at for the same bytes.
    let mut trailing = b.envelopes[0].clone();
    trailing.push(0);
    let via_verify = label(proof::verify(&trailing, &c, &m0, &r0, &Frontier::default()));
    let via_at = label(proof::verify_at(&trailing, &c, &m0, &r0, b.verified[0].frontier()));
    println!("trailing envelope: verify={via_verify} verify_at={via_at}");
    assert!(via_at != "ACCEPT");
}

#[test]
fn review_predecessor_is_caller_authority() {
    // verify() trusts whatever predecessor it is handed: build it from the row itself.
    let f = fixture();
    let b = rows(&f);
    let issuer = f["pinnedIssuer"].as_str().unwrap();
    let c = ctx(issuer, &f);
    let (m1, r1) = (decode_record(&b.manifests[1]), decode_record(&b.receipts[1]));
    let self_derived = Frontier {
        through: 1,
        manifest: b.verified[0].frontier().manifest.clone(),
        attestation: b.verified[0].frontier().attestation.clone(),
        archive: Some(c.archive),
        scope: Some(c.scope),
        issuer: Some(issuer.into()),
    };
    // Row 1 is never verified here; row 2 still yields a Verified.
    assert_eq!(label(proof::verify(&b.envelopes[1], &c, &m1, &r1, &self_derived)), "ACCEPT");
}

#[test]
fn review_codec_permits_store_level_invariants() {
    // Pure codec: duplicate manifest across heights and retained-verified before
    // admitted are individually valid. The planned store must refuse both.
    let f = fixture();
    let b = rows(&f);
    let issuer = f["pinnedIssuer"].as_str().unwrap();
    let c = ctx(issuer, &f);
    let key = signer(1);
    let (m0, r0) = (decode_record(&b.manifests[0]), decode_record(&b.receipts[0]));
    let rv = proof::issue(&key, &c, &m0, &r0, &Frontier::default(), Purpose::RetainedVerified, 5).unwrap();
    let again = proof::issue(&key, &c, &m0, &r0, rv.frontier(), Purpose::Admitted, 4).unwrap();
    assert_eq!(again.frontier().through, 2);
    assert_eq!(again.frontier().manifest, rv.frontier().manifest);
    // issuedAt regression accepted (issuer observation, not ordering authority).
    assert!(again.issued_at() < rv.issued_at());
    // Admitted with a historical receipt issuer is refused even by the signer.
    let (m1, r1) = (decode_record(&b.manifests[1]), decode_record(&b.receipts[1]));
    assert_eq!(label(proof::issue(&key, &c, &m1, &r1, b.verified[0].frontier(), Purpose::Admitted, 9)), "admitted-issuer");
    // Signer for a different key than the configured issuer.
    assert_eq!(label(proof::issue(&signer(2), &c, &m0, &r0, &Frontier::default(), Purpose::Admitted, 9)), "pinned-issuer");
}

fn issuer_statement_label(did: &str) -> String {
    let f = fixture();
    let b = rows(&f);
    let row = &f["positive"][0];
    let mut statement = ipld(&row["statement"]);
    if let Ipld::Map(top) = &mut statement {
        if let Some(Ipld::Map(body)) = top.get_mut("body") {
            let author = Ipld::Map(
                [
                    ("principal".to_string(), Ipld::String(did.into())),
                    ("verificationMethod".to_string(), Ipld::String(format!("{did}#{}", did.get(8..).unwrap_or("")))),
                    (
                        "identityVersion".to_string(),
                        Ipld::Map([("kind".to_string(), Ipld::String("static".into())), ("value".to_string(), Ipld::Null)].into()),
                    ),
                ]
                .into(),
            );
            body.insert("issuer".into(), author);
        }
    }
    let envelope = atproto_dasl::to_vec(&Ipld::Map(
        [
            ("statement".to_string(), Ipld::Bytes(atproto_dasl::to_vec(&statement).unwrap())),
            ("signature".to_string(), Ipld::Bytes(vec![1; 64])),
        ]
        .into(),
    ))
    .unwrap();
    let c = proof::Context { issuer: did, archive: raw(&f["archiveHex"]).try_into().unwrap(), scope: raw(&f["scopeHex"]).try_into().unwrap() };
    catch_unwind(AssertUnwindSafe(|| {
        label(proof::verify_encoded(&envelope, &c, &b.manifests[0], &b.receipts[0], &Frontier::default()))
    }))
    .unwrap_or_else(|_| "RUST-PANIC".into())
}

#[test]
fn review_short_did_never_reaches_dependency_panic() {
    for did in ["did:key:z", "did:key:z2", "did:key:z1", "did:key:zz"] {
        let got = issuer_statement_label(did);
        println!("{did:14} -> {got}");
        assert_eq!(got, "issuer-encoding", "{did}");
    }
}

#[test]
fn review_hostile_bytes_never_accept_or_panic() {
    let f = fixture();
    let b = rows(&f);
    let issuer = f["pinnedIssuer"].as_str().unwrap();
    let c = ctx(issuer, &f);
    let mut checked = 0usize;
    for i in 0..2 {
        let previous = if i == 0 { Frontier::default() } else { b.verified[0].frontier().clone() };
        let (m, r) = (decode_record(&b.manifests[i]), decode_record(&b.receipts[i]));
        let parts: [&Vec<u8>; 3] = [&b.envelopes[i], &b.manifests[i], &b.receipts[i]];
        for (which, original) in parts.iter().enumerate() {
            let mut variants: Vec<Vec<u8>> = (0..original.len()).map(|n| original[..n].to_vec()).collect();
            for at in 0..original.len() {
                for x in [0x01u8, 0x80, 0xff] {
                    let mut v = original.to_vec();
                    v[at] ^= x;
                    variants.push(v);
                }
            }
            for v in variants {
                let (e, mb, rb) = match which {
                    0 => (v.clone(), b.manifests[i].clone(), b.receipts[i].clone()),
                    1 => (b.envelopes[i].clone(), v.clone(), b.receipts[i].clone()),
                    _ => (b.envelopes[i].clone(), b.manifests[i].clone(), v.clone()),
                };
                let outcome = catch_unwind(AssertUnwindSafe(|| {
                    let a = label(proof::verify_encoded(&e, &c, &mb, &rb, &previous));
                    let at = if which == 0 {
                        label(proof::verify_at(&e, &c, &m, &r, b.verified[i].frontier()))
                    } else {
                        "n/a".into()
                    };
                    (a, at)
                }));
                let (a, at) = outcome.unwrap_or_else(|_| panic!("panic on part {which} row {i}"));
                assert_ne!(a, "ACCEPT", "mutated part {which} row {i} accepted");
                assert_ne!(at, "ACCEPT", "verify_at accepted mutated envelope row {i}");
                checked += 1;
            }
        }
    }
    println!("{checked} hostile byte variants rejected without panic");
}
