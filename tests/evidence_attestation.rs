#![cfg(feature = "v2-storage")]
use atproto_dasl::Ipld;
use kan::{
    evidence::{self, Decoded, Record},
    evidence_attestation::{self as proof, Frontier, Purpose},
    evidence_service::{hex, unhex},
    sign::Identity,
};
use serde_json::Value;
fn fixture() -> Value {
    serde_json::from_str(include_str!(
        "../.design/fixtures/service-attestation-v1.json"
    ))
    .unwrap()
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
        Value::Object(m) if m.len() == 1 && m.contains_key("$bytes") => {
            Ipld::Bytes(raw(&m["$bytes"]))
        }
        Value::Object(m) if m.len() == 1 && m.contains_key("$link") => {
            Ipld::Link(m["$link"].as_str().unwrap().parse().unwrap())
        }
        Value::Object(m) => Ipld::Map(m.iter().map(|(k, v)| (k.clone(), ipld(v))).collect()),
    }
}
fn record(value: &Value) -> Record {
    let Decoded::Known(r) = evidence::encode(&ipld(value)).unwrap() else {
        panic!("known record")
    };
    r
}
fn signer() -> Identity {
    let f = tempfile::NamedTempFile::new().unwrap();
    let mut scalar = [0; 32];
    scalar[31] = 1;
    std::fs::write(f.path(), scalar).unwrap();
    Identity::load_existing(f.path()).unwrap()
}
fn context(issuer: &str) -> proof::Context<'_> {
    proof::Context {
        issuer,
        archive: [9; 32],
        scope: [3; 32],
    }
}
fn verified_rows(f: &Value) -> Vec<proof::Verified> {
    let mut previous = Frontier::default();
    let mut rows = Vec::new();
    for row in f["positive"].as_array().unwrap() {
        let p = proof::verify(
            &raw(&row["envelopeHex"]),
            &context(f["pinnedIssuer"].as_str().unwrap()),
            &record(&row["manifest"]),
            &record(&row["receipt"]),
            &previous,
        )
        .unwrap();
        previous = p.frontier().clone();
        rows.push(p);
    }
    rows
}
#[test]
fn independent_bytes_signatures_and_chain_match() {
    let f = fixture();
    let verified = verified_rows(&f);
    let mut previous = Frontier::default();
    let key = signer();
    assert_eq!(key.did().to_string(), f["pinnedIssuer"]);
    for (row, p) in f["positive"].as_array().unwrap().iter().zip(verified) {
        assert_eq!(hex(p.statement_bytes()), row["statementHex"]);
        assert_eq!(
            p.frontier().attestation.as_ref().unwrap().to_string(),
            row["statementCid"]
        );
        assert_eq!(hex(&p.signing_preimage()), row["signingHex"]);
        assert_eq!(p.purpose().as_str(), row["name"]);
        assert_eq!(
            p.issued_at(),
            row["statement"]["body"]["issuedAt"].as_u64().unwrap()
        );
        let issued = proof::issue(
            &key,
            &context(f["pinnedIssuer"].as_str().unwrap()),
            &record(&row["manifest"]),
            &record(&row["receipt"]),
            &previous,
            p.purpose(),
            p.issued_at(),
        )
        .unwrap();
        assert_eq!(
            issued.bytes(),
            p.bytes(),
            "deterministic P-256 exact oracle parity"
        );
        previous = p.frontier().clone();
    }
}
#[test]
fn independent_resigned_negative_vectors_fail_at_named_check() {
    let f = fixture();
    let verified = verified_rows(&f);
    for negative in f["negative"].as_array().unwrap() {
        let i = negative["base"].as_u64().unwrap() as usize;
        let row = &f["positive"][i];
        let issuer = negative
            .get("pinnedIssuer")
            .unwrap_or(&f["pinnedIssuer"])
            .as_str()
            .unwrap();
        let ctx = proof::Context {
            issuer,
            archive: raw(negative.get("archiveHex").unwrap_or(&f["archiveHex"]))
                .try_into()
                .unwrap(),
            scope: raw(negative.get("scopeHex").unwrap_or(&f["scopeHex"]))
                .try_into()
                .unwrap(),
        };
        let previous = if i == 0 {
            Frontier::default()
        } else {
            verified[i - 1].frontier().clone()
        };
        let error = proof::verify_encoded(
            &raw(&negative["envelopeHex"]),
            &ctx,
            &raw(negative.get("manifestHex").unwrap_or(&row["manifestHex"])),
            &raw(negative.get("receiptHex").unwrap_or(&row["receiptHex"])),
            &previous,
        )
        .expect_err(negative["name"].as_str().unwrap());
        let evidence::Error::Schema(label) = error else {
            panic!("unclassified rejection: {error}")
        };
        assert_eq!(
            label, negative["expected"],
            "negative {} must trip its intended check",
            negative["name"]
        );
    }
}
#[test]
fn valid_same_manifest_alternate_statement_does_not_replace_pinned_predecessor() {
    let f = fixture();
    let verified = verified_rows(&f);
    let row = &f["positive"][0];
    let next = &f["positive"][1];
    let ctx = context(f["pinnedIssuer"].as_str().unwrap());
    let alternate = proof::issue(
        &signer(),
        &ctx,
        &record(&row["manifest"]),
        &record(&row["receipt"]),
        &Frontier::default(),
        Purpose::Admitted,
        verified[0].issued_at() + 1,
    )
    .unwrap();
    assert_ne!(
        alternate.frontier().attestation,
        verified[0].frontier().attestation
    );
    assert_eq!(
        alternate.frontier().manifest,
        verified[0].frontier().manifest
    );
    assert!(proof::verify(
        &raw(&next["envelopeHex"]),
        &ctx,
        &record(&next["manifest"]),
        &record(&next["receipt"]),
        alternate.frontier()
    )
    .is_err());
}
#[test]
fn issuance_cannot_sign_mismatched_records_or_overflow_frontiers() {
    let f = fixture();
    let row = &f["positive"][0];
    let key = signer();
    let m = record(&row["manifest"]);
    let r = record(&row["receipt"]);
    let ctx = context(f["pinnedIssuer"].as_str().unwrap());
    let mut wrong = context(ctx.issuer);
    wrong.scope = [4; 32];
    assert!(proof::issue(
        &key,
        &wrong,
        &m,
        &r,
        &Frontier::default(),
        Purpose::Admitted,
        1
    )
    .is_err());
    assert!(proof::issue(
        &Identity::generate(),
        &ctx,
        &m,
        &r,
        &Frontier::default(),
        Purpose::Admitted,
        1
    )
    .is_err());
    let valid = verified_rows(&f)[0].frontier().clone();
    for previous in [
        Frontier {
            through: u64::MAX,
            ..valid.clone()
        },
        Frontier {
            through: 1,
            ..Frontier::default()
        },
        Frontier {
            through: 0,
            ..valid.clone()
        },
        Frontier {
            through: 9_007_199_254_740_991,
            ..valid
        },
    ] {
        assert!(proof::issue(&key, &ctx, &m, &r, &previous, Purpose::Admitted, 1).is_err());
    }
    assert!(proof::issue(
        &key,
        &ctx,
        &m,
        &r,
        &Frontier::default(),
        Purpose::Admitted,
        u64::MAX
    )
    .is_err());
}

#[test]
fn descending_pages_link_to_the_exact_pin_and_terminate_at_genesis() {
    let f = fixture();
    let verified = verified_rows(&f);
    let ctx = context(f["pinnedIssuer"].as_str().unwrap());
    let mut frontier = verified.last().unwrap().frontier().clone();
    for row in f["positive"].as_array().unwrap().iter().rev() {
        let p = proof::verify_at(
            &raw(&row["envelopeHex"]),
            &ctx,
            &record(&row["manifest"]),
            &record(&row["receipt"]),
            &frontier,
        )
        .unwrap();
        frontier = p.previous().clone();
    }
    assert_eq!(frontier, Frontier::default());
    let row = &f["positive"][1];
    let m = record(&row["manifest"]);
    let r = record(&row["receipt"]);
    assert!(proof::verify_at(&raw(&row["envelopeHex"]), &ctx, &m, &r, &frontier).is_err());
    let alternate = proof::issue(
        &signer(),
        &ctx,
        &m,
        &r,
        verified[0].frontier(),
        Purpose::RetainedVerified,
        verified[1].issued_at() + 1,
    )
    .unwrap();
    assert!(
        proof::verify_at(alternate.bytes(), &ctx, &m, &r, verified[1].frontier()).is_err(),
        "same-height fork must fail at pinned frontier"
    );
    assert!(
        proof::verify_at(
            &raw(&row["envelopeHex"]),
            &ctx,
            &m,
            &r,
            verified[0].frontier()
        )
        .is_err(),
        "wrong page height must fail"
    );
}
