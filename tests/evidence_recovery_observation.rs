#![cfg(feature = "v2-storage")]
use kan::{
    evidence_recovery_observation as observation,
    evidence_service::{hex, unhex},
    sign::Identity,
};
use serde_json::Value;
fn fixture() -> Value {
    serde_json::from_str(include_str!(
        "../.design/fixtures/recovery-observation-v1.json"
    ))
    .unwrap()
}
fn raw(v: &Value) -> Vec<u8> {
    unhex(v.as_str().unwrap(), 65536).unwrap()
}
fn context(f: &Value) -> observation::Context {
    let c = &f["context"];
    observation::Context {
        bundle: raw(&c["bundle"]["$bytes"]).try_into().unwrap(),
        profile: c["profile"].as_u64().unwrap() as u8,
        archive: raw(&c["archive"]["$bytes"]).try_into().unwrap(),
        scope: raw(&c["scope"]["$bytes"]).try_into().unwrap(),
        issuer: c["issuer"].as_str().unwrap().into(),
        observer: c["observer"].as_str().unwrap().into(),
    }
}
fn chain(f: &Value) -> Vec<observation::Authenticated> {
    let ctx = context(f);
    let mut chain = Vec::new();
    for row in f["positive"].as_array().unwrap() {
        chain.push(
            observation::authenticate(&raw(&row["envelopeHex"]), &ctx, chain.last()).unwrap(),
        );
    }
    chain
}
fn key(scalar: u8) -> Identity {
    let file = tempfile::NamedTempFile::new().unwrap();
    let mut bytes = [0; 32];
    bytes[31] = scalar;
    std::fs::write(file.path(), bytes).unwrap();
    Identity::load_existing(file.path()).unwrap()
}
#[test]
fn independent_python_bytes_signatures_and_predecessors_match() {
    let f = fixture();
    let rows = chain(&f);
    let ctx = context(&f);
    let key = key(3);
    for (i, (row, verified)) in f["positive"]
        .as_array()
        .unwrap()
        .iter()
        .zip(&rows)
        .enumerate()
    {
        assert_eq!(hex(verified.statement_bytes()), row["statementHex"]);
        assert_eq!(verified.statement_cid().to_string(), row["statementCid"]);
        assert_eq!(hex(&verified.signing_preimage()), row["signingHex"]);
        assert_eq!(hex(verified.bytes()), row["envelopeHex"]);
        assert_eq!(verified.sequence(), i as u64 + 1);
        assert_eq!(verified.context(), &ctx);
        let signed = observation::sign_claim(
            &raw(&row["statementHex"]),
            &key,
            &ctx,
            i.checked_sub(1).map(|j| &rows[j]),
        )
        .unwrap();
        assert_eq!(signed.bytes(), verified.bytes());
    }
}
#[test]
fn independently_resigned_hostile_vectors_refuse_with_named_error() {
    let f = fixture();
    let ctx = context(&f);
    let chain = chain(&f);
    for row in f["negative"].as_array().unwrap() {
        let index = row["base"].as_u64().unwrap() as usize;
        let e = observation::authenticate(
            &raw(&row["envelopeHex"]),
            &ctx,
            index.checked_sub(1).map(|i| &chain[i]),
        )
        .unwrap_err();
        let kan::evidence::Error::Schema(reason) = e else {
            panic!("wrong error: {e:?}")
        };
        assert_eq!(reason, row["expected"], "{}", row["name"]);
    }
}
#[test]
fn caller_pins_predecessors_and_signer_are_not_learned_from_envelope() {
    let f = fixture();
    let ctx = context(&f);
    let chain = chain(&f);
    let rows = f["positive"].as_array().unwrap();
    for kind in 0..6 {
        let mut wrong = ctx.clone();
        match kind {
            0 => wrong.bundle[0] ^= 1,
            1 => wrong.scope[0] ^= 1,
            2 => wrong.archive[0] ^= 1,
            3 => wrong.profile = 3,
            4 => wrong.issuer = key(4).did().to_string(),
            _ => wrong.observer = key(4).did().to_string(),
        }
        assert!(observation::authenticate(chain[0].bytes(), &wrong, None).is_err());
    }
    assert!(observation::authenticate(chain[1].bytes(), &ctx, None).is_err());
    assert!(observation::authenticate(chain[0].bytes(), &ctx, Some(&chain[0])).is_err());
    assert!(observation::authenticate(chain[2].bytes(), &ctx, Some(&chain[0])).is_err());
    assert!(observation::sign_claim(&raw(&rows[0]["statementHex"]), &key(4), &ctx, None).is_err());
    for bad in ["", "did:key:z", "did:key:z000", "did:key:zé"] {
        let mut wrong = ctx.clone();
        wrong.observer = bad.into();
        assert!(observation::authenticate(chain[0].bytes(), &wrong, None).is_err());
    }
}
#[test]
fn truncation_and_oversized_envelopes_cannot_authenticate() {
    let f = fixture();
    let ctx = context(&f);
    let rows = chain(&f);
    for row in rows {
        for end in 0..row.bytes().len() {
            assert!(observation::authenticate(&row.bytes()[..end], &ctx, None).is_err());
        }
    }
    assert!(
        observation::authenticate(&vec![0; observation::MAX_ENVELOPE + 1], &ctx, None).is_err()
    );
}

#[test]
fn independent_maximum_shape_vectors_authenticate_without_claiming_semantics() {
    let f = fixture();
    let ctx = context(&f);
    let chain = chain(&f);
    for row in f["shapePositive"].as_array().unwrap() {
        let index = row["base"].as_u64().unwrap() as usize;
        let previous = index.checked_sub(1).map(|i| &chain[i]);
        let value = observation::authenticate(&raw(&row["envelopeHex"]), &ctx, previous).unwrap();
        assert_eq!(value.statement_cid().to_string(), row["statementCid"]);
        assert_eq!(hex(&value.signing_preimage()), row["signingHex"]);
        let signed =
            observation::sign_claim(&raw(&row["statementHex"]), &key(3), &ctx, previous).unwrap();
        assert_eq!(signed.bytes(), value.bytes());
    }
}

#[test]
fn signed_cross_context_chain_and_profile_confusion_refuse() {
    use atproto_dasl::Ipld;
    let f = fixture();
    let ctx = context(&f);
    let chain = chain(&f);
    let signer = key(3);
    let mut foreign_context = ctx.clone();
    foreign_context.bundle[0] ^= 1;
    foreign_context.profile = 3;
    let mut foreign_statement = chain[0].statement().clone();
    let Ipld::Map(ref mut fields) = foreign_statement else {
        panic!()
    };
    fields.insert(
        "bundle".into(),
        Ipld::Bytes(foreign_context.bundle.to_vec()),
    );
    fields.insert("profile".into(), Ipld::Integer(3));
    let foreign = observation::sign_claim(
        &atproto_dasl::to_vec(&foreign_statement).unwrap(),
        &signer,
        &foreign_context,
        None,
    )
    .unwrap();
    let mut next = chain[1].statement().clone();
    let Ipld::Map(ref mut fields) = next else {
        panic!()
    };
    fields.insert(
        "previous".into(),
        Ipld::Link(foreign.statement_cid().clone()),
    );
    assert!(observation::sign_claim(
        &atproto_dasl::to_vec(&next).unwrap(),
        &signer,
        &ctx,
        Some(&foreign)
    )
    .is_err());
    assert!(observation::authenticate(foreign.bytes(), &ctx, None).is_err());
}

#[test]
fn explicitly_pinned_same_key_roles_are_wire_valid_without_combining_authority() {
    let f = fixture();
    let same = &f["sameKeyRoles"];
    let ctx = context(same);
    assert_eq!(ctx.observer, ctx.issuer);
    let observation = observation::authenticate(&raw(&same["envelopeHex"]), &ctx, None).unwrap();
    assert_eq!(observation.context(), &ctx);
}
