use atproto_dasl::Ipld;
use ed25519_dalek::{Signer, SigningKey};
use kan::identity::{
    control::{verify_static_did_key_proof, IdentityVersion, Proof, SigningInput},
    CryptographicValidity,
};

fn input() -> SigningInput {
    SigningInput::new(
        "kan.test.ed25519.v1",
        "vector",
        Ipld::Map(std::collections::BTreeMap::from([(
            "value".to_string(),
            Ipld::String("exact canonical input".to_string()),
        )])),
    )
    .unwrap()
}

fn fingerprint(codec: &[u8], key: &[u8]) -> String {
    let mut multikey = codec.to_vec();
    multikey.extend_from_slice(key);
    atrium_crypto::multibase::encode(atrium_crypto::multibase::Base::Base58Btc, multikey)
}

fn proof(fingerprint: &str, alg: &str, sig: Vec<u8>) -> Proof {
    Proof {
        method: format!("did:key:{fingerprint}#{fingerprint}"),
        controller_state: IdentityVersion::Static,
        alg: alg.to_string(),
        sig,
    }
}

#[test]
fn fixed_ed25519_did_key_vector_verifies_exact_signing_input() {
    let signing = SigningKey::from_bytes(&[0x42; 32]);
    let fingerprint = fingerprint(&[0xed, 0x01], signing.verifying_key().as_bytes());
    let input = input();
    let bytes = input.canonical_bytes().unwrap();
    let signature = signing.sign(&bytes).to_bytes().to_vec();

    assert_eq!(
        fingerprint,
        "z6MkghLt1e8m1fmANsdJJco3aCLV8Xnigr5UWwC3u5iZFPd3"
    );
    assert_eq!(
        signature
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>(),
        "aaadb3db193b9caa67826b4a1bdb27e75dfb5c1c36291a005e3ecbf300b2f8d547dd5ac63c07a8ac93b713a354707edaeb5635045422c7a970479c55965c0806"
    );
    assert_eq!(
        verify_static_did_key_proof(&input, &proof(&fingerprint, "Ed25519", signature)),
        CryptographicValidity::Valid
    );
}

#[test]
fn signature_or_input_mutation_is_invalid() {
    let signing = SigningKey::from_bytes(&[0x42; 32]);
    let fingerprint = fingerprint(&[0xed, 0x01], signing.verifying_key().as_bytes());
    let input = input();
    let signature = signing
        .sign(&input.canonical_bytes().unwrap())
        .to_bytes()
        .to_vec();
    let mut changed_signature = signature.clone();
    changed_signature[0] ^= 1;
    assert_eq!(
        verify_static_did_key_proof(&input, &proof(&fingerprint, "Ed25519", changed_signature)),
        CryptographicValidity::Invalid
    );

    let changed_input = SigningInput::new(
        "kan.test.ed25519.v1",
        "changed-vector",
        input.payload.clone(),
    )
    .unwrap();
    assert_eq!(
        verify_static_did_key_proof(&changed_input, &proof(&fingerprint, "Ed25519", signature)),
        CryptographicValidity::Invalid
    );
}

#[test]
fn strict_verification_rejects_weak_keys_and_noncanonical_signatures() {
    let input = input();
    let weak = fingerprint(&[0xed, 0x01], &[0; 32]);
    assert_eq!(
        verify_static_did_key_proof(&input, &proof(&weak, "Ed25519", vec![0; 64])),
        CryptographicValidity::Invalid
    );

    let signing = SigningKey::from_bytes(&[0x42; 32]);
    let fingerprint = fingerprint(&[0xed, 0x01], signing.verifying_key().as_bytes());
    let mut noncanonical = signing
        .sign(&input.canonical_bytes().unwrap())
        .to_bytes()
        .to_vec();
    noncanonical[32..].fill(0xff);
    assert_eq!(
        verify_static_did_key_proof(&input, &proof(&fingerprint, "Ed25519", noncanonical)),
        CryptographicValidity::Invalid
    );
}

#[test]
fn algorithm_substitution_is_invalid_and_unknown_codecs_are_unsupported() {
    let signing = SigningKey::from_bytes(&[0x42; 32]);
    let ed25519 = fingerprint(&[0xed, 0x01], signing.verifying_key().as_bytes());
    let input = input();
    let signature = signing
        .sign(&input.canonical_bytes().unwrap())
        .to_bytes()
        .to_vec();
    assert_eq!(
        verify_static_did_key_proof(&input, &proof(&ed25519, "P256", signature.clone())),
        CryptographicValidity::Invalid
    );

    let unknown = fingerprint(&[0x01, 0x01], signing.verifying_key().as_bytes());
    assert_eq!(
        verify_static_did_key_proof(&input, &proof(&unknown, "Ed25519", signature)),
        CryptographicValidity::Unsupported
    );
}
