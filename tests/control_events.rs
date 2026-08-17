use std::collections::BTreeMap;

use atproto_dasl::Ipld;
use kan::{
    identity::{
        control::{
            verify_static_did_key_proof, ControlEvent, Error, IdentityVersion, Proof, SigningInput,
        },
        CryptographicValidity,
    },
    sign::Identity,
};

fn payload(nonce: u8) -> Ipld {
    Ipld::Map(BTreeMap::from([
        ("nonce".to_string(), Ipld::Bytes(vec![nonce; 32])),
        ("v".to_string(), Ipld::Integer(1)),
    ]))
}

fn method(did: &str) -> String {
    format!("{did}#{}", did.strip_prefix("did:key:").unwrap())
}

fn signed_proof(input: &SigningInput, identity: &Identity) -> Proof {
    Proof {
        method: method(&identity.did()),
        controller_state: IdentityVersion::Static,
        alg: "P256".to_string(),
        sig: identity.sign(&input.canonical_bytes().unwrap()).unwrap(),
    }
}

#[test]
fn identity_versions_encode_the_required_kind_and_value_fields() {
    let static_bytes = atproto_dasl::to_vec(&IdentityVersion::Static).unwrap();
    let decoded: Ipld = atproto_dasl::from_reader(&static_bytes[..]).unwrap();
    assert_eq!(
        decoded,
        Ipld::Map(BTreeMap::from([
            ("kind".to_string(), Ipld::String("static".to_string())),
            ("value".to_string(), Ipld::Null),
        ]))
    );
    let version: IdentityVersion = atproto_dasl::from_reader(&static_bytes[..]).unwrap();
    assert_eq!(version, IdentityVersion::Static);
}

#[test]
fn proof_bytes_change_the_proved_cid_but_not_the_logical_event() {
    let input = SigningInput::new("kan.did.genesis.v1", "genesis", payload(7)).unwrap();
    let identity = Identity::generate();
    let event = ControlEvent::new(input.clone(), vec![signed_proof(&input, &identity)]).unwrap();
    let mut changed = event.clone();
    changed.proofs[0].sig[0] ^= 0x01;

    assert_eq!(event.logical_cid().unwrap(), changed.logical_cid().unwrap());
    assert_ne!(event.proved_cid().unwrap(), changed.proved_cid().unwrap());
}

#[test]
fn domain_separation_changes_the_message_and_invalidates_the_proof() {
    let identity = Identity::generate();
    let genesis = SigningInput::new("kan.did.genesis.v1", "genesis", payload(1)).unwrap();
    let proof = signed_proof(&genesis, &identity);
    let repository = SigningInput::new("kan.repo.inception.v1", "genesis", payload(1)).unwrap();

    assert_eq!(
        verify_static_did_key_proof(&genesis, &proof),
        CryptographicValidity::Valid
    );
    assert_eq!(
        verify_static_did_key_proof(&repository, &proof),
        CryptographicValidity::Invalid
    );
    assert_ne!(
        genesis.logical_cid().unwrap(),
        repository.logical_cid().unwrap()
    );
}

#[test]
fn constructor_sorts_proofs_and_validator_rejects_unsorted_input() {
    let input = SigningInput::new("kan.test.v1", "test", payload(2)).unwrap();
    let first = Identity::generate();
    let second = Identity::generate();
    let one = signed_proof(&input, &first);
    let two = signed_proof(&input, &second);
    let canonical = ControlEvent::new(input.clone(), vec![two.clone(), one.clone()]).unwrap();

    assert!(canonical.proofs[0].method < canonical.proofs[1].method);
    let mut reversed = canonical.clone();
    reversed.proofs.reverse();
    assert!(matches!(reversed.validate(), Err(Error::UnsortedProofs)));
}

#[test]
fn duplicate_proof_identity_is_rejected_even_when_signature_bytes_differ() {
    let input = SigningInput::new("kan.test.v1", "test", payload(3)).unwrap();
    let identity = Identity::generate();
    let proof = signed_proof(&input, &identity);
    let mut alternate = proof.clone();
    alternate.sig[0] ^= 0x01;

    assert!(matches!(
        ControlEvent::new(input, vec![proof, alternate]),
        Err(Error::DuplicateProof)
    ));
}

#[test]
fn common_envelope_rejects_non_map_and_float_payloads() {
    assert!(matches!(
        SigningInput::new("kan.test.v1", "test", Ipld::List(vec![])),
        Err(Error::PayloadNotMap)
    ));
    assert!(matches!(
        SigningInput::new(
            "kan.test.v1",
            "test",
            Ipld::Map(BTreeMap::from([(
                "notAllowed".to_string(),
                Ipld::Float(1.5),
            )])),
        ),
        Err(Error::FloatNotAllowed)
    ));
}

#[test]
fn static_proof_requires_the_exact_absolute_method_fragment() {
    let input = SigningInput::new("kan.test.v1", "test", payload(4)).unwrap();
    let identity = Identity::generate();
    let mut proof = signed_proof(&input, &identity);
    proof.method = format!("{}#wrong", identity.did());

    assert_eq!(
        verify_static_did_key_proof(&input, &proof),
        CryptographicValidity::Invalid
    );
}
