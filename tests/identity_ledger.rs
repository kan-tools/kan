use std::collections::BTreeMap;

use atproto_dasl::Ipld;
use kan::{
    identity::{
        control::{ControlEvent, IdentityVersion, Proof, SigningInput},
        ledger::{Error, IdentityLedger},
    },
    sign::Identity,
};

fn input() -> SigningInput {
    SigningInput::new(
        "kan.test.ledger.v1",
        "test",
        Ipld::Map(BTreeMap::from([(
            "message".to_string(),
            Ipld::String("retained exactly".to_string()),
        )])),
    )
    .unwrap()
}

fn proof(identity: &Identity, input: &SigningInput) -> Proof {
    Proof {
        method: format!(
            "{}#{}",
            identity.did(),
            identity.did().strip_prefix("did:key:").unwrap()
        ),
        controller_state: IdentityVersion::Static,
        alg: "P256".to_string(),
        sig: identity.sign(&input.canonical_bytes().unwrap()).unwrap(),
    }
}

#[test]
fn append_is_idempotent_and_reopen_preserves_proof_variants() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("identity").join("ledger");
    let ledger = IdentityLedger::at(&root);
    assert!(ledger.read_all().unwrap().is_empty());
    assert!(!root.exists(), "a read-only open must create nothing");

    let first_identity = Identity::generate();
    let second_identity = Identity::generate();
    let input = input();
    let first = ControlEvent::new(input.clone(), vec![proof(&first_identity, &input)]).unwrap();
    let second = ControlEvent::new(input.clone(), vec![proof(&second_identity, &input)]).unwrap();
    assert_eq!(first.logical_cid().unwrap(), second.logical_cid().unwrap());
    assert_ne!(first.proved_cid().unwrap(), second.proved_cid().unwrap());

    let first_id = ledger.append(&first).unwrap();
    assert_eq!(ledger.append(&first).unwrap(), first_id);
    let second_id = ledger.append(&second).unwrap();

    let reopened = IdentityLedger::at(&root).read_all().unwrap();
    assert_eq!(reopened.len(), 2);
    let mut proved = reopened
        .iter()
        .map(|event| event.proved_cid().unwrap())
        .collect::<Vec<_>>();
    proved.sort_by_key(|cid| cid.to_bytes());
    let mut expected = vec![first_id, second_id];
    expected.sort_by_key(|cid| cid.to_bytes());
    assert_eq!(proved, expected);
}

#[test]
fn lossless_additive_events_round_trip_without_narrowing() {
    let temp = tempfile::tempdir().unwrap();
    let ledger = IdentityLedger::at(temp.path().join("identity").join("ledger"));
    let identity = Identity::generate();
    let input = input();
    let event = ControlEvent::new(input.clone(), vec![proof(&identity, &input)]).unwrap();
    let encoded = event.canonical_bytes().unwrap();
    let mut raw: Ipld = atproto_dasl::from_reader(&encoded[..]).unwrap();
    let Ipld::Map(fields) = &mut raw else {
        unreachable!();
    };
    fields.insert("futureEnvelopeField".to_string(), Ipld::Bool(true));
    let future_bytes = atproto_dasl::to_vec(&raw).unwrap();

    let proved = ledger.append_canonical(&future_bytes).unwrap();
    let events = ledger.read_all().unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].proved_cid().unwrap(), proved);
    assert_eq!(events[0].canonical_bytes(), future_bytes);
    assert_eq!(
        events[0].unsupported_fields(),
        &["futureEnvelopeField".to_string()]
    );
}

#[test]
fn temporary_residue_is_ignored_but_address_mismatch_fails_closed() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("identity").join("ledger");
    let ledger = IdentityLedger::at(&root);
    let identity = Identity::generate();
    let input = input();
    let event = ControlEvent::new(input.clone(), vec![proof(&identity, &input)]).unwrap();
    ledger.append(&event).unwrap();
    let events_dir = root.join("events");
    std::fs::write(events_dir.join(".tmp-interrupted"), b"partial").unwrap();
    assert_eq!(ledger.read_all().unwrap().len(), 1);

    let stored = events_dir.join(format!("{}.cbor", event.proved_cid().unwrap()));
    let wrong = events_dir.join(format!("{}.cbor", input.logical_cid().unwrap()));
    std::fs::rename(stored, wrong).unwrap();
    assert!(matches!(
        ledger.read_all(),
        Err(Error::IdentifierMismatch { .. })
    ));
}

#[cfg(unix)]
#[test]
fn append_refuses_a_symlinked_events_directory() {
    use std::os::unix::fs::symlink;

    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("identity").join("ledger");
    let outside = temp.path().join("outside");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::create_dir_all(&outside).unwrap();
    symlink(&outside, root.join("events")).unwrap();
    let identity = Identity::generate();
    let input = input();
    let event = ControlEvent::new(input.clone(), vec![proof(&identity, &input)]).unwrap();

    assert!(matches!(
        IdentityLedger::at(&root).append(&event),
        Err(Error::UnsafeEntry(_))
    ));
    assert!(std::fs::read_dir(outside).unwrap().next().is_none());
}
