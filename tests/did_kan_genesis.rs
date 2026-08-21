use kan::{
    identity::{
        control::{IdentityVersion, Proof},
        did_kan::{
            DidKanGenesis, Error, Service, VerificationMethod, VerificationPurpose, GENESIS_DOMAIN,
            GENESIS_EVENT_TYPE,
        },
    },
    sign::Identity,
};

const RECOVERY: &str = "did:key:zDnaenWDM6qp5Ra829d9wPUzBKBA3V6fm2cg4KVP3WFKqsYTv";

fn vector_genesis() -> DidKanGenesis {
    DidKanGenesis::new(
        [0x11; 32],
        vec![RECOVERY.to_string()],
        vec![RECOVERY.to_string()],
        vec![],
        vec![],
    )
    .unwrap()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn verification_method() -> VerificationMethod {
    let (_, multikey) =
        atrium_crypto::multibase::decode(RECOVERY.strip_prefix("did:key:").unwrap()).unwrap();
    VerificationMethod {
        id: format!("{RECOVERY}#{}", RECOVERY.strip_prefix("did:key:").unwrap()),
        controller: RECOVERY.to_string(),
        alg: "P256".to_string(),
        public_key: multikey[2..].to_vec(),
        purposes: vec![
            VerificationPurpose::Recovery,
            VerificationPurpose::Assertion,
        ],
    }
}

#[test]
fn fixed_genesis_vector_pins_canonical_bytes_and_did() {
    let genesis = vector_genesis();
    let bytes = hex(&genesis.canonical_bytes().unwrap());
    let did = genesis.did().unwrap();
    assert_eq!(
        bytes,
        "a7617601656e6f6e636558201111111111111111111111111111111111111111111111111111111111111111687365727669636573806d7265636f7665727945706f636800737265636f76657279436f6e74726f6c6c6572738178396469643a6b65793a7a446e61656e57444d36717035526138323964397750557a424b4241335636666d326367344b56503357464b717359547673766572696669636174696f6e4d6574686f647380781961646d696e697374726174696f6e436f6e74726f6c6c6572738178396469643a6b65793a7a446e61656e57444d36717035526138323964397750557a424b4241335636666d326367344b56503357464b7173595476"
    );
    assert_eq!(
        did,
        "did:kan:bciqmjeylstwnlm7bwtqgfe3somb7dl2n45pmm636dj747olz6jdek2a"
    );
}

#[test]
fn signing_input_uses_the_genesis_domain_and_exact_payload_bytes() {
    let genesis = vector_genesis();
    let input = genesis.signing_input().unwrap();

    assert_eq!(input.domain, GENESIS_DOMAIN);
    assert_eq!(input.event_type, GENESIS_EVENT_TYPE);
    assert_eq!(
        atproto_dasl::to_vec(&input.payload).unwrap(),
        genesis.canonical_bytes().unwrap()
    );
}

#[test]
fn changing_any_identifier_input_changes_the_did() {
    let baseline = vector_genesis();
    let baseline_did = baseline.did().unwrap();

    let changed_nonce = DidKanGenesis::new(
        [0x12; 32],
        baseline.recovery_controllers.clone(),
        baseline.administration_controllers.clone(),
        vec![],
        vec![],
    )
    .unwrap();
    let second = "did:key:zDnaeZQRXpcTkQojRMTux2jYL8UDJvJAtLdyP7V3i36KcjjZF".to_string();
    let changed_controllers = DidKanGenesis::new(
        [0x11; 32],
        vec![RECOVERY.to_string(), second.clone()],
        vec![RECOVERY.to_string(), second],
        vec![],
        vec![],
    )
    .unwrap();
    let changed_method = DidKanGenesis::new(
        [0x11; 32],
        baseline.recovery_controllers.clone(),
        baseline.administration_controllers.clone(),
        vec![verification_method()],
        vec![],
    )
    .unwrap();
    let changed_service = DidKanGenesis::new(
        [0x11; 32],
        baseline.recovery_controllers.clone(),
        baseline.administration_controllers.clone(),
        vec![],
        vec![Service {
            id: "did:web:example.com#inbox".to_string(),
            service_type: "KanInbox".to_string(),
            endpoint: "https://example.com/kan".to_string(),
        }],
    )
    .unwrap();

    assert_ne!(baseline_did, changed_nonce.did().unwrap());
    assert_ne!(baseline_did, changed_controllers.did().unwrap());
    assert_ne!(baseline_did, changed_method.did().unwrap());
    assert_ne!(baseline_did, changed_service.did().unwrap());
}

#[test]
fn constructor_sorts_but_never_silently_deduplicates_controllers() {
    let second = "did:key:zDnaeZQRXpcTkQojRMTux2jYL8UDJvJAtLdyP7V3i36KcjjZF".to_string();
    let sorted = DidKanGenesis::new(
        [0x22; 32],
        vec![RECOVERY.to_string(), second.clone()],
        vec![RECOVERY.to_string(), second],
        vec![],
        vec![],
    )
    .unwrap();
    assert!(sorted
        .recovery_controllers
        .windows(2)
        .all(|pair| pair[0] < pair[1]));

    assert!(matches!(
        DidKanGenesis::new(
            [0x22; 32],
            vec![RECOVERY.to_string(), RECOVERY.to_string()],
            vec![RECOVERY.to_string()],
            vec![],
            vec![],
        ),
        Err(Error::Duplicate("recoveryControllers"))
    ));
}

#[test]
fn genesis_rejects_non_self_certifying_recovery_controllers() {
    assert!(matches!(
        DidKanGenesis::new(
            [0x33; 32],
            vec!["did:web:example.com".to_string()],
            vec![RECOVERY.to_string()],
            vec![],
            vec![],
        ),
        Err(Error::RecoveryController(_))
    ));
}

#[test]
fn verification_purposes_are_sorted_by_their_wire_names() {
    let genesis = DidKanGenesis::new(
        [0x44; 32],
        vec![RECOVERY.to_string()],
        vec![RECOVERY.to_string()],
        vec![verification_method()],
        vec![],
    )
    .unwrap();

    assert_eq!(
        genesis.verification_methods[0].purposes,
        vec![
            VerificationPurpose::Assertion,
            VerificationPurpose::Recovery,
        ]
    );
}

#[test]
fn proved_genesis_requires_a_valid_listed_recovery_controller() {
    let recovery = Identity::generate();
    let did = recovery.did();
    let genesis = DidKanGenesis::new(
        [0x55; 32],
        vec![did.clone()],
        vec![did.clone()],
        vec![],
        vec![],
    )
    .unwrap();
    let input = genesis.signing_input().unwrap();
    let proof_for = |identity: &Identity| Proof {
        method: format!(
            "{}#{}",
            identity.did(),
            identity.did().strip_prefix("did:key:").unwrap()
        ),
        controller_state: IdentityVersion::Static,
        alg: "P256".to_string(),
        sig: identity.sign(&input.canonical_bytes().unwrap()).unwrap(),
    };

    let event = genesis.proved_event(vec![proof_for(&recovery)]).unwrap();
    assert_eq!(event.logical_cid().unwrap(), input.logical_cid().unwrap());

    let stranger = Identity::generate();
    assert!(matches!(
        genesis.proved_event(vec![proof_for(&stranger)]),
        Err(Error::NoRecoveryProof)
    ));
}
