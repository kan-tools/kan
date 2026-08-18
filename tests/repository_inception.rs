use kan::{
    identity::{
        control::{IdentityVersion, Proof},
        did_kan::VerificationPurpose,
        did_kan_update::{resolve, DidKanResolution},
        enrollment::DailyDeviceEnrollment,
        repository_inception::{
            AnchorValue, Error, RepositoryInception, SubstrateAnchor, INCEPTION_DOMAIN,
            INCEPTION_EVENT_TYPE,
        },
        system::CredentialReference,
    },
    sign::Identity,
};

const GOVERNANCE_ROOT: &str = "did:key:zDnaenWDM6qp5Ra829d9wPUzBKBA3V6fm2cg4KVP3WFKqsYTv";

fn vector_inception() -> RepositoryInception {
    RepositoryInception::new(
        [0x22; 32],
        vec!["kan".to_string()],
        vec![GOVERNANCE_ROOT.to_string()],
        vec![SubstrateAnchor {
            anchor_type: "gitCommit".to_string(),
            value: AnchorValue::Text("0000000000000000000000000000000000000000".to_string()),
        }],
    )
    .unwrap()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn proof(identity: &Identity, inception: &RepositoryInception) -> Proof {
    let input = inception.signing_input().unwrap();
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
fn fixed_inception_vector_pins_canonical_bytes_and_repository_id() {
    let inception = vector_inception();

    assert_eq!(
        hex(&inception.canonical_bytes().unwrap()),
        "a5617601656e616d657381636b616e656e6f6e63655820222222222222222222222222222222222222222222222222222222222222222267616e63686f727381a2647479706569676974436f6d6d69746576616c75657828303030303030303030303030303030303030303030303030303030303030303030303030303030306f676f7665726e616e6365526f6f74738178396469643a6b65793a7a446e61656e57444d36717035526138323964397750557a424b4241335636666d326367344b56503357464b7173595476"
    );
    assert_eq!(
        inception.repository_id().unwrap(),
        "kan-repo:bciqlonzrmcwluircewwu7evclx6tdwnc7aupnf6kb5no6nzlegmsiei"
    );
}

#[test]
fn signing_input_uses_the_repository_domain_and_exact_payload() {
    let inception = vector_inception();
    let input = inception.signing_input().unwrap();

    assert_eq!(input.domain, INCEPTION_DOMAIN);
    assert_eq!(input.event_type, INCEPTION_EVENT_TYPE);
    assert_eq!(
        atproto_dasl::to_vec(&input.payload).unwrap(),
        inception.canonical_bytes().unwrap()
    );
}

#[test]
fn constructor_sorts_by_canonical_encoded_value_not_rust_string_order() {
    let inception = RepositoryInception::new(
        [0x33; 32],
        vec!["aa".to_string(), "b".to_string()],
        vec![GOVERNANCE_ROOT.to_string()],
        vec![],
    )
    .unwrap();

    // DAG-CBOR's one-byte text precedes its two-byte text even though Rust's
    // lexical string order would put "aa" first.
    assert_eq!(inception.names, vec!["b", "aa"]);
}

#[test]
fn every_identifier_input_changes_the_repository_id() {
    let baseline = vector_inception();
    let baseline_id = baseline.repository_id().unwrap();

    let changed_nonce = RepositoryInception::new(
        [0x23; 32],
        baseline.names.clone(),
        baseline.governance_roots.clone(),
        baseline.anchors.clone(),
    )
    .unwrap();
    let changed_name = RepositoryInception::new(
        [0x22; 32],
        vec!["kan-tools".to_string()],
        baseline.governance_roots.clone(),
        baseline.anchors.clone(),
    )
    .unwrap();
    let changed_root = RepositoryInception::new(
        [0x22; 32],
        baseline.names.clone(),
        vec![Identity::generate().did()],
        baseline.anchors.clone(),
    )
    .unwrap();
    let changed_anchor = RepositoryInception::new(
        [0x22; 32],
        baseline.names.clone(),
        baseline.governance_roots.clone(),
        vec![SubstrateAnchor {
            anchor_type: "gitCommit".to_string(),
            value: AnchorValue::Text("1111111111111111111111111111111111111111".to_string()),
        }],
    )
    .unwrap();

    assert_ne!(baseline_id, changed_nonce.repository_id().unwrap());
    assert_ne!(baseline_id, changed_name.repository_id().unwrap());
    assert_ne!(baseline_id, changed_root.repository_id().unwrap());
    assert_ne!(baseline_id, changed_anchor.repository_id().unwrap());
}

#[test]
fn duplicate_inputs_and_an_empty_root_set_are_rejected() {
    assert!(matches!(
        RepositoryInception::new(
            [0x44; 32],
            vec!["kan".to_string(), "kan".to_string()],
            vec![GOVERNANCE_ROOT.to_string()],
            vec![],
        ),
        Err(Error::Duplicate("names"))
    ));
    assert!(matches!(
        RepositoryInception::new([0x44; 32], vec![], vec![], vec![]),
        Err(Error::NoGovernanceRoots)
    ));
}

#[test]
fn byte_and_text_anchor_values_round_trip_without_conflation() {
    let inception = RepositoryInception::new(
        [0x45; 32],
        vec![],
        vec![GOVERNANCE_ROOT.to_string()],
        vec![
            SubstrateAnchor {
                anchor_type: "binary".to_string(),
                value: AnchorValue::Bytes(vec![0x61, 0x62]),
            },
            SubstrateAnchor {
                anchor_type: "text".to_string(),
                value: AnchorValue::Text("ab".to_string()),
            },
        ],
    )
    .unwrap();
    let decoded: RepositoryInception =
        atproto_dasl::from_reader(&inception.canonical_bytes().unwrap()[..]).unwrap();

    assert_eq!(decoded, inception);
    assert!(decoded
        .anchors
        .iter()
        .any(|anchor| matches!(&anchor.value, AnchorValue::Bytes(_))));
    assert!(decoded
        .anchors
        .iter()
        .any(|anchor| matches!(&anchor.value, AnchorValue::Text(_))));
}

#[test]
fn proved_inception_requires_a_listed_governance_root() {
    let root = Identity::generate();
    let second_root = Identity::generate();
    let inception = RepositoryInception::new(
        [0x55; 32],
        vec!["kan".to_string()],
        vec![root.did(), second_root.did()],
        vec![],
    )
    .unwrap();

    let one_proof = inception
        .proved_event(vec![proof(&root, &inception)])
        .unwrap();
    let two_proofs = inception
        .proved_event(vec![
            proof(&root, &inception),
            proof(&second_root, &inception),
        ])
        .unwrap();
    assert_eq!(
        one_proof.logical_cid().unwrap(),
        two_proofs.logical_cid().unwrap()
    );
    assert_ne!(
        one_proof.proved_cid().unwrap(),
        two_proofs.proved_cid().unwrap()
    );
    assert_eq!(
        one_proof.signing_input().payload,
        two_proofs.signing_input().payload
    );

    let stranger = Identity::generate();
    assert!(matches!(
        inception.proved_event(vec![proof(&stranger, &inception)]),
        Err(Error::NoGovernanceProof)
    ));
}

#[test]
fn active_did_kan_daily_method_can_govern_repository_inception() {
    let recovery = Identity::generate();
    let daily = Identity::generate();
    let enrollment = DailyDeviceEnrollment::new(
        [0x66; 32],
        "daily".to_string(),
        &recovery,
        CredentialReference::OwnerOnlyFile {
            path: "recovery.key".to_string(),
        },
        &daily,
        CredentialReference::OwnerOnlyFile {
            path: "daily.key".to_string(),
        },
    )
    .unwrap();
    let DidKanResolution::Active(state) = resolve(
        enrollment.genesis(),
        enrollment.genesis_event(),
        &[enrollment.administration_event().clone()],
    ) else {
        panic!("daily enrollment must resolve active");
    };
    let inception = RepositoryInception::new(
        [0x77; 32],
        vec!["kan".to_string()],
        vec![state.did.clone()],
        vec![],
    )
    .unwrap();
    let input = inception.signing_input().unwrap();
    let proof = Proof {
        method: enrollment.daily_method().id.clone(),
        controller_state: IdentityVersion::Event(state.active_event.clone()),
        alg: "P256".to_string(),
        sig: daily.sign(&input.canonical_bytes().unwrap()).unwrap(),
    };

    let event = inception
        .proved_event_with_did_kan_state(&state, vec![proof.clone()])
        .unwrap();
    assert_eq!(event.signing_input(), input);

    let mut wrong_state = proof.clone();
    wrong_state.controller_state =
        IdentityVersion::Event(enrollment.genesis_event().proved_cid().unwrap());
    assert!(matches!(
        inception.proved_event_with_did_kan_state(&state, vec![wrong_state]),
        Err(Error::NoGovernanceProof)
    ));

    let mut no_delegation = (*state).clone();
    no_delegation.verification_methods[0]
        .purposes
        .retain(|purpose| *purpose != VerificationPurpose::CapabilityDelegation);
    assert!(matches!(
        inception.proved_event_with_did_kan_state(&no_delegation, vec![proof.clone()]),
        Err(Error::NoGovernanceProof)
    ));

    let mut bad_signature = proof;
    bad_signature.sig[0] ^= 1;
    assert!(matches!(
        inception.proved_event_with_did_kan_state(&state, vec![bad_signature]),
        Err(Error::NoGovernanceProof)
    ));
}
