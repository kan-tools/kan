use atproto_dasl::Ipld;
use kan::{
    cid::content_cid,
    identity::{
        control::{ControlEvent, IdentityVersion, Proof, SigningInput},
        governance::{
            resolve, GovernanceEvent, GovernanceMode, GovernanceResolution, GovernanceState,
            NonActiveGovernanceStanding, GOVERNANCE_DOMAIN, GOVERNANCE_EVENT_TYPE,
        },
        repository_inception::RepositoryInception,
    },
    sign::Identity,
};

const VECTOR_ROOT: &str = "did:key:zDnaenWDM6qp5Ra829d9wPUzBKBA3V6fm2cg4KVP3WFKqsYTv";

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

fn repository(root: &Identity) -> (RepositoryInception, ControlEvent, GovernanceState) {
    let inception = RepositoryInception::new(
        [0x71; 32],
        vec!["governed".to_string()],
        vec![root.did()],
        vec![],
    )
    .unwrap();
    let input = inception.signing_input().unwrap();
    let event = inception.proved_event(vec![proof(root, &input)]).unwrap();
    let state = GovernanceState::from_inception(&inception).unwrap();
    (inception, event, state)
}

fn proved(
    payload: &GovernanceEvent,
    parents: &[GovernanceState],
    signers: &[&Identity],
) -> (ControlEvent, GovernanceState) {
    let input = payload.signing_input().unwrap();
    let event = payload
        .proved_event(
            parents,
            signers.iter().map(|signer| proof(signer, &input)).collect(),
        )
        .unwrap();
    let state = payload
        .resulting_state(parents, event.logical_cid().unwrap())
        .unwrap();
    (event, state)
}

fn active(result: GovernanceResolution) -> kan::identity::governance::ActiveGovernance {
    match result {
        GovernanceResolution::Active(active) => active,
        other => panic!("expected active governance, found {other:?}"),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn fixed_update_vector_pins_domain_payload_and_logical_identifier() {
    let inception =
        RepositoryInception::new([0x72; 32], vec![], vec![VECTOR_ROOT.to_string()], vec![])
            .unwrap();
    let state = GovernanceState::from_inception(&inception).unwrap();
    let update = GovernanceEvent::update(&state, vec![VECTOR_ROOT.to_string()]).unwrap();
    let input = update.signing_input().unwrap();

    assert_eq!(input.domain, GOVERNANCE_DOMAIN);
    assert_eq!(input.event_type, GOVERNANCE_EVENT_TYPE);
    assert_eq!(
        hex(&update.canonical_bytes().unwrap()),
        "a6617601646d6f64656675706461746567706172656e747381d82a58250001711220bed7f40df21a4c571b4406cfd0ba1f29f0e6ce523a411a74595bff7d71bbdaf56873657175656e6365016a7265706f7369746f727978416b616e2d7265706f3a6263697170706434323362716763366864677470626b666b6f7971337835616774717a3233336164357a346d64347779357a66746f3775696f676f7665726e616e6365526f6f74738178396469643a6b65793a7a446e61656e57444d36717035526138323964397750557a424b4241335636666d326367344b56503357464b7173595476"
    );
    assert_eq!(
        input.logical_cid().unwrap().to_string(),
        "bafyreiew5smxe66aed37yhsrgfvwzbr72dryn7wd5b2uyslz2sn5wyuadi"
    );
}

#[test]
fn reversed_linear_evidence_resolves_to_the_same_active_state() {
    let root_a = Identity::generate();
    let root_b = Identity::generate();
    let root_c = Identity::generate();
    let (inception, inception_event, state_0) = repository(&root_a);
    let update_1 = GovernanceEvent::update(&state_0, vec![root_b.did()]).unwrap();
    let (event_1, state_1) = proved(&update_1, &[state_0], &[&root_a]);
    let update_2 = GovernanceEvent::update(&state_1, vec![root_c.did()]).unwrap();
    let (event_2, _) = proved(&update_2, &[state_1], &[&root_b]);

    let forward = resolve(
        &inception,
        &inception_event,
        &[event_1.clone(), event_2.clone()],
    );
    let reverse = resolve(&inception, &inception_event, &[event_2, event_1]);

    assert_eq!(forward, reverse);
    assert_eq!(active(forward).governance_roots, vec![root_c.did()]);
}

#[test]
fn sibling_updates_are_contested_regardless_of_input_order() {
    let root_a = Identity::generate();
    let root_b = Identity::generate();
    let root_c = Identity::generate();
    let (inception, inception_event, state_0) = repository(&root_a);
    let left = GovernanceEvent::update(&state_0, vec![root_b.did()]).unwrap();
    let right = GovernanceEvent::update(&state_0, vec![root_c.did()]).unwrap();
    let (left_event, _) = proved(&left, std::slice::from_ref(&state_0), &[&root_a]);
    let (right_event, _) = proved(&right, &[state_0], &[&root_a]);

    let first = resolve(
        &inception,
        &inception_event,
        &[left_event.clone(), right_event.clone()],
    );
    let second = resolve(&inception, &inception_event, &[right_event, left_event]);

    assert_eq!(first, second);
    let GovernanceResolution::NonActive(result) = first else {
        panic!("fork must be contested");
    };
    assert_eq!(result.standing, NonActiveGovernanceStanding::Contested);
    assert_eq!(result.active_leaves.len(), 2);
}

#[test]
fn reconciliation_requires_authorization_at_every_parent_and_closes_the_fork() {
    let root_a = Identity::generate();
    let root_b = Identity::generate();
    let root_c = Identity::generate();
    let root_d = Identity::generate();
    let (inception, inception_event, state_0) = repository(&root_a);
    let inception_id = state_0.event.clone();
    let left = GovernanceEvent::update(&state_0, vec![root_b.did()]).unwrap();
    let right = GovernanceEvent::update(&state_0, vec![root_c.did()]).unwrap();
    let (left_event, left_state) = proved(&left, std::slice::from_ref(&state_0), &[&root_a]);
    let (right_event, right_state) = proved(&right, &[state_0], &[&root_a]);
    let left_id = left_event.logical_cid().unwrap();
    let right_id = right_event.logical_cid().unwrap();
    let reconcile = GovernanceEvent::reconcile(
        &[left_state.clone(), right_state.clone()],
        vec![root_d.did()],
    )
    .unwrap();
    let input = reconcile.signing_input().unwrap();
    assert!(reconcile
        .proved_event(
            &[left_state.clone(), right_state.clone()],
            vec![proof(&root_b, &input)]
        )
        .is_err());
    let (reconcile_event, _) = proved(&reconcile, &[left_state, right_state], &[&root_b, &root_c]);
    let reconcile_id = reconcile_event.logical_cid().unwrap();

    let result = resolve(
        &inception,
        &inception_event,
        &[reconcile_event, right_event, left_event],
    );
    let resolved = active(result);
    assert_eq!(resolved.governance_roots, vec![root_d.did()]);
    assert_eq!(resolved.ancestral_events().len(), 4);
    for expected in [inception_id, left_id, right_id, reconcile_id] {
        assert!(resolved.ancestral_events().contains(&expected));
    }
}

#[test]
fn proof_variants_collapse_by_logical_event_identifier() {
    let root = Identity::generate();
    let next_root = Identity::generate();
    let stranger = Identity::generate();
    let (inception, inception_event, state) = repository(&root);
    let update = GovernanceEvent::update(&state, vec![next_root.did()]).unwrap();
    let input = update.signing_input().unwrap();
    let valid = ControlEvent::new(input.clone(), vec![proof(&root, &input)]).unwrap();
    let invalid = ControlEvent::new(input.clone(), vec![proof(&stranger, &input)]).unwrap();
    assert_eq!(valid.logical_cid().unwrap(), invalid.logical_cid().unwrap());

    let result = resolve(&inception, &inception_event, &[invalid, valid]);
    assert_eq!(active(result).governance_roots, vec![next_root.did()]);
}

#[test]
fn a_noncanonical_proof_variant_does_not_poison_a_valid_variant() {
    let root = Identity::generate();
    let next_root = Identity::generate();
    let (inception, inception_event, state) = repository(&root);
    let update = GovernanceEvent::update(&state, vec![next_root.did()]).unwrap();
    let input = update.signing_input().unwrap();
    let valid = ControlEvent::new(input.clone(), vec![proof(&root, &input)]).unwrap();
    let mut noncanonical = valid.clone();
    noncanonical.proofs.push(noncanonical.proofs[0].clone());

    let result = resolve(&inception, &inception_event, &[noncanonical, valid]);
    assert_eq!(active(result).governance_roots, vec![next_root.did()]);
}

#[test]
fn a_missing_update_parent_is_an_orphan_but_does_not_poison_the_active_head() {
    let root = Identity::generate();
    let (inception, inception_event, state) = repository(&root);
    let missing = content_cid(&"missing-governance-parent").unwrap();
    let update = GovernanceEvent::new(
        GovernanceMode::Update,
        state.repository.clone(),
        vec![missing.clone()],
        1,
        vec![root.did()],
    )
    .unwrap();
    let input = update.signing_input().unwrap();
    let orphan = ControlEvent::new(input.clone(), vec![proof(&root, &input)]).unwrap();

    let result = active(resolve(&inception, &inception_event, &[orphan]));
    assert_eq!(result.active_event, state.event);
    assert_eq!(result.orphans.len(), 1);
    assert_eq!(result.missing_references, vec![missing]);
}

#[test]
fn an_authenticated_reconciliation_with_a_missing_parent_is_unknown_history() {
    let root = Identity::generate();
    let (inception, inception_event, state) = repository(&root);
    let missing = content_cid(&"missing-reconciliation-parent").unwrap();
    let reconcile = GovernanceEvent::new(
        GovernanceMode::Reconcile,
        state.repository.clone(),
        vec![state.event.clone(), missing.clone()],
        1,
        vec![root.did()],
    )
    .unwrap();
    let input = reconcile.signing_input().unwrap();
    let candidate = ControlEvent::new(input.clone(), vec![proof(&root, &input)]).unwrap();

    let GovernanceResolution::NonActive(result) =
        resolve(&inception, &inception_event, &[candidate])
    else {
        panic!("credible missing reconciliation must be non-active");
    };
    assert_eq!(result.standing, NonActiveGovernanceStanding::UnknownHistory);
    assert_eq!(result.missing_references, vec![missing]);
}

#[test]
fn an_authorized_additive_field_is_unsupported_without_displacing_its_parent() {
    let root = Identity::generate();
    let (inception, inception_event, state) = repository(&root);
    let update = GovernanceEvent::update(&state, vec![root.did()]).unwrap();
    let mut input = update.signing_input().unwrap();
    let Ipld::Map(fields) = &mut input.payload else {
        unreachable!();
    };
    fields.insert("future".to_string(), Ipld::String("preserved".to_string()));
    let candidate = ControlEvent::new(input.clone(), vec![proof(&root, &input)]).unwrap();

    let GovernanceResolution::NonActive(result) =
        resolve(&inception, &inception_event, &[candidate])
    else {
        panic!("authorized unknown field must be unsupported");
    };
    assert_eq!(result.standing, NonActiveGovernanceStanding::Unsupported);
    assert_eq!(result.known_leaves, vec![state.event]);
    assert_eq!(result.orphans.len(), 1);
}

#[test]
fn an_invalid_sequence_is_disclosed_and_ignored() {
    let root = Identity::generate();
    let (inception, inception_event, state) = repository(&root);
    let invalid = GovernanceEvent::new(
        GovernanceMode::Update,
        state.repository.clone(),
        vec![state.event.clone()],
        7,
        vec![root.did()],
    )
    .unwrap();
    let input = invalid.signing_input().unwrap();
    let candidate = ControlEvent::new(input.clone(), vec![proof(&root, &input)]).unwrap();

    let result = active(resolve(&inception, &inception_event, &[candidate]));
    assert_eq!(result.active_event, state.event);
    assert_eq!(result.orphans.len(), 1);
    assert!(result
        .diagnostics
        .iter()
        .any(|reason| reason.contains("sequence must be 1")));
}

#[test]
fn an_authorized_future_version_is_unsupported_but_an_unreachable_one_is_only_an_orphan() {
    let root = Identity::generate();
    let (inception, inception_event, state) = repository(&root);
    let update = GovernanceEvent::update(&state, vec![root.did()]).unwrap();
    let mut recognized_input = update.signing_input().unwrap();
    let Ipld::Map(fields) = &mut recognized_input.payload else {
        unreachable!();
    };
    fields.insert("v".to_string(), Ipld::Integer(2));
    let recognized = ControlEvent::new(
        recognized_input.clone(),
        vec![proof(&root, &recognized_input)],
    )
    .unwrap();

    let GovernanceResolution::NonActive(result) =
        resolve(&inception, &inception_event, &[recognized])
    else {
        panic!("authorized future version must be unsupported");
    };
    assert_eq!(result.standing, NonActiveGovernanceStanding::Unsupported);

    let missing = content_cid(&"future-version-missing-parent").unwrap();
    let unreachable = GovernanceEvent::new(
        GovernanceMode::Update,
        state.repository.clone(),
        vec![missing.clone()],
        1,
        vec![root.did()],
    )
    .unwrap();
    let mut unreachable_input = unreachable.signing_input().unwrap();
    let Ipld::Map(fields) = &mut unreachable_input.payload else {
        unreachable!();
    };
    fields.insert("v".to_string(), Ipld::Integer(2));
    let unreachable = ControlEvent::new(
        unreachable_input.clone(),
        vec![proof(&root, &unreachable_input)],
    )
    .unwrap();

    let result = active(resolve(&inception, &inception_event, &[unreachable]));
    assert_eq!(result.active_event, state.event);
    assert_eq!(result.missing_references, vec![missing]);
    assert_eq!(result.orphans.len(), 1);
}

#[test]
fn an_invalid_present_parent_is_not_misreported_as_missing_history() {
    let root = Identity::generate();
    let (inception, inception_event, state) = repository(&root);
    let invalid_parent = GovernanceEvent::new(
        GovernanceMode::Update,
        state.repository.clone(),
        vec![state.event.clone()],
        9,
        vec![root.did()],
    )
    .unwrap();
    let invalid_input = invalid_parent.signing_input().unwrap();
    let invalid_event =
        ControlEvent::new(invalid_input.clone(), vec![proof(&root, &invalid_input)]).unwrap();
    let invalid_id = invalid_event.logical_cid().unwrap();
    let reconcile = GovernanceEvent::new(
        GovernanceMode::Reconcile,
        state.repository.clone(),
        vec![state.event.clone(), invalid_id],
        1,
        vec![root.did()],
    )
    .unwrap();
    let reconcile_input = reconcile.signing_input().unwrap();
    let reconcile_event = ControlEvent::new(
        reconcile_input.clone(),
        vec![proof(&root, &reconcile_input)],
    )
    .unwrap();

    let result = active(resolve(
        &inception,
        &inception_event,
        &[reconcile_event, invalid_event],
    ));
    assert_eq!(result.active_event, state.event);
    assert!(result.missing_references.is_empty());
    assert_eq!(result.orphans.len(), 2);
}
