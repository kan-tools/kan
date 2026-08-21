use std::collections::BTreeMap;

use atproto_dasl::Ipld;
use kan::{
    identity::{
        control::{IdentityVersion, Proof, SigningInput},
        did_kan::{DidKanGenesis, Service, VerificationMethod, VerificationPurpose},
        did_kan_state::{DidKanState, IdentityOperation},
        did_kan_update::{
            resolve, DidKanResolution, DidKanUpdate, Error, IdentityUpdateMode,
            NonActiveIdentityStanding, ValidatedDidKanUpdate, UPDATE_DOMAIN,
        },
    },
    sign::Identity,
};

const ROOT: &str = "did:key:zDnaenWDM6qp5Ra829d9wPUzBKBA3V6fm2cg4KVP3WFKqsYTv";
const SECOND: &str = "did:key:zDnaeZQRXpcTkQojRMTux2jYL8UDJvJAtLdyP7V3i36KcjjZF";

fn method(did: &str, fragment: &str, purposes: Vec<VerificationPurpose>) -> VerificationMethod {
    let (_, multikey) =
        atrium_crypto::multibase::decode(did.strip_prefix("did:key:").unwrap()).unwrap();
    VerificationMethod {
        id: format!("{did}#{fragment}"),
        controller: did.to_string(),
        alg: "P256".to_string(),
        public_key: multikey[2..].to_vec(),
        purposes,
    }
}

fn service(did: &str) -> Service {
    Service {
        id: format!("{did}#inbox"),
        service_type: "KanInbox".to_string(),
        endpoint: "https://example.com/kan".to_string(),
    }
}

fn vector_genesis() -> DidKanGenesis {
    DidKanGenesis::new(
        [0x11; 32],
        vec![ROOT.to_string()],
        vec![ROOT.to_string()],
        vec![],
        vec![],
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

fn identity_history(
    root: &Identity,
) -> (
    DidKanGenesis,
    kan::identity::control::ControlEvent,
    DidKanState,
) {
    let genesis = DidKanGenesis::new(
        [0x51; 32],
        vec![root.did()],
        vec![root.did()],
        vec![],
        vec![],
    )
    .unwrap();
    let input = genesis.signing_input().unwrap();
    let event = genesis.proved_event(vec![proof(root, &input)]).unwrap();
    let state = DidKanState::from_genesis(&genesis).unwrap();
    (genesis, event, state)
}

fn proved_update(
    update: &ValidatedDidKanUpdate,
    signer: &Identity,
) -> kan::identity::control::ControlEvent {
    let input = update.signing_input().unwrap();
    update.proved_event(vec![proof(signer, &input)]).unwrap()
}

fn active(result: DidKanResolution) -> kan::identity::did_kan_update::ResolvedDidKanState {
    match result {
        DidKanResolution::Active(active) => *active,
        other => panic!("expected active identity, found {other:?}"),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn every_operation_has_an_exact_typed_internally_tagged_map() {
    let method = method(ROOT, "daily", vec![VerificationPurpose::Administration]);
    let operations = vec![
        (
            IdentityOperation::AddMethod {
                method: method.clone(),
            },
            "addMethod",
            "method",
        ),
        (
            IdentityOperation::RemoveMethod {
                id: method.id.clone(),
            },
            "removeMethod",
            "id",
        ),
        (
            IdentityOperation::SetMethodPurposes {
                id: method.id.clone(),
                purposes: vec![VerificationPurpose::Assertion],
            },
            "setMethodPurposes",
            "id",
        ),
        (
            IdentityOperation::AddAdministrationController {
                did: SECOND.to_string(),
            },
            "addAdministrationController",
            "did",
        ),
        (
            IdentityOperation::RemoveAdministrationController {
                did: ROOT.to_string(),
            },
            "removeAdministrationController",
            "did",
        ),
        (
            IdentityOperation::AddRecoveryController {
                did: SECOND.to_string(),
            },
            "addRecoveryController",
            "did",
        ),
        (
            IdentityOperation::RemoveRecoveryController {
                did: ROOT.to_string(),
            },
            "removeRecoveryController",
            "did",
        ),
        (
            IdentityOperation::AddService {
                service: service(ROOT),
            },
            "addService",
            "service",
        ),
        (
            IdentityOperation::RemoveService {
                id: service(ROOT).id,
            },
            "removeService",
            "id",
        ),
    ];

    for (operation, tag, operand) in operations {
        let bytes = atproto_dasl::to_vec(&operation).unwrap();
        let ipld: Ipld = atproto_dasl::from_reader(&bytes[..]).unwrap();
        let Ipld::Map(fields) = ipld else {
            panic!("operation must encode as a map");
        };
        assert_eq!(fields.get("op"), Some(&Ipld::String(tag.to_string())));
        assert!(fields.contains_key(operand));
        let expected_len = if tag == "setMethodPurposes" { 3 } else { 2 };
        assert_eq!(fields.len(), expected_len);
        let decoded: IdentityOperation = atproto_dasl::from_reader(&bytes[..]).unwrap();
        assert_eq!(decoded, operation);
    }
}

#[test]
fn recovery_controller_operation_vectors_pin_canonical_maps() {
    let add = IdentityOperation::AddRecoveryController {
        did: SECOND.to_string(),
    };
    let remove = IdentityOperation::RemoveRecoveryController {
        did: ROOT.to_string(),
    };

    assert_eq!(
        hex(&atproto_dasl::to_vec(&add).unwrap()),
        "a2626f70756164645265636f76657279436f6e74726f6c6c65726364696478396469643a6b65793a7a446e61655a5152587063546b516f6a524d547578326a594c3855444a764a41744c6479503756336933364b636a6a5a46"
    );
    assert_eq!(
        hex(&atproto_dasl::to_vec(&remove).unwrap()),
        "a2626f70781872656d6f76655265636f76657279436f6e74726f6c6c65726364696478396469643a6b65793a7a446e61656e57444d36717035526138323964397750557a424b4241335636666d326367344b56503357464b7173595476"
    );
}

#[test]
fn fixed_administration_vector_pins_typed_bytes_and_logical_cid() {
    let state = DidKanState::from_genesis(&vector_genesis()).unwrap();
    let daily = method(ROOT, "daily", vec![VerificationPurpose::Administration]);
    let inbox = service(ROOT);
    let update = DidKanUpdate::administration(
        &state,
        vec![
            IdentityOperation::AddAdministrationController {
                did: SECOND.to_string(),
            },
            IdentityOperation::RemoveAdministrationController {
                did: ROOT.to_string(),
            },
            IdentityOperation::AddMethod {
                method: daily.clone(),
            },
            IdentityOperation::SetMethodPurposes {
                id: daily.id.clone(),
                purposes: vec![
                    VerificationPurpose::Assertion,
                    VerificationPurpose::Authentication,
                ],
            },
            IdentityOperation::RemoveMethod {
                id: daily.id.clone(),
            },
            IdentityOperation::AddService {
                service: inbox.clone(),
            },
            IdentityOperation::RemoveService { id: inbox.id },
        ],
    )
    .unwrap();

    assert_eq!(update.payload().mode(), IdentityUpdateMode::Administration);
    assert_eq!(update.signing_input().unwrap().domain, UPDATE_DOMAIN);
    assert_eq!(
        hex(&update.canonical_bytes().unwrap()),
        "a96176016364696478406469643a6b616e3a626369716d6a65796c7374776e6c6d376277747167666533736f6d6237646c326e3435706d6d363336646a3734376f6c7a366a64656b3261646d6f64656e61646d696e697374726174696f6e6870726576696f7573d82a5825000171122010d2be2bfc612b757346d500bb809168ac8d28f3b46eefecfd0deca72db500656873657175656e6365016a6f7065726174696f6e7387a2626f70781b61646441646d696e697374726174696f6e436f6e74726f6c6c65726364696478396469643a6b65793a7a446e61655a5152587063546b516f6a524d547578326a594c3855444a764a41744c6479503756336933364b636a6a5a46a2626f70781e72656d6f766541646d696e697374726174696f6e436f6e74726f6c6c65726364696478396469643a6b65793a7a446e61656e57444d36717035526138323964397750557a424b4241335636666d326367344b56503357464b7173595476a2626f70696164644d6574686f64666d6574686f64a5626964783f6469643a6b65793a7a446e61656e57444d36717035526138323964397750557a424b4241335636666d326367344b56503357464b7173595476236461696c7963616c67645032353668707572706f736573816e61646d696e697374726174696f6e697075626c69634b657958210347f79b24faa9e36e7ca1b012431e13b97e31b533878b1b8664f06abdd3c267856a636f6e74726f6c6c657278396469643a6b65793a7a446e61656e57444d36717035526138323964397750557a424b4241335636666d326367344b56503357464b7173595476a3626964783f6469643a6b65793a7a446e61656e57444d36717035526138323964397750557a424b4241335636666d326367344b56503357464b7173595476236461696c79626f70717365744d6574686f64507572706f73657368707572706f7365738269617373657274696f6e6e61757468656e7469636174696f6ea2626964783f6469643a6b65793a7a446e61656e57444d36717035526138323964397750557a424b4241335636666d326367344b56503357464b7173595476236461696c79626f706c72656d6f76654d6574686f64a2626f706a616464536572766963656773657276696365a3626964783f6469643a6b65793a7a446e61656e57444d36717035526138323964397750557a424b4241335636666d326367344b56503357464b717359547623696e626f786474797065684b616e496e626f7868656e64706f696e747768747470733a2f2f6578616d706c652e636f6d2f6b616ea2626964783f6469643a6b65793a7a446e61656e57444d36717035526138323964397750557a424b4241335636666d326367344b56503357464b717359547623696e626f78626f706d72656d6f7665536572766963656a73757065727365646573806d7265636f7665727945706f6368006e7265636f76657279506172656e74f6"
    );
    assert_eq!(
        update
            .signing_input()
            .unwrap()
            .logical_cid()
            .unwrap()
            .to_string(),
        "bafyreic6kuqtl67f4uffxqtvhzuw45uepq4f2fj6objcsd7komip6ldfqq"
    );
}

#[test]
fn operation_order_is_signed_and_semantic() {
    let initial = method(ROOT, "daily", vec![VerificationPurpose::Administration]);
    let genesis = DidKanGenesis::new(
        [0x31; 32],
        vec![ROOT.to_string()],
        vec![ROOT.to_string()],
        vec![initial.clone()],
        vec![],
    )
    .unwrap();
    let state = DidKanState::from_genesis(&genesis).unwrap();
    let mut replacement = initial.clone();
    replacement.purposes = vec![VerificationPurpose::Assertion];

    assert!(DidKanUpdate::administration(
        &state,
        vec![
            IdentityOperation::RemoveMethod {
                id: initial.id.clone(),
            },
            IdentityOperation::AddMethod {
                method: replacement.clone(),
            },
        ],
    )
    .is_ok());
    assert!(DidKanUpdate::administration(
        &state,
        vec![
            IdentityOperation::AddMethod {
                method: replacement,
            },
            IdentityOperation::RemoveMethod { id: initial.id },
        ],
    )
    .is_err());

    let first = DidKanUpdate::administration(
        &state,
        vec![
            IdentityOperation::AddAdministrationController {
                did: SECOND.to_string(),
            },
            IdentityOperation::AddService {
                service: service(ROOT),
            },
        ],
    )
    .unwrap();
    let second = DidKanUpdate::administration(
        &state,
        vec![
            IdentityOperation::AddService {
                service: service(ROOT),
            },
            IdentityOperation::AddAdministrationController {
                did: SECOND.to_string(),
            },
        ],
    )
    .unwrap();
    assert_eq!(
        first.resulting_state().administration_controllers,
        second.resulting_state().administration_controllers
    );
    assert_eq!(
        first.resulting_state().verification_methods,
        second.resulting_state().verification_methods
    );
    assert_eq!(
        first.resulting_state().services,
        second.resulting_state().services
    );
    assert_ne!(
        first.signing_input().unwrap().logical_cid().unwrap(),
        second.signing_input().unwrap().logical_cid().unwrap()
    );
}

#[test]
fn producer_rejects_absent_removals_for_every_target_class() {
    let state = DidKanState::from_genesis(&vector_genesis()).unwrap();
    let missing_id = format!("{}#missing", state.did);
    for operation in [
        IdentityOperation::RemoveMethod {
            id: missing_id.clone(),
        },
        IdentityOperation::RemoveAdministrationController {
            did: SECOND.to_string(),
        },
        IdentityOperation::RemoveService { id: missing_id },
    ] {
        assert!(DidKanUpdate::administration(&state, vec![operation]).is_err());
    }

    assert!(DidKanUpdate::recovery(
        &state,
        &state,
        vec![IdentityOperation::RemoveRecoveryController {
            did: SECOND.to_string(),
        }],
        vec![],
    )
    .is_err());
}

#[test]
fn recovery_rotates_recovery_authority_but_administration_cannot() {
    let state = DidKanState::from_genesis(&vector_genesis()).unwrap();
    let operations = vec![
        IdentityOperation::AddRecoveryController {
            did: SECOND.to_string(),
        },
        IdentityOperation::RemoveRecoveryController {
            did: ROOT.to_string(),
        },
    ];
    assert!(matches!(
        DidKanUpdate::administration(&state, operations.clone()),
        Err(Error::AdministrationRecoveryOperation)
    ));

    let recovery = DidKanUpdate::recovery(&state, &state, operations, vec![]).unwrap();
    assert_eq!(recovery.payload().mode(), IdentityUpdateMode::Recovery);
    assert_eq!(recovery.payload().recovery_parent(), Some(&state.event));
    assert_eq!(recovery.resulting_state().recovery_epoch, 1);
    assert_eq!(
        recovery.resulting_state().recovery_parent.as_ref(),
        Some(&recovery.resulting_state().event)
    );
    assert_eq!(
        recovery.resulting_state().recovery_controllers,
        vec![SECOND.to_string()]
    );

    let second_recovery = DidKanUpdate::recovery(
        recovery.resulting_state(),
        recovery.resulting_state(),
        vec![
            IdentityOperation::AddRecoveryController {
                did: ROOT.to_string(),
            },
            IdentityOperation::RemoveRecoveryController {
                did: SECOND.to_string(),
            },
        ],
        vec![],
    )
    .unwrap();
    assert_eq!(second_recovery.payload().recovery_epoch(), 2);
    assert_eq!(
        second_recovery.payload().recovery_parent(),
        Some(&recovery.resulting_state().event)
    );
}

#[test]
fn proved_update_requires_the_selected_static_controller() {
    let administrator = Identity::generate();
    let stranger = Identity::generate();
    let genesis = DidKanGenesis::new(
        [0x41; 32],
        vec![administrator.did()],
        vec![administrator.did()],
        vec![],
        vec![],
    )
    .unwrap();
    let state = DidKanState::from_genesis(&genesis).unwrap();
    let update = DidKanUpdate::administration(
        &state,
        vec![IdentityOperation::AddService {
            service: service(&administrator.did()),
        }],
    )
    .unwrap();
    let input = update.signing_input().unwrap();

    assert!(update
        .proved_event(vec![proof(&administrator, &input)])
        .is_ok());
    assert!(matches!(
        update.proved_event(vec![proof(&stranger, &input)]),
        Err(Error::NoAuthorization)
    ));
}

#[test]
fn serde_shape_rejects_additive_fields_on_a_known_operation() {
    let operation = IdentityOperation::RemoveMethod {
        id: format!("{ROOT}#daily"),
    };
    let bytes = atproto_dasl::to_vec(&operation).unwrap();
    let mut fields: BTreeMap<String, Ipld> = atproto_dasl::from_reader(&bytes[..]).unwrap();
    fields.insert("future".to_string(), Ipld::Bool(true));
    let bytes = atproto_dasl::to_vec(&fields).unwrap();

    let decoded: Result<IdentityOperation, _> = atproto_dasl::from_reader(&bytes[..]);
    assert!(decoded.is_err());
}

#[test]
fn reversed_linear_evidence_resolves_to_the_same_active_state() {
    let root = Identity::generate();
    let (genesis, genesis_event, state_0) = identity_history(&root);
    let first = DidKanUpdate::administration(
        &state_0,
        vec![IdentityOperation::AddService {
            service: service(&root.did()),
        }],
    )
    .unwrap();
    let event_1 = proved_update(&first, &root);
    let state_1 = first.resulting_state().clone();
    let second = DidKanUpdate::administration(
        &state_1,
        vec![IdentityOperation::RemoveService {
            id: service(&root.did()).id,
        }],
    )
    .unwrap();
    let event_2 = proved_update(&second, &root);

    let forward = resolve(
        &genesis,
        &genesis_event,
        &[event_1.clone(), event_2.clone()],
    );
    let reverse = resolve(&genesis, &genesis_event, &[event_2, event_1]);
    assert_eq!(forward, reverse);
    assert_eq!(active(forward).active_event, second.resulting_state().event);
}

#[test]
fn sibling_updates_are_contested_and_recovery_can_retire_both() {
    let root = Identity::generate();
    let replacement = Identity::generate();
    let (genesis, genesis_event, state) = identity_history(&root);
    let left = DidKanUpdate::administration(
        &state,
        vec![IdentityOperation::AddService {
            service: Service {
                id: format!("{}#left", root.did()),
                service_type: "Left".to_string(),
                endpoint: "https://left.example".to_string(),
            },
        }],
    )
    .unwrap();
    let right = DidKanUpdate::administration(
        &state,
        vec![IdentityOperation::AddService {
            service: Service {
                id: format!("{}#right", root.did()),
                service_type: "Right".to_string(),
                endpoint: "https://right.example".to_string(),
            },
        }],
    )
    .unwrap();
    let left_event = proved_update(&left, &root);
    let right_event = proved_update(&right, &root);

    let DidKanResolution::NonActive(contested) = resolve(
        &genesis,
        &genesis_event,
        &[right_event.clone(), left_event.clone()],
    ) else {
        panic!("siblings must contest");
    };
    assert_eq!(contested.standing, NonActiveIdentityStanding::Contested);
    assert_eq!(contested.active_leaves.len(), 2);

    let recovery = DidKanUpdate::recovery(
        left.resulting_state(),
        &state,
        vec![
            IdentityOperation::AddRecoveryController {
                did: replacement.did(),
            },
            IdentityOperation::RemoveRecoveryController { did: root.did() },
        ],
        vec![
            left.resulting_state().event.clone(),
            right.resulting_state().event.clone(),
        ],
    )
    .unwrap();
    let recovery_event = proved_update(&recovery, &root);
    let resolved = active(resolve(
        &genesis,
        &genesis_event,
        &[recovery_event, right_event, left_event],
    ));
    assert_eq!(resolved.active_event, recovery.resulting_state().event);
    assert_eq!(resolved.retired_heads.len(), 2);
    assert_eq!(resolved.recovery_controllers, vec![replacement.did()]);
}

#[test]
fn proof_variants_collapse_by_logical_event_identifier() {
    let root = Identity::generate();
    let stranger = Identity::generate();
    let (genesis, genesis_event, state) = identity_history(&root);
    let update = DidKanUpdate::administration(
        &state,
        vec![IdentityOperation::AddService {
            service: service(&root.did()),
        }],
    )
    .unwrap();
    let input = update.signing_input().unwrap();
    let valid = update.proved_event(vec![proof(&root, &input)]).unwrap();
    let invalid =
        kan::identity::control::ControlEvent::new(input.clone(), vec![proof(&stranger, &input)])
            .unwrap();

    assert_eq!(valid.logical_cid().unwrap(), invalid.logical_cid().unwrap());
    assert_eq!(
        active(resolve(&genesis, &genesis_event, &[invalid, valid])).active_event,
        update.resulting_state().event
    );
}

#[test]
fn semantic_invalidity_is_disclosed_without_displacing_the_parent() {
    let root = Identity::generate();
    let (genesis, genesis_event, state) = identity_history(&root);
    let valid = DidKanUpdate::administration(
        &state,
        vec![IdentityOperation::AddService {
            service: service(&root.did()),
        }],
    )
    .unwrap();
    let mut input = valid.signing_input().unwrap();
    let Ipld::Map(payload) = &mut input.payload else {
        unreachable!();
    };
    let Some(Ipld::List(operations)) = payload.get_mut("operations") else {
        unreachable!();
    };
    operations[0] = Ipld::Map(BTreeMap::from([
        (
            "id".to_string(),
            Ipld::String(format!("{}#missing", root.did())),
        ),
        ("op".to_string(), Ipld::String("removeService".to_string())),
    ]));
    let candidate =
        kan::identity::control::ControlEvent::new(input.clone(), vec![proof(&root, &input)])
            .unwrap();

    let resolved = active(resolve(&genesis, &genesis_event, &[candidate]));
    assert_eq!(resolved.active_event, state.event);
    assert_eq!(resolved.orphans.len(), 1);
}

#[test]
fn authenticated_unknown_operation_is_unsupported_without_partial_application() {
    let root = Identity::generate();
    let (genesis, genesis_event, state) = identity_history(&root);
    let valid = DidKanUpdate::administration(
        &state,
        vec![IdentityOperation::AddService {
            service: service(&root.did()),
        }],
    )
    .unwrap();
    let mut input = valid.signing_input().unwrap();
    let Ipld::Map(payload) = &mut input.payload else {
        unreachable!();
    };
    let Some(Ipld::List(operations)) = payload.get_mut("operations") else {
        unreachable!();
    };
    let Ipld::Map(operation) = &mut operations[0] else {
        unreachable!();
    };
    operation.insert(
        "op".to_string(),
        Ipld::String("futureOperation".to_string()),
    );
    let unknown =
        kan::identity::control::ControlEvent::new(input.clone(), vec![proof(&root, &input)])
            .unwrap();

    let mut additive_input = valid.signing_input().unwrap();
    let Ipld::Map(payload) = &mut additive_input.payload else {
        unreachable!();
    };
    let Some(Ipld::List(operations)) = payload.get_mut("operations") else {
        unreachable!();
    };
    let Ipld::Map(operation) = &mut operations[0] else {
        unreachable!();
    };
    operation.insert("future".to_string(), Ipld::Bool(true));
    let additive = kan::identity::control::ControlEvent::new(
        additive_input.clone(),
        vec![proof(&root, &additive_input)],
    )
    .unwrap();

    for candidate in [unknown, additive] {
        let DidKanResolution::NonActive(result) = resolve(&genesis, &genesis_event, &[candidate])
        else {
            panic!("authenticated extension must be unsupported");
        };
        assert_eq!(result.standing, NonActiveIdentityStanding::Unsupported);
        assert_eq!(result.known_leaves, vec![state.event.clone()]);
    }
}

#[test]
fn authenticated_recovery_with_missing_previous_is_unknown_history() {
    let root = Identity::generate();
    let replacement = Identity::generate();
    let (genesis, genesis_event, state) = identity_history(&root);
    let recovery = DidKanUpdate::recovery(
        &state,
        &state,
        vec![
            IdentityOperation::AddRecoveryController {
                did: replacement.did(),
            },
            IdentityOperation::RemoveRecoveryController { did: root.did() },
        ],
        vec![],
    )
    .unwrap();
    let mut input = recovery.signing_input().unwrap();
    let missing = kan::cid::content_cid(&"missing-identity-previous").unwrap();
    let Ipld::Map(payload) = &mut input.payload else {
        unreachable!();
    };
    payload.insert("previous".to_string(), Ipld::Link(missing.clone()));
    let candidate =
        kan::identity::control::ControlEvent::new(input.clone(), vec![proof(&root, &input)])
            .unwrap();

    let DidKanResolution::NonActive(result) = resolve(&genesis, &genesis_event, &[candidate])
    else {
        panic!("credible missing recovery history must be non-active");
    };
    assert_eq!(result.standing, NonActiveIdentityStanding::UnknownHistory);
    assert_eq!(result.missing_references, vec![missing]);
}
