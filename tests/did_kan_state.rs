use kan::{
    cid::content_cid,
    identity::{
        did_kan::{DidKanGenesis, Service, VerificationMethod, VerificationPurpose},
        did_kan_state::{DidKanState, Error, IdentityOperation},
    },
    sign::Identity,
};

fn method(identity: &Identity, name: &str) -> VerificationMethod {
    let did = identity.did();
    let (_, multikey) =
        atrium_crypto::multibase::decode(did.strip_prefix("did:key:").unwrap()).unwrap();
    VerificationMethod {
        id: format!("{did}#{name}"),
        controller: did,
        alg: "P256".to_string(),
        public_key: multikey[2..].to_vec(),
        purposes: vec![VerificationPurpose::Administration],
    }
}

fn state() -> (DidKanState, Identity, Identity) {
    let recovery = Identity::generate();
    let administrator = Identity::generate();
    let genesis = DidKanGenesis::new(
        [0x66; 32],
        vec![recovery.did()],
        vec![administrator.did()],
        vec![],
        vec![],
    )
    .unwrap();
    (
        DidKanState::from_genesis(&genesis).unwrap(),
        recovery,
        administrator,
    )
}

#[test]
fn genesis_projects_to_sequence_zero_without_conflating_did_and_event() {
    let (state, _, _) = state();

    assert_eq!(state.sequence, 0);
    assert_eq!(state.recovery_epoch, 0);
    assert!(state.did.starts_with("did:kan:"));
    assert_ne!(state.did, state.event.to_string());
}

#[test]
fn administration_applies_operations_in_order_and_preserves_recovery_authority() {
    let (state, _, old_administrator) = state();
    let new_administrator = Identity::generate();
    let device = Identity::generate();
    let device_method = method(&device, "daily");
    let service = Service {
        id: format!("{}#inbox", state.did),
        service_type: "KanInbox".to_string(),
        endpoint: "https://example.com/kan".to_string(),
    };
    let next_event = content_cid(&"administration-1").unwrap();

    let next = state
        .apply_administration(
            next_event.clone(),
            &[
                IdentityOperation::AddAdministrationController(new_administrator.did()),
                IdentityOperation::RemoveAdministrationController(old_administrator.did()),
                IdentityOperation::AddMethod(device_method.clone()),
                IdentityOperation::SetMethodPurposes {
                    id: device_method.id.clone(),
                    purposes: vec![
                        VerificationPurpose::Assertion,
                        VerificationPurpose::Authentication,
                    ],
                },
                IdentityOperation::AddService(service.clone()),
            ],
        )
        .unwrap();

    assert_eq!(next.event, next_event);
    assert_eq!(next.sequence, 1);
    assert_eq!(next.recovery_epoch, state.recovery_epoch);
    assert_eq!(next.recovery_controllers, state.recovery_controllers);
    assert_eq!(
        next.administration_controllers,
        vec![new_administrator.did()]
    );
    assert_eq!(next.verification_methods[0].id, device_method.id);
    assert_eq!(
        next.verification_methods[0].purposes,
        vec![
            VerificationPurpose::Assertion,
            VerificationPurpose::Authentication,
        ]
    );
    assert_eq!(next.services, vec![service]);
}

#[test]
fn listed_order_is_semantic() {
    let (state, _, _) = state();
    let device = Identity::generate();
    let device_method = method(&device, "daily");
    let event = content_cid(&"ordered").unwrap();

    assert!(state
        .apply_administration(
            event.clone(),
            &[
                IdentityOperation::AddMethod(device_method.clone()),
                IdentityOperation::SetMethodPurposes {
                    id: device_method.id.clone(),
                    purposes: vec![VerificationPurpose::Assertion],
                },
            ],
        )
        .is_ok());
    assert!(matches!(
        state.apply_administration(
            event.clone(),
            &[
                IdentityOperation::SetMethodPurposes {
                    id: device_method.id.clone(),
                    purposes: vec![VerificationPurpose::Assertion],
                },
                IdentityOperation::AddMethod(device_method),
            ],
        ),
        Err(Error::MissingMethod(_))
    ));
}

#[test]
fn administration_rejects_recovery_changes_and_empty_controller_results() {
    let (state, recovery, administrator) = state();
    let event = content_cid(&"invalid-administration").unwrap();

    assert!(matches!(
        state.apply_administration(
            event.clone(),
            &[IdentityOperation::RemoveRecoveryController(recovery.did())]
        ),
        Err(Error::RecoveryOperationInAdministration)
    ));
    assert!(matches!(
        state.apply_administration(
            event.clone(),
            &[IdentityOperation::RemoveAdministrationController(
                administrator.did()
            )]
        ),
        Err(Error::NoAdministrationControllers)
    ));
    assert!(matches!(
        state.apply_administration(event.clone(), &[]),
        Err(Error::EmptyOperations)
    ));
}

#[test]
fn duplicate_ids_fail_instead_of_overwriting_state() {
    let (state, _, administrator) = state();
    let device = Identity::generate();
    let device_method = method(&device, "daily");
    let event = content_cid(&"duplicates").unwrap();

    assert!(matches!(
        state.apply_administration(
            event.clone(),
            &[
                IdentityOperation::AddMethod(device_method.clone()),
                IdentityOperation::AddMethod(device_method),
            ]
        ),
        Err(Error::DuplicateMethod(_))
    ));
    assert!(matches!(
        state.apply_administration(
            event,
            &[IdentityOperation::AddAdministrationController(
                administrator.did()
            )]
        ),
        Err(Error::DuplicateAdministrationController(_))
    ));
}

#[test]
fn absent_removal_stays_blocked_until_rfc1_defines_its_validity() {
    let (state, _, _) = state();
    let event = content_cid(&"absent-removal").unwrap();

    assert!(matches!(
        state.apply_administration(
            event,
            &[IdentityOperation::RemoveService(format!(
                "{}#missing",
                state.did
            ))]
        ),
        Err(Error::UndefinedRemovalTarget(_))
    ));
}
