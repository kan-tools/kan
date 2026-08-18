use kan::{
    identity::{
        control::IdentityVersion,
        did_kan::VerificationPurpose,
        did_kan_update::{resolve, DidKanResolution},
        enrollment::{DailyDeviceEnrollment, Error},
        system::{CredentialReference, SystemIdentityStore},
    },
    sign::Identity,
};

fn plan(root: &std::path::Path, nonce: [u8; 32]) -> (DailyDeviceEnrollment, Identity, Identity) {
    let recovery = Identity::generate();
    let daily = Identity::generate();
    recovery
        .save(&root.join("credentials").join("recovery.key"))
        .unwrap();
    daily
        .save(&root.join("credentials").join("daily.key"))
        .unwrap();
    let plan = DailyDeviceEnrollment::new(
        nonce,
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
    (plan, recovery, daily)
}

#[test]
fn plan_creates_genesis_then_an_invocable_daily_device_state() {
    let temp = tempfile::tempdir().unwrap();
    let (plan, recovery, daily) = plan(temp.path(), [0x31; 32]);
    let genesis = plan.genesis();
    assert_eq!(genesis.recovery_controllers, vec![recovery.did()]);
    assert_eq!(genesis.administration_controllers, vec![recovery.did()]);
    assert!(genesis.verification_methods.is_empty());

    let resolved = resolve(
        genesis,
        plan.genesis_event(),
        &[plan.administration_event().clone()],
    );
    let DidKanResolution::Active(active) = resolved else {
        panic!("daily enrollment must resolve active: {resolved:?}");
    };
    assert_eq!(
        active.verification_methods,
        vec![plan.daily_method().clone()]
    );
    assert_eq!(
        plan.daily_method().purposes,
        vec![
            VerificationPurpose::Administration,
            VerificationPurpose::Assertion,
            VerificationPurpose::Authentication,
            VerificationPurpose::CapabilityDelegation,
            VerificationPurpose::CapabilityInvocation,
        ]
    );
    assert_ne!(recovery.did(), daily.did());
    assert_eq!(plan.profile().principal(), active.did);
    assert_eq!(
        plan.profile().actor().controller_state(),
        &IdentityVersion::Event(active.active_event)
    );
}

#[test]
fn install_proves_the_credential_then_publishes_events_then_selects_profile() {
    let temp = tempfile::tempdir().unwrap();
    let (plan, _, _) = plan(temp.path(), [0x41; 32]);
    let installed = plan.install(temp.path()).unwrap();
    assert_eq!(plan.install(temp.path()).unwrap(), installed);

    let store = SystemIdentityStore::at(temp.path());
    assert_eq!(
        store.default_profile().unwrap(),
        Some(plan.profile().clone())
    );
    let events =
        kan::identity::ledger::IdentityLedger::at(temp.path().join("identity").join("ledger"))
            .read_all()
            .unwrap();
    assert_eq!(events.len(), 2);
    assert_eq!(installed.principal, plan.profile().principal());
    assert_eq!(
        installed.genesis_event,
        plan.genesis_event().proved_cid().unwrap()
    );
    assert_eq!(
        installed.administration_event,
        plan.administration_event().proved_cid().unwrap()
    );
}

#[test]
fn absent_or_substituted_credential_selects_nothing_and_publishes_nothing() {
    let temp = tempfile::tempdir().unwrap();
    let recovery = Identity::generate();
    let daily = Identity::generate();
    recovery
        .save(&temp.path().join("credentials").join("recovery.key"))
        .unwrap();
    let plan = DailyDeviceEnrollment::new(
        [0x51; 32],
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
    assert!(matches!(plan.install(temp.path()), Err(Error::Profile(_))));
    assert_uninitialized(temp.path());

    Identity::generate()
        .save(&temp.path().join("credentials").join("daily.key"))
        .unwrap();
    assert!(matches!(plan.install(temp.path()), Err(Error::Profile(_))));
    assert_uninitialized(temp.path());
}

#[test]
fn ledger_failure_never_makes_the_actor_selectable() {
    let temp = tempfile::tempdir().unwrap();
    let (plan, _, _) = plan(temp.path(), [0x61; 32]);
    let events = temp.path().join("identity").join("ledger").join("events");
    std::fs::create_dir_all(events.parent().unwrap()).unwrap();
    std::fs::write(&events, b"not a directory").unwrap();

    assert!(matches!(plan.install(temp.path()), Err(Error::Profile(_))));
    let store = SystemIdentityStore::at(temp.path());
    assert!(store.default_profile().unwrap().is_none());
    assert!(store.profile("daily").unwrap().is_none());
}

#[test]
fn external_provider_refusal_happens_before_public_or_profile_state() {
    let temp = tempfile::tempdir().unwrap();
    let recovery = Identity::generate();
    let daily = Identity::generate();
    let plan = DailyDeviceEnrollment::new(
        [0x71; 32],
        "daily".to_string(),
        &recovery,
        CredentialReference::ExternalSigner {
            uri: "https://signer.example/recovery".to_string(),
        },
        &daily,
        CredentialReference::ExternalSigner {
            uri: "https://signer.example/device".to_string(),
        },
    )
    .unwrap();
    assert!(matches!(plan.install(temp.path()), Err(Error::Profile(_))));
    assert_uninitialized(temp.path());
}

#[test]
fn competing_first_enrollments_publish_only_the_selected_history() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().to_path_buf();
    let make = |alias: &str, nonce: u8| {
        let recovery = Identity::generate();
        let daily = Identity::generate();
        recovery
            .save(
                &root
                    .join("credentials")
                    .join(format!("{alias}-recovery.key")),
            )
            .unwrap();
        daily
            .save(&root.join("credentials").join(format!("{alias}.key")))
            .unwrap();
        DailyDeviceEnrollment::new(
            [nonce; 32],
            alias.to_string(),
            &recovery,
            CredentialReference::OwnerOnlyFile {
                path: format!("{alias}-recovery.key"),
            },
            &daily,
            CredentialReference::OwnerOnlyFile {
                path: format!("{alias}.key"),
            },
        )
        .unwrap()
    };
    let plans = [make("one", 0x81), make("two", 0x82)];
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
    let mut handles = Vec::new();
    for plan in plans.clone() {
        let root = root.clone();
        let barrier = std::sync::Arc::clone(&barrier);
        handles.push(std::thread::spawn(move || {
            barrier.wait();
            plan.install(&root)
        }));
    }
    barrier.wait();
    let outcomes = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(outcomes.iter().filter(|result| result.is_ok()).count(), 1);

    let selected = SystemIdentityStore::at(&root)
        .default_profile()
        .unwrap()
        .unwrap();
    let winner = plans
        .iter()
        .find(|plan| plan.profile().principal() == selected.principal())
        .unwrap();
    let mut actual =
        kan::identity::ledger::IdentityLedger::at(root.join("identity").join("ledger"))
            .read_all()
            .unwrap()
            .into_iter()
            .map(|event| event.proved_cid().unwrap().to_bytes())
            .collect::<Vec<_>>();
    actual.sort();
    let mut expected = vec![
        winner.genesis_event().proved_cid().unwrap().to_bytes(),
        winner
            .administration_event()
            .proved_cid()
            .unwrap()
            .to_bytes(),
    ];
    expected.sort();
    assert_eq!(actual, expected);
}

fn assert_uninitialized(root: &std::path::Path) {
    let store = SystemIdentityStore::at(root);
    assert!(store.default_profile().unwrap().is_none());
    assert!(store.profile("daily").unwrap().is_none());
    assert!(
        kan::identity::ledger::IdentityLedger::at(root.join("identity").join("ledger"))
            .read_all()
            .unwrap()
            .is_empty()
    );
}
