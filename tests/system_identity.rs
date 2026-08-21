use std::sync::{Arc, Barrier};

use kan::{
    identity::{
        control::{verify_static_did_key_proof, IdentityVersion, SigningInput},
        did_kan::{VerificationMethod, VerificationPurpose},
        system::{
            ActorReference, CredentialReference, Error, IdentityProfile, SystemIdentityStore,
        },
        CryptographicValidity,
    },
    sign::Identity,
};

fn actor(identity: &Identity) -> ActorReference {
    let principal = identity.did();
    let fingerprint = principal.strip_prefix("did:key:").unwrap();
    ActorReference::new(
        principal.clone(),
        format!("{principal}#{fingerprint}"),
        IdentityVersion::Static,
    )
    .unwrap()
}

fn profile(alias: &str) -> IdentityProfile {
    let identity = Identity::generate();
    IdentityProfile::new(
        alias.to_string(),
        actor(&identity),
        CredentialReference::OsKeychain {
            service: "dev.kan.identity".to_string(),
            account: format!("profile-{alias}"),
        },
    )
    .unwrap()
}

#[test]
fn reads_create_nothing_and_initialization_round_trips_without_accessing_credentials() {
    let temp = tempfile::tempdir().unwrap();
    let config = temp.path().join("config");
    let store = SystemIdentityStore::at(&config);
    assert!(store.default_profile().unwrap().is_none());
    assert!(store.profile("daily").unwrap().is_none());
    assert!(!config.exists());

    let daily = profile("daily");
    store.initialize(&daily).unwrap();
    store.initialize(&daily).unwrap();
    let reopened = SystemIdentityStore::at(&config);
    assert_eq!(reopened.default_profile().unwrap(), Some(daily.clone()));
    assert_eq!(reopened.profile("daily").unwrap(), Some(daily));
    assert!(!config.join("credentials").exists());
}

#[test]
fn aliases_and_credential_references_are_typed_and_path_safe() {
    let identity = Identity::generate();
    let selected_actor = actor(&identity);
    for alias in ["", ".hidden", "../escape", "Upper", "with/slash"] {
        assert!(matches!(
            IdentityProfile::new(
                alias.to_string(),
                selected_actor.clone(),
                CredentialReference::OwnerOnlyFile {
                    path: "daily/key".to_string(),
                },
            ),
            Err(Error::InvalidAlias(_))
        ));
    }
    assert!(IdentityProfile::new(
        "daily-device_1".to_string(),
        selected_actor,
        CredentialReference::Agent {
            socket: "/run/kan-agent.sock".to_string(),
            key_id: "daily".to_string(),
        },
    )
    .is_ok());

    let identity = Identity::generate();
    assert!(matches!(
        IdentityProfile::new(
            "daily".to_string(),
            actor(&identity),
            CredentialReference::OwnerOnlyFile {
                path: "../escape".to_string(),
            },
        ),
        Err(Error::InvalidCredentialPath(_))
    ));
}

#[test]
fn actor_reference_requires_the_method_and_version_form_of_its_principal() {
    let identity = Identity::generate();
    let principal = identity.did();
    let fingerprint = principal.strip_prefix("did:key:").unwrap();
    assert!(matches!(
        ActorReference::new(
            principal.clone(),
            format!("{principal}#other"),
            IdentityVersion::Static,
        ),
        Err(Error::StaticMethod(_))
    ));
    assert!(matches!(
        ActorReference::new(
            principal.clone(),
            format!("{principal}#{fingerprint}"),
            IdentityVersion::VersionId("1".to_string()),
        ),
        Err(Error::ControllerStateKind { .. })
    ));
}

fn method(identity: &Identity) -> VerificationMethod {
    let did = identity.did();
    let (_, multikey) =
        atrium_crypto::multibase::decode(did.strip_prefix("did:key:").unwrap()).unwrap();
    VerificationMethod {
        id: format!("{did}#{}", did.strip_prefix("did:key:").unwrap()),
        controller: did,
        alg: "P256".to_string(),
        public_key: multikey[2..].to_vec(),
        purposes: vec![VerificationPurpose::Assertion],
    }
}

fn input() -> SigningInput {
    SigningInput::new(
        "kan.test.system-credential.v1",
        "sign",
        atproto_dasl::Ipld::Map(std::collections::BTreeMap::from([(
            "message".to_string(),
            atproto_dasl::Ipld::String("exact".to_string()),
        )])),
    )
    .unwrap()
}

#[test]
fn owner_only_file_executes_only_for_the_resolved_method_key() {
    let temp = tempfile::tempdir().unwrap();
    let credentials = temp.path().join("credentials");
    let key_path = credentials.join("daily.key");
    let identity = Identity::generate();
    identity.save(&key_path).unwrap();
    let profile = IdentityProfile::new(
        "daily".to_string(),
        actor(&identity),
        CredentialReference::OwnerOnlyFile {
            path: "daily.key".to_string(),
        },
    )
    .unwrap();
    let store = SystemIdentityStore::at(temp.path());
    let input = input();
    let proof = store.sign(&profile, &method(&identity), &input).unwrap();
    assert_eq!(
        verify_static_did_key_proof(&input, &proof),
        CryptographicValidity::Valid
    );

    let wrong = Identity::generate();
    assert!(matches!(
        store.sign(&profile, &method(&wrong), &input),
        Err(Error::CredentialMethodMismatch { .. })
    ));
}

#[test]
fn credential_key_substitution_and_unsupported_providers_fail_closed() {
    let temp = tempfile::tempdir().unwrap();
    let selected = Identity::generate();
    let wrong = Identity::generate();
    wrong
        .save(&temp.path().join("credentials").join("daily.key"))
        .unwrap();
    let profile = IdentityProfile::new(
        "daily".to_string(),
        actor(&selected),
        CredentialReference::OwnerOnlyFile {
            path: "daily.key".to_string(),
        },
    )
    .unwrap();
    let store = SystemIdentityStore::at(temp.path());
    assert!(matches!(
        store.sign(&profile, &method(&selected), &input()),
        Err(Error::CredentialKeyMismatch { .. })
    ));

    let external = IdentityProfile::new(
        "external".to_string(),
        actor(&selected),
        CredentialReference::ExternalSigner {
            uri: "https://signer.example/key/daily".to_string(),
        },
    )
    .unwrap();
    assert!(matches!(
        store.sign(&external, &method(&selected), &input()),
        Err(Error::ProviderUnsupported(_))
    ));
}

#[cfg(unix)]
#[test]
fn owner_only_provider_refuses_loose_permissions_and_symlinks() {
    use std::os::unix::fs::{symlink, PermissionsExt};

    let temp = tempfile::tempdir().unwrap();
    let identity = Identity::generate();
    let credentials = temp.path().join("credentials");
    let target = credentials.join("target.key");
    identity.save(&target).unwrap();
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o644)).unwrap();
    let loose = IdentityProfile::new(
        "loose".to_string(),
        actor(&identity),
        CredentialReference::OwnerOnlyFile {
            path: "target.key".to_string(),
        },
    )
    .unwrap();
    let store = SystemIdentityStore::at(temp.path());
    assert!(matches!(
        store.sign(&loose, &method(&identity), &input()),
        Err(Error::CredentialPermissions(_))
    ));

    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
    symlink(&target, credentials.join("linked.key")).unwrap();
    let linked = IdentityProfile::new(
        "linked".to_string(),
        actor(&identity),
        CredentialReference::OwnerOnlyFile {
            path: "linked.key".to_string(),
        },
    )
    .unwrap();
    assert!(matches!(
        store.sign(&linked, &method(&identity), &input()),
        Err(Error::UnsafeCredential(_))
    ));
}

#[test]
fn conflicting_reinitialization_does_not_install_or_switch_the_actor() {
    let temp = tempfile::tempdir().unwrap();
    let store = SystemIdentityStore::at(temp.path());
    let first = profile("first");
    let second = profile("second");
    store.initialize(&first).unwrap();

    assert!(matches!(
        store.initialize(&second),
        Err(Error::AlreadyInitialized(alias)) if alias == "first"
    ));
    assert_eq!(store.default_profile().unwrap(), Some(first));
    assert!(store.profile("second").unwrap().is_none());
}

#[test]
fn concurrent_first_initialization_selects_exactly_one_complete_profile() {
    let temp = tempfile::tempdir().unwrap();
    let store = Arc::new(SystemIdentityStore::at(temp.path()));
    let barrier = Arc::new(Barrier::new(3));
    let candidates = [profile("one"), profile("two")];
    let mut handles = Vec::new();
    for candidate in candidates.clone() {
        let store = Arc::clone(&store);
        let barrier = Arc::clone(&barrier);
        handles.push(std::thread::spawn(move || {
            barrier.wait();
            store.initialize(&candidate)
        }));
    }
    barrier.wait();
    let outcomes = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(outcomes.iter().filter(|result| result.is_ok()).count(), 1);

    let selected = store.default_profile().unwrap().unwrap();
    assert!(candidates.contains(&selected));
    let loser = candidates
        .iter()
        .find(|candidate| candidate.alias() != selected.alias())
        .unwrap();
    assert!(store.profile(loser.alias()).unwrap().is_none());
}

#[cfg(unix)]
#[test]
fn initialization_refuses_a_symlinked_coordination_lock() {
    use std::os::unix::fs::symlink;

    let temp = tempfile::tempdir().unwrap();
    let profiles = temp.path().join("identity").join("profiles");
    std::fs::create_dir_all(&profiles).unwrap();
    let outside = temp.path().join("outside-lock");
    std::fs::write(&outside, b"not a kan lock").unwrap();
    symlink(&outside, profiles.join("LOCK")).unwrap();
    let store = SystemIdentityStore::at(temp.path());

    assert!(matches!(
        store.initialize(&profile("daily")),
        Err(Error::UnsafeEntry(_))
    ));
    assert!(!profiles.join("daily.json").exists());
    assert!(!profiles.join("default").exists());
}
