use std::sync::{Arc, Barrier};

use kan::{
    identity::system::{CredentialReference, Error, IdentityProfile, SystemIdentityStore},
    sign::Identity,
};

fn profile(alias: &str) -> IdentityProfile {
    IdentityProfile::new(
        alias.to_string(),
        Identity::generate().did(),
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
    let principal = Identity::generate().did();
    for alias in ["", ".hidden", "../escape", "Upper", "with/slash"] {
        assert!(matches!(
            IdentityProfile::new(
                alias.to_string(),
                principal.clone(),
                CredentialReference::OwnerOnlyFile {
                    path: "/secure/key".to_string(),
                },
            ),
            Err(Error::InvalidAlias(_))
        ));
    }
    assert!(IdentityProfile::new(
        "daily-device_1".to_string(),
        principal,
        CredentialReference::Agent {
            socket: "/run/kan-agent.sock".to_string(),
            key_id: "daily".to_string(),
        },
    )
    .is_ok());
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
