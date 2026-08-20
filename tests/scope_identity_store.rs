use kan::{
    identity::{
        control::{IdentityVersion, Proof},
        scope_inception::ScopeInception,
        scope_store::{Error, ScopeIdentityStore},
    },
    sign::Identity,
};

fn event(nonce: [u8; 32], root: &Identity) -> kan::identity::control::ControlEvent {
    let inception =
        ScopeInception::new(nonce, vec!["kan".to_string()], vec![root.did()], vec![]).unwrap();
    let input = inception.signing_input().unwrap();
    let did = root.did();
    let proof = Proof {
        method: format!("{did}#{}", did.strip_prefix("did:key:").unwrap()),
        controller_state: IdentityVersion::Static,
        alg: "P256".to_string(),
        sig: root.sign(&input.canonical_bytes().unwrap()).unwrap(),
    };
    inception.proved_event(vec![proof]).unwrap()
}

#[test]
fn reads_create_nothing_and_nonce_is_stable() {
    let temp = tempfile::tempdir().unwrap();
    let directory = temp.path().join(".kan/scope");
    let store = ScopeIdentityStore::at(&directory);
    assert!(store.read().unwrap().is_none());
    assert!(!directory.exists());

    let first = store.initialization_nonce().unwrap();
    assert_eq!(store.initialization_nonce().unwrap(), first);
    assert_eq!(
        std::fs::read(directory.join("initialization-nonce")).unwrap(),
        first
    );
}

#[test]
fn proved_inception_installs_immutably_and_reopens() {
    let temp = tempfile::tempdir().unwrap();
    let store = ScopeIdentityStore::at(temp.path().join(".kan/scope"));
    let root = Identity::generate();
    let first_event = event([0x11; 32], &root);

    let installed = store.install(&first_event).unwrap();
    assert_eq!(store.install(&first_event).unwrap(), installed);
    assert_eq!(store.install(&event([0x11; 32], &root)).unwrap(), installed);
    assert_eq!(store.read().unwrap(), Some(installed.clone()));
    assert_eq!(installed.inception.nonce, vec![0x11; 32]);
    assert!(installed.scope.to_string().starts_with("bciq"));
}

#[test]
fn a_different_inception_never_replaces_the_installed_scope() {
    let temp = tempfile::tempdir().unwrap();
    let store = ScopeIdentityStore::at(temp.path().join(".kan/scope"));
    let root = Identity::generate();
    let first = store.install(&event([0x21; 32], &root)).unwrap();

    assert!(matches!(
        store.install(&event([0x22; 32], &root)),
        Err(Error::Conflict { .. })
    ));
    assert_eq!(store.read().unwrap(), Some(first));
}

#[cfg(unix)]
#[test]
fn symlinked_scope_entries_fail_closed() {
    use std::os::unix::fs::symlink;

    let temp = tempfile::tempdir().unwrap();
    let directory = temp.path().join(".kan/scope");
    std::fs::create_dir_all(&directory).unwrap();
    let target = temp.path().join("target");
    std::fs::write(&target, b"not inception").unwrap();
    symlink(&target, directory.join("inception.cbor")).unwrap();

    assert!(matches!(
        ScopeIdentityStore::at(directory).read(),
        Err(Error::UnsafeEntry(_))
    ));
}
