use kan::identity::transport::LocalRepositoryTransportStore;

#[test]
fn read_is_absent_and_creates_nothing() {
    let temp = tempfile::tempdir().unwrap();
    let directory = temp.path().join(".kan/transport");
    let store = LocalRepositoryTransportStore::at(&directory);

    assert!(store.read().unwrap().is_none());
    assert!(!directory.exists());
}

#[test]
fn creation_is_stable_owner_only_and_distinct_from_a_kan_actor() {
    let temp = tempfile::tempdir().unwrap();
    let directory = temp.path().join(".kan/transport");
    let store = LocalRepositoryTransportStore::at(&directory);
    let kan_actor = kan::sign::Identity::generate();

    let first = store.load_or_create().unwrap();
    let second = store.load_or_create().unwrap();
    assert_eq!(first.did(), second.did());
    assert_ne!(first.did(), kan_actor.did());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(directory.join("identity"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o077, 0);
    }
}

#[test]
fn released_repository_owner_is_copied_without_rebinding_its_did() {
    let temp = tempfile::tempdir().unwrap();
    let directory = temp.path().join(".kan/transport");
    let store = LocalRepositoryTransportStore::at(&directory);
    let released_owner = kan::sign::Identity::generate();

    let adopted = store
        .continue_from_released_repository(&released_owner)
        .unwrap();
    assert_eq!(adopted.did(), released_owner.did());
    assert_eq!(store.read().unwrap().unwrap().did(), released_owner.did());
}

#[test]
fn an_existing_transport_credential_cannot_be_rebound_by_continuity() {
    let temp = tempfile::tempdir().unwrap();
    let directory = temp.path().join(".kan/transport");
    let store = LocalRepositoryTransportStore::at(&directory);
    let installed = store.load_or_create().unwrap().did();
    let other = kan::sign::Identity::generate();

    assert!(matches!(
        store.continue_from_released_repository(&other),
        Err(kan::identity::transport::Error::ContinuityMismatch { expected, actual })
            if expected == other.did() && actual == installed
    ));
}

#[cfg(unix)]
#[test]
fn loose_or_symlinked_identity_is_refused() {
    use std::os::unix::fs::{symlink, PermissionsExt};

    let temp = tempfile::tempdir().unwrap();
    let directory = temp.path().join("transport");
    std::fs::create_dir(&directory).unwrap();
    let identity = kan::sign::Identity::generate();
    let loose = temp.path().join("loose-key");
    identity.save(&loose).unwrap();
    std::fs::set_permissions(&loose, std::fs::Permissions::from_mode(0o644)).unwrap();
    symlink(&loose, directory.join("identity")).unwrap();

    assert!(LocalRepositoryTransportStore::at(&directory)
        .read()
        .is_err());

    std::fs::remove_file(directory.join("identity")).unwrap();
    std::fs::copy(&loose, directory.join("identity")).unwrap();
    assert!(LocalRepositoryTransportStore::at(&directory)
        .read()
        .is_err());
}
