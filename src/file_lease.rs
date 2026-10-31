//! Ownership of an already acquired advisory lock. Independent open files must
//! have independent owners; a raw inherited/duplicated descriptor is not an owner.
use std::fs::File;

/// Construct immediately after successful acquisition, before any fallible work.
/// Deliberately not Clone: ownership may move, but never split implicitly.
pub(crate) struct FileLease(pub(crate) File);
impl Drop for FileLease {
    fn drop(&mut self) {
        // Close alone may leave a flock held by an inherited descriptor.
        let _ = fs4::FileExt::unlock(&self.0);
    }
}

#[cfg(all(test, unix))]
mod lease_tests {
    use super::*;

    #[test]
    fn shared_owner_drop_preserves_independent_reader_and_replacement() {
        let path = tempfile::NamedTempFile::new().unwrap();
        let first = File::open(path.path()).unwrap();
        fs4::FileExt::try_lock_shared(&first).unwrap();
        let first = FileLease(first);
        let inherited = first.0.try_clone().unwrap();
        let second = File::open(path.path()).unwrap();
        fs4::FileExt::try_lock_shared(&second).unwrap();
        let second = FileLease(second);
        let contender = File::open(path.path()).unwrap();
        drop(first);
        assert!(fs4::FileExt::try_lock(&contender).is_err());
        drop(second);
        fs4::FileExt::try_lock(&contender).unwrap();
        let contender = FileLease(contender);
        drop(inherited);
        let probe = File::open(path.path()).unwrap();
        assert!(fs4::FileExt::try_lock_shared(&probe).is_err());
        drop(contender);
        fs4::FileExt::try_lock(&probe).unwrap();
        drop(FileLease(probe));
    }

    #[test]
    fn upgraded_owner_moves_and_releases_on_error_despite_inherited_descriptor() {
        let path = tempfile::NamedTempFile::new().unwrap();
        let file = File::open(path.path()).unwrap();
        fs4::FileExt::try_lock_shared(&file).unwrap();
        let owner = FileLease(file);
        let inherited = owner.0.try_clone().unwrap();
        fs4::FileExt::try_lock(&owner.0).unwrap();
        let probe = File::open(path.path()).unwrap();
        assert!(fs4::FileExt::try_lock_shared(&probe).is_err());
        fn rejected(_owner: FileLease) -> Result<(), ()> {
            Err(())
        }
        assert!(rejected(owner).is_err());
        fs4::FileExt::try_lock(&probe).unwrap();
        let replacement = FileLease(probe);
        drop(inherited);
        let reader = File::open(path.path()).unwrap();
        assert!(fs4::FileExt::try_lock_shared(&reader).is_err());
        drop(replacement);
        fs4::FileExt::try_lock_shared(&reader).unwrap();
        drop(FileLease(reader));
    }
}
