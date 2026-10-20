#![cfg(feature = "v2-crypto")]
use kan::{
    evidence_crypto as crypto,
    evidence_keys::{Access, Record, RecoveryPackage},
    evidence_proof_service::{Binding, Profile},
    evidence_service::{self as service, Failure},
    sign::Identity,
};
use std::io::Write;
fn identity() -> Identity {
    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(&[91; 32]).unwrap();
    Identity::load_existing(file.path()).unwrap()
}
fn directory() -> tempfile::TempDir {
    let d = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    d
}
fn config(directory: &std::path::Path) -> Access {
    Access {
        directory: directory.to_owned(),
        binding: Binding {
            profile: Profile::Admitted,
            archive: service::hex(&[2; 32]),
            scope: service::hex(&[1; 32]),
            issuer: identity().did().to_string(),
        },
        owner: identity().did().to_string(),
        recovery_recipient: service::hex(&crypto::public_key(&[92; 32]).unwrap()),
        minimum: None,
    }
}
fn rotate(access: &Access, n: u8) -> Record {
    let change = access.preview(service::hex(&[n; 32])).unwrap();
    let record = Record::sign(change, &identity()).unwrap();
    access.append(record.clone()).unwrap();
    record
}
#[test]
fn rotation_preserves_old_keys_and_independent_package_restores_without_original_directory() {
    let original = directory();
    let access = config(original.path());
    access.initialize().unwrap();
    assert!(access.read().unwrap().current().is_err());
    let first = rotate(&access, 1);
    let old = first.change.unlock(&[92; 32]).unwrap();
    let ciphertext = crypto::seal(
        &crypto::public_key(&old).unwrap(),
        &[1; 32],
        b"old retained conversation",
    )
    .unwrap();
    let second = rotate(&access, 2);
    assert_ne!(first.change.recipient, second.change.recipient);
    assert_eq!(
        access.append(first.clone()).unwrap()["state"],
        "already-applied"
    );
    let keys = access.read().unwrap().unlock(&[92; 32]).unwrap();
    assert_eq!(keys.len(), 2);
    assert_eq!(keys[0], old);
    assert!(access.read().unwrap().unlock(&[93; 32]).is_err());
    let package_value = access.export().unwrap();
    let package_bytes = serde_json::to_vec(&package_value).unwrap();
    assert!(!String::from_utf8_lossy(&package_bytes).contains(&service::hex(&old)));
    assert!(!String::from_utf8_lossy(&package_bytes).contains(&service::hex(&[92; 32])));
    let package: RecoveryPackage = serde_json::from_value(package_value).unwrap();
    let tip = package.tip.clone();
    drop(original);
    let recovered = directory();
    let mut destination = config(recovered.path());
    destination.initialize().unwrap();
    destination.minimum = tip;
    assert_eq!(destination.restore(&package).unwrap()["state"], "restored");
    assert_eq!(destination.restore(&package).unwrap()["state"], "restored");
    let restored = destination.read().unwrap().unlock(&[92; 32]).unwrap();
    assert_eq!(
        crypto::open(&restored[0], &[1; 32], &ciphertext).unwrap(),
        b"old retained conversation"
    );
    assert_eq!(
        destination.read().unwrap().current().unwrap(),
        second.change.recipient
    );
}
#[test]
fn stale_rotations_tampered_packages_wrong_binding_and_witnessed_rollback_are_refused() {
    let d = directory();
    let access = config(d.path());
    access.initialize().unwrap();
    let pending = access.preview(service::hex(&[1; 32])).unwrap();
    let first = rotate(&access, 2);
    assert!(matches!(
        access.append(Record::sign(pending, &identity()).unwrap()),
        Err(Failure::Conflict)
    ));
    let second = rotate(&access, 3);
    let lock = access.read().unwrap();
    assert!(matches!(
        access.append(first.clone()),
        Err(Failure::Unavailable)
    ));
    drop(lock);
    let clean = access.export().unwrap();
    let mut bad = clean.clone();
    bad["records"][0]["change"]["recipient"] = serde_json::json!(service::hex(&[23; 32]));
    let destination_dir = directory();
    let destination = config(destination_dir.path());
    destination.initialize().unwrap();
    assert!(destination
        .restore(&serde_json::from_value(bad).unwrap())
        .is_err());
    assert!(destination.read().unwrap().history.is_empty());
    let mut wrong = clean.clone();
    wrong["binding"]["scope"] = serde_json::json!(service::hex(&[9; 32]));
    assert!(destination
        .restore(&serde_json::from_value(wrong).unwrap())
        .is_err());
    let mut pinned = destination.clone();
    pinned.minimum = Some(second.id().unwrap());
    let mut truncated = clean.clone();
    truncated["records"].as_array_mut().unwrap().pop();
    truncated["tip"] = serde_json::json!(first.id().unwrap());
    assert!(matches!(
        pinned.restore(&serde_json::from_value(truncated).unwrap()),
        Err(Failure::AccessLimited)
    ));
    assert_eq!(
        pinned
            .restore(&serde_json::from_value(clean).unwrap())
            .unwrap()["epochs"],
        2
    );
    let mut bad_wrap = access.preview(service::hex(&[4; 32])).unwrap();
    let mut damaged = service::unhex(&bad_wrap.wrapped, 1024).unwrap();
    damaged[80] ^= 1;
    bad_wrap.wrapped = service::hex(&damaged);
    assert!(bad_wrap.unlock(&[92; 32]).is_err());
    assert!(access.read().unwrap().unlock(&[92; 32]).is_ok());
}
#[test]
fn partial_restore_retries_preserve_prefix_and_ignore_incomplete_publications() {
    let d = directory();
    let access = config(d.path());
    access.initialize().unwrap();
    let first = rotate(&access, 1);
    rotate(&access, 2);
    let package: RecoveryPackage = serde_json::from_value(access.export().unwrap()).unwrap();
    let out = directory();
    let destination = config(out.path());
    destination.initialize().unwrap();
    destination.append(first.clone()).unwrap();
    std::fs::write(
        out.path().join(".pending-interrupted"),
        b"incomplete wrapped record",
    )
    .unwrap();
    destination.restore(&package).unwrap();
    assert_eq!(
        destination.read().unwrap().history[0].id().unwrap(),
        first.id().unwrap()
    );
    assert_eq!(
        std::fs::read(out.path().join(".pending-interrupted")).unwrap(),
        b"incomplete wrapped record"
    );
    let divergent = directory();
    let different = config(divergent.path());
    different.initialize().unwrap();
    rotate(&different, 4);
    assert!(matches!(
        different.restore(&package),
        Err(Failure::Conflict)
    ));
}

#[test]
fn transferred_custody_preserves_origins_and_only_unlocks_explicit_epochs() {
    use kan::evidence_keys::TransferPurpose;
    let source_dir = directory();
    let access = config(source_dir.path());
    access.initialize().unwrap();
    let first = rotate(&access, 1);
    let second = rotate(&access, 2);
    let ids = vec![first.id().unwrap(), second.id().unwrap()];
    let recipient = service::hex(&crypto::public_key(&[94; 32]).unwrap());
    let plan = access
        .preview_transfer(
            recipient.clone(),
            vec![ids[1].clone()],
            TransferPurpose::ShareEpochs,
        )
        .unwrap();
    let preview = serde_json::to_value(&plan).unwrap();
    assert!(!preview.to_string().contains("wrapped"));
    assert!(access
        .transfer(&plan, "wrong", &[92; 32], &identity())
        .is_err());
    assert!(access
        .transfer(&plan, &plan.digest().unwrap(), &[93; 32], &identity())
        .is_err());
    let package: RecoveryPackage = serde_json::from_value(
        access
            .transfer(&plan, &plan.digest().unwrap(), &[92; 32], &identity())
            .unwrap(),
    )
    .unwrap();
    assert_eq!(package.records.len(), 1);
    assert_eq!(
        package.records[0].change.origin.as_ref().unwrap().record,
        ids[1]
    );
    let out = directory();
    let mut dest = config(out.path());
    dest.recovery_recipient = recipient.clone();
    dest.minimum = package.tip.clone();
    dest.initialize().unwrap();
    dest.restore(&package).unwrap();
    let keys = dest.read().unwrap().unlock(&[94; 32]).unwrap();
    assert_eq!(keys, vec![second.change.unlock(&[92; 32]).unwrap()]);
    assert!(dest.read().unwrap().unlock(&[92; 32]).is_err());
    assert_eq!(access.read().unwrap().tip, Some(ids[1].clone()));
    assert!(access
        .preview_transfer(
            recipient.clone(),
            vec![ids[1].clone()],
            TransferPurpose::ReplaceRecovery
        )
        .is_err());
    for invalid in [
        vec![],
        vec![ids[0].clone(), ids[0].clone()],
        vec![ids[1].clone(), ids[0].clone()],
        vec![service::hex(&[11; 32])],
    ] {
        assert!(access
            .preview_transfer(recipient.clone(), invalid, TransferPurpose::ShareEpochs)
            .is_err());
    }
    let plan = access
        .preview_transfer(recipient, ids, TransferPurpose::ReplaceRecovery)
        .unwrap();
    let complete: RecoveryPackage = serde_json::from_value(
        access
            .transfer(&plan, &plan.digest().unwrap(), &[92; 32], &identity())
            .unwrap(),
    )
    .unwrap();
    assert_eq!(complete.records.len(), 2);
    let out2 = directory();
    let mut dest2 = dest.clone();
    dest2.directory = out2.path().to_owned();
    dest2.minimum = complete.tip.clone();
    dest2.initialize().unwrap();
    dest2.restore(&complete).unwrap();
    assert_eq!(
        dest2.read().unwrap().unlock(&[94; 32]).unwrap(),
        access.read().unwrap().unlock(&[92; 32]).unwrap()
    );
    let fresh = dest2.preview(service::hex(&[10; 32])).unwrap();
    assert!(fresh.unlock(&[92; 32]).is_err());
    assert!(fresh.unlock(&[94; 32]).is_ok());
    let mut tampered: RecoveryPackage =
        serde_json::from_value(serde_json::to_value(&complete).unwrap()).unwrap();
    tampered.records[0].change.origin.as_mut().unwrap().record = service::hex(&[31; 32]);
    assert!(dest2.verify_package(&tampered).is_err());
    rotate(&access, 3);
    assert!(matches!(
        access.transfer(&plan, &plan.digest().unwrap(), &[92; 32], &identity()),
        Err(Failure::Conflict)
    ));
}
