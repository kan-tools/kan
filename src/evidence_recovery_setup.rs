//! Explicit offline recipient-key recovery setup. Never activates or migrates an archive.
use crate::{
    evidence_crypto as crypto,
    evidence_keys::{Access, RecoveryPackage},
    evidence_proof_service::Binding,
    evidence_service::hex,
    sign::Identity,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::Read,
    path::{Component, Path, PathBuf},
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
const MAX_PACKAGE: u64 = 128 * 1024;

fn digest(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

// Explicit canonical paths and existing private directories avoid creating an
// unexpected tree or following a symlink in the output's ancestry.
fn parent(path: &Path) -> Result<PathBuf> {
    if path.to_str().is_none() {
        return Err("recovery paths must be UTF-8; no files were written".into());
    }
    if !cfg!(unix)
        || !path.is_absolute()
        || path.file_name().is_none()
        || path
            .components()
            .any(|c| !matches!(c, Component::RootDir | Component::Normal(_)))
    {
        return Err("recovery paths must be absolute canonical Unix file paths".into());
    }
    let p = path.parent().ok_or("missing recovery parent")?;
    if fs::canonicalize(p)? != p {
        return Err("recovery parent must not traverse symlinks".into());
    }
    let m = fs::symlink_metadata(p)?;
    if !m.is_dir() {
        return Err("recovery parent must be an existing private directory".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if m.permissions().mode() & 0o077 != 0 {
            return Err("recovery parent must have owner-only permissions (0700)".into());
        }
    }
    Ok(p.to_owned())
}
fn new_path(path: &Path) -> Result<PathBuf> {
    let p = parent(path)?;
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(p),
        Err(e) => Err(e.into()),
        Ok(_) => Err("recovery output already exists; preserve it and choose a new path".into()),
    }
}
fn read_package(path: &Path) -> Result<Vec<u8>> {
    parent(path)?;
    let before = fs::symlink_metadata(path)?;
    if before.file_type().is_symlink() || !before.is_file() || before.len() > MAX_PACKAGE {
        return Err("recovery package must be a bounded regular file".into());
    }
    let file = fs::File::open(path)?;
    let actual = file.metadata()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if !actual.is_file()
            || actual.permissions().mode() & 0o077 != 0
            || actual.nlink() != 1
            || actual.dev() != before.dev()
            || actual.ino() != before.ino()
        {
            return Err("recovery package must be an unchanged private singly linked file".into());
        }
    }
    let mut bytes = Vec::new();
    file.take(MAX_PACKAGE + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_PACKAGE {
        return Err("recovery package exceeds its bound".into());
    }
    Ok(bytes)
}
fn checked(package: &Path, secret: &Path, expected: &str) -> Result<(RecoveryPackage, [u8; 32])> {
    let bytes = read_package(package).map_err(|e| format!("recovery package: {e}"))?;
    if digest(&bytes) != expected {
        return Err(
            "recovery package does not match the independently retained SHA-256 pin".into(),
        );
    }
    let p: RecoveryPackage = serde_json::from_slice(&bytes)?;
    // This command's recovery unit is one explicitly selected existing key.
    // Multi-epoch histories continue to use the existing owner recovery flow.
    if p.records.len() != 1 {
        return Err("recipient-key setup requires exactly one signed key record".into());
    }
    let access = Access {
        directory: parent(package)?,
        binding: p.binding.clone(),
        owner: p.owner.clone(),
        recovery_recipient: p.recovery_recipient.clone(),
        minimum: p.tip.clone(),
    };
    access
        .verify_package(&p)
        .map_err(|e| format!("recovery package signature or binding: {e}"))?;
    parent(secret).map_err(|e| format!("recovery secret parent: {e}"))?;
    let recovery = crypto::read_private_key(secret).map_err(|e| format!("recovery secret: {e}"))?;
    let key = p.records[0].change.unlock(&recovery)?;
    Ok((p, key))
}
fn summary(p: &RecoveryPackage, sha: &str) -> Value {
    json!({"status":"verified","package_sha256":sha,"owner":p.owner,"binding":p.binding,
        "recipient":p.records[0].change.recipient,"recovery_recipient":p.recovery_recipient,
        "key_recovery_verified":true,"independent_storage_verified":false,
        "archive_restore_verified":false,"routing_changed":false,
        "coverage":"one archive recipient key; excludes signing credentials, workspace keys, archive data and configuration"})
}
/// Create two new files only. An interrupted write is retained and never reused
/// implicitly. The operational key and signing credential are read-only inputs.
pub fn setup(
    binding: Binding,
    signer: &Identity,
    recipient_key: &Path,
    expected_recipient: &str,
    package: &Path,
    secret: &Path,
) -> Result<Value> {
    let package_parent = new_path(package).map_err(|e| format!("recovery package output: {e}"))?;
    let secret_parent = new_path(secret).map_err(|e| format!("recovery secret output: {e}"))?;
    if package_parent.starts_with(&secret_parent) || secret_parent.starts_with(&package_parent) {
        return Err(
            "package and recovery secret need separate, non-nested private directories".into(),
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let a = fs::metadata(&package_parent)?;
        let b = fs::metadata(&secret_parent)?;
        if (a.dev(), a.ino()) == (b.dev(), b.ino()) {
            return Err("package and secret directories alias".into());
        }
    }
    let key = crypto::read_private_key(recipient_key)
        .map_err(|e| format!("operational recipient key: {e}"))?;
    if hex(&crypto::public_key(&key)?) != expected_recipient {
        return Err("selected key does not match the expected archive recipient".into());
    }
    let recovery = rand::random::<[u8; 32]>();
    let p =
        RecoveryPackage::for_existing_key(binding, signer, &key, &crypto::public_key(&recovery)?)?;
    if p.records[0].change.unlock(&recovery)? != key {
        return Err("recovery round trip failed".into());
    }
    let bytes = serde_json::to_vec_pretty(&p)?;
    let sha = digest(&bytes);
    write_pair(
        package,
        &package_parent,
        secret,
        &secret_parent,
        &recovery,
        &bytes,
    )?;
    let (verified, readback) = checked(package, secret, &sha)?;
    if readback != key {
        return Err("written recovery package changed the selected key".into());
    }
    let mut report = summary(&verified, &sha);
    report["status"] = json!("created-and-verified");
    report["package"] = json!(package);
    report["recovery_secret"] = json!(secret);
    report["next_steps"] = json!([
        "Retain package_sha256 independently of the package.",
        "Copy the encrypted package to backup storage; store the raw recovery secret separately.",
        "Use recovery verify on those retained copies, then recovery restore to a new private key file.",
        "Test an actual archive restore before relying on this setup. Separate paths do not prove separate failure domains."
    ]);
    Ok(report)
}
pub fn verify(package: &Path, secret: &Path, expected: &str) -> Result<Value> {
    let (p, _) = checked(package, secret, expected)?;
    Ok(summary(&p, expected))
}
pub fn restore(package: &Path, secret: &Path, expected: &str, output: &Path) -> Result<Value> {
    let output_parent = new_path(output).map_err(|e| format!("recovered key output: {e}"))?;
    let (p, key) = checked(package, secret, expected)?;
    // surface-write: evidence-keys:recovered-recipient-key
    crate::persistence::write_new_owner_only(
        crate::persistence::SurfaceWrite::EvidenceKeys,
        output,
        &key,
    )?;
    fs::File::open(output_parent)?.sync_all()?;
    if crypto::read_private_key(output)? != key {
        return Err("restored key readback failed".into());
    }
    let mut report = summary(&p, expected);
    report["status"] = json!("restored-to-new-file");
    report["output"] = json!(output);
    Ok(report)
}

// Preflight belongs to setup; create-new is still authoritative if a path changes
// after preflight. Keep interrupted outputs, including on package creation failure.
fn write_pair(
    package: &Path,
    package_parent: &Path,
    secret: &Path,
    secret_parent: &Path,
    recovery: &[u8; 32],
    bytes: &[u8],
) -> Result<()> {
    // Write the secret first: if a later step fails, retain it and the partial
    // package for diagnosis. Never overwrite an existing secret or package.
    // surface-write: evidence-keys:recovery-secret
    crate::persistence::write_new_owner_only(
        crate::persistence::SurfaceWrite::EvidenceKeys,
        secret,
        recovery,
    )?;
    fs::File::open(secret_parent)?.sync_all()?;
    // surface-write: evidence-keys:recovery-package
    crate::persistence::write_new_owner_only(
        crate::persistence::SurfaceWrite::EvidenceKeys,
        package,
        bytes,
    )?;
    fs::File::open(package_parent)?.sync_all()?;
    Ok(())
}

#[cfg(all(test, unix))]
mod recovery_tests {
    use super::*;

    #[test]
    fn package_creation_failure_retains_secret_and_never_reuses_partial_outputs() {
        let dir = tempfile::tempdir().unwrap();
        let package = tempfile::NamedTempFile::new_in(dir.path()).unwrap();
        let secret = dir.path().join("secret");
        // Models a package appearing after setup's preflight. Real create-new
        // must fail after the secret was durably written; no production fault hook.
        let error = write_pair(
            package.path(),
            dir.path(),
            &secret,
            dir.path(),
            &[7; 32],
            b"package",
        )
        .unwrap_err();
        assert_eq!(
            error.downcast_ref::<std::io::Error>().unwrap().kind(),
            std::io::ErrorKind::AlreadyExists
        );
        assert_eq!(fs::read(&secret).unwrap(), [7; 32]);
        assert!(fs::read(package.path()).unwrap().is_empty());
        assert!(write_pair(
            package.path(),
            dir.path(),
            &secret,
            dir.path(),
            &[8; 32],
            b"other"
        )
        .is_err());
        assert_eq!(fs::read(&secret).unwrap(), [7; 32]);
        assert!(fs::read(package.path()).unwrap().is_empty());
    }
}
