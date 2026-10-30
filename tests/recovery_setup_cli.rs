#![cfg(all(feature = "v2-crypto", unix))]
use kan::{evidence_crypto as crypto, evidence_service::hex, sign::Identity};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Output},
};

fn private_file(path: &Path, bytes: &[u8]) {
    kan::persistence::write_new_owner_only(
        kan::persistence::SurfaceWrite::EvidenceKeys,
        path,
        bytes,
    )
    .unwrap();
}
fn sha(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}
struct Fixture {
    _temp: tempfile::TempDir,
    root: PathBuf,
    package: PathBuf,
    secret: PathBuf,
    key: PathBuf,
    signer: PathBuf,
    binding: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        for name in ["operational", "backup", "secret", "restored"] {
            let p = root.join(name);
            fs::create_dir(&p).unwrap();
            fs::set_permissions(p, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let key = root.join("operational/recipient.key");
        private_file(&key, &[52; 32]);
        let signer = root.join("operational/signer.key");
        private_file(&signer, &[51; 32]);
        let binding = root.join("operational/binding.json");
        private_file(&binding,serde_json::to_vec(&json!({"profile":"admitted","archive":hex(&[2;32]),"scope":hex(&[1;32]),"issuer":Identity::load_existing(&signer).unwrap().did()})).unwrap().as_slice());
        Self {
            _temp: temp,
            package: root.join("backup/package.json"),
            secret: root.join("secret/recovery.key"),
            root,
            key,
            signer,
            binding,
        }
    }
    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_kan"))
            .current_dir(&self.root)
            .arg("--no-migration-notice")
            .args(args)
            .output()
            .unwrap()
    }
    fn setup_at(&self, package: &Path, secret: &Path, recipient: &str) -> Output {
        self.run(&[
            "recovery",
            "setup",
            "--binding",
            self.binding.to_str().unwrap(),
            "--signing-key",
            self.signer.to_str().unwrap(),
            "--recipient-key",
            self.key.to_str().unwrap(),
            "--expected-recipient",
            recipient,
            "--package",
            package.to_str().unwrap(),
            "--recovery-key",
            secret.to_str().unwrap(),
        ])
    }
    fn setup(&self) -> Value {
        let out = self.setup_at(
            &self.package,
            &self.secret,
            &hex(&crypto::public_key(&[52; 32]).unwrap()),
        );
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        serde_json::from_slice(&out.stdout).unwrap()
    }
    fn verify(&self, pin: &str) -> Output {
        self.run(&[
            "recovery",
            "verify",
            "--package",
            self.package.to_str().unwrap(),
            "--recovery-key",
            self.secret.to_str().unwrap(),
            "--expected-sha256",
            pin,
        ])
    }
    fn restore(&self, pin: &str, output: &Path) -> Output {
        self.run(&[
            "recovery",
            "restore",
            "--package",
            self.package.to_str().unwrap(),
            "--recovery-key",
            self.secret.to_str().unwrap(),
            "--expected-sha256",
            pin,
            "--output",
            output.to_str().unwrap(),
        ])
    }
}
#[test]
fn setup_then_offline_recovery_uses_only_package_secret_and_independent_pin() {
    let f = Fixture::new();
    let original = fs::read(&f.key).unwrap();
    let signer = fs::read(&f.signer).unwrap();
    let report = f.setup();
    let pin = report["package_sha256"].as_str().unwrap();
    assert_eq!(report["status"], "created-and-verified");
    assert_eq!(report["key_recovery_verified"], true);
    assert_eq!(report["independent_storage_verified"], false);
    assert_eq!(report["archive_restore_verified"], false);
    assert_eq!(report["routing_changed"], false);
    let package = fs::read(&f.package).unwrap();
    let secret = fs::read(&f.secret).unwrap();
    assert_eq!(pin, sha(&package));
    assert_eq!(secret.len(), 32);
    assert!(!package.windows(32).any(|w| w == original || w == secret));
    assert!(!report.to_string().contains(&hex(&original)));
    assert!(!report.to_string().contains(&hex(&secret)));
    assert_eq!(fs::read(&f.key).unwrap(), original);
    assert_eq!(fs::read(&f.signer).unwrap(), signer);
    for p in [&f.package, &f.secret] {
        assert_eq!(fs::metadata(p).unwrap().permissions().mode() & 0o777, 0o600);
    }
    let cipher = crypto::seal(
        &crypto::public_key(&[52; 32]).unwrap(),
        &[1; 32],
        b"retained archive payload",
    )
    .unwrap();
    // Hide the complete operational directory, including signing key/binding.
    fs::rename(
        f.root.join("operational"),
        f.root.join("unavailable-operational"),
    )
    .unwrap();
    assert!(f.verify(pin).status.success());
    let target = f.root.join("restored/recipient.key");
    let out = f.restore(pin, &target);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let recovered = crypto::read_private_key(&target).unwrap();
    assert_eq!(recovered, [52; 32]);
    assert_eq!(
        crypto::open(&recovered, &[1; 32], &cipher).unwrap(),
        b"retained archive payload"
    );
    assert!(!String::from_utf8_lossy(&out.stdout).contains(&hex(&recovered)));
    assert!(!f.restore(pin, &target).status.success());
    assert_eq!(fs::read(&target).unwrap(), original);
    assert_eq!(fs::read(&f.package).unwrap(), package);
    assert_eq!(fs::read(&f.secret).unwrap(), secret);
    let parsed: kan::evidence_keys::RecoveryPackage = serde_json::from_slice(&package).unwrap();
    let history = f.root.join("restored/history");
    fs::create_dir(&history).unwrap();
    fs::set_permissions(&history, fs::Permissions::from_mode(0o700)).unwrap();
    let access = kan::evidence_keys::Access {
        directory: history,
        binding: parsed.binding.clone(),
        owner: parsed.owner.clone(),
        recovery_recipient: parsed.recovery_recipient.clone(),
        minimum: parsed.tip.clone(),
    };
    access.initialize().unwrap();
    access.restore(&parsed).unwrap();
    let recovery: [u8; 32] = secret.try_into().unwrap();
    assert_eq!(
        access.read().unwrap().unlock(&recovery).unwrap(),
        vec![[52; 32]]
    );
}
#[test]
fn wrong_missing_secret_tampering_and_wrong_pin_refuse_without_output() {
    let f = Fixture::new();
    let report = f.setup();
    let pin = report["package_sha256"].as_str().unwrap();
    let secret = fs::read(&f.secret).unwrap();
    let package = fs::read(&f.package).unwrap();
    let out = f.root.join("restored/key");
    fs::write(&f.secret, [53; 32]).unwrap();
    assert!(!f.restore(pin, &out).status.success());
    assert!(!out.exists());
    fs::remove_file(&f.secret).unwrap();
    assert!(!f.verify(pin).status.success());
    assert!(!f.restore(pin, &out).status.success());
    private_file(&f.secret, &secret);
    assert!(!f.verify(&"0".repeat(64)).status.success());
    assert!(!out.exists());
    let mut damaged: Value = serde_json::from_slice(&package).unwrap();
    damaged["records"][0]["change"]["recorded_at"] = json!("0");
    let bytes = serde_json::to_vec(&damaged).unwrap();
    fs::write(&f.package, &bytes).unwrap();
    assert!(!f.verify(pin).status.success());
    // Even a caller-supplied new digest cannot bless a broken signature.
    assert!(!f.restore(&sha(&bytes), &out).status.success());
    assert!(!out.exists());
    fs::write(&f.package, &package).unwrap();
    assert!(f.verify(pin).status.success());
    fs::write(&f.package, vec![b'x'; 128 * 1024 + 1]).unwrap();
    assert!(!f.verify(pin).status.success());
}
#[test]
fn setup_never_replaces_existing_outputs_and_requires_matching_recipient() {
    let f = Fixture::new();
    let recipient = hex(&crypto::public_key(&[52; 32]).unwrap());
    assert!(!f
        .setup_at(&f.package, &f.secret, &"0".repeat(64))
        .status
        .success());
    assert!(!f.package.exists() && !f.secret.exists());
    private_file(&f.secret, b"retained partial secret");
    assert!(!f
        .setup_at(&f.package, &f.secret, &recipient)
        .status
        .success());
    assert!(!f.package.exists());
    assert_eq!(fs::read(&f.secret).unwrap(), b"retained partial secret");
    fs::remove_file(&f.secret).unwrap();
    private_file(&f.package, b"retained partial package");
    assert!(!f
        .setup_at(&f.package, &f.secret, &recipient)
        .status
        .success());
    assert!(!f.secret.exists());
    assert_eq!(fs::read(&f.package).unwrap(), b"retained partial package");
    fs::remove_file(&f.package).unwrap();
    f.setup();
    let before = (fs::read(&f.package).unwrap(), fs::read(&f.secret).unwrap());
    assert!(!f
        .setup_at(&f.package, &f.secret, &recipient)
        .status
        .success());
    assert_eq!(
        before,
        (fs::read(&f.package).unwrap(), fs::read(&f.secret).unwrap())
    );
}
#[test]
fn setup_refuses_shared_nested_symlink_and_permissive_locations() {
    let f = Fixture::new();
    let recipient = hex(&crypto::public_key(&[52; 32]).unwrap());
    let adjacent = f.root.join("backup/secret");
    assert!(!f
        .setup_at(&f.package, &adjacent, &recipient)
        .status
        .success());
    let nested = f.root.join("backup/inside");
    fs::create_dir(&nested).unwrap();
    fs::set_permissions(&nested, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(!f
        .setup_at(&f.package, &nested.join("key"), &recipient)
        .status
        .success());
    std::os::unix::fs::symlink(f.root.join("secret"), f.root.join("alias")).unwrap();
    assert!(!f
        .setup_at(&f.package, &f.root.join("alias/key"), &recipient)
        .status
        .success());
    std::os::unix::fs::symlink(&f.key, &f.secret).unwrap();
    assert!(!f
        .setup_at(&f.package, &f.secret, &recipient)
        .status
        .success());
    fs::remove_file(&f.secret).unwrap();
    fs::set_permissions(f.root.join("secret"), fs::Permissions::from_mode(0o755)).unwrap();
    assert!(!f
        .setup_at(&f.package, &f.secret, &recipient)
        .status
        .success());
    assert!(!f.package.exists() && !f.secret.exists());
    assert_eq!(fs::read(&f.key).unwrap(), [52; 32]);
}
#[test]
fn verification_refuses_symlink_hardlink_and_public_files() {
    let f = Fixture::new();
    let report = f.setup();
    let pin = report["package_sha256"].as_str().unwrap();
    let saved = f.root.join("backup/saved");
    fs::rename(&f.package, &saved).unwrap();
    std::os::unix::fs::symlink(&saved, &f.package).unwrap();
    assert!(!f.verify(pin).status.success());
    fs::remove_file(&f.package).unwrap();
    fs::hard_link(&saved, &f.package).unwrap();
    assert!(!f.verify(pin).status.success());
    fs::remove_file(&f.package).unwrap();
    fs::rename(&saved, &f.package).unwrap();
    fs::set_permissions(&f.package, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(!f.verify(pin).status.success());
    fs::set_permissions(&f.package, fs::Permissions::from_mode(0o600)).unwrap();
    fs::set_permissions(&f.secret, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(!f.verify(pin).status.success());
}
