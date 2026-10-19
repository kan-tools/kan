//! REVIEWER PROBES round 2 (cold review of d9b2110). Temporary in tests/.
#![cfg(feature = "v2-storage")]
use kan::{
    evidence_service::{self as service, Command, Grant, Request, Service, SignedRequest},
    evidence_store::Ledger,
    sign::Identity,
};
use std::{io::Write, path::{Path, PathBuf}};

fn identity(n: u8) -> Identity {
    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(&[n; 32]).unwrap();
    Identity::load_existing(file.path()).unwrap()
}
fn request(writer: u8, audience: u8, n: u8, previous: Option<String>) -> Vec<u8> {
    let signer = identity(writer);
    SignedRequest::sign(
        Request {
            version: 1,
            scope: service::hex(&[1; 32]),
            principal: signer.did().to_string(),
            audience: identity(audience).did().to_string(),
            expires: None,
            command: Command::Append { id: service::hex(&[n + 1; 16]), position: n as u64, previous, ciphertext: service::hex(b"synthetic opaque payload") },
        },
        &signer,
    )
    .unwrap()
    .bytes()
    .unwrap()
}
fn fixture(parent: &Path) -> PathBuf {
    let root = parent.join("source");
    let mut s = Service::new(Ledger::create(&root).unwrap(), [1; 32], identity(7), vec![Grant { principal: identity(6).did().to_string(), append: true, inventory: false }]).unwrap();
    assert!(s.dispatch(&request(6, 7, 0, None), 100).unwrap().reply.result.is_ok());
    drop(s);
    root.join("archive.sqlite")
}
fn cli(args: &[&str]) -> std::process::Output {
    std::process::Command::new(env!("CARGO_BIN_EXE_kan-v2")).args(args).output().unwrap()
}
fn show(label: &str, o: &std::process::Output) {
    println!("PROBE {label}: exit={:?} stdout={} stderr={}", o.status.code(), String::from_utf8_lossy(&o.stdout).trim(), String::from_utf8_lossy(&o.stderr).trim());
}

/// P-L: the plan artifact sits at <destination root>/archive.sqlite and the
/// owner passes --resume. Does the writable resume path open (and possibly
/// write) the plan artifact as SQLite?
#[test]
fn probe_l_plan_artifact_named_as_destination_database() {
    let t = tempfile::tempdir().unwrap();
    let db = fixture(t.path());
    let dest = t.path().join("dest");
    std::fs::create_dir(&dest).unwrap();
    let plan = dest.join("archive.sqlite");
    let scope = service::hex(&[1; 32]);
    let issuer = identity(8).did().to_string();
    let o = cli(&["copy-plan", db.to_str().unwrap(), plan.to_str().unwrap(), "--scope", &scope, "--issuer", &issuer, "--historical-issuer", &identity(7).did().to_string(), "--nonce", &service::hex(&[9; 32])]);
    show("L copy-plan PLAN=<dest>/archive.sqlite", &o);
    assert!(o.status.success());
    let pin = serde_json::from_slice::<serde_json::Value>(&o.stdout).unwrap()["archive"].as_str().unwrap().to_owned();
    let exact = std::fs::read(&plan).unwrap();
    let key = t.path().join("key");
    std::fs::write(&key, [8; 32]).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    for extra in [&[][..], &["--resume"][..]] {
        let mut a = vec!["copy-batch", db.to_str().unwrap(), dest.to_str().unwrap(), "--plan", plan.to_str().unwrap(), "--key", key.to_str().unwrap(), "--copy-profile", "--proof-archive", &pin, "--proof-scope", &scope, "--proof-issuer", &issuer];
        a.extend(extra);
        let o = cli(&a);
        show(&format!("L copy-batch DEST=<plan dir> {extra:?}"), &o);
        assert!(!o.status.success());
        let now = std::fs::read(&plan).unwrap();
        println!("PROBE L plan bytes unchanged: {}; sidecars: {:?}", now == exact, std::fs::read_dir(&dest).unwrap().map(|e| e.unwrap().file_name()).collect::<Vec<_>>());
        assert_eq!(now, exact, "plan artifact rewritten");
    }
}
