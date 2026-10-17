#![cfg(feature = "v2-crypto")]
use hpke::{
    aead::ChaCha20Poly1305, kdf::HkdfSha256, kem::X25519HkdfSha256, Deserializable, Kem, OpModeR,
};
use kan::{
    evidence_crypto as crypto,
    evidence_service::{hex, unhex, Command, Grant, Output, Request, Service, SignedRequest},
    evidence_store::Ledger,
    sign::Identity,
};

#[test]
fn published_rfc9180_vector() {
    type K = X25519HkdfSha256;
    let v: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/hpke/rfc9180-x25519-chacha.json")).unwrap();
    let b = |name: &str| unhex(v[name].as_str().unwrap(), 4096).unwrap();
    let key = <K as Kem>::PrivateKey::from_bytes(&b("skRm")).unwrap();
    let enc = <K as Kem>::EncappedKey::from_bytes(&b("enc")).unwrap();
    let mut ctx = hpke::setup_receiver::<ChaCha20Poly1305, HkdfSha256, K>(
        &OpModeR::Base,
        &key,
        &enc,
        &b("info"),
    )
    .unwrap();
    for case in v["encryptions"].as_array().unwrap() {
        let b = |name: &str| unhex(case[name].as_str().unwrap(), 4096).unwrap();
        assert_eq!(ctx.open(&b("ct"), &b("aad")).unwrap(), b("pt"));
    }
}

#[test]
fn authenticated_boundaries_and_fresh_encapsulation() {
    let private = [17; 32];
    let public = crypto::public_key(&private).unwrap();
    let scope = [19; 32];
    let frame = crypto::seal(&public, &scope, b"fixture").unwrap();
    assert_ne!(frame, crypto::seal(&public, &scope, b"fixture").unwrap());
    assert_eq!(crypto::open(&private, &scope, &frame).unwrap(), b"fixture");
    assert!(crypto::open(&[18; 32], &scope, &frame).is_err());
    assert!(crypto::open(&private, &[20; 32], &frame).is_err());
    // Every byte, including all authenticated header fields and the tag.
    for i in 0..frame.len() {
        let mut changed = frame.clone();
        changed[i] ^= 1;
        assert!(
            crypto::open(&private, &scope, &changed).is_err(),
            "byte {i}"
        );
    }
    for len in 0..frame.len() {
        assert!(crypto::open(&private, &scope, &frame[..len]).is_err());
    }
    let mut longer = frame.clone();
    longer.push(0);
    assert!(crypto::open(&private, &scope, &longer).is_err());
    assert!(crypto::seal(&[0; 32], &scope, b"invalid DH recipient").is_err());
    let empty = crypto::seal(&public, &scope, b"").unwrap();
    assert_eq!(crypto::open(&private, &scope, &empty).unwrap(), b"");
    let maximum = vec![42; crypto::MAX_PLAINTEXT];
    let full = crypto::seal(&public, &scope, &maximum).unwrap();
    assert_eq!(full.len(), kan::evidence_service::MAX_PAYLOAD);
    assert_eq!(crypto::open(&private, &scope, &full).unwrap(), maximum);
    assert!(crypto::seal(&public, &scope, &vec![0; crypto::MAX_PLAINTEXT + 1]).is_err());
}

fn oracle(
    private: &[u8; 32],
    scope: &[u8; 32],
    frame: &[u8],
    plaintext: &[u8],
) -> std::process::Output {
    let python = std::env::var_os("KAN_CRYPTO_ORACLE_PYTHON").unwrap_or_else(|| "python3".into());
    let mut child = std::process::Command::new(python)
        .arg("-I")
        .arg("scripts/verify_archive_encryption.py")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    serde_json::to_writer(child.stdin.take().unwrap(), &serde_json::json!({"private":hex(private),"scope":hex(scope),"frame":hex(frame),"plaintext":hex(plaintext)})).unwrap();
    child.wait_with_output().unwrap()
}

#[test]
fn independent_receiver_accepts_and_rejects_authenticated_data() {
    let private = [29; 32];
    let scope = [31; 32];
    let frame = crypto::seal(
        &crypto::public_key(&private).unwrap(),
        &scope,
        b"independent oracle fixture",
    )
    .unwrap();
    let accepted = oracle(&private, &scope, &frame, b"independent oracle fixture");
    assert!(
        accepted.status.success(),
        "{}",
        String::from_utf8_lossy(&accepted.stderr)
    );
    let mut changed = frame;
    *changed.last_mut().unwrap() ^= 1;
    let rejected = oracle(&private, &scope, &changed, b"independent oracle fixture");
    assert!(!rejected.status.success());
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("InvalidTag"));
}

#[test]
fn blind_service_backup_recovers_original_ciphertext_and_plaintext() {
    let t = tempfile::tempdir().unwrap();
    let root = t.path().join("archive");
    let private = [37; 32];
    let scope = [41; 32];
    let plaintext = b"UNIQUE-PLAINTEXT-CANARY-ONLY-THE-OWNER-SHOULD-RECOVER-2026";
    let frame = crypto::seal(&crypto::public_key(&private).unwrap(), &scope, plaintext).unwrap();
    let writer = Identity::generate();
    let server = Identity::generate();
    let audience = server.did().to_string();
    let make = |command, expires| {
        SignedRequest::sign(
            Request {
                version: 1,
                scope: hex(&scope),
                audience: audience.clone(),
                principal: writer.did().to_string(),
                expires,
                command,
            },
            &writer,
        )
        .unwrap()
        .bytes()
        .unwrap()
    };
    let raw = make(
        Command::Append {
            id: hex(&[43; 16]),
            position: 0,
            previous: None,
            ciphertext: hex(&frame),
        },
        None,
    );
    let mut service = Service::new(
        Ledger::create(&root).unwrap(),
        scope,
        server,
        vec![Grant {
            principal: writer.did().to_string(),
            append: true,
            inventory: true,
        }],
    )
    .unwrap();
    assert!(matches!(
        service.dispatch(&raw, 1000).unwrap().reply.result,
        Ok(Output::Committed {
            duplicate: false,
            ..
        })
    ));
    assert!(matches!(
        service.dispatch(&raw, 1000).unwrap().reply.result,
        Ok(Output::Committed {
            duplicate: true,
            ..
        })
    ));
    drop(service);
    let backup = t.path().join("backup.sqlite");
    Ledger::open(&root).unwrap().backup(&backup).unwrap();
    for path in [root.join("archive.sqlite"), backup.clone()] {
        let bytes = std::fs::read(path).unwrap();
        assert!(!bytes.windows(plaintext.len()).any(|w| w == plaintext));
    }
    // Restore standalone SQLite backup into a fresh namespace. No original DB.
    let restored = t.path().join("restored");
    std::fs::create_dir(&restored).unwrap();
    std::fs::copy(&backup, restored.join("archive.sqlite")).unwrap();
    let mut service = Service::new(
        Ledger::open(&restored).unwrap(),
        scope,
        Identity::generate(),
        vec![Grant {
            principal: writer.did().to_string(),
            append: false,
            inventory: true,
        }],
    )
    .unwrap();
    let read = SignedRequest::sign(
        Request {
            version: 1,
            scope: hex(&scope),
            audience: service.issuer(),
            principal: writer.did().to_string(),
            expires: Some(1100),
            command: Command::Read { sequence: 1 },
        },
        &writer,
    )
    .unwrap()
    .bytes()
    .unwrap();
    let Output::Evidence { signed_request, .. } =
        service.dispatch(&read, 1000).unwrap().reply.result.unwrap()
    else {
        panic!()
    };
    let recovered = unhex(&signed_request, 4 * 1024 * 1024).unwrap();
    assert_eq!(recovered, raw);
    let Command::Append { ciphertext, .. } =
        SignedRequest::decode(&recovered).unwrap().request.command
    else {
        panic!()
    };
    let ciphertext = unhex(&ciphertext, 1048576).unwrap();
    assert_eq!(ciphertext, frame);
    assert_eq!(
        crypto::open(&private, &scope, &ciphertext).unwrap(),
        plaintext
    );
}
