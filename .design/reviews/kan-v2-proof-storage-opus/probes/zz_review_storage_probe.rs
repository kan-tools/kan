#![cfg(feature = "v2-storage")]
//! Independent reviewer probes for 9f1dffa. Temporary; removed after the review.
use kan::{
    evidence_attestation::{self as proof, Context, Frontier, Purpose},
    evidence_service::{hex, Command as Operation, Failure, Grant, Request, Service, SignedRequest},
    evidence_store::{
        attested::{Archive, Binding},
        Boundary, Ledger, RecoveryReader,
    },
    sign::Identity,
};
use sha2::{Digest, Sha256};
use std::{io::Write, path::Path};

fn identity(byte: u8) -> Identity {
    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(&[byte; 32]).unwrap();
    Identity::load_existing(file.path()).unwrap()
}
fn binding() -> Binding {
    Binding {
        archive: [8; 32],
        scope: [9; 32],
        issuer: identity(7).did().to_string(),
    }
}
fn grant_for(writer: u8) -> Grant {
    Grant {
        principal: identity(writer).did().to_string(),
        append: true,
        inventory: false,
    }
}
fn request_to(
    writer: u8,
    audience: &str,
    op: u8,
    position: u64,
    previous: Option<String>,
) -> Vec<u8> {
    let w = identity(writer);
    SignedRequest::sign(
        Request {
            version: 1,
            scope: hex(&[9; 32]),
            audience: audience.into(),
            principal: w.did().to_string(),
            expires: None,
            command: Operation::Append {
                id: hex(&[op; 16]),
                position,
                previous,
                ciphertext: hex(format!("payload {writer} {op}").as_bytes()),
            },
        },
        &w,
    )
    .unwrap()
    .bytes()
    .unwrap()
}
fn request(position: u64, previous: Option<String>) -> Vec<u8> {
    request_to(6, &binding().issuer, position as u8, position, previous)
}
fn conn(root: &Path) -> rusqlite::Connection {
    rusqlite::Connection::open(root.join("archive.sqlite")).unwrap()
}
fn ctx(b: &Binding) -> Context<'_> {
    Context {
        issuer: &b.issuer,
        archive: b.archive,
        scope: b.scope,
    }
}
fn file_digest(path: &Path) -> String {
    format!("{:x}", Sha256::digest(std::fs::read(path).unwrap()))
}

/// P1: an existing profile-1 archive is refused by the profile-2 opener before
/// any byte of the authoritative database changes.
#[test]
fn p1_profile1_archive_is_refused_by_attested_open_without_writes() {
    let temp = tempfile::tempdir().unwrap();
    drop(Ledger::create(temp.path()).unwrap());
    let db = temp.path().join("archive.sqlite");
    let before = file_digest(&db);
    let err = Archive::open(temp.path(), binding()).err().expect("profile 1 opened as profile 2");
    assert!(err.to_string().contains("unknown database profile"), "{err}");
    assert_eq!(before, file_digest(&db), "profile-1 database bytes changed");
    let v: i64 = conn(temp.path())
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap();
    assert_eq!(v, 1);
}

/// P2: change only the 64 signature bytes (the author's "signature" mutation
/// flips the final envelope byte, which lies in the nested statement).
#[test]
fn p2_signature_only_mutation_refuses_open_with_named_audit_error() {
    let temp = tempfile::tempdir().unwrap();
    let mut archive = Archive::create(temp.path(), binding()).unwrap();
    let row = archive
        .admit(&request(0, None), &identity(7), &grant_for(6), 100)
        .unwrap();
    drop(archive);
    let mut bytes = row.attestation.bytes().to_vec();
    let key = bytes.windows(9).position(|w| w == b"signature").unwrap();
    assert_eq!(&bytes[key + 9..key + 11], &[0x58, 0x40], "signature header");
    let last_sig = key + 11 + 63;
    // Also show the author's last-byte flip is inside the statement, not the signature.
    let stmt = bytes.windows(9).position(|w| w == b"statement").unwrap();
    assert!(stmt > last_sig && bytes.len() - 1 > stmt);
    bytes[key + 11 + 10] ^= 0x01;
    conn(temp.path())
        .execute("UPDATE attestations SET envelope=?", [bytes])
        .unwrap();
    let err = Archive::open(temp.path(), binding()).err().expect("accepted forged signature");
    assert!(err.to_string().contains("invalid attestation chain"), "{err}");
}

/// P3: an exact retry of a NON-tip row whose stored proof is replaced by a
/// valid alternate statement between audit and the writer lock must not return
/// the audited bytes while the database holds different ones.
#[test]
fn p3_retry_of_earlier_row_detects_proof_replacement_under_lock() {
    let temp = tempfile::tempdir().unwrap();
    let b = binding();
    let mut archive = Archive::create(temp.path(), b.clone()).unwrap();
    let first = archive
        .admit(&request(0, None), &identity(7), &grant_for(6), 100)
        .unwrap();
    archive
        .admit(
            &request(1, Some(first.record.manifest.cid().to_string())),
            &identity(7),
            &grant_for(6),
            101,
        )
        .unwrap();
    let alternate = proof::issue(
        &identity(7),
        &ctx(&b),
        &first.record.manifest,
        &first.record.receipt,
        &Frontier::default(),
        Purpose::Admitted,
        777_000,
    )
    .unwrap();
    assert_ne!(alternate.bytes(), first.attestation.bytes());
    let mut swapped = false;
    let result = archive.admit_observed(
        &request(0, None),
        &identity(7),
        &grant_for(6),
        500,
        &mut |boundary| {
            if boundary == Boundary::ObjectDurable && !swapped {
                swapped = true;
                conn(temp.path())
                    .execute(
                        "UPDATE attestations SET envelope=? WHERE sequence=1",
                        [alternate.bytes()],
                    )
                    .unwrap();
            }
        },
    );
    assert!(swapped);
    assert_eq!(
        result.map(|a| a.attestation.bytes().to_vec()).unwrap_err(),
        Failure::Conflict,
        "retry returned audited proof although stored proof changed"
    );
}

/// P4: same, but the stored RECEIPT of the earlier row is replaced by another
/// receipt that structurally binds the same manifest (different issuedAt).
#[test]
fn p4_retry_of_earlier_row_detects_receipt_replacement_under_lock() {
    let temp = tempfile::tempdir().unwrap();
    let donor = tempfile::tempdir().unwrap();
    let mut archive = Archive::create(temp.path(), binding()).unwrap();
    let first = archive
        .admit(&request(0, None), &identity(7), &grant_for(6), 100)
        .unwrap();
    archive
        .admit(
            &request(1, Some(first.record.manifest.cid().to_string())),
            &identity(7),
            &grant_for(6),
            101,
        )
        .unwrap();
    let other = Archive::create(donor.path(), binding())
        .unwrap()
        .admit(&request(0, None), &identity(7), &grant_for(6), 555)
        .unwrap();
    assert_eq!(other.record.manifest.cid(), first.record.manifest.cid());
    assert_ne!(other.record.receipt.bytes(), first.record.receipt.bytes());
    let mut swapped = false;
    let result = archive.admit_observed(
        &request(0, None),
        &identity(7),
        &grant_for(6),
        500,
        &mut |boundary| {
            if boundary == Boundary::ObjectDurable && !swapped {
                swapped = true;
                conn(temp.path())
                    .execute(
                        "UPDATE commits SET receipt=? WHERE sequence=1",
                        [other.record.receipt.bytes()],
                    )
                    .unwrap();
            }
        },
    );
    assert!(swapped);
    match result {
        Ok(a) => panic!(
            "retry acknowledged a receipt its stored proof does not attest: receipt_matches_first={}",
            a.record.receipt.bytes() == first.record.receipt.bytes()
        ),
        Err(f) => eprintln!("P4 failure class: {f:?}"),
    }
}

/// Build a profile-2 archive whose first rows are legacy records admitted by
/// historical issuers, then attested `retained-verified` by current issuer C.
fn upgraded(historical: [u8; 2]) -> (tempfile::TempDir, Vec<tempfile::TempDir>, Frontier) {
    let target = tempfile::tempdir().unwrap();
    let b = binding();
    drop(Archive::create(target.path(), b.clone()).unwrap());
    let mut sources = Vec::new();
    let mut records = Vec::new();
    for (i, h) in historical.into_iter().enumerate() {
        let writer = 20 + i as u8;
        let dir = tempfile::tempdir().unwrap();
        let ledger = Ledger::create(dir.path()).unwrap();
        let mut service = Service::new(ledger, [9; 32], identity(h), vec![grant_for(writer)]).unwrap();
        let req = request_to(writer, identity(h).did().as_str(), 1, 0, None);
        let reply = service.dispatch(&req, 100 + i as u64).unwrap();
        assert!(reply.reply.result.is_ok(), "{:?}", reply.reply.result);
        drop(service);
        let reader = RecoveryReader::open(&dir.path().join("archive.sqlite")).unwrap();
        records.push(reader.record(1).unwrap());
        drop(reader);
        let c = conn(target.path());
        c.execute(
            "ATTACH DATABASE ? AS src",
            [dir.path().join("archive.sqlite").to_str().unwrap()],
        )
        .unwrap();
        c.execute_batch(
            "INSERT INTO objects SELECT * FROM src.objects;
             INSERT INTO commits(cid,scope,writer,operation,position,previous,manifest,receipt)
               SELECT cid,scope,writer,operation,position,previous,manifest,receipt FROM src.commits ORDER BY sequence;
             INSERT INTO bindings SELECT * FROM src.bindings;",
        )
        .unwrap();
        sources.push(dir);
    }
    let mut frontier = Frontier::default();
    for (i, r) in records.iter().enumerate() {
        let p = proof::issue(
            &identity(7),
            &ctx(&b),
            &r.manifest,
            &r.receipt,
            &frontier,
            Purpose::RetainedVerified,
            900_000 + i as u64,
        )
        .unwrap();
        conn(target.path())
            .execute(
                "INSERT INTO attestations VALUES(?,?)",
                rusqlite::params![i as i64 + 1, p.bytes()],
            )
            .unwrap();
        frontier = p.frontier().clone();
    }
    (target, sources, frontier)
}

/// P5a: realistic upgrade shape with historical issuer H != current issuer C,
/// followed by ordinary admission. Store must accept it.
#[test]
fn p5a_single_historical_issuer_prefix_then_admission_is_accepted() {
    let (target, _s, frontier) = upgraded([11, 11]);
    let mut archive = Archive::open(target.path(), binding()).unwrap();
    assert_eq!(archive.verify().unwrap(), frontier);
    let next = archive
        .admit(&request(0, None), &identity(7), &grant_for(6), 200)
        .unwrap();
    assert_eq!(next.attestation.purpose(), Purpose::Admitted);
    assert_eq!(next.attestation.previous(), &frontier);
    assert_eq!(archive.verify().unwrap().through, 3);
}

/// P5b: a retained-verified prefix that mixes two historical issuers must be
/// refused by the full-chain audit ("one pinned historical receipt issuer").
#[test]
fn p5b_mixed_historical_issuers_in_prefix_are_refused() {
    let (target, _s, _) = upgraded([11, 12]);
    let err = Archive::open(target.path(), binding())
        .err()
        .expect("mixed historical issuers accepted");
    assert!(err.to_string().contains("retained-verified prefix"), "{err}");
}

/// P6: a second profile-2 handle performs a fully proven append between the
/// first handle's audit and its writer lock. The first must conflict.
#[test]
fn p6_concurrent_proven_append_from_second_handle_conflicts() {
    let temp = tempfile::tempdir().unwrap();
    let mut a = Archive::create(temp.path(), binding()).unwrap();
    a.admit(&request(0, None), &identity(7), &grant_for(6), 100)
        .unwrap();
    let mut raced = false;
    let path = temp.path().to_path_buf();
    let result = a.admit_observed(
        &request_to(30, &binding().issuer, 1, 0, None),
        &identity(7),
        &grant_for(30),
        101,
        &mut |boundary| {
            if boundary == Boundary::ObjectDurable && !raced {
                raced = true;
                let mut b = Archive::open(&path, binding()).unwrap();
                b.admit(
                    &request_to(31, &binding().issuer, 1, 0, None),
                    &identity(7),
                    &grant_for(31),
                    102,
                )
                .unwrap();
            }
        },
    );
    assert!(raced);
    assert_eq!(result.unwrap_err(), Failure::Conflict);
    let mut a = Archive::open(temp.path(), binding()).unwrap();
    assert_eq!(a.verify().unwrap().through, 2);
    // The loser's exact retry then succeeds on the new frontier.
    let retry = a
        .admit(
            &request_to(30, &binding().issuer, 1, 0, None),
            &identity(7),
            &grant_for(30),
            103,
        )
        .unwrap();
    assert!(!retry.record.duplicate);
    assert_eq!(retry.record.sequence, 3);
}

/// P7: canonical non-P-256 did:key issuer (secp256k1 example from the did:key
/// spec) is refused at archive creation.
#[test]
fn p7_non_p256_issuer_binding_is_refused_at_create() {
    let temp = tempfile::tempdir().unwrap();
    let k256 = "did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme";
    let root = temp.path().join("k256");
    let err = Archive::create(
        &root,
        Binding {
            issuer: k256.into(),
            ..binding()
        },
    )
    .err()
    .expect("non-P-256 issuer bound to a profile-2 archive");
    eprintln!("P7 error: {err}");
    assert!(!root.exists(), "refused create left a directory");
}

/// P8 (documentation probe): a crash after Archive::create wrote its empty file
/// but before the schema commit leaves an empty file. Record what each opener does.
#[test]
fn p8_interrupted_profile2_create_is_adopted_by_legacy_resume_as_profile1() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("a");
    std::fs::create_dir(&root).unwrap();
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(root.join("archive.sqlite"))
            .unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let create = Archive::create(&root, binding()).err().map(|e| e.to_string());
    let open = Archive::open(&root, binding()).err().map(|e| e.to_string());
    eprintln!("P8 Archive::create on interrupted dir: {create:?}");
    eprintln!("P8 Archive::open on interrupted dir: {open:?}");
    assert!(create.is_some() && open.is_some());
    let resumed = Ledger::resume_initialization(&root);
    eprintln!("P8 legacy resume_initialization: ok={}", resumed.is_ok());
    drop(resumed);
    let v: i64 = conn(&root)
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap();
    eprintln!("P8 resulting user_version={v}");
}

/// P9 workers for hostile materialization; driven externally under /usr/bin/time.
#[test]
fn p9_hostile_prepare() {
    let Ok(dir) = std::env::var("KAN_PROBE_DIR") else {
        return;
    };
    let kind = std::env::var("KAN_PROBE_KIND").unwrap();
    let mib: usize = std::env::var("KAN_PROBE_MIB").unwrap().parse().unwrap();
    let root = Path::new(&dir);
    let mut archive = Archive::create(root, binding()).unwrap();
    archive
        .admit(&request(0, None), &identity(7), &grant_for(6), 100)
        .unwrap();
    drop(archive);
    let c = conn(root);
    c.execute_batch("PRAGMA ignore_check_constraints=ON").unwrap();
    let big = vec![0x5au8; mib * 1024 * 1024];
    match kind.as_str() {
        "object" => {
            c.execute("INSERT INTO objects VALUES('zzzz-hostile',?)", [&big])
                .unwrap();
        }
        "envelope" => {
            c.execute("UPDATE attestations SET envelope=? WHERE sequence=1", [&big])
                .unwrap();
        }
        "none" => {}
        _ => unreachable!(),
    }
}
#[test]
fn p9_hostile_open_worker() {
    let Ok(dir) = std::env::var("KAN_PROBE_OPEN") else {
        return;
    };
    match Archive::open(Path::new(&dir), binding()) {
        Ok(_) => println!("P9 OPEN-RESULT ok"),
        Err(e) => println!("P9 OPEN-RESULT err: {e}"),
    }
}
#[test]
fn p9_legacy_prepare_and_open() {
    let Ok(dir) = std::env::var("KAN_PROBE_LEGACY_DIR") else {
        return;
    };
    let root = Path::new(&dir);
    if std::env::var("KAN_PROBE_PHASE").unwrap() == "prepare" {
        drop(Ledger::create(root).unwrap());
        let c = conn(root);
        c.execute_batch("PRAGMA ignore_check_constraints=ON").unwrap();
        c.execute(
            "INSERT INTO objects VALUES('zzzz-hostile',?)",
            [vec![0x5au8; 96 * 1024 * 1024]],
        )
        .unwrap();
    } else {
        match Ledger::open(root) {
            Ok(_) => println!("P9 LEGACY-OPEN ok"),
            Err(e) => println!("P9 LEGACY-OPEN err: {e}"),
        }
    }
}

/// P10 worker: admit one record and exit without closing SQLite (WAL retained).
#[test]
fn p10_wal_worker() {
    let Ok(dir) = std::env::var("KAN_PROBE_WAL") else {
        return;
    };
    let mut a = Archive::open(Path::new(&dir), binding()).unwrap();
    a.admit(&request(0, None), &identity(7), &grant_for(6), 100)
        .unwrap();
    std::process::exit(0);
}
fn media(root: &Path) -> Vec<(String, Option<String>)> {
    ["archive.sqlite", "archive.sqlite-wal", "archive.sqlite-shm"]
        .iter()
        .map(|n| {
            let p = root.join(n);
            (n.to_string(), p.exists().then(|| file_digest(&p)))
        })
        .collect()
}
/// P10: do legacy openers that refuse profile 2 change authoritative media
/// (main database / retained WAL) when a crash left committed rows in the WAL?
#[test]
fn p10_legacy_refusal_physical_media_effects() {
    for opener in ["Ledger::open", "Ledger::resume_initialization", "RecoveryReader::open"] {
        let temp = tempfile::tempdir().unwrap();
        drop(Archive::create(temp.path(), binding()).unwrap());
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "p10_wal_worker"])
            .env("KAN_PROBE_WAL", temp.path())
            .status()
            .unwrap();
        assert!(status.success());
        let before = media(temp.path());
        assert!(before[1].1.is_some(), "worker left no WAL");
        let refused = match opener {
            "Ledger::open" => Ledger::open(temp.path()).is_err(),
            "Ledger::resume_initialization" => Ledger::resume_initialization(temp.path()).is_err(),
            _ => RecoveryReader::open(&temp.path().join("archive.sqlite")).is_err(),
        };
        let after = media(temp.path());
        eprintln!(
            "P10 {opener}: refused={refused} main_changed={} wal_before={} wal_after={:?}",
            before[0].1 != after[0].1,
            before[1].1.is_some(),
            after[1].1.as_ref().map(|d| d == before[1].1.as_ref().unwrap())
        );
        assert!(refused);
        // Logical content must survive regardless of any SQLite checkpoint.
        let mut a = Archive::open(temp.path(), binding()).unwrap();
        assert_eq!(a.verify().unwrap().through, 1, "{opener}");
        drop(a);
    }
}
