#![cfg(feature = "v2-storage")]
//! TEMPORARY reviewer probes for 423054a. Removed after the run; a copy is kept
//! in review-evidence/probes/. Synthetic fixtures only.
use kan::{
    evidence_copy_plan::Target,
    evidence_service::{self as service, hex, Command, Grant, Request, Service, SignedRequest},
    evidence_store::{
        copy_upgrade::{read_plan_for_copy, retain_plan, PlannedCopy},
        Ledger,
    },
    sign::Identity,
};
use std::{
    io::Write,
    path::{Path, PathBuf},
};

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
            command: Command::Append {
                id: service::hex(&[n + 1; 16]),
                position: n as u64,
                previous,
                ciphertext: service::hex(b"synthetic opaque payload"),
            },
        },
        &signer,
    )
    .unwrap()
    .bytes()
    .unwrap()
}
fn fixture_in(dir: &Path, records: usize, staged: usize) -> PathBuf {
    let root = dir.to_path_buf();
    let mut s = Service::new(
        Ledger::create(&root).unwrap(),
        [1; 32],
        identity(7),
        vec![Grant {
            principal: identity(6).did().to_string(),
            append: true,
            inventory: false,
        }],
    )
    .unwrap();
    let mut previous = None;
    for n in 0..records {
        let bytes = request(6, 7, n as u8, previous);
        assert!(s
            .dispatch(&bytes, 100 + n as u64)
            .unwrap()
            .reply
            .result
            .is_ok());
        previous = Some(service::append_manifest(&bytes).unwrap().cid().to_string());
    }
    drop(s);
    let mut ledger = Ledger::open(&root).unwrap();
    for n in 0..staged {
        ledger.stage(&vec![n as u8; 17 + n]).unwrap();
    }
    drop(ledger);
    root.join("archive.sqlite")
}
fn source(path: &Path) -> PlannedCopy {
    PlannedCopy::open(
        path,
        Target {
            scope: [1; 32],
            issuer: identity(8).did().to_string(),
        },
        identity(7).did().to_string(),
        [9; 32],
    )
    .unwrap()
}
fn private(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}
fn key(dir: &Path) -> PathBuf {
    let key = dir.join("key");
    std::fs::write(&key, [8; 32]).unwrap();
    private(&key);
    key
}
fn cli_in(cwd: &Path, args: &[&str]) -> std::process::Output {
    std::process::Command::new(env!("CARGO_BIN_EXE_kan-v2"))
        .current_dir(cwd)
        .args(args)
        .output()
        .unwrap()
}
fn batch_args<'a>(
    db: &'a str,
    root: &'a str,
    plan: &'a str,
    key: &'a str,
    pins: &'a [String; 3],
    resume: bool,
) -> Vec<&'a str> {
    let mut v = vec![
        "copy-batch",
        db,
        root,
        "--plan",
        plan,
        "--key",
        key,
        "--copy-profile",
        "--proof-archive",
        &pins[0],
        "--proof-scope",
        &pins[1],
        "--proof-issuer",
        &pins[2],
        "--objects",
        "1",
        "--records",
        "1",
        "--bytes",
        "4194304",
    ];
    if resume {
        v.push("--resume");
    }
    v
}
fn pins(source: &PlannedCopy) -> [String; 3] {
    [
        hex(&source.plan().archive_id()),
        hex(&[1; 32]),
        identity(8).did().to_string(),
    ]
}
fn show(o: &std::process::Output) -> String {
    format!(
        "exit={:?} stdout={} stderr={}",
        o.status.code(),
        String::from_utf8_lossy(&o.stdout).trim(),
        String::from_utf8_lossy(&o.stderr).trim()
    )
}
fn listing(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}
// U+017F LATIN SMALL LETTER LONG S case-folds to ASCII 's' on case-insensitive APFS.
const LONG_S_SHM: &str = "archive.sqlite-\u{17f}hm";

/// P1: destination family, Unicode case-fold alias of `-shm`, via the real CLI.
#[test]
fn p1_destination_long_s_shm_alias_on_resume() {
    let t = tempfile::tempdir().unwrap();
    let srcdir = t.path().join("source");
    let db = fixture_in(&srcdir, 3, 1);
    let s = source(&db);
    let pins = pins(&s);
    let good = t.path().join("plan.cbor");
    retain_plan(&good, &s).unwrap();
    let plan_bytes = std::fs::read(&good).unwrap();
    drop(s);
    let key = key(t.path());
    let root = t.path().join("copy");
    let (d, r, g, k) = (
        db.to_str().unwrap(),
        root.to_str().unwrap(),
        good.to_str().unwrap(),
        key.to_str().unwrap(),
    );
    let first = cli_in(t.path(), &batch_args(d, r, g, k, &pins, false));
    println!("P1 first batch (legit plan): {}", show(&first));
    assert!(first.status.success());
    println!("P1 dest listing after first batch: {:?}", listing(&root));
    // ASCII control: -shm is refused by read_plan_for_copy.
    let ascii = root.join("archive.sqlite-shm");
    if !ascii.exists() {
        std::fs::write(&ascii, &plan_bytes).unwrap();
        private(&ascii);
        let e = read_plan_for_copy(&ascii, &db, &root, &s_pin(&pins));
        println!("P1 control ASCII -shm read_plan_for_copy: {:?}", e.map(|p| p.bytes().len()));
        std::fs::remove_file(&ascii).unwrap();
    } else {
        println!("P1 control skipped: -shm exists");
    }
    let alias = root.join(LONG_S_SHM);
    println!("P1 -shm exists before alias placement: {}", ascii.exists());
    std::fs::write(&alias, &plan_bytes).unwrap();
    private(&alias);
    println!(
        "P1 alias visible as ASCII -shm (same file): {}",
        ascii.exists()
    );
    let api = read_plan_for_copy(&alias, &db, &root, &s_pin(&pins));
    println!(
        "P1 read_plan_for_copy(DEST/{LONG_S_SHM}): {:?}",
        api.as_ref().map(|p| p.bytes().len()).map_err(|e| e.to_string())
    );
    let before_db = std::fs::read(&db).unwrap();
    let a = alias.to_str().unwrap();
    let resumed = cli_in(t.path(), &batch_args(d, r, a, k, &pins, true));
    println!("P1 resume with alias plan: {}", show(&resumed));
    let after = std::fs::read(&alias).ok();
    println!(
        "P1 alias plan after resume: exists={} unchanged={} len={:?} (orig {})",
        after.is_some(),
        after.as_deref() == Some(plan_bytes.as_slice()),
        after.as_ref().map(Vec::len),
        plan_bytes.len()
    );
    println!("P1 dest listing after resume: {:?}", listing(&root));
    assert_eq!(std::fs::read(&db).unwrap(), before_db, "source bytes changed");
}

fn s_pin(pins: &[String; 3]) -> [u8; 32] {
    service::unhex(&pins[0], 32).unwrap().try_into().unwrap()
}

/// P2: source family, Unicode case-fold alias of `-shm`.
#[test]
fn p2_source_long_s_shm_alias() {
    let t = tempfile::tempdir().unwrap();
    let srcdir = t.path().join("source");
    let db = fixture_in(&srcdir, 2, 0);
    let s = source(&db);
    let pin = s.plan().archive_id();
    let bytes = s.plan().bytes().to_vec();
    let alias = srcdir.join(LONG_S_SHM);
    println!(
        "P2 with live reader: -shm exists={} listing={:?}",
        srcdir.join("archive.sqlite-shm").exists(),
        listing(&srcdir)
    );
    let shm_before = std::fs::read(srcdir.join("archive.sqlite-shm")).ok();
    let r = retain_plan(&alias, &s);
    println!(
        "P2 retain_plan(SRC/{LONG_S_SHM}) with live reader: {:?}",
        r.map_err(|e| e.to_string())
    );
    println!(
        "P2 existing -shm unchanged after refusal: {}",
        std::fs::read(srcdir.join("archive.sqlite-shm")).ok() == shm_before
    );
    drop(s);
    println!(
        "P2 after drop: -shm exists={} listing={:?}",
        srcdir.join("archive.sqlite-shm").exists(),
        listing(&srcdir)
    );
    if srcdir.join("archive.sqlite-shm").exists() {
        println!("P2 source shm persists after close; alias placement would overwrite it, stop");
        return;
    }
    std::fs::write(&alias, &bytes).unwrap();
    private(&alias);
    let root = t.path().join("copy");
    let api = read_plan_for_copy(&alias, &db, &root, &pin);
    println!(
        "P2 read_plan_for_copy(SRC/{LONG_S_SHM}): {:?}",
        api.as_ref().map(|p| p.bytes().len()).map_err(|e| e.to_string())
    );
    if let Ok(recipe) = api {
        let c = PlannedCopy::confirm(&db, &recipe, &pin);
        println!("P2 confirm after accepted alias: ok={}", c.is_ok());
        drop(c);
        let after = std::fs::read(&alias).ok();
        println!(
            "P2 alias plan after source open: exists={} unchanged={} len={:?}",
            after.is_some(),
            after.as_deref() == Some(bytes.as_slice()),
            after.as_ref().map(Vec::len)
        );
    }
}

/// L: legitimate placements and relative CLI paths must keep working.
#[test]
fn l_legitimate_paths_complete_and_resume() {
    let t = tempfile::tempdir().unwrap();
    let srcdir = t.path().join("source");
    let db = fixture_in(&srcdir, 2, 1);
    let s = source(&db);
    let pin = s.plan().archive_id();
    let pins = pins(&s);
    let root = t.path().join("copy");
    for name in [
        "archive.sqlite.plan",
        "archive.sqlite-journal.cbor",
        "archive.sqlite-wal-plan",
        "plan-shm",
    ] {
        let p = srcdir.join(name);
        let r = retain_plan(&p, &s).map_err(|e| e.to_string());
        let rr = read_plan_for_copy(&p, &db, &root, &pin)
            .map(|p| p.bytes() == s.plan().bytes())
            .map_err(|e| e.to_string());
        println!("L source-dir neighbour {name}: retain={r:?} read_for_copy_exact={rr:?}");
        assert!(r.is_ok() && rr == Ok(true), "legit {name} refused");
    }
    drop(s);
    let _key = key(t.path());
    // Relative paths from the scratch cwd: copy-plan then batches to completion.
    let o = cli_in(
        t.path(),
        &[
            "copy-plan",
            "source/archive.sqlite",
            "rel-plan.cbor",
            "--scope",
            &pins[1],
            "--issuer",
            &pins[2],
            "--historical-issuer",
            &identity(7).did().to_string(),
            "--nonce",
            &hex(&[9; 32]),
        ],
    );
    println!("L relative copy-plan: {}", show(&o));
    assert!(o.status.success());
    let args = |resume| batch_args("source/archive.sqlite", "copy", "rel-plan.cbor", "key", &pins, resume);
    let first = cli_in(t.path(), &args(false));
    println!("L relative first batch: {}", show(&first));
    assert!(first.status.success());
    // A non-sidecar plan inside the existing destination directory on resume.
    std::fs::copy(t.path().join("rel-plan.cbor"), root.join("recipe.cbor")).unwrap();
    private(&root.join("recipe.cbor"));
    let inside = root.join("recipe.cbor");
    let inside_bytes = std::fs::read(&inside).unwrap();
    let mut complete = false;
    for n in 0..12 {
        let o = cli_in(
            t.path(),
            &batch_args(
                "source/archive.sqlite",
                "copy",
                if n % 2 == 0 { "copy/recipe.cbor" } else { "rel-plan.cbor" },
                "key",
                &pins,
                true,
            ),
        );
        assert!(o.status.success(), "L resume {n}: {}", show(&o));
        let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
        if v["copy"]["source_copy_complete"] == serde_json::Value::Bool(true) {
            println!("L complete after resume {n}: {}", show(&o));
            complete = true;
            break;
        }
    }
    assert!(complete);
    assert_eq!(std::fs::read(&inside).unwrap(), inside_bytes);
    println!("L dest listing: {:?}", listing(&root));
    // Absent destination with absent parent refuses before anything is created.
    let deep = t.path().join("missing-parent").join("copy");
    let e = read_plan_for_copy(&t.path().join("rel-plan.cbor"), &db, &deep, &pin)
        .map(|_| ())
        .map_err(|e| e.to_string());
    println!("L absent destination parent: {e:?}");
    assert!(e.is_err() && !t.path().join("missing-parent").exists());
}

/// A: alias attacks on the source family through directory and name spellings.
#[test]
fn a_alias_attacks_refuse_and_preserve_bytes() {
    let t = tempfile::tempdir().unwrap();
    let nfc = t.path().join("caf\u{e9}");
    let db = fixture_in(&nfc, 2, 0);
    let s = source(&db);
    let pin = s.plan().archive_id();
    let bytes = s.plan().bytes().to_vec();
    let db_before = std::fs::read(&db).unwrap();
    std::os::unix::fs::symlink(&nfc, t.path().join("link")).unwrap();
    let root = t.path().join("copy");
    let cases: Vec<(&str, PathBuf)> = vec![
        ("symlinked dir", t.path().join("link/archive.sqlite-journal")),
        ("NFD dir spelling", t.path().join("cafe\u{301}/archive.sqlite-journal")),
        ("ASCII-case dir", t.path().join("CAF\u{e9}/archive.sqlite-journal")),
        ("dotdot", nfc.join("x/../archive.sqlite-journal")),
        ("long-s main name + -journal", nfc.join("archive.\u{17f}qlite-journal")),
        ("upper main + -Journal", nfc.join("ARCHIVE.SQLITE-Journal")),
    ];
    std::fs::create_dir(nfc.join("x")).unwrap();
    for (label, p) in &cases {
        let r = retain_plan(p, &s).map_err(|e| e.to_string());
        let journal = nfc.join("archive.sqlite-journal").exists();
        println!("A retain {label} -> {r:?}; journal created={journal}");
        assert!(r.is_err(), "{label} accepted");
        assert!(!journal);
    }
    drop(s);
    // Read side: an existing plan at the real -journal, reached through aliases.
    let real = nfc.join("archive.sqlite-journal");
    std::fs::write(&real, &bytes).unwrap();
    private(&real);
    for (label, p) in &cases {
        let r = read_plan_for_copy(p, &db, &root, &pin)
            .map(|_| ())
            .map_err(|e| e.to_string());
        println!("A read_for_copy {label} -> {r:?}");
        assert!(r.is_err(), "{label} read accepted");
    }
    std::fs::remove_file(&real).unwrap();
    // Main-file aliases at read time.
    for (label, p) in [
        ("long-s main", nfc.join("archive.\u{17f}qlite")),
        ("NFD main dir", t.path().join("cafe\u{301}/archive.sqlite")),
    ] {
        let r = read_plan_for_copy(&p, &db, &root, &pin)
            .map(|_| ())
            .map_err(|e| e.to_string());
        println!("A read_for_copy {label} -> {r:?}");
        assert!(r.is_err());
    }
    // Destination root through a symlink: plan at the real DEST sidecar.
    std::fs::create_dir(&root).unwrap();
    std::os::unix::fs::symlink(&root, t.path().join("copy-link")).unwrap();
    let dj = root.join("archive.sqlite-journal");
    std::fs::write(&dj, &bytes).unwrap();
    private(&dj);
    let r = read_plan_for_copy(&dj, &db, &t.path().join("copy-link"), &pin)
        .map(|_| ())
        .map_err(|e| e.to_string());
    println!("A read_for_copy dest-root symlink -> {r:?}");
    assert!(r.is_err());
    assert_eq!(std::fs::read(&dj).unwrap(), bytes);
    // Plan as a symlink to a good plan file (F7 wording).
    let good = t.path().join("good.cbor");
    std::fs::write(&good, &bytes).unwrap();
    private(&good);
    std::os::unix::fs::symlink(&good, t.path().join("plan-link")).unwrap();
    let r = read_plan_for_copy(&t.path().join("plan-link"), &db, &root, &pin)
        .map(|_| ())
        .map_err(|e| e.to_string());
    println!("A read_for_copy symlink plan file -> {r:?}");
    assert!(r.is_err());
    assert_eq!(std::fs::read(&db).unwrap(), db_before);
    assert_eq!(std::fs::read(&good).unwrap(), bytes);
}

/// P3: source family alias after a legacy writer closed and removed its sidecars.
#[test]
fn p3_source_long_s_shm_alias_after_clean_writer_close() {
    let t = tempfile::tempdir().unwrap();
    let srcdir = t.path().join("source");
    let db = fixture_in(&srcdir, 2, 0);
    let s = source(&db);
    let pin = s.plan().archive_id();
    let bytes = s.plan().bytes().to_vec();
    drop(s);
    for f in ["archive.sqlite-shm", "archive.sqlite-wal"] {
        let p = srcdir.join(f);
        if p.exists() && std::fs::metadata(&p).unwrap().len() == 0 {
            // Only empty reader-created sidecars; a legacy writer then closes cleanly.
        }
    }
    drop(Ledger::open(&srcdir).unwrap());
    println!("P3 after clean writer close: listing={:?}", listing(&srcdir));
    if srcdir.join("archive.sqlite-shm").exists() {
        println!("P3 -shm still present; cannot place alias without overwriting it, stop");
        return;
    }
    let alias = srcdir.join(LONG_S_SHM);
    std::fs::write(&alias, &bytes).unwrap();
    private(&alias);
    let db_before = std::fs::read(&db).unwrap();
    let root = t.path().join("copy");
    let api = read_plan_for_copy(&alias, &db, &root, &pin);
    println!(
        "P3 read_plan_for_copy(SRC/{LONG_S_SHM}): {:?}",
        api.as_ref().map(|p| p.bytes().len()).map_err(|e| e.to_string())
    );
    if let Ok(recipe) = api {
        let c = PlannedCopy::confirm(&db, &recipe, &pin);
        println!("P3 confirm: ok={}", c.is_ok());
        let during = std::fs::read(&alias).ok();
        println!(
            "P3 alias plan while source reader open: exists={} unchanged={}",
            during.is_some(),
            during.as_deref() == Some(bytes.as_slice())
        );
        drop(c);
        drop(Ledger::open(&srcdir).unwrap());
        let after = std::fs::read(&alias).ok();
        println!(
            "P3 alias plan after next legacy writer open/close: exists={} unchanged={}",
            after.is_some(),
            after.as_deref() == Some(bytes.as_slice())
        );
    }
    let _ = db_before;
}
