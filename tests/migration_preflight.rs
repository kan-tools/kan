#![cfg(feature = "v2-storage")]

use kan::migration_preflight::{
    discover, preview, preview_identity, preview_store, scan_car, NoticeKind,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{Seek, Write},
    path::Path,
    process::Command,
};

// Independently framed CAR fixture: canonical {roots: [], version: 1} header.
fn varint(mut n: u64) -> Vec<u8> {
    let mut out = vec![];
    while n >= 128 {
        out.push((n as u8 & 127) | 128);
        n >>= 7;
    }
    out.push(n as u8);
    out
}
fn car(blocks: usize, size: usize) -> Vec<u8> {
    let header = b"\xa2\x65roots\x80\x67version\x01";
    let mut raw = varint(header.len() as u64);
    raw.extend(header);
    for i in 0..blocks {
        let data = vec![i as u8; size];
        let digest = Sha256::digest(&data);
        raw.extend(varint((36 + size) as u64));
        raw.extend([1, 0x55, 0x12, 32]);
        raw.extend(digest);
        raw.extend(data);
    }
    raw
}
fn scan(raw: &[u8]) -> kan::migration_preflight::CarScan {
    let mut file = tempfile::tempfile().unwrap();
    file.write_all(raw).unwrap();
    file.rewind().unwrap();
    scan_car(&mut file)
}
fn workspace(root: &Path) {
    fs::create_dir_all(root.join(".kan/log")).unwrap();
    fs::create_dir_all(root.join(".claims")).unwrap();
    fs::write(root.join(".kan/log/repo.car"), car(1, 32)).unwrap();
    fs::write(root.join(".kan/log/HEAD"), "original head").unwrap();
    fs::write(
        root.join(".claims/provenance.md"),
        "original signed publication bytes",
    )
    .unwrap();
}
fn run(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_kan"))
        .args(args)
        .env("PATH", "/no-legacy-kan-binary-here")
        .output()
        .unwrap()
}

#[test]
fn independent_car_frames_stream_beyond_ten_megabytes() {
    let result = scan(&car(4, 3 * 1024 * 1024));
    assert_eq!(result.verified_blocks, 4);
    assert_eq!(result.unsupported_blocks, 0);
    assert!(result.error.is_none(), "{:?}", result.error);
}

#[test]
fn publication_only_workspace_is_discovered_without_creating_a_store() {
    let t = tempfile::tempdir().unwrap();
    fs::create_dir(t.path().join(".claims")).unwrap();
    let bytes = b"original signed publication";
    fs::write(t.path().join(".claims/record.md"), bytes).unwrap();
    assert_eq!(
        discover(&[t.path().into()]).roots,
        vec![t.path().canonicalize().unwrap()]
    );
    let report = preview(t.path()).unwrap();
    assert!(report.selected_inventory_complete);
    assert_eq!(report.selection, "workspace");
    assert_eq!(report.public_identity_history, "not-inventoried");
    assert_eq!(report.files.len(), 1);
    assert_eq!(
        report.files[0].sha256,
        format!("{:x}", Sha256::digest(bytes))
    );
    assert!(!t.path().join(".kan").exists());
    let result = run(&["preview", t.path().to_str().unwrap()]);
    assert!(result.status.success());
    let json: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(json["selected_inventory_complete"], true);
    assert_eq!(json["notices"][0]["kind"], "excluded");
}

#[test]
fn explicit_store_and_public_identity_selection_exclude_private_material() {
    let t = tempfile::tempdir().unwrap();
    let raw = car(4, 3 * 1024 * 1024);
    fs::write(t.path().join("repo.car"), &raw).unwrap();
    fs::write(t.path().join("HEAD"), b"original head").unwrap();
    fs::write(t.path().join("identity"), b"PRIVATE-CANARY").unwrap();
    let report = preview_store(t.path()).unwrap();
    assert!(report.selected_inventory_complete);
    assert_eq!(report.files.len(), 2);
    assert!(report
        .notices
        .iter()
        .all(|n| n.kind == NoticeKind::Excluded));
    let result = run(&["preview", t.path().to_str().unwrap(), "--store"]);
    assert!(result.status.success());
    let json: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(json["selection"], "log-directory");
    assert_eq!(json["selected_inventory_complete"], true);
    assert_eq!(fs::read(t.path().join("repo.car")).unwrap(), raw);

    let config = tempfile::tempdir().unwrap();
    let missing = preview_identity(config.path()).unwrap();
    assert!(!missing.selected_inventory_complete);
    assert_eq!(missing.notices[0].kind, NoticeKind::Unavailable);
    fs::create_dir_all(config.path().join("identity/ledger/events")).unwrap();
    fs::create_dir(config.path().join("credentials")).unwrap();
    fs::create_dir(config.path().join("identity/profiles")).unwrap();
    fs::write(config.path().join("credentials/secret"), b"PRIVATE-CANARY").unwrap();
    let event = config.path().join("identity/ledger/events/event.cbor");
    fs::write(&event, b"unknown exact public event").unwrap();
    fs::write(
        config.path().join("identity/ledger/events/.tmp-ignored"),
        b"ignored",
    )
    .unwrap();
    let report = preview_identity(config.path()).unwrap();
    assert!(report.selected_inventory_complete);
    assert_eq!(report.files.len(), 1);
    assert_eq!(
        report.files[0].path.to_str().unwrap(),
        "identity/ledger/events/event.cbor"
    );
    assert_eq!(
        report.public_identity_history,
        "selected-public-files-not-verified"
    );
    let result = run(&["preview-identity", config.path().to_str().unwrap()]);
    assert!(result.status.success());
    assert!(!String::from_utf8_lossy(&result.stdout).contains("PRIVATE-CANARY"));
    assert_eq!(fs::read(&event).unwrap(), b"unknown exact public event");
}

#[cfg(unix)]
#[test]
fn selected_public_history_symlinks_and_bad_car_report_incomplete() {
    let t = tempfile::tempdir().unwrap();
    fs::create_dir_all(t.path().join("identity/ledger/events")).unwrap();
    let outside = tempfile::tempdir().unwrap();
    fs::write(outside.path().join("secret"), b"PRIVATE-CANARY").unwrap();
    std::os::unix::fs::symlink(
        outside.path().join("secret"),
        t.path().join("identity/ledger/events/evil.cbor"),
    )
    .unwrap();
    let report = preview_identity(t.path()).unwrap();
    assert!(!report.selected_inventory_complete);
    assert!(report.files.is_empty());
    assert_eq!(report.notices[0].kind, NoticeKind::Unavailable);
    fs::write(t.path().join("repo.car"), b"broken").unwrap();
    let report = preview_store(t.path()).unwrap();
    assert!(!report.selected_inventory_complete);
    assert!(report
        .notices
        .iter()
        .any(|n| n.kind == NoticeKind::Unsupported));
    assert_eq!(report.files.len(), 1);
}
#[test]
fn malformed_and_unsupported_sources_are_explicit() {
    let valid = car(1, 128);
    let mut wrong_digest = valid.clone();
    *wrong_digest.last_mut().unwrap() ^= 1;
    let mut huge = car(0, 0);
    huge.extend(varint(u64::MAX));
    let mut truncated = valid.clone();
    truncated.pop();
    let mut unknown_hash = car(0, 0);
    unknown_hash.extend(varint(69));
    unknown_hash.extend([1, 0x55, 0x13, 64]);
    unknown_hash.extend([0; 64]);
    unknown_hash.push(0);
    for raw in [
        &wrong_digest,
        &huge,
        &truncated,
        &vec![0x80],
        &vec![0xff; 10],
        &vec![1, 0],
    ] {
        assert!(scan(raw).error.is_some());
    }
    let unsupported = scan(&unknown_hash);
    assert!(unsupported.error.is_none());
    assert_eq!(unsupported.unsupported_blocks, 1);
    assert_eq!(unsupported.verified_blocks, 0);
    let mut nonminimal = vec![0x91, 0];
    nonminimal.extend(&valid[1..]);
    assert!(scan(&nonminimal).error.is_some());
}
#[test]
fn discovery_and_preview_preserve_bytes_and_exclude_credentials() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("one");
    workspace(&root);
    workspace(&root.join("nested"));
    workspace(&root.join("target/excluded"));
    fs::write(root.join(".kan/identity"), "DO-NOT-READ-PRIVATE-KEY").unwrap();
    fs::write(root.join(".kan/index.sqlite"), "DO-NOT-READ-INDEX").unwrap();
    fs::create_dir(root.join(".kan/overlay")).unwrap();
    fs::write(root.join(".kan/overlay/repo.car"), b"broken recovery data").unwrap();
    let before = fs::read(root.join(".kan/log/repo.car")).unwrap();
    let metadata = fs::metadata(root.join(".kan/log/repo.car")).unwrap();
    let report = discover(&[temp.path().to_path_buf()]);
    assert_eq!(report.roots.len(), 2);
    assert!(report.notices.iter().any(|n| n.path.ends_with("target")));
    let p = preview(&root).unwrap();
    assert_eq!(p.files.len(), 4);
    assert!(!p.ready_for_cutover);
    assert_eq!(p.claim_signatures, "not-verified");
    assert_eq!(p.graph_reachability, "not-verified");
    let json = serde_json::to_string(&p).unwrap();
    assert!(!json.contains("DO-NOT-READ"));
    let primary = p
        .files
        .iter()
        .find(|f| f.path.ends_with("log/repo.car"))
        .unwrap();
    assert_eq!(primary.sha256, format!("{:x}", Sha256::digest(&before)));
    let overlay = p
        .files
        .iter()
        .find(|f| f.medium == "derived-recovery")
        .unwrap();
    assert!(overlay.car.as_ref().unwrap().error.is_some());
    assert_eq!(fs::read(root.join(".kan/log/repo.car")).unwrap(), before);
    assert_eq!(
        fs::metadata(root.join(".kan/log/repo.car"))
            .unwrap()
            .modified()
            .unwrap(),
        metadata.modified().unwrap()
    );
    let output = run(&["preview", root.to_str().unwrap()]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["ready_for_cutover"], false);
    assert_eq!(json["files"].as_array().unwrap().len(), 4);
    let output = run(&["discover", temp.path().to_str().unwrap()]);
    assert!(output.status.success());
    let json: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["roots"].as_array().unwrap().len(), 2);
}
#[test]
#[cfg(unix)]
fn symlink_sources_and_intermediate_scope_links_are_not_followed() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("repo");
    workspace(&root);
    let outside = temp.path().join("outside");
    fs::create_dir(&outside).unwrap();
    fs::write(outside.join("inception.cbor"), "PRIVATE-OUTSIDE").unwrap();
    std::os::unix::fs::symlink(&outside, root.join(".kan/scope")).unwrap();
    std::os::unix::fs::symlink(outside.join("inception.cbor"), root.join(".claims/evil.md"))
        .unwrap();
    std::os::unix::fs::symlink(temp.path().join("absent"), root.join("dangling")).unwrap();
    let p = preview(&root).unwrap();
    assert!(!p
        .files
        .iter()
        .any(|f| f.medium == "public-scope" || f.path.ends_with("evil.md")));
    assert!(p
        .notices
        .iter()
        .any(|n| n.reason.contains("scope directory")));
    assert!(p.notices.iter().any(|n| n.reason.contains("symlink")));
    let d = discover(&[root]);
    assert!(d
        .notices
        .iter()
        .any(|n| n.path.ends_with("dangling") && n.reason.contains("symlink")));
}
#[test]
#[allow(clippy::disallowed_types)] // Deliberate concurrent mutation of a test fixture.
fn changed_sources_are_not_certified_as_stable() {
    let temp = tempfile::tempdir().unwrap();
    workspace(temp.path());
    let path = temp.path().join(".kan/log/repo.car");
    fs::write(&path, car(1, 16 * 1024 * 1024)).unwrap();
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let signal = stop.clone();
    let (ready, wait) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        let mut file = fs::OpenOptions::new().write(true).open(&path).unwrap();
        let mut n = 0u8;
        file.write_all(&[n]).unwrap();
        ready.send(()).unwrap();
        while !signal.load(std::sync::atomic::Ordering::Relaxed) {
            file.rewind().unwrap();
            file.write_all(&[n]).unwrap();
            n = n.wrapping_add(1);
            std::thread::yield_now();
        }
    });
    wait.recv().unwrap();
    let report = preview(temp.path()).unwrap();
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    worker.join().unwrap();
    assert!(report
        .notices
        .iter()
        .any(|n| n.reason.contains("source changed")));
    assert!(!report.files.iter().any(|f| f.path.ends_with("repo.car")));
}
#[test]
fn real_cli_initialization_verification_and_backup_are_explicit() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("archive");
    let backup = temp.path().join("backup.sqlite");
    let output = run(&["init", root.to_str().unwrap()]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!run(&["init", root.to_str().unwrap()]).status.success());
    let output = run(&["backup", root.to_str().unwrap(), backup.to_str().unwrap()]);
    assert!(output.status.success());
    let json: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["independent_backup"], false);
    let before = fs::read(&backup).unwrap();
    let output = run(&["verify", backup.to_str().unwrap()]);
    assert!(output.status.success());
    assert_eq!(fs::read(&backup).unwrap(), before);
    assert!(
        !run(&["backup", root.to_str().unwrap(), backup.to_str().unwrap()])
            .status
            .success()
    );
    assert_eq!(fs::read(&backup).unwrap(), before);
}

#[test]
fn unknown_identity_entries_and_empty_selections_are_incomplete() {
    let t = tempfile::tempdir().unwrap();
    assert!(!preview_store(t.path()).unwrap().selected_inventory_complete);
    let events = t.path().join("identity/ledger/events");
    fs::create_dir_all(&events).unwrap();
    assert!(
        !preview_identity(t.path())
            .unwrap()
            .selected_inventory_complete
    );
    fs::write(events.join("event.cbor"), b"original public bytes").unwrap();
    fs::write(events.join(".tmp-event.cbor"), b"temporary bytes").unwrap();
    let report = preview_identity(t.path()).unwrap();
    assert!(report.selected_inventory_complete);
    assert_eq!(report.files.len(), 1);
    fs::write(events.join("notes.txt"), b"unknown evidence").unwrap();
    fs::create_dir(events.join("nested")).unwrap();
    let report = preview_identity(t.path()).unwrap();
    assert!(!report.selected_inventory_complete);
    assert_eq!(
        report
            .notices
            .iter()
            .filter(|n| n.kind == NoticeKind::Unsupported)
            .count(),
        2
    );
}

#[test]
fn verification_discloses_structural_scope_without_admission_claim() {
    let t = tempfile::tempdir().unwrap();
    let root = t.path().join("archive");
    drop(kan::evidence_store::Ledger::create(&root).unwrap());
    let result = run(&["verify", root.join("archive.sqlite").to_str().unwrap()]);
    assert!(result.status.success());
    let json: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(json["verification"], "structural-closure");
    assert_eq!(json["writable_admission"], "not-checked");
    assert_eq!(json["cryptographic_admission"], "not-verified");
    assert_eq!(json["historical_completeness"], "not-verified");
}
