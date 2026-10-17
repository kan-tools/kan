#![cfg(feature = "v2-crypto")]
use kan::{
    evidence_crypto as crypto, evidence_delivery,
    evidence_import::{Plan, Selection},
    evidence_service::{
        hex, unhex, Command as ServiceCommand, Grant, Output as ServiceOutput, Request, Service,
        SignedRequest, MAX_REQUEST,
    },
    evidence_spool::Spool,
    evidence_store::Ledger,
    sign::Identity,
};
use sha2::{Digest, Sha256};
use std::{
    path::Path,
    process::{Command, Output},
};
const SCOPE: [u8; 32] = [6; 32];
const PRIVATE: [u8; 32] = [7; 32];
const SOURCE: [u8; 32] = [8; 32];
fn cli(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_kan-v2"))
        .args(args)
        .output()
        .unwrap()
}
fn success(out: &Output) {
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}
fn store(root: &Path, bytes: &[u8]) {
    std::fs::create_dir_all(root).unwrap();
    std::fs::write(root.join("repo.car"), bytes).unwrap();
}
fn queue(root: &Path, writer: &Identity, server: &Identity, budget: u64) -> Spool {
    Spool::create(
        &root.join("spool.sqlite"),
        &hex(&SCOPE),
        writer.did().as_str(),
        server.did().as_str(),
        budget,
    )
    .unwrap()
}
fn service(root: &Path, writer: &Identity, server: Identity) -> Service {
    Service::new(
        Ledger::create(&root.join("archive")).unwrap(),
        SCOPE,
        server,
        vec![Grant {
            principal: writer.did().to_string(),
            append: true,
            inventory: true,
        }],
    )
    .unwrap()
}
fn drain(
    spool: &mut Spool,
    server: &mut Service,
    frames: &Path,
    writer: &Identity,
    next: &mut usize,
) {
    while let Some(request) = spool.head().unwrap() {
        // Deliver first, recover the exact admitted bytes and decrypt independently of the planner.
        let reply = server.dispatch(&request, 1).unwrap();
        let sequence = match &reply.reply.result {
            Ok(ServiceOutput::Committed { record, .. }) => record.sequence,
            other => panic!("unexpected append result: {other:?}"),
        };
        let read = SignedRequest::sign(
            Request {
                version: 1,
                scope: hex(&SCOPE),
                audience: server.issuer().to_string(),
                principal: writer.did().to_string(),
                expires: Some(10),
                command: ServiceCommand::Read { sequence },
            },
            writer,
        )
        .unwrap()
        .bytes()
        .unwrap();
        let response = server.dispatch(&read, 1).unwrap();
        response.verify(&read, &server.issuer()).unwrap();
        let archived = match response.reply.result {
            Ok(ServiceOutput::Evidence { signed_request, .. }) => {
                unhex(&signed_request, MAX_REQUEST).unwrap()
            }
            other => panic!("unexpected read result: {other:?}"),
        };
        assert_eq!(archived, request);
        let plaintext =
            evidence_delivery::decrypt_request(&archived, &PRIVATE, &SCOPE, writer.did().as_str())
                .unwrap();
        std::fs::write(frames.join(format!("{next}.bin")), plaintext).unwrap();
        *next += 1;
        spool.acknowledge(&reply.bytes().unwrap()).unwrap();
    }
}
#[test]
fn cli_resumes_large_malformed_snapshot_and_independent_decoder_recovers_exact_bytes() {
    let t = tempfile::tempdir().unwrap();
    let source = t.path().join("source");
    let bytes = (0..(11 * 1024 * 1024 + 37))
        .map(|i| (i % 251) as u8)
        .collect::<Vec<_>>();
    store(&source, &bytes);
    std::fs::write(source.join("HEAD"), b"invalid-original-head\n").unwrap();
    std::fs::write(source.join("identity.key"), b"PRIVATE-KEY-MUST-NOT-UPLOAD").unwrap();
    let writer = Identity::generate();
    let destination = Identity::generate();
    let key = t.path().join("writer.key");
    writer.save(&key).unwrap();
    let mut spool = queue(t.path(), &writer, &destination, 10_000_000);
    let mut server = service(t.path(), &writer, destination);
    let path = t.path().join("spool.sqlite");
    let recipient = hex(&crypto::public_key(&PRIVATE).unwrap());
    let common = [
        source.to_str().unwrap(),
        "--spool",
        path.to_str().unwrap(),
        "--source-id",
        &hex(&SOURCE),
        "--recipient",
        &recipient,
        "--selection",
        "store",
    ];
    let mut args = vec!["import-plan"];
    args.extend(common);
    let out = cli(&args);
    success(&out);
    let preview: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let id = preview["plan"]["plan"].as_str().unwrap();
    assert_eq!(
        preview["plan"]["inventory"]["selected_inventory_complete"],
        false
    );
    assert!(!String::from_utf8_lossy(&out.stdout).contains("PRIVATE-KEY-MUST-NOT-UPLOAD"));
    let frames = t.path().join("frames");
    std::fs::create_dir(&frames).unwrap();
    let mut next = 0;
    loop {
        let mut args = vec!["import-v1"];
        args.extend(common);
        args.extend([
            "--expected-plan",
            id,
            "--key",
            key.to_str().unwrap(),
            "--limit",
            "4",
        ]);
        let out = cli(&args);
        success(&out);
        let progress: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(progress["ready_for_cutover"], false);
        assert_eq!(progress["recovery_verified"], false);
        let complete = progress["queue_coverage_complete"].as_bool().unwrap();
        drop(spool);
        spool = Spool::open(&path).unwrap();
        drain(&mut spool, &mut server, &frames, &writer, &mut next);
        if complete {
            break;
        }
    }
    let count = spool.status().unwrap().next;
    let mut args = vec!["import-v1"];
    args.extend(common);
    args.extend(["--expected-plan", id, "--key", key.to_str().unwrap()]);
    let out = cli(&args);
    success(&out);
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&out.stdout).unwrap()["newly_queued"],
        0
    );
    assert_eq!(spool.status().unwrap().next, count);
    let verified = Command::new("python3")
        .args(["scripts/verify_import_stream.py", frames.to_str().unwrap()])
        .output()
        .unwrap();
    success(&verified);
    let report: serde_json::Value = serde_json::from_slice(&verified.stdout).unwrap();
    let file = report["files"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["path"] == "repo.car")
        .unwrap();
    assert_eq!(file["sha256"], hex(&Sha256::digest(&bytes)));
    assert_eq!(std::fs::read(source.join("repo.car")).unwrap(), bytes);
    assert!(report["files"]
        .as_array()
        .unwrap()
        .iter()
        .all(|f| f["path"] != "identity.key"));
    // An independent consumer refuses a missing chunk instead of certifying a partial copy.
    std::fs::remove_file(frames.join("2.bin")).unwrap();
    assert!(!Command::new("python3")
        .args(["scripts/verify_import_stream.py", frames.to_str().unwrap()])
        .output()
        .unwrap()
        .status
        .success());
}
#[test]
fn pinned_inventory_detects_changes_and_route_identity_changes_before_admission() {
    let t = tempfile::tempdir().unwrap();
    let source = t.path().join("source");
    store(&source, b"old bytes");
    let writer = Identity::generate();
    let server = Identity::generate();
    let mut spool = queue(t.path(), &writer, &server, 10_000_000);
    let recipient = crypto::public_key(&PRIVATE).unwrap();
    let make = |spool: &mut Spool| {
        Plan::build(&source, Selection::Store, SOURCE, recipient, spool).unwrap()
    };
    let plan = make(&mut spool);
    assert_eq!(plan.id(), make(&mut spool).id());
    assert!(plan.enqueue("wrong", &mut spool, &writer, 2).is_err());
    assert!(plan
        .enqueue(plan.id(), &mut spool, &Identity::generate(), 2)
        .is_err());
    assert_ne!(
        plan.id(),
        Plan::build(&source, Selection::Store, [9; 32], recipient, &mut spool)
            .unwrap()
            .id()
    );
    assert_ne!(
        plan.id(),
        Plan::build(
            &source,
            Selection::Store,
            SOURCE,
            crypto::public_key(&[1; 32]).unwrap(),
            &mut spool
        )
        .unwrap()
        .id()
    );
    store(&source, b"new bytes");
    assert_ne!(plan.id(), make(&mut spool).id());
    assert!(plan.enqueue(plan.id(), &mut spool, &writer, 2).is_err());
    assert_eq!(spool.status().unwrap().next, 0);
    #[cfg(unix)]
    {
        std::fs::remove_file(source.join("repo.car")).unwrap();
        let secret = t.path().join("secret");
        std::fs::write(&secret, b"secret").unwrap();
        std::os::unix::fs::symlink(&secret, source.join("repo.car")).unwrap();
        assert!(plan.enqueue(plan.id(), &mut spool, &writer, 2).is_err());
        let linked = t.path().join("link");
        std::os::unix::fs::symlink(&source, &linked).unwrap();
        assert!(Plan::build(&linked, Selection::Store, SOURCE, recipient, &mut spool).is_err());
    }
}
#[test]
fn full_queue_preserves_partial_progress_and_resumes_without_resealing() {
    let t = tempfile::tempdir().unwrap();
    let source = t.path().join("source");
    store(&source, &vec![1; 600_000]);
    let writer = Identity::generate();
    let destination = Identity::generate();
    let mut spool = queue(t.path(), &writer, &destination, 1_060_000);
    let mut server = service(t.path(), &writer, destination);
    let plan = Plan::build(
        &source,
        Selection::Store,
        SOURCE,
        crypto::public_key(&PRIVATE).unwrap(),
        &mut spool,
    )
    .unwrap();
    assert!(plan.enqueue(plan.id(), &mut spool, &writer, 128).is_err());
    assert!(spool.status().unwrap().next > 0);
    let retained = spool.head().unwrap().unwrap();
    assert!(plan.enqueue(plan.id(), &mut spool, &writer, 128).is_err());
    assert_eq!(spool.head().unwrap().unwrap(), retained);
    let frames = t.path().join("frames");
    std::fs::create_dir(&frames).unwrap();
    let mut next = 0;
    while !plan.progress(&mut spool).unwrap().queue_coverage_complete {
        drain(&mut spool, &mut server, &frames, &writer, &mut next);
        let _ = plan.enqueue(plan.id(), &mut spool, &writer, 1);
    }
    drain(&mut spool, &mut server, &frames, &writer, &mut next);
    assert_eq!(plan.progress(&mut spool).unwrap().pending_operations, 0);
    success(
        &Command::new("python3")
            .args(["scripts/verify_import_stream.py", frames.to_str().unwrap()])
            .output()
            .unwrap(),
    );
}

#[test]
fn workspace_identity_empty_and_exact_boundary_sources_remain_distinct() {
    let t = tempfile::tempdir().unwrap();
    let writer = Identity::generate();
    let destination = Identity::generate();
    let mut spool = queue(t.path(), &writer, &destination, 10_000_000);
    let workspace = t.path().join("workspace");
    store(
        &workspace.join(".kan/log"),
        &vec![0; kan::evidence_import::CHUNK],
    );
    std::fs::write(workspace.join(".kan/log/HEAD"), b"").unwrap();
    std::fs::write(workspace.join(".kan/identity.key"), b"secret").unwrap();
    let recipient = crypto::public_key(&PRIVATE).unwrap();
    let plan = Plan::build(
        &workspace,
        Selection::Workspace,
        SOURCE,
        recipient,
        &mut spool,
    )
    .unwrap();
    assert_eq!(plan.summary()["data_chunks"], 2);
    let progress = plan.enqueue(plan.id(), &mut spool, &writer, 1).unwrap();
    assert_eq!(progress.retained_operations, 1);
    assert!(!progress.queue_coverage_complete);
    store(&workspace.join(".kan/log"), b"changed-after-first-batch");
    assert!(plan.enqueue(plan.id(), &mut spool, &writer, 128).is_err());
    assert_eq!(spool.status().unwrap().next, 1);
    let config = t.path().join("config");
    let events = config.join("identity/ledger/events");
    std::fs::create_dir_all(&events).unwrap();
    std::fs::write(events.join("public.cbor"), b"unverified public record").unwrap();
    std::fs::write(config.join("secret.key"), b"private").unwrap();
    let identity =
        Plan::build(&config, Selection::Identity, SOURCE, recipient, &mut spool).unwrap();
    assert_eq!(identity.summary()["data_chunks"], 1);
    assert_ne!(identity.id(), plan.id());
    let empty = t.path().join("empty");
    std::fs::create_dir(&empty).unwrap();
    let absent = Plan::build(&empty, Selection::Store, SOURCE, recipient, &mut spool).unwrap();
    assert_eq!(absent.summary()["data_chunks"], 0);
    assert_eq!(
        absent.summary()["inventory"]["selected_inventory_complete"],
        false
    );
}

#[test]
fn changed_chunk_after_plan_validation_cannot_be_sealed() {
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join("source");
    store(&source, b"original");
    let writer = Identity::generate();
    let server = Identity::generate();
    let mut spool = queue(temp.path(), &writer, &server, 10_000_000);
    let plan = Plan::build(
        &source,
        Selection::Store,
        SOURCE,
        crypto::public_key(&PRIVATE).unwrap(),
        &mut spool,
    )
    .unwrap();
    assert_eq!(plan.read_source_chunk(0, 0).unwrap(), b"original");
    store(&source, b"modified");
    assert!(plan.read_source_chunk(0, 0).is_err());
    assert!(plan.read_source_chunk(100, 0).is_err());
    assert_eq!(spool.status().unwrap().next, 0);
}
