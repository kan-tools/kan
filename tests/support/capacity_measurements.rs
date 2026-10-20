//! Opt-in real-byte storage measurement. Run via scripts/measure-v2-capacity.py.
//! Fixture creation and each measured operation run in separate processes so
//! fixture allocation cannot masquerade as the serving memory high-water mark.
use super::*;
use rand::RngCore;
use serde_json::{json, Value};
use std::time::Instant;

const CHUNK: usize = 1024 * 1024;

fn binding() -> attested::Binding {
    attested::Binding {
        archive: [2; 32],
        scope: [1; 32],
        issuer: identity(8).did().to_string(),
    }
}

fn signed(position: u64, previous: Option<String>) -> Vec<u8> {
    // Actual random bytes, not sparse files, SQL padding, repeated CAS objects,
    // or compressible zeroes. This measures opaque storage, not an encryption job.
    let mut payload = vec![0; CHUNK];
    rand::thread_rng().fill_bytes(&mut payload);
    SignedRequest::sign(
        Request {
            version: 1,
            scope: service::hex(&[1; 32]),
            principal: identity(6).did().to_string(),
            audience: identity(8).did().to_string(),
            expires: None,
            command: Command::Append {
                id: service::hex(&u128::from(position + 1).to_be_bytes()),
                position,
                previous,
                ciphertext: service::hex(&payload),
            },
        },
        &identity(6),
    )
    .unwrap()
    .bytes()
    .unwrap()
}

fn seed(root: &Path, chunks: u64) {
    assert!(chunks > 0);
    let mut archive = attested::Archive::create(root, binding()).unwrap();
    archive.rebuild_serving_index(&identity(8)).unwrap();
    let mut previous = None;
    for position in 0..chunks {
        let admitted = archive
            .admit_indexed(
                &signed(position, previous),
                &identity(8),
                &grant(),
                position + 1,
                None,
            )
            .unwrap();
        previous = Some(admitted.record.manifest.cid().to_string());
        if position % 1024 == 0 {
            eprintln!("capacity fixture: {} MiB opaque payload", position + 1);
        }
    }
}

fn counters() -> (u64, u64) {
    let text = std::fs::read_to_string("/proc/self/io").unwrap();
    let field = |key: &str| {
        text.lines()
            .find_map(|line| line.strip_prefix(key))
            .unwrap()
            .trim()
            .parse::<u64>()
            .unwrap()
    };
    (field("rchar:"), field("read_bytes:"))
}

fn rss_kib() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .unwrap()
        .lines()
        .find_map(|line| line.strip_prefix("VmHWM:"))
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .parse()
        .unwrap()
}

fn measured<T>(name: &str, operation: impl FnOnce() -> T) -> (T, Value) {
    let before = counters();
    let start = Instant::now();
    let value = operation();
    let micros = start.elapsed().as_micros();
    let after = counters();
    let peak = rss_kib();
    let result = json!({
        "operation": name, "latency_us": micros,
        "syscall_read_bytes": after.0 - before.0,
        "physical_read_bytes": after.1 - before.1,
        "process_peak_rss_kib": peak,
    });
    // Emit failure evidence before the memory gate. Process RSS includes the
    // harness/crypto/SQLite; kernel page cache is deliberately not process RSS.
    println!("KAN_CAPACITY_SAMPLE={result}");
    if std::env::var_os("KAN_CAPACITY_OPERATION").is_some() {
        assert!(peak <= 512 * 1024, "storage process exceeded 512 MiB");
    }
    (value, result)
}

fn probe(root: &Path, operation: &str) -> Value {
    let db = root.join("archive.sqlite");
    match operation {
        "open" => {
            measured("open", || {
                attested::Archive::open_indexed(root, binding(), None).unwrap()
            })
            .1
        }
        "append" => {
            let mut archive = attested::Archive::open_indexed(root, binding(), None).unwrap();
            let frontier = archive.indexed_frontier(None).unwrap();
            let request = signed(frontier.through, frontier.manifest.map(|id| id.to_string()));
            let signer = identity(8);
            let permission = grant();
            measured("append", || {
                archive
                    .admit_indexed(&request, &signer, &permission, frontier.through + 1, None)
                    .unwrap()
            })
            .1
        }
        "page" | "source" => {
            // One selected row and at most one 1 MiB opaque payload (encoded as
            // a ~2 MiB signed request), with identical limits at every size.
            let mut work = budget();
            work.items = 1;
            let inventory = Inventory::open_indexed(
                &db,
                Profile::Admitted,
                binding(),
                None,
                None,
                work.clone(),
            )
            .unwrap();
            let read_page = || {
                inventory
                    .page(
                        None,
                        PageBudget {
                            rows: 1,
                            record_bytes: 64 * 1024,
                            payload_bytes: service::MAX_REQUEST,
                        },
                        work.clone(),
                    )
                    .unwrap()
            };
            if operation == "page" {
                measured("page", read_page).1
            } else {
                let page = read_page();
                let selection = page.records[0].selection.clone();
                drop(inventory);
                measured("source", || {
                    let Source::Available { bytes, .. } = inventory::source(
                        &db,
                        Profile::Admitted,
                        binding(),
                        &selection,
                        service::MAX_REQUEST,
                        work,
                    )
                    .unwrap() else {
                        panic!("selected evidence unavailable")
                    };
                    assert!(bytes.len() > 2 * CHUNK);
                })
                .1
            }
        }
        _ => panic!("unknown capacity operation"),
    }
}

#[test]
fn capacity_measurement_smoke() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("archive");
    seed(&root, 2);
    for operation in ["open", "append", "page", "source"] {
        let result = probe(&root, operation);
        assert!(result["syscall_read_bytes"].as_u64().unwrap() > 0);
    }
}

#[test]
#[ignore = "real large fixtures require an explicitly selected remote disk"]
fn capacity_worker() {
    let root = PathBuf::from(std::env::var_os("KAN_CAPACITY_ARCHIVE").unwrap());
    let operation = std::env::var("KAN_CAPACITY_OPERATION").unwrap();
    if operation == "seed" {
        let chunks = std::env::var("KAN_CAPACITY_CHUNKS")
            .unwrap()
            .parse()
            .unwrap();
        seed(&root, chunks);
    } else {
        probe(&root, &operation);
    }
}
