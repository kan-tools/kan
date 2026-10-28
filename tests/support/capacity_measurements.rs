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

fn signed(writer: &Identity, audience: &str, position: u64, previous: Option<String>) -> Vec<u8> {
    // Actual random bytes, not sparse files, SQL padding, repeated CAS objects,
    // or compressible zeroes. This measures opaque storage, not an encryption job.
    let mut payload = vec![0; CHUNK];
    rand::thread_rng().fill_bytes(&mut payload);
    SignedRequest::sign(
        Request {
            version: 1,
            scope: service::hex(&[1; 32]),
            principal: writer.did().to_string(),
            audience: audience.to_string(),
            expires: None,
            command: Command::Append {
                id: service::hex(&u128::from(position + 1).to_be_bytes()),
                position,
                previous,
                ciphertext: service::hex(&payload),
            },
        },
        writer,
    )
    .unwrap()
    .bytes()
    .unwrap()
}

fn seed(root: &Path, chunks: u64) {
    assert!(chunks > 0);
    let signer = identity(8);
    let writer = identity(6);
    let permission = grant();
    let mut archive = attested::Archive::create(root, binding()).unwrap();
    archive.rebuild_serving_index(&signer).unwrap();
    let mut previous = None;
    for position in 0..chunks {
        let admitted = archive
            .admit_indexed(
                &signed(&writer, signer.did().as_str(), position, previous),
                &signer,
                &permission,
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

// Qualification-only recovery: checkpoint each closed batch and derive progress
// from authenticated archive metadata. Existing bytes are never regenerated.
fn seed_batch(root: &Path, chunks: u64, batch: u64) -> u64 {
    assert!(chunks > 0 && batch > 0 && batch <= 1024);
    let signer = identity(8);
    let writer = identity(6);
    let permission = grant();
    let mut archive = if root.exists() {
        attested::Archive::open_indexed(root, binding(), None).unwrap()
    } else {
        let archive = attested::Archive::create(root, binding()).unwrap();
        archive.rebuild_serving_index(&signer).unwrap();
        archive
    };
    let frontier = archive.indexed_frontier(None).unwrap();
    let start = frontier.through;
    let end = chunks.min(start.saturating_add(batch)).max(start);
    let mut previous = frontier.manifest.map(|cid| cid.to_string());
    let crash_after: Option<u64> = std::env::var("KAN_CAPACITY_CRASH_AFTER")
        .ok()
        .map(|value| value.parse().unwrap());
    for position in start..end {
        let admitted = archive
            .admit_indexed(
                &signed(&writer, signer.did().as_str(), position, previous),
                &signer,
                &permission,
                position + 1,
                None,
            )
            .unwrap();
        previous = Some(admitted.record.manifest.cid().to_string());
        if crash_after == Some(position + 1) {
            std::process::exit(73); // Fault probe: no destructors/clean connection close.
        }
    }
    assert_eq!(archive.indexed_frontier(None).unwrap().through, end);
    end
}

#[test]
fn capacity_seed_resume_preserves_prefix_and_rejects_bad_checkpoint() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("archive");
    seed(&root, 2); // Represents the old interrupted runner's retained prefix.
    let before = attested::Archive::open_indexed(&root, binding(), None)
        .unwrap()
        .indexed_frontier(None)
        .unwrap();
    let child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "capacity_measurements::capacity_worker",
            "--ignored",
            "--nocapture",
        ])
        .env("KAN_CAPACITY_ARCHIVE", &root)
        .env("KAN_CAPACITY_OPERATION", "seed-batch")
        .env("KAN_CAPACITY_CHUNKS", "6")
        .env("KAN_CAPACITY_BATCH", "4")
        .env("KAN_CAPACITY_CRASH_AFTER", "4")
        .status()
        .unwrap();
    assert_eq!(child.code(), Some(73));
    assert_eq!(seed_batch(&root, 6, 1), 5);
    assert_eq!(seed_batch(&root, 6, 1), 6);
    assert_eq!(seed_batch(&root, 6, 1), 6); // Duplicate wakeup adds nothing.
    let conn = rusqlite::Connection::open(root.join("archive.sqlite")).unwrap();
    let retained: String = conn
        .query_row("SELECT cid FROM commits WHERE sequence=2", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(retained, before.manifest.unwrap().to_string());
    let positions: i64 = conn
        .query_row("SELECT count(DISTINCT position) FROM commits", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(positions, 6);
    conn.execute("UPDATE serving_checkpoint SET body=x'00'", [])
        .unwrap();
    drop(conn);
    assert!(std::panic::catch_unwind(|| seed_batch(&root, 7, 1)).is_err());
    let conn = rusqlite::Connection::open(root.join("archive.sqlite")).unwrap();
    let count: i64 = conn
        .query_row("SELECT count(*) FROM commits", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 6);
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
    // Modal may omit VmHWM. An explicitly selected fresh supervisor supplies
    // kernel child-lifetime peak RSS; null is never accepted as a measurement.
    let external_rss = std::env::var("KAN_CAPACITY_EXTERNAL_RSS").as_deref() == Ok("rusage");
    let peak = if external_rss { None } else { Some(rss_kib()) };
    let result = json!({
        "operation": name, "latency_us": micros,
        "syscall_read_bytes": after.0 - before.0,
        "physical_read_bytes": after.1 - before.1,
        "process_peak_rss_kib": peak,
        "rss_source": if external_rss { "pending-external-rusage" } else { "proc-vmhwm" },
    });
    // Emit failure evidence before the memory gate. Process RSS includes the
    // harness/crypto/SQLite; kernel page cache is deliberately not process RSS.
    println!("KAN_CAPACITY_SAMPLE={result}");
    if let (true, Some(peak)) = (std::env::var_os("KAN_CAPACITY_OPERATION").is_some(), peak) {
        assert!(peak <= 512 * 1024, "storage process exceeded 512 MiB");
    }
    (value, result)
}

fn probe(root: &Path, operation: &str) -> Value {
    let db = root.join("archive.sqlite");
    let owner_binding = binding();
    match operation {
        "open" => {
            measured("open", || {
                attested::Archive::open_indexed(root, owner_binding, None).unwrap()
            })
            .1
        }
        "append-phases" => {
            let start = Instant::now();
            let mut archive =
                attested::Archive::open_indexed(root, owner_binding.clone(), None).unwrap();
            let opened = start.elapsed().as_micros();
            let frontier = archive.indexed_frontier(None).unwrap();
            let request = signed(
                &identity(6),
                &owner_binding.issuer,
                frontier.through,
                frontier.manifest.map(|id| id.to_string()),
            );
            let prepared = start.elapsed().as_micros();
            let mut events = Vec::new();
            archive.admit_indexed_observed(&request,&identity(8),&grant(),frontier.through+1,None,&mut |boundary| {
                events.push(json!({"boundary":format!("{boundary:?}"),"elapsed_us":start.elapsed().as_micros()}));
            }).unwrap();
            let admitted = start.elapsed().as_micros();
            drop(archive);
            let result = json!({"operation":"append-phases","prior_records":frontier.through,"open_us":opened,"prepared_us":prepared,"admitted_us":admitted,"closed_us":start.elapsed().as_micros(),"boundaries":events});
            println!("KAN_APPEND_PHASES={result}");
            result
        }
        "append" => {
            let mut archive =
                attested::Archive::open_indexed(root, owner_binding.clone(), None).unwrap();
            let frontier = archive.indexed_frontier(None).unwrap();
            let request = signed(
                &identity(6),
                &owner_binding.issuer,
                frontier.through,
                frontier.manifest.map(|id| id.to_string()),
            );
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
                owner_binding.clone(),
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
                        owner_binding,
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
    } else if operation == "seed-batch" {
        let chunks = std::env::var("KAN_CAPACITY_CHUNKS")
            .unwrap()
            .parse()
            .unwrap();
        let batch = std::env::var("KAN_CAPACITY_BATCH")
            .unwrap()
            .parse()
            .unwrap();
        println!("KAN_CAPACITY_FRONTIER={}", seed_batch(&root, chunks, batch));
    } else {
        probe(&root, &operation);
    }
}

/// Representative HTTP/crypto supplement, separate from the 10/100 GiB opaque
/// storage sweep. Four independent writers; actual 64 KiB KANC2 frame payloads.
#[cfg(feature = "v2-crypto")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "remote qualification; emits a retained measurement report"]
async fn capacity_http_capture_sample() {
    use kan::{
        evidence_crypto as crypto, evidence_proof_service as wire, evidence_reader::proof as client,
    };
    use sha2::{Digest, Sha256};
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("archive");
    let count: usize = std::env::var("KAN_HTTP_CAPTURE_FRAMES")
        .ok()
        .map(|s| s.parse().unwrap())
        .unwrap_or(256);
    assert!((32..=4096).contains(&count));
    let writer_ids = [6u8, 7, 10, 11];
    let grants: Vec<_> = writer_ids
        .iter()
        .map(|id| Grant {
            principal: identity(*id).did().to_string(),
            append: true,
            inventory: true,
        })
        .collect();
    let signer = identity(8);
    let owner_binding = binding();
    let archive = attested::Archive::create(&root, owner_binding.clone()).unwrap();
    archive.rebuild_serving_index(&signer).unwrap();
    let service =
        service::AdmittingService::new_indexed(archive, signer, grants.clone(), None).unwrap();
    let listener = kan::evidence_http::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let endpoint = format!("http://{}/v1/rpc", listener.local_addr().unwrap());
    let admission = tokio::spawn(kan::evidence_http::serve_admitted(listener, service));
    let private = [73; 32];
    let public = crypto::public_key(&private).unwrap();
    let canary = b"KAN_BLIND_HTTP_CAPTURE_CANARY_7bbd2e9f";
    let before = counters();
    let started = Instant::now();
    let mut senders = tokio::task::JoinSet::new();
    for writer_id in writer_ids {
        let endpoint = endpoint.clone();
        let issuer = owner_binding.issuer.clone();
        senders.spawn(async move {
            let writer=identity(writer_id);let http=reqwest::Client::builder().no_proxy().timeout(Duration::from_secs(30)).build().unwrap();
            let mut previous=None;let mut latencies=Vec::new();let mut digests=std::collections::BTreeSet::new();
            for position in 0..count {
                let begin=Instant::now();
                let mut body=vec![0;kan::evidence_capture::CHUNK];rand::thread_rng().fill_bytes(&mut body);body[..canary.len()].copy_from_slice(canary);
                let header=serde_json::to_vec(&json!({"version":2,"attempt":service::hex(&[writer_id;32]),"observer":"collector","ordinal":position,"observed_at_unix_micros":null,"elapsed_micros":0,"unconfirmed_before":0,"event":{"type":"request-chunk","offset":position*kan::evidence_capture::CHUNK}})).unwrap();
                let mut frame=b"KANC2".to_vec();frame.extend_from_slice(&(header.len() as u32).to_be_bytes());frame.extend(header);frame.extend(body);
                digests.insert(service::hex(&Sha256::digest(&frame)));
                let request=SignedRequest::sign(Request{version:1,scope:service::hex(&[1;32]),principal:writer.did().to_string(),audience:issuer.clone(),expires:None,command:Command::Append{id:service::hex(&((position+1) as u128).to_be_bytes()),position:position as u64,previous,ciphertext:service::hex(&crypto::seal(&public,&[1;32],&frame).unwrap())}},&writer).unwrap().bytes().unwrap();
                let response=http.post(&endpoint).header("content-type","application/json").body(request.clone()).send().await.unwrap();assert_eq!(response.status(),200);
                let reply:service::SignedReply=response.json().await.unwrap();assert!(reply.verify(&request,&issuer).unwrap().result.is_ok());
                previous=Some(service::append_manifest(&request).unwrap().cid().to_string());
                latencies.push(begin.elapsed().as_micros() as u64);
            }
            (latencies,digests)
        });
    }
    let mut writes = Vec::new();
    let mut expected = std::collections::BTreeSet::new();
    while let Some(result) = senders.join_next().await {
        let (latencies, digests) = result.unwrap();
        writes.extend(latencies);
        expected.extend(digests);
    }
    let elapsed = started.elapsed().as_millis();
    admission.abort();
    let _ = admission.await;
    let binding = wire::Binding {
        profile: wire::Profile::Admitted,
        archive: service::hex(&[2; 32]),
        scope: service::hex(&[1; 32]),
        issuer: owner_binding.issuer,
    };
    let listener = kan::evidence_http::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let endpoint = format!("http://{}/v2/read", listener.local_addr().unwrap());
    let mut read_budget = budget();
    read_budget.items = 10000;
    read_budget.duration = Duration::from_secs(30);
    let service = wire::Service::new_indexed(
        root.join("archive.sqlite"),
        binding.clone(),
        identity(8),
        grants,
        read_budget,
        None,
    )
    .unwrap();
    let reading = tokio::spawn(kan::evidence_http::serve_proof(listener, service));
    let reader = client::Reader::new(
        identity(6),
        client::Access {
            binding,
            endpoint,
            private_key: private,
        },
    )
    .unwrap();
    let pin = reader.snapshot().await.unwrap();
    let page = reader.page(&pin, None, 40).await.unwrap();
    let mut reads = Vec::new();
    for row in page.records.iter().take(32) {
        let begin = Instant::now();
        let client::Source::Available { plaintext, .. } =
            reader.source(&pin, &row.selection).await.unwrap()
        else {
            panic!("encrypted capture unavailable")
        };
        assert!(expected.contains(&service::hex(&Sha256::digest(&plaintext))));
        assert!(matches!(
            kan::evidence_reconstruction::decode(&plaintext).unwrap(),
            kan::evidence_reconstruction::Decoded::Capture(_)
        ));
        reads.push(begin.elapsed().as_micros() as u64);
    }
    reading.abort();
    let _ = reading.await;
    let backup = temp.path().join("independent.sqlite");
    attested::Archive::open(&root, self::binding())
        .unwrap()
        .backup(&backup)
        .unwrap();
    // Scan persisted storage and any sidecars with a bounded overlapping buffer.
    // Searchable plaintext is held only at the authorized test reader.
    use std::io::Read;
    for path in std::fs::read_dir(&root)
        .unwrap()
        .map(|p| p.unwrap().path())
        .filter(|p| p.is_file())
        .chain(std::iter::once(backup))
    {
        let mut file = std::fs::File::open(path).unwrap();
        let mut tail = Vec::new();
        let mut block = [0u8; 65536];
        loop {
            let n = file.read(&mut block).unwrap();
            if n == 0 {
                break;
            }
            tail.extend_from_slice(&block[..n]);
            assert!(
                !tail.windows(canary.len()).any(|w| w == canary),
                "plaintext canary leaked to storage"
            );
            tail = tail[tail.len().saturating_sub(canary.len() - 1)..].to_vec();
        }
    }
    fn percentiles(mut v: Vec<u64>) -> Value {
        v.sort_unstable();
        json!({"count":v.len(),"p50_us":v[v.len().div_ceil(2)-1],"p95_us":v[(v.len()*95).div_ceil(100)-1],"p99_us":v[(v.len()*99).div_ceil(100)-1],"max_us":v.last()})
    }
    let after = counters();
    let peak = rss_kib();
    let report = json!({"version":1,"scope":"HTTP admission with signing/encryption, proof reading/decryption and blind-storage canary; combined in-process client/server RSS; OS cache retained","writers":4,"frames":count*4,"payload_bytes":count*4*kan::evidence_capture::CHUNK,"frame_chunk_bytes":kan::evidence_capture::CHUNK,"write_elapsed_ms":elapsed,"append":percentiles(writes),"source":percentiles(reads),"process_peak_rss_kib":peak,"syscall_read_bytes":after.0-before.0,"physical_read_bytes":after.1-before.1,"blind_storage_canary":"absent in database, sidecars and standalone backup","coverage":"Sample includes one scope and four independent writer streams; not a replacement for 100 GiB capacity qualification"});
    println!("KAN_HTTP_CAPTURE_REPORT={report}");
    if let Some(path) = std::env::var_os("KAN_HTTP_CAPTURE_REPORT") {
        std::fs::write(path, serde_json::to_vec_pretty(&report).unwrap()).unwrap();
    }
    assert!(peak <= 512 * 1024, "combined HTTP sample exceeded 512 MiB");
}
