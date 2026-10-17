#![cfg(feature = "v2-crypto")]
//! Regression probes retained from the independent Opus 5.5 restore review.
use atproto_dasl::Ipld;
use kan::{
    evidence::{self, Decoded},
    evidence_crypto as crypto, evidence_delivery as delivery,
    evidence_import::{Plan, Selection, CHUNK},
    evidence_restore::{self as restore, Pins},
    evidence_service::{hex, Grant, Service},
    evidence_spool::Spool,
    evidence_store::Ledger,
    sign::Identity,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fs, path::PathBuf, process::Command};

const PRIVATE: [u8; 32] = [7; 32];
const SCOPE: [u8; 32] = [9; 32];

struct World {
    root: tempfile::TempDir,
    service: Service,
    writers: Vec<(Identity, Spool)>,
}
impl World {
    fn new(n: usize) -> Self {
        let root = tempfile::tempdir().unwrap();
        let server = Identity::generate();
        let ids: Vec<Identity> = (0..n).map(|_| Identity::generate()).collect();
        let grants = ids
            .iter()
            .map(|w| Grant {
                principal: w.did().to_string(),
                append: true,
                inventory: true,
            })
            .collect();
        let issuer = server.did().to_string();
        let service = Service::new(
            Ledger::create(&root.path().join("archive")).unwrap(),
            SCOPE,
            server,
            grants,
        )
        .unwrap();
        let writers = ids
            .into_iter()
            .enumerate()
            .map(|(i, w)| {
                let spool = Spool::create(
                    &root.path().join(format!("spool{i}.sqlite")),
                    &hex(&SCOPE),
                    w.did().as_str(),
                    &issuer,
                    256 * 1024 * 1024,
                )
                .unwrap();
                (w, spool)
            })
            .collect();
        World {
            root,
            service,
            writers,
        }
    }
    fn db(&self) -> PathBuf {
        self.root.path().join("archive/archive.sqlite")
    }
    fn did(&self, i: usize) -> String {
        self.writers[i].0.did().to_string()
    }
    fn send(&mut self, w: usize, plan: &str, frames: &[(usize, Vec<u8>)]) {
        for (ordinal, frame) in frames {
            let (id, spool) = &mut self.writers[w];
            delivery::queue(
                spool,
                id,
                &crypto::public_key(&PRIVATE).unwrap(),
                &op(plan, *ordinal),
                frame,
            )
            .unwrap();
        }
        let (_, spool) = &mut self.writers[w];
        while let Some(bytes) = spool.head().unwrap() {
            let reply = self.service.dispatch(&bytes, 1000).unwrap();
            assert!(reply.reply.result.is_ok(), "{:?}", reply.reply.result);
            spool.acknowledge(&reply.bytes().unwrap()).unwrap();
        }
    }
    fn pins<'a>(&self, plan: &'a str, writer: &'a str) -> Pins<'a> {
        Pins {
            expected_plan: plan,
            scope: SCOPE,
            writer,
            recipient_private: PRIVATE,
            max_records: 100_000,
        }
    }
}
fn op(plan: &str, i: usize) -> [u8; 16] {
    let mut h = Sha256::new();
    h.update(b"tools.kan.import.operation.v1\0");
    h.update(plan.as_bytes());
    h.update((i as u64).to_be_bytes());
    h.finalize()[..16].try_into().unwrap()
}
fn sha(b: &[u8]) -> String {
    hex(&Sha256::digest(b))
}
fn kani(
    plan: &str,
    i: usize,
    kind: &str,
    file: Option<usize>,
    part: usize,
    parts: usize,
    body: &[u8],
) -> Vec<u8> {
    let header = serde_json::to_vec(&json!({"version":1,"plan":plan,"ordinal":i,"kind":kind,"file":file,"part":part,"parts":parts})).unwrap();
    raw_frame(&header, body)
}
fn raw_frame(header: &[u8], body: &[u8]) -> Vec<u8> {
    let mut f = b"KANI\x01".to_vec();
    f.extend((header.len() as u32).to_be_bytes());
    f.extend(header);
    f.extend(body);
    f
}
fn plan_id(doc: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(b"tools.kan.import.plan.v1\0");
    h.update(doc);
    hex(&h.finalize())
}
fn doc_for(w: &World, writer: usize, files: &[(&str, &[u8])], pad: usize) -> Vec<u8> {
    let fs_ = files
        .iter()
        .map(|(p, b)| {
            let chunks: Vec<Value> = if b.is_empty() {
                vec![json!({"length":0,"sha256":sha(b)})]
            } else {
                b.chunks(CHUNK)
                    .map(|c| json!({"length":c.len(),"sha256":sha(c)}))
                    .collect()
            };
            json!({"path":p,"length":b.len(),"sha256":sha(b),"chunks":chunks})
        })
        .collect::<Vec<_>>();
    let inv = fs_
        .iter()
        .map(|v| json!({"path":v["path"],"length":v["length"],"sha256":v["sha256"]}))
        .collect::<Vec<_>>();
    serde_json::to_vec(&json!({"profile":1,"source_id":hex(&[5;32]),"selection":"store","recipient":hex(&crypto::public_key(&PRIVATE).unwrap()),
        "route":{"scope":hex(&SCOPE),"writer":w.did(writer),"audience":w.service.issuer()},
        "inventory":{"files":inv,"notices":[{"kind":"synthetic-pad","detail":"x".repeat(pad)}],"selected_inventory_complete":false},"files":fs_})).unwrap()
}
/// Standard frames for a plan document; returns (plan id, frames).
fn frames_for(doc: &[u8], files: &[(&str, &[u8])]) -> (String, Vec<(usize, Vec<u8>)>) {
    let plan = plan_id(doc);
    let parts = doc.len().div_ceil(CHUNK);
    let mut out = Vec::new();
    for (i, c) in doc.chunks(CHUNK).enumerate() {
        out.push((i, kani(&plan, i, "inventory", None, i, parts, c)));
    }
    let mut o = parts;
    for (fi, (_, b)) in files.iter().enumerate() {
        let chunks: Vec<&[u8]> = if b.is_empty() {
            vec![&b[..]]
        } else {
            b.chunks(CHUNK).collect()
        };
        for (j, c) in chunks.iter().enumerate() {
            out.push((o, kani(&plan, o, "data", Some(fi), j, chunks.len(), c)));
            o += 1;
        }
    }
    let complete = serde_json::to_vec(&json!({"plan":plan,"observation":"selected-snapshot-queued","recovery_verified":false,"independent_backup":false,"ready_for_cutover":false})).unwrap();
    out.push((o, kani(&plan, o, "complete", None, 0, 1, &complete)));
    (plan, out)
}

/// Multi-part inventory (> 1 MiB plan) restores, and an independent archive oracle agrees.
#[test]
fn probe_multipart_inventory_roundtrip_and_archive_oracle() {
    let mut w = World::new(1);
    let big: Vec<u8> = (0..(CHUNK * 2 + 99)).map(|i| (i * 7 % 256) as u8).collect();
    let exact: Vec<u8> = vec![3u8; CHUNK];
    let files: Vec<(&str, &[u8])> = vec![
        ("a/b/c.car", &big),
        ("empty", b""),
        ("exact", &exact),
        ("report.json", b"{}"),
    ];
    let doc = doc_for(&w, 0, &files, 1_200_000);
    assert!(doc.len() > 2 * CHUNK);
    let (plan, frames) = frames_for(&doc, &files);
    w.send(0, &plan, &frames);
    let did = w.did(0);
    let out = w.root.path().join("out");
    let report = restore::restore(&w.db(), &out, &w.pins(&plan, &did)).unwrap();
    assert_eq!(fs::read(out.join("plan.json")).unwrap(), doc);
    assert_eq!(report["operations"].as_array().unwrap().len(), frames.len());
    assert_eq!(report["selected_inventory_complete"], false);
    // Independent oracle over a standalone backup.
    let backup = w.root.path().join("backup.sqlite");
    Ledger::open(&w.root.path().join("archive"))
        .unwrap()
        .backup(&backup)
        .unwrap();
    let key = w.root.path().join("key");
    fs::write(&key, PRIVATE).unwrap();
    let python = std::env::var("KAN_CRYPTO_ORACLE_PYTHON").unwrap_or_else(|_| "python3".into());
    let oracle = "scripts/verify_restored_archive.py";
    let o = Command::new(python)
        .arg("-I")
        .arg(oracle)
        .arg(&backup)
        .arg(&plan)
        .arg(hex(&SCOPE))
        .arg(&did)
        .arg(&key)
        .arg(&out)
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    eprintln!("ORACLE {}", String::from_utf8_lossy(&o.stdout));
    // Oracle self-check: one tampered restored byte must be rejected.
    let victim = out.join("files/a/b/c.car");
    let mut bytes = fs::read(&victim).unwrap();
    bytes[CHUNK + 5] ^= 1;
    fs::write(&victim, bytes).unwrap();
    let o = Command::new(
        std::env::var("KAN_CRYPTO_ORACLE_PYTHON").unwrap_or_else(|_| "python3".into()),
    )
    .arg("-I")
    .arg("scripts/verify_restored_archive.py")
    .arg(&backup)
    .arg(&plan)
    .arg(hex(&SCOPE))
    .arg(&did)
    .arg(&key)
    .arg(&out)
    .output()
    .unwrap();
    assert!(!o.status.success(), "oracle accepted tampered output");
    eprintln!("ORACLE-NEGATIVE {}", String::from_utf8_lossy(&o.stderr));
}

/// Swapped (validly signed) inventory bodies or wrong per-part `parts` fail closed.
#[test]
fn probe_multipart_inventory_tampering() {
    for case in 0..3 {
        let mut w = World::new(1);
        let files: Vec<(&str, &[u8])> = vec![("x", b"raw")];
        let doc = doc_for(&w, 0, &files, 1_200_000);
        let (plan, mut frames) = frames_for(&doc, &files);
        match case {
            0 => {
                let b0 = doc[..CHUNK].to_vec();
                let b1 = doc[CHUNK..2 * CHUNK].to_vec();
                frames[0].1 = kani(&plan, 0, "inventory", None, 0, 3, &b1);
                frames[1].1 = kani(&plan, 1, "inventory", None, 1, 3, &b0);
            }
            1 => frames[1].1 = kani(&plan, 1, "inventory", None, 1, 2, &doc[CHUNK..2 * CHUNK]),
            _ => {
                frames[2].1 = kani(
                    &plan,
                    2,
                    "inventory",
                    None,
                    2,
                    3,
                    &doc[2 * CHUNK..doc.len() - 1],
                )
            }
        }
        w.send(0, &plan, &frames);
        let did = w.did(0);
        let out = w.root.path().join("out");
        assert!(
            restore::restore(&w.db(), &out, &w.pins(&plan, &did)).is_err(),
            "case {case}"
        );
        assert!(
            !out.exists(),
            "case {case}: output created before plan verification"
        );
    }
}

/// A second authorized writer flooding the same operation IDs with hostile content
/// in the same scope must neither be accepted nor block restore under the pinned writer.
#[test]
fn probe_second_writer_cannot_substitute_or_block() {
    let mut w = World::new(2);
    let files: Vec<(&str, &[u8])> = vec![("x", b"genuine")];
    let doc = doc_for(&w, 0, &files, 0);
    let (plan, frames) = frames_for(&doc, &files);
    // Attacker sends first: same op IDs, same plan id, hostile bytes.
    let hostile: Vec<(usize, Vec<u8>)> = frames
        .iter()
        .map(|(i, f)| {
            if *i == 1 {
                (*i, kani(&plan, 1, "data", Some(0), 0, 1, b"hostile"))
            } else {
                (*i, f.clone())
            }
        })
        .collect();
    w.send(1, &plan, &hostile);
    w.send(0, &plan, &frames);
    let (good, bad) = (w.did(0), w.did(1));
    let out = w.root.path().join("out");
    restore::restore(&w.db(), &out, &w.pins(&plan, &good)).unwrap();
    assert_eq!(fs::read(out.join("files/x")).unwrap(), b"genuine");
    // Pinning the attacker writer must fail (plan route binds original writer).
    let out2 = w.root.path().join("out2");
    assert!(restore::restore(&w.db(), &out2, &w.pins(&plan, &bad)).is_err());
    assert!(!out2.exists());
}

fn reencode(kind: &str, body: BTreeMap<String, Ipld>) -> Vec<u8> {
    let top = Ipld::Map(BTreeMap::from([
        ("v".to_string(), Ipld::Integer(1)),
        ("kind".to_string(), Ipld::String(kind.into())),
        ("body".to_string(), Ipld::Map(body)),
    ]));
    let Decoded::Known(r) = evidence::encode(&top).unwrap() else {
        panic!("unknown")
    };
    r.bytes().to_vec()
}
fn known(bytes: &[u8]) -> evidence::Record {
    let Decoded::Known(r) = evidence::decode(bytes).unwrap() else {
        panic!("unknown")
    };
    r
}
fn simple(w: &mut World) -> String {
    let files: Vec<(&str, &[u8])> = vec![("x", b"one"), ("y", b"two")];
    let doc = doc_for(w, 0, &files, 0);
    let (plan, frames) = frames_for(&doc, &files);
    w.send(0, &plan, &frames);
    plan
}

/// Owner-coherent rewrite of an unsigned receipt to another issuer: the structural
/// receipt/audience binding claimed in REQ-2 must reject it.
#[test]
fn probe_receipt_issuer_rewrite_rejected() {
    let mut w = World::new(1);
    let plan = simple(&mut w);
    let sql = rusqlite::Connection::open(w.db()).unwrap();
    let bytes: Vec<u8> = sql
        .query_row("SELECT receipt FROM commits WHERE sequence=2", [], |r| {
            r.get(0)
        })
        .unwrap();
    let mut body = known(&bytes).body().clone();
    let other = Identity::generate().did().to_string();
    let Ipld::Map(mut issuer) = body["issuer"].clone() else {
        panic!()
    };
    let fp = other.strip_prefix("did:key:").unwrap().to_string();
    issuer.insert("principal".into(), Ipld::String(other.clone()));
    issuer.insert(
        "verificationMethod".into(),
        Ipld::String(format!("{other}#{fp}")),
    );
    body.insert("issuer".into(), Ipld::Map(issuer));
    sql.execute(
        "UPDATE commits SET receipt=? WHERE sequence=2",
        [reencode("receipt", body)],
    )
    .unwrap();
    drop(sql);
    let did = w.did(0);
    let out = w.root.path().join("out");
    let r = restore::restore(&w.db(), &out, &w.pins(&plan, &did));
    assert!(r.is_err(), "receipt issuer rewrite accepted");
    assert!(!out.join("report.json").exists());
}

/// Owner-coherent manifest+receipt rewrite pointing ordinal 2's record at ordinal 1's
/// validly signed request object must fail (request/manifest/operation binding).
#[test]
fn probe_manifest_object_substitution_rejected() {
    let mut w = World::new(1);
    let plan = simple(&mut w);
    let sql = rusqlite::Connection::open(w.db()).unwrap();
    let get = |s: i64, c: &str| -> Vec<u8> {
        sql.query_row(
            &format!("SELECT {c} FROM commits WHERE sequence=?"),
            [s],
            |r| r.get(0),
        )
        .unwrap()
    };
    let m1 = known(&get(2, "manifest"));
    let m2 = known(&get(3, "manifest"));
    let r2 = known(&get(3, "receipt"));
    let Ipld::List(e1) = &m1.body()["entries"] else {
        panic!()
    };
    let Ipld::Map(e1) = &e1[0] else { panic!() };
    let mut body = m2.body().clone();
    let Ipld::List(mut e2) = body["entries"].clone() else {
        panic!()
    };
    let Ipld::Map(mut entry) = e2[0].clone() else {
        panic!()
    };
    entry.insert("ciphertext".into(), e1["ciphertext"].clone());
    entry.insert("length".into(), e1["length"].clone());
    e2[0] = Ipld::Map(entry);
    body.insert("entries".into(), Ipld::List(e2));
    let new_manifest = reencode("manifest", body);
    let cid = known(&new_manifest).cid().clone();
    let mut rb = r2.body().clone();
    rb.insert("manifest".into(), Ipld::Link(cid));
    let new_receipt = reencode("receipt", rb);
    sql.execute(
        "UPDATE commits SET manifest=?, receipt=? WHERE sequence=3",
        [new_manifest, new_receipt],
    )
    .unwrap();
    drop(sql);
    let did = w.did(0);
    let out = w.root.path().join("out");
    assert!(restore::restore(&w.db(), &out, &w.pins(&plan, &did)).is_err());
    assert!(!out.join("report.json").exists());
}

/// Plan must be canonical JSON even when the pin matches its exact bytes.
#[test]
fn probe_noncanonical_but_pinned_plan_rejected() {
    let mut w = World::new(1);
    let files: Vec<(&str, &[u8])> = vec![("x", b"raw")];
    let mut doc = doc_for(&w, 0, &files, 0);
    doc.push(b' ');
    let (plan, frames) = frames_for(&doc, &files);
    w.send(0, &plan, &frames);
    let did = w.did(0);
    let out = w.root.path().join("out");
    assert!(restore::restore(&w.db(), &out, &w.pins(&plan, &did)).is_err());
    assert!(!out.exists());
}

/// Malformed headers: unknown field, duplicate key, missing `file`.
#[test]
fn probe_header_shape_rejected() {
    for case in 0..3 {
        let mut w = World::new(1);
        let files: Vec<(&str, &[u8])> = vec![("x", b"raw")];
        let doc = doc_for(&w, 0, &files, 0);
        let (plan, mut frames) = frames_for(&doc, &files);
        let header = match case {
            0 => format!(
                r#"{{"version":1,"plan":"{plan}","ordinal":1,"kind":"data","file":0,"part":0,"parts":1,"extra":1}}"#
            ),
            1 => format!(
                r#"{{"version":1,"plan":"{plan}","ordinal":1,"kind":"data","file":0,"file":0,"part":0,"parts":1}}"#
            ),
            _ => format!(
                r#"{{"version":1,"plan":"{plan}","ordinal":1,"kind":"data","part":0,"parts":1}}"#
            ),
        };
        frames[1].1 = raw_frame(header.as_bytes(), b"raw");
        w.send(0, &plan, &frames);
        let did = w.did(0);
        let out = w.root.path().join("out");
        assert!(
            restore::restore(&w.db(), &out, &w.pins(&plan, &did)).is_err(),
            "case {case}"
        );
        assert!(!out.join("report.json").exists());
    }
}

/// Unicode-normalization and case aliases: either both distinct files restore
/// exactly, or the restore fails without a report. Never silent overwrite.
#[test]
fn probe_filesystem_alias_paths_never_silently_merge() {
    for pair in [["\u{e9}", "e\u{301}"], ["D/a", "d/b"], ["f", "F/x"]] {
        let mut w = World::new(1);
        let files: Vec<(&str, &[u8])> = vec![(pair[0], b"first"), (pair[1], b"second")];
        let doc = doc_for(&w, 0, &files, 0);
        let (plan, frames) = frames_for(&doc, &files);
        w.send(0, &plan, &frames);
        let did = w.did(0);
        let out = w.root.path().join("out");
        match restore::restore(&w.db(), &out, &w.pins(&plan, &did)) {
            Ok(_) => {
                assert_eq!(fs::read(out.join("files").join(pair[0])).unwrap(), b"first");
                assert_eq!(
                    fs::read(out.join("files").join(pair[1])).unwrap(),
                    b"second"
                );
            }
            Err(e) => {
                eprintln!("alias {pair:?}: {e}");
                assert!(!out.join("report.json").exists());
            }
        }
    }
}

/// Destination edge cases: dangling symlink, nested missing parent, existing file.
#[test]
fn probe_destination_edges() {
    let mut w = World::new(1);
    let plan = simple(&mut w);
    let did = w.did(0);
    let target = w.root.path().join("victim");
    #[cfg(unix)]
    {
        let link = w.root.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(restore::restore(&w.db(), &link, &w.pins(&plan, &did)).is_err());
        assert!(!target.exists(), "followed dangling symlink");
    }
    assert!(restore::restore(
        &w.db(),
        &w.root.path().join("no/such/out"),
        &w.pins(&plan, &did)
    )
    .is_err());
    let file = w.root.path().join("file");
    fs::write(&file, b"keep").unwrap();
    assert!(restore::restore(&w.db(), &file, &w.pins(&plan, &did)).is_err());
    assert_eq!(fs::read(&file).unwrap(), b"keep");
}

/// Gap in sequence rows anywhere fails; max_records boundary is inclusive.
#[test]
fn probe_record_limit_boundary_and_holes() {
    let mut w = World::new(1);
    let plan = simple(&mut w);
    let did = w.did(0);
    let through: i64 = rusqlite::Connection::open(w.db())
        .unwrap()
        .query_row("SELECT MAX(sequence) FROM commits", [], |r| r.get(0))
        .unwrap();
    let mut pins = w.pins(&plan, &did);
    pins.max_records = through as u64 - 1;
    assert!(restore::restore(&w.db(), &w.root.path().join("o1"), &pins).is_err());
    pins.max_records = through as u64;
    restore::restore(&w.db(), &w.root.path().join("o2"), &pins).unwrap();
    pins.max_records = 0;
    assert!(restore::restore(&w.db(), &w.root.path().join("o3"), &pins).is_err());
    let sql = rusqlite::Connection::open(w.db()).unwrap();
    sql.execute_batch("PRAGMA foreign_keys=OFF;").unwrap();
    sql.execute("DELETE FROM commits WHERE sequence=1", [])
        .unwrap();
    drop(sql);
    assert!(restore::restore(&w.db(), &w.root.path().join("o4"), &w.pins(&plan, &did)).is_err());
}

/// Real importer round trip with a file whose size is an exact chunk multiple.
#[test]
fn probe_importer_exact_chunk_multiple() {
    let mut w = World::new(1);
    let source = w.root.path().join("source");
    fs::create_dir(&source).unwrap();
    let bytes = vec![0xAB; 2 * CHUNK];
    fs::write(source.join("repo.car"), &bytes).unwrap();
    let (id, spool) = &mut w.writers[0];
    let plan = Plan::build(
        &source,
        Selection::Store,
        [1; 32],
        crypto::public_key(&PRIVATE).unwrap(),
        spool,
    )
    .unwrap();
    let pid = plan.id().to_string();
    plan.enqueue(&pid, spool, id, 1024).unwrap();
    w.send(0, &pid, &[]);
    let did = w.did(0);
    let out = w.root.path().join("out");
    let report = restore::restore(&w.db(), &out, &w.pins(&pid, &did)).unwrap();
    assert_eq!(fs::read(out.join("files/repo.car")).unwrap(), bytes);
    assert_eq!(report["files"][0]["length"], 2 * CHUNK);
}
