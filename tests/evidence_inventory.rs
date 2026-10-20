#![cfg(feature = "v2-storage")]
use kan::{
    evidence_copy_plan::Target,
    evidence_service::{self as service, Command, Grant, Request, Service, SignedRequest},
    evidence_store::{
        self as store, attested, copied,
        copy_upgrade::PlannedCopy,
        inventory::{self, Availability, Budget, Inventory, PageBudget, Profile, Source},
        Ledger,
    },
    sign::Identity,
};
use std::{
    io::Write,
    path::{Path, PathBuf},
    sync::{atomic::AtomicBool, Arc},
    time::Duration,
};
#[cfg(target_os = "linux")]
#[path = "support/capacity_measurements.rs"]
mod capacity_measurements;
#[path = "support/proof_service_tests.rs"]
mod proof_service_tests;
fn identity(n: u8) -> Identity {
    let mut f = tempfile::NamedTempFile::new().unwrap();
    f.write_all(&[n; 32]).unwrap();
    Identity::load_existing(f.path()).unwrap()
}
fn grant() -> Grant {
    Grant {
        principal: identity(6).did().to_string(),
        append: true,
        inventory: true,
    }
}
fn request(n: u8, audience: u8, previous: Option<String>) -> Vec<u8> {
    SignedRequest::sign(
        Request {
            version: 1,
            scope: service::hex(&[1; 32]),
            principal: identity(6).did().to_string(),
            audience: identity(audience).did().to_string(),
            expires: None,
            command: Command::Append {
                id: service::hex(&[n + 1; 16]),
                position: n as u64,
                previous,
                ciphertext: service::hex(b"synthetic encrypted capture"),
            },
        },
        &identity(6),
    )
    .unwrap()
    .bytes()
    .unwrap()
}
struct Fixture {
    root: PathBuf,
    binding: attested::Binding,
    requests: Vec<Vec<u8>>,
    profile: Profile,
}
fn fixture(parent: &Path, profile: Profile) -> Fixture {
    fixture_requests(parent, profile, request)
}
fn fixture_requests(
    parent: &Path,
    profile: Profile,
    mut make_request: impl FnMut(u8, u8, Option<String>) -> Vec<u8>,
) -> Fixture {
    let root = parent.join("archive");
    let mut requests = Vec::new();
    let mut previous = None;
    let binding = if profile == Profile::Admitted {
        let binding = attested::Binding {
            archive: [2; 32],
            scope: [1; 32],
            issuer: identity(8).did().to_string(),
        };
        let mut a = attested::Archive::create(&root, binding.clone()).unwrap();
        for n in 0..3 {
            let bytes = make_request(n, 8, previous);
            let r = a
                .admit(&bytes, &identity(8), &grant(), 100 + n as u64)
                .unwrap();
            previous = Some(r.record.manifest.cid().to_string());
            requests.push(bytes);
        }
        binding
    } else {
        let legacy = parent.join("legacy");
        let mut a = Service::new(
            Ledger::create(&legacy).unwrap(),
            [1; 32],
            identity(7),
            vec![grant()],
        )
        .unwrap();
        for n in 0..3 {
            let bytes = make_request(n, 7, previous);
            assert!(a
                .dispatch(&bytes, 100 + n as u64)
                .unwrap()
                .reply
                .result
                .is_ok());
            previous = Some(service::append_manifest(&bytes).unwrap().cid().to_string());
            requests.push(bytes);
        }
        drop(a);
        let source = PlannedCopy::open(
            &legacy.join("archive.sqlite"),
            Target {
                scope: [1; 32],
                issuer: identity(8).did().to_string(),
            },
            identity(7).did().to_string(),
            [9; 32],
        )
        .unwrap();
        let binding = attested::Binding {
            archive: source.plan().archive_id(),
            scope: [1; 32],
            issuer: identity(8).did().to_string(),
        };
        let mut a = copied::Archive::create(&root, &source, binding.clone()).unwrap();
        assert!(
            a.copy_batch(
                &source,
                &identity(8),
                1000,
                copied::Budget {
                    objects: 100,
                    records: 100,
                    bytes: 16 * 1024 * 1024
                }
            )
            .unwrap()
            .status
            .source_copy_complete
        );
        binding
    };
    Fixture {
        root,
        binding,
        requests,
        profile,
    }
}
fn budget() -> Budget {
    Budget {
        items: 100,
        metadata_bytes: 4 * 1024 * 1024,
        duration: Duration::from_secs(10),
        cancelled: Arc::new(AtomicBool::new(false)),
    }
}
fn page_budget() -> PageBudget {
    PageBudget {
        rows: 40,
        record_bytes: 4 * 1024 * 1024,
        payload_bytes: 16 * 1024 * 1024,
    }
}
impl Fixture {
    fn db(&self) -> PathBuf {
        self.root.join("archive.sqlite")
    }
    fn open(&self) -> Inventory {
        Inventory::open(&self.db(), self.profile, self.binding.clone(), budget()).unwrap()
    }
    fn edit(&self, sql: &str) {
        let c = rusqlite::Connection::open(self.db()).unwrap();
        c.execute_batch("PRAGMA foreign_keys=OFF").unwrap(); // synthetic damage
        c.execute_batch(sql).unwrap();
    }
    fn id(&self, n: usize) -> String {
        store::ciphertext_cid(&self.requests[n]).to_string()
    }
    fn remove(&self, n: usize) {
        let c = rusqlite::Connection::open(self.db()).unwrap();
        c.execute_batch("PRAGMA foreign_keys=OFF").unwrap(); // synthetic loss
        c.execute("DELETE FROM objects WHERE cid=?", [self.id(n)])
            .unwrap();
    }
}

#[test]
fn reopening_an_older_proof_pin_excludes_later_appends_and_resumes_descending() {
    for profile in [Profile::Admitted, Profile::Copied] {
        let t = tempfile::tempdir().unwrap();
        let f = fixture(t.path(), profile);
        let opened = f.open();
        let page = opened.page(None, page_budget(), budget()).unwrap();
        let pin = page.records[1].proof.frontier().clone();
        let tail = page.records[1].proof.previous().clone();
        let previous = page.records[0].record.manifest.cid().to_string();
        drop(opened);
        let bytes = request(3, 8, Some(previous));
        if profile == Profile::Admitted {
            attested::Archive::open(&f.root, f.binding.clone())
                .unwrap()
                .admit(&bytes, &identity(8), &grant(), 200)
                .unwrap();
        } else {
            copied::Archive::open(&f.root, f.binding.clone())
                .unwrap()
                .admit(&bytes, &identity(8), &grant(), 200)
                .unwrap();
        }
        let selected =
            Inventory::open_at(&f.db(), profile, f.binding.clone(), &pin, budget()).unwrap();
        assert_eq!(selected.frontier(), &pin);
        assert_eq!(
            selected.recipe_metadata_match(),
            if profile == Profile::Copied {
                Some(false)
            } else {
                None
            }
        );
        let first = selected
            .page_from(
                &pin,
                PageBudget {
                    rows: 1,
                    ..page_budget()
                },
                budget(),
            )
            .unwrap();
        assert_eq!(first.records.len(), 1);
        assert_eq!(first.records[0].record.sequence, 2);
        assert_eq!(first.records[0].selection.snapshot(), &pin);
        drop(selected);
        let resumed =
            Inventory::open_at(&f.db(), profile, f.binding.clone(), &pin, budget()).unwrap();
        let next = resumed.page_from(&tail, page_budget(), budget()).unwrap();
        assert_eq!(
            next.records
                .iter()
                .map(|r| r.record.sequence)
                .collect::<Vec<_>>(),
            vec![1]
        );
        assert!(next.next.is_none());
        let fresh = f.open();
        assert_eq!(fresh.frontier().through, 4);
        assert_eq!(
            fresh.recipe_metadata_match(),
            if profile == Profile::Copied {
                Some(true)
            } else {
                None
            }
        );
    }
}

#[test]
fn proof_pin_and_stateless_continuation_reject_forks_future_and_malformed_empty() {
    for profile in [Profile::Admitted, Profile::Copied] {
        let t = tempfile::tempdir().unwrap();
        let f = fixture(t.path(), profile);
        let opened = f.open();
        let page = opened.page(None, page_budget(), budget()).unwrap();
        let pin = page.records[1].proof.frontier().clone();
        let newer = page.records[0].proof.frontier().clone();
        drop(opened);
        let mut forged = pin.clone();
        forged.attestation = Some(store::ciphertext_cid(b"forged statement"));
        assert!(
            Inventory::open_at(&f.db(), profile, f.binding.clone(), &forged, budget()).is_err()
        );
        let selected =
            Inventory::open_at(&f.db(), profile, f.binding.clone(), &pin, budget()).unwrap();
        assert!(selected.page_from(&newer, page_budget(), budget()).is_err());
        assert!(selected
            .page_from(&forged, page_budget(), budget())
            .is_err());
        forged.through = 0;
        assert!(selected
            .page_from(&forged, page_budget(), budget())
            .is_err());
        assert!(
            Inventory::open_at(&f.db(), profile, f.binding.clone(), &forged, budget()).is_err()
        );
        let empty = kan::evidence_attestation::Frontier::default();
        let at_empty =
            Inventory::open_at(&f.db(), profile, f.binding.clone(), &empty, budget()).unwrap();
        assert!(at_empty
            .page_from(&empty, page_budget(), budget())
            .unwrap()
            .records
            .is_empty());
        assert!(at_empty.page_from(&pin, page_budget(), budget()).is_err());
        drop(selected);
        drop(at_empty);
        f.edit("DELETE FROM attestations WHERE sequence>1; DELETE FROM commits WHERE sequence>1;");
        assert!(Inventory::open_at(&f.db(), profile, f.binding.clone(), &pin, budget()).is_err());
    }
}

#[test]
fn old_proof_pin_still_audits_current_metadata_and_browses_payload_loss() {
    for profile in [Profile::Admitted, Profile::Copied] {
        let t = tempfile::tempdir().unwrap();
        let f = fixture(t.path(), profile);
        let opened = f.open();
        let page = opened.page(None, page_budget(), budget()).unwrap();
        let pin = page.records[1].proof.frontier().clone();
        drop(opened);
        f.remove(1);
        let reopened =
            Inventory::open_at(&f.db(), profile, f.binding.clone(), &pin, budget()).unwrap();
        let rows = reopened.page_from(&pin, page_budget(), budget()).unwrap();
        assert_eq!(rows.records[0].availability, Availability::Missing);
        assert_eq!(rows.records[1].availability, Availability::Available);
        assert!(matches!(
            inventory::source(
                &f.db(),
                profile,
                f.binding.clone(),
                &rows.records[0].selection,
                service::MAX_REQUEST,
                budget()
            )
            .unwrap(),
            Source::Unavailable(Availability::Missing)
        ));
        drop(reopened);
        let mut limited = budget();
        limited.items = 2;
        assert!(Inventory::open_at(&f.db(), profile, f.binding.clone(), &pin, limited).is_err());
        f.edit("UPDATE attestations SET envelope=x'00' WHERE sequence=3;");
        assert!(
            Inventory::open_at(&f.db(), profile, f.binding.clone(), &pin, budget()).is_err(),
            "old pins do not bypass current metadata integrity"
        );
    }
}
#[test]
fn missing_and_corrupt_tip_or_middle_remain_visible_after_restart_with_healthy_neighbours() {
    for profile in [Profile::Admitted, Profile::Copied] {
        for n in [1, 2] {
            for corrupt in [false, true] {
                let t = tempfile::tempdir().unwrap();
                let f = fixture(t.path(), profile);
                if corrupt {
                    let c = rusqlite::Connection::open(f.db()).unwrap();
                    c.execute(
                        "UPDATE objects SET bytes=? WHERE cid=?",
                        rusqlite::params![vec![0u8; f.requests[n].len()], f.id(n)],
                    )
                    .unwrap();
                } else {
                    f.remove(n);
                }
                for _ in 0..2 {
                    let a = f.open();
                    assert_eq!(a.frontier().through, 3);
                    assert_eq!(
                        a.recipe_metadata_match(),
                        if profile == Profile::Copied {
                            Some(true)
                        } else {
                            None
                        }
                    );
                    let page = a.page(None, page_budget(), budget()).unwrap();
                    assert_eq!(page.records.len(), 3);
                    assert!(page.next.is_none());
                    for row in page.records {
                        let index = row.record.sequence as usize - 1;
                        let expected = if index == n {
                            if corrupt {
                                Availability::Corrupt
                            } else {
                                Availability::Missing
                            }
                        } else {
                            Availability::Available
                        };
                        assert_eq!(row.availability, expected);
                        match inventory::source(
                            &f.db(),
                            profile,
                            f.binding.clone(),
                            &row.selection,
                            service::MAX_REQUEST,
                            budget(),
                        )
                        .unwrap()
                        {
                            Source::Available { bytes, writer } => {
                                assert_eq!(expected, Availability::Available);
                                assert_eq!(bytes, f.requests[index]);
                                assert_eq!(writer, identity(6).did().to_string());
                            }
                            Source::Unavailable(state) => assert_eq!(state, expected),
                        }
                    }
                }
                assert!(match profile {
                    Profile::Admitted =>
                        attested::Archive::open(&f.root, f.binding.clone()).is_err(),
                    Profile::Copied => copied::Archive::open(&f.root, f.binding.clone()).is_err(),
                });
            }
        }
    }
}
#[test]
fn source_rechecks_current_payload_and_selected_metadata_in_a_fresh_transaction() {
    for profile in [Profile::Admitted, Profile::Copied] {
        let t = tempfile::tempdir().unwrap();
        let f = fixture(t.path(), profile);
        let a = f.open();
        let p = a.page(None, page_budget(), budget()).unwrap();
        let row = &p.records[0];
        assert_eq!(row.availability, Availability::Available);
        f.remove(2);
        assert!(matches!(
            inventory::source(
                &f.db(),
                profile,
                f.binding.clone(),
                &row.selection,
                service::MAX_REQUEST,
                budget()
            )
            .unwrap(),
            Source::Unavailable(Availability::Missing)
        ));
        // The old pinned page can still report its original sample; it is not a grant.
        assert_eq!(
            a.page(None, page_budget(), budget()).unwrap().records[0].availability,
            Availability::Available
        );
        f.edit("UPDATE attestations SET envelope=x'00' WHERE sequence=3");
        assert!(inventory::source(
            &f.db(),
            profile,
            f.binding.clone(),
            &row.selection,
            service::MAX_REQUEST,
            budget()
        )
        .is_err());
    }
}
#[test]
fn owner_schema_and_metadata_failures_are_never_unavailable_badges() {
    for profile in [Profile::Admitted, Profile::Copied] {
        for sql in [
            "UPDATE attestations SET envelope=x'00' WHERE sequence=2",
            "DELETE FROM attestations WHERE sequence=2",
            "INSERT INTO attestations SELECT 99,envelope FROM attestations WHERE sequence=1",
            "DELETE FROM commits WHERE sequence=1",
            "UPDATE commits SET receipt=x'00' WHERE sequence=1",
            "CREATE INDEX extra ON commits(writer)",
            "UPDATE archive_identity SET archive=zeroblob(32)",
        ] {
            let t = tempfile::tempdir().unwrap();
            let f = fixture(t.path(), profile);
            f.edit(sql);
            let before = std::fs::read(f.db()).unwrap();
            assert!(
                Inventory::open(&f.db(), profile, f.binding.clone(), budget()).is_err(),
                "{sql}"
            );
            assert_eq!(std::fs::read(f.db()).unwrap(), before);
        }
    }
    let t = tempfile::tempdir().unwrap();
    let f = fixture(t.path(), Profile::Admitted);
    for field in 0..3 {
        let mut wrong = f.binding.clone();
        match field {
            0 => wrong.archive[0] ^= 1,
            1 => wrong.scope[0] ^= 1,
            _ => wrong.issuer = identity(9).did().to_string(),
        }
        assert!(Inventory::open(&f.db(), f.profile, wrong, budget()).is_err());
    }
    assert!(Inventory::open(&f.db(), Profile::Copied, f.binding.clone(), budget()).is_err());
}
#[test]
fn descending_pages_and_budgets_preserve_exact_frontiers() {
    let t = tempfile::tempdir().unwrap();
    let f = fixture(t.path(), Profile::Copied);
    let a = f.open();
    let limit = PageBudget {
        rows: 1,
        ..page_budget()
    };
    let mut cursor = None;
    for expected in (1..=3).rev() {
        let p = a.page(cursor.as_ref(), limit, budget()).unwrap();
        assert_eq!(p.records.len(), 1);
        assert_eq!(p.records[0].record.sequence, expected);
        cursor = p.next;
    }
    assert!(cursor.is_none());
    assert!(a
        .page(
            None,
            PageBudget {
                record_bytes: 1,
                ..page_budget()
            },
            budget()
        )
        .is_err());
    assert!(a
        .page(
            None,
            PageBudget {
                payload_bytes: 1,
                ..page_budget()
            },
            budget()
        )
        .is_err());
    let mut b = budget();
    b.items = 1;
    assert!(Inventory::open(&f.db(), f.profile, f.binding.clone(), b).is_err());
    let mut b = budget();
    b.metadata_bytes = 1;
    assert!(Inventory::open(&f.db(), f.profile, f.binding.clone(), b.clone()).is_err());
    assert!(a.page(None, page_budget(), b).is_err());
    let b = budget();
    b.cancelled
        .store(true, std::sync::atomic::Ordering::Relaxed);
    assert!(Inventory::open(&f.db(), f.profile, f.binding.clone(), b).is_err());
    let p = a.page(None, page_budget(), budget()).unwrap();
    assert!(inventory::source(
        &f.db(),
        f.profile,
        f.binding.clone(),
        &p.records[0].selection,
        1,
        budget()
    )
    .is_err());
}
#[test]
fn oversized_payload_is_classified_by_length_without_full_materialization() {
    let t = tempfile::tempdir().unwrap();
    let f = fixture(t.path(), Profile::Admitted);
    let c = rusqlite::Connection::open(f.db()).unwrap();
    c.execute_batch("PRAGMA ignore_check_constraints=ON")
        .unwrap();
    c.execute(
        "UPDATE objects SET bytes=zeroblob(16777216) WHERE cid=?",
        [f.id(1)],
    )
    .unwrap();
    drop(c);
    let a = f.open();
    let p = a.page(None, page_budget(), budget()).unwrap();
    assert_eq!(p.records[1].availability, Availability::Corrupt);
    assert_eq!(p.records[0].availability, Availability::Available);
}

fn known(bytes: &[u8]) -> kan::evidence::Record {
    match kan::evidence::decode(bytes).unwrap() {
        kan::evidence::Decoded::Known(r) => r,
        _ => panic!("known fixture record"),
    }
}
fn change_body(
    record: &kan::evidence::Record,
    change: impl FnOnce(&mut std::collections::BTreeMap<String, atproto_dasl::Ipld>),
) -> kan::evidence::Record {
    use atproto_dasl::Ipld;
    let mut value: Ipld = atproto_dasl::from_slice(record.bytes()).unwrap();
    let Ipld::Map(outer) = &mut value else {
        panic!()
    };
    let Ipld::Map(body) = outer.get_mut("body").unwrap() else {
        panic!()
    };
    change(body);
    known(&atproto_dasl::to_vec(&value).unwrap())
}
#[test]
fn issuer_attested_available_metadata_does_not_replace_original_writer_verification() {
    use atproto_dasl::Ipld;
    use kan::evidence_attestation::{self as proof, Context, Purpose};
    let t = tempfile::tempdir().unwrap();
    let f = fixture(t.path(), Profile::Admitted);
    let a = f.open();
    let page = a.page(None, page_budget(), budget()).unwrap();
    let old = &page.records[0];
    let mut request: serde_json::Value = serde_json::from_slice(&f.requests[2]).unwrap();
    request["signature"] = serde_json::Value::String("00".repeat(64));
    let bytes = serde_json::to_vec(&request).unwrap();
    let id = store::ciphertext_cid(&bytes);
    let manifest = change_body(&old.record.manifest, |body| {
        let Ipld::List(entries) = body.get_mut("entries").unwrap() else {
            panic!()
        };
        let Ipld::Map(entry) = &mut entries[0] else {
            panic!()
        };
        entry.insert("ciphertext".into(), Ipld::Link(id.clone()));
        entry.insert("length".into(), Ipld::Integer(bytes.len() as i128));
    });
    let receipt = change_body(&old.record.receipt, |body| {
        body.insert("manifest".into(), Ipld::Link(manifest.cid().clone()));
    });
    let signed = proof::issue(
        &identity(8),
        &Context {
            archive: f.binding.archive,
            scope: f.binding.scope,
            issuer: &f.binding.issuer,
        },
        &manifest,
        &receipt,
        page.records[1].proof.frontier(),
        Purpose::Admitted,
        1000,
    )
    .unwrap();
    drop(a);
    let c = rusqlite::Connection::open(f.db()).unwrap();
    c.execute_batch("PRAGMA foreign_keys=OFF").unwrap(); // synthetic signed forgery
    c.execute(
        "INSERT INTO objects VALUES(?,?)",
        rusqlite::params![id.to_string(), bytes],
    )
    .unwrap();
    c.execute(
        "UPDATE commits SET cid=?,manifest=?,receipt=? WHERE sequence=3",
        rusqlite::params![
            manifest.cid().to_string(),
            manifest.bytes(),
            receipt.bytes()
        ],
    )
    .unwrap();
    c.execute(
        "UPDATE attestations SET envelope=? WHERE sequence=3",
        [signed.bytes()],
    )
    .unwrap();
    drop(c);
    let a = f.open();
    let page = a.page(None, page_budget(), budget()).unwrap();
    assert_eq!(page.records[0].availability, Availability::Available);
    assert_eq!(
        inventory::source(
            &f.db(),
            f.profile,
            f.binding.clone(),
            &page.records[0].selection,
            service::MAX_REQUEST,
            budget()
        )
        .err()
        .unwrap()
        .to_string(),
        "corrupt evidence: selected writer request"
    );
}
#[test]
fn read_only_inventory_preserves_main_and_retained_wal_bytes() {
    let t = tempfile::tempdir().unwrap();
    let f = fixture(t.path(), Profile::Admitted);
    let c = rusqlite::Connection::open(f.db()).unwrap();
    c.execute_batch("PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0;")
        .unwrap();
    c.execute("UPDATE objects SET bytes=x'00' WHERE cid=?", [f.id(1)])
        .unwrap();
    let wal = PathBuf::from(format!("{}-wal", f.db().display()));
    assert!(std::fs::metadata(&wal).unwrap().len() > 0);
    let before = std::fs::read(f.db()).unwrap();
    let wal_before = std::fs::read(&wal).unwrap();
    {
        let a = f.open();
        let page = a.page(None, page_budget(), budget()).unwrap();
        assert_eq!(page.records[1].availability, Availability::Corrupt);
        let _ = inventory::source(
            &f.db(),
            f.profile,
            f.binding.clone(),
            &page.records[0].selection,
            service::MAX_REQUEST,
            budget(),
        )
        .unwrap();
    }
    assert_eq!(std::fs::read(f.db()).unwrap(), before);
    assert_eq!(std::fs::read(&wal).unwrap(), wal_before);
    drop(c);
}

#[test]
fn selected_valid_same_height_proof_replacement_is_rejected() {
    use kan::evidence_attestation::{self as proof, Context, Purpose};
    let t = tempfile::tempdir().unwrap();
    let f = fixture(t.path(), Profile::Admitted);
    let a = f.open();
    let page = a.page(None, page_budget(), budget()).unwrap();
    let row = &page.records[0];
    let changed = proof::issue(
        &identity(8),
        &Context {
            archive: f.binding.archive,
            scope: f.binding.scope,
            issuer: &f.binding.issuer,
        },
        &row.record.manifest,
        &row.record.receipt,
        page.records[1].proof.frontier(),
        Purpose::Admitted,
        999999,
    )
    .unwrap();
    let c = rusqlite::Connection::open(f.db()).unwrap();
    c.execute(
        "UPDATE attestations SET envelope=? WHERE sequence=3",
        [changed.bytes()],
    )
    .unwrap();
    drop(c);
    assert_eq!(
        inventory::source(
            &f.db(),
            f.profile,
            f.binding.clone(),
            &row.selection,
            service::MAX_REQUEST,
            budget()
        )
        .err()
        .unwrap()
        .to_string(),
        "corrupt evidence: selected proof changed"
    );
}
#[test]
fn complete_retained_metadata_requires_exact_original_inventory_and_recipe() {
    for sql in [
        "DELETE FROM upgrade_objects WHERE cid=(SELECT cid FROM upgrade_objects LIMIT 1)",
        "UPDATE upgrade_plan SET envelope=x'00'",
    ] {
        let t = tempfile::tempdir().unwrap();
        let f = fixture(t.path(), Profile::Copied);
        f.edit(sql);
        assert!(
            Inventory::open(&f.db(), f.profile, f.binding.clone(), budget()).is_err(),
            "{sql}"
        );
    }
}

#[test]
fn inventory_large_row_worker() {
    let Ok(db) = std::env::var("KAN_INVENTORY_LARGE_SOURCE") else {
        return;
    };
    let binding = attested::Binding {
        archive: [2; 32],
        scope: [1; 32],
        issuer: identity(8).did().to_string(),
    };
    let opened = Inventory::open(Path::new(&db), Profile::Admitted, binding, budget());
    if std::env::var("KAN_INVENTORY_LARGE_KIND").unwrap() == "manifest" {
        assert!(
            matches!(opened.err().unwrap(), store::Error::Sql(rusqlite::Error::SqliteFailure(e,_)) if e.code == rusqlite::ErrorCode::TooBig)
        );
    } else {
        let a = opened.unwrap();
        let page = a.page(None, page_budget(), budget()).unwrap();
        assert_eq!(page.records[1].availability, Availability::Corrupt);
        assert_eq!(page.records[0].availability, Availability::Available);
    }
}

#[test]
fn inventory_large_rows_stay_below_the_materialization_memory_ceiling() {
    for kind in ["object", "text-object", "manifest"] {
        let t = tempfile::tempdir().unwrap();
        let f = fixture(t.path(), Profile::Admitted);
        let c = rusqlite::Connection::open(f.db()).unwrap();
        c.execute_batch("PRAGMA ignore_check_constraints=ON")
            .unwrap();
        if kind == "object" {
            c.execute(
                "UPDATE objects SET bytes=zeroblob(100663296) WHERE cid=?",
                [f.id(1)],
            )
            .unwrap();
        } else if kind == "text-object" {
            c.execute(
                "UPDATE objects SET bytes=replace(hex(zeroblob(50331648)),'0','x') WHERE cid=?",
                [f.id(1)],
            )
            .unwrap();
        } else {
            c.execute_batch("UPDATE commits SET manifest=zeroblob(100663296) WHERE sequence=2")
                .unwrap();
        }
        drop(c);
        // Only the fresh reader is measured; fixture creation is outside the child.
        #[cfg(unix)]
        let out = std::process::Command::new("python3").args(["-c", r#"import json,resource,subprocess,sys
p=subprocess.run([sys.argv[1],'--exact','inventory_large_row_worker','--nocapture'],capture_output=True,text=True,timeout=30)
peak=resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
if sys.platform != 'darwin': peak*=1024
print(json.dumps({'exit':p.returncode,'peak_bytes':peak,'stdout':p.stdout,'stderr':p.stderr}))
sys.exit(0 if p.returncode==0 and peak<64*1024*1024 else 1)
"#]).arg(std::env::current_exe().unwrap()).env("KAN_INVENTORY_LARGE_SOURCE", f.db()).env("KAN_INVENTORY_LARGE_KIND", kind).output().unwrap();
        #[cfg(not(unix))]
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "inventory_large_row_worker", "--nocapture"])
            .env("KAN_INVENTORY_LARGE_SOURCE", f.db())
            .env("KAN_INVENTORY_LARGE_KIND", kind)
            .output()
            .unwrap();
        println!("{kind}: {}", String::from_utf8_lossy(&out.stdout));
        assert!(
            out.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

fn replace_tip_purpose(
    f: &Fixture,
    purpose: kan::evidence_attestation::Purpose,
    receipt_issuer: Option<u8>,
) {
    use kan::evidence_attestation::{self as proof, Context};
    let a = f.open();
    let page = a.page(None, page_budget(), budget()).unwrap();
    let tip = &page.records[0];
    let receipt = if let Some(n) = receipt_issuer {
        change_body(&tip.record.receipt, |body| {
            let atproto_dasl::Ipld::Map(author) = body.get_mut("issuer").unwrap() else {
                panic!("author")
            };
            let did = identity(n).did().to_string();
            let method = format!("{did}#{}", did.strip_prefix("did:key:").unwrap());
            author.insert("principal".into(), atproto_dasl::Ipld::String(did));
            author.insert(
                "verificationMethod".into(),
                atproto_dasl::Ipld::String(method),
            );
        })
    } else {
        tip.record.receipt.clone()
    };
    let ctx = Context {
        archive: f.binding.archive,
        scope: f.binding.scope,
        issuer: &f.binding.issuer,
    };
    let envelope = proof::issue(
        &identity(8),
        &ctx,
        &tip.record.manifest,
        &receipt,
        tip.proof.previous(),
        purpose,
        9999,
    )
    .unwrap();
    let sequence = tip.record.sequence as i64;
    drop(a);
    let c = rusqlite::Connection::open(f.db()).unwrap();
    c.execute(
        "UPDATE commits SET receipt=? WHERE sequence=?",
        rusqlite::params![receipt.bytes(), sequence],
    )
    .unwrap();
    c.execute(
        "UPDATE attestations SET envelope=? WHERE sequence=?",
        rusqlite::params![envelope.bytes(), sequence],
    )
    .unwrap();
}

#[test]
fn inventory_purpose_checks_pin_specific_refusals_before_recipe_digest_checks() {
    use kan::evidence_attestation::Purpose;
    for (profile, purpose, issuer, expected) in [
        (
            Profile::Admitted,
            Purpose::RetainedVerified,
            None,
            "corrupt evidence: retained-verified prefix requires copy profile",
        ),
        (
            Profile::Copied,
            Purpose::Admitted,
            Some(8),
            "corrupt evidence: admission inside planned retained prefix",
        ),
        (
            Profile::Copied,
            Purpose::RetainedVerified,
            Some(9),
            "corrupt evidence: retained-verified historical issuer differs from copy plan",
        ),
    ] {
        let t = tempfile::tempdir().unwrap();
        let f = fixture(t.path(), profile);
        replace_tip_purpose(&f, purpose, issuer);
        assert_eq!(
            Inventory::open(&f.db(), f.profile, f.binding.clone(), budget())
                .err()
                .unwrap()
                .to_string(),
            expected
        );
    }
    let t = tempfile::tempdir().unwrap();
    let f = fixture(t.path(), Profile::Copied);
    let mut archive = copied::Archive::open(&f.root, f.binding.clone()).unwrap();
    let prev = service::append_manifest(&f.requests[2])
        .unwrap()
        .cid()
        .to_string();
    archive
        .admit(&request(3, 8, Some(prev)), &identity(8), &grant(), 200)
        .unwrap();
    drop(archive);
    replace_tip_purpose(&f, Purpose::RetainedVerified, None);
    assert_eq!(
        Inventory::open(&f.db(), f.profile, f.binding.clone(), budget())
            .err()
            .unwrap()
            .to_string(),
        "corrupt evidence: retained-verified row after planned prefix"
    );
}

#[test]
fn byte_limited_pages_and_wrong_context_cursors_never_report_false_coverage() {
    let t = tempfile::tempdir().unwrap();
    let f = fixture(t.path(), Profile::Admitted);
    let a = f.open();
    let first = a
        .page(
            None,
            PageBudget {
                rows: 1,
                ..page_budget()
            },
            budget(),
        )
        .unwrap();
    let row = &first.records[0];
    let bytes = row.record.manifest.bytes().len()
        + row.record.receipt.bytes().len()
        + row.proof.bytes().len();
    for limit in [
        PageBudget {
            record_bytes: bytes,
            ..page_budget()
        },
        PageBudget {
            payload_bytes: f.requests[2].len(),
            ..page_budget()
        },
    ] {
        let page = a.page(None, limit, budget()).unwrap();
        assert_eq!(page.records.len(), 1);
        assert_eq!(page.records[0].record.sequence, 3);
        let second = a.page(page.next.as_ref(), page_budget(), budget()).unwrap();
        assert_eq!(
            second
                .records
                .iter()
                .map(|r| r.record.sequence)
                .collect::<Vec<_>>(),
            vec![2, 1]
        );
    }
    let other_parent = tempfile::tempdir().unwrap();
    let other = fixture(other_parent.path(), Profile::Copied);
    assert!(other
        .open()
        .page(first.next.as_ref(), page_budget(), budget())
        .is_err());
    assert!(inventory::source(
        &other.db(),
        other.profile,
        other.binding,
        &row.selection,
        service::MAX_REQUEST,
        budget()
    )
    .is_err());
    let mut work = budget();
    work.items = 1;
    assert!(a.page(None, page_budget(), work).is_err());
    let cancelled = budget();
    cancelled
        .cancelled
        .store(true, std::sync::atomic::Ordering::Relaxed);
    assert!(a.page(None, page_budget(), cancelled.clone()).is_err());
    assert!(inventory::source(
        &f.db(),
        f.profile,
        f.binding.clone(),
        &row.selection,
        service::MAX_REQUEST,
        cancelled
    )
    .is_err());
    // Resetting per-call limits after failure must leave the pinned reader usable.
    assert_eq!(
        a.page(None, page_budget(), budget()).unwrap().records.len(),
        3
    );
}

#[test]
fn maximum_service_request_is_available_under_the_metadata_allocation_limit() {
    let t = tempfile::tempdir().unwrap();
    let root = t.path().join("archive");
    let binding = attested::Binding {
        archive: [2; 32],
        scope: [1; 32],
        issuer: identity(8).did().to_string(),
    };
    let bytes = SignedRequest::sign(
        Request {
            version: 1,
            scope: service::hex(&binding.scope),
            principal: identity(6).did().to_string(),
            audience: binding.issuer.clone(),
            expires: None,
            command: Command::Append {
                id: service::hex(&[1; 16]),
                position: 0,
                previous: None,
                ciphertext: service::hex(&vec![42; service::MAX_PAYLOAD]),
            },
        },
        &identity(6),
    )
    .unwrap()
    .bytes()
    .unwrap();
    let mut a = attested::Archive::create(&root, binding.clone()).unwrap();
    a.admit(&bytes, &identity(8), &grant(), 100).unwrap();
    drop(a);
    let db = root.join("archive.sqlite");
    let a = Inventory::open(&db, Profile::Admitted, binding.clone(), budget()).unwrap();
    let page = a.page(None, page_budget(), budget()).unwrap();
    assert_eq!(page.records.len(), 1);
    assert_eq!(page.records[0].availability, Availability::Available);
    match inventory::source(
        &db,
        Profile::Admitted,
        binding,
        &page.records[0].selection,
        service::MAX_REQUEST,
        budget(),
    )
    .unwrap()
    {
        Source::Available { bytes: actual, .. } => assert_eq!(actual, bytes),
        _ => panic!("maximum valid request unavailable"),
    }
}

#[test]
fn empty_admitted_and_incomplete_retained_snapshots_do_not_claim_copy_readiness() {
    let t = tempfile::tempdir().unwrap();
    let empty = t.path().join("empty");
    let binding = attested::Binding {
        archive: [2; 32],
        scope: [1; 32],
        issuer: identity(8).did().to_string(),
    };
    drop(attested::Archive::create(&empty, binding.clone()).unwrap());
    let a = Inventory::open(
        &empty.join("archive.sqlite"),
        Profile::Admitted,
        binding,
        budget(),
    )
    .unwrap();
    assert_eq!(a.frontier().through, 0);
    assert_eq!(a.recipe_metadata_match(), None);
    let page = a
        .page(
            None,
            PageBudget {
                payload_bytes: 0,
                ..page_budget()
            },
            budget(),
        )
        .unwrap();
    assert!(page.records.is_empty() && page.next.is_none());
    let f = fixture(t.path(), Profile::Copied);
    let src = PlannedCopy::open(
        &t.path().join("legacy/archive.sqlite"),
        Target {
            scope: f.binding.scope,
            issuer: f.binding.issuer.clone(),
        },
        identity(7).did().to_string(),
        [9; 32],
    )
    .unwrap();
    let root = t.path().join("partial");
    let mut copy = copied::Archive::create(&root, &src, f.binding.clone()).unwrap();
    copy.copy_batch(
        &src,
        &identity(8),
        1000,
        copied::Budget {
            objects: 100,
            records: 1,
            bytes: 16 * 1024 * 1024,
        },
    )
    .unwrap();
    assert!(!copy.verify().unwrap().copy.source_copy_complete);
    drop(copy);
    let a = Inventory::open(
        &root.join("archive.sqlite"),
        f.profile,
        f.binding.clone(),
        budget(),
    )
    .unwrap();
    assert_eq!(a.frontier().through, 1);
    assert_eq!(a.recipe_metadata_match(), Some(false));
    let page = a.page(None, page_budget(), budget()).unwrap();
    assert_eq!(page.records.len(), 1);
    assert_eq!(page.records[0].availability, Availability::Available);
    assert!(matches!(
        inventory::source(
            &root.join("archive.sqlite"),
            f.profile,
            f.binding.clone(),
            &page.records[0].selection,
            service::MAX_REQUEST,
            budget()
        )
        .unwrap(),
        Source::Available { .. }
    ));
}

#[test]
fn wrong_sql_payload_types_are_corrupt_without_failing_healthy_neighbours() {
    for profile in [Profile::Admitted, Profile::Copied] {
        for index in [1, 2] {
            for expression in ["CAST(bytes AS TEXT)", "123", "1.25"] {
                let t = tempfile::tempdir().unwrap();
                let f = fixture(t.path(), profile);
                let before = f.open();
                let old = before.page(None, page_budget(), budget()).unwrap();
                let selected = &old
                    .records
                    .iter()
                    .find(|r| r.record.sequence == index as u64 + 1)
                    .unwrap()
                    .selection;
                let c = rusqlite::Connection::open(f.db()).unwrap();
                c.execute(
                    &format!("UPDATE objects SET bytes={expression} WHERE cid=?"),
                    [f.id(index)],
                )
                .unwrap();
                drop(c);
                // Fresh source cannot accept even byte-identical TEXT after selection.
                assert!(matches!(
                    inventory::source(
                        &f.db(),
                        f.profile,
                        f.binding.clone(),
                        selected,
                        service::MAX_REQUEST,
                        budget()
                    )
                    .unwrap(),
                    Source::Unavailable(Availability::Corrupt)
                ));
                drop(before);
                let restarted = f.open();
                let page = restarted.page(None, page_budget(), budget()).unwrap();
                assert_eq!(page.records.len(), 3);
                for row in page.records {
                    let expected = if row.record.sequence == index as u64 + 1 {
                        Availability::Corrupt
                    } else {
                        Availability::Available
                    };
                    assert_eq!(row.availability, expected);
                    if expected == Availability::Available {
                        assert!(matches!(
                            inventory::source(
                                &f.db(),
                                f.profile,
                                f.binding.clone(),
                                &row.selection,
                                service::MAX_REQUEST,
                                budget()
                            )
                            .unwrap(),
                            Source::Available { .. }
                        ));
                    }
                }
            }
        }
    }
}

#[test]
fn startup_item_budget_counts_each_metadata_record_before_accepting_a_snapshot() {
    let t = tempfile::tempdir().unwrap();
    let f = fixture(t.path(), Profile::Admitted);
    let mut limited = budget();
    limited.items = 2;
    assert_eq!(
        Inventory::open(&f.db(), f.profile, f.binding.clone(), limited)
            .err()
            .unwrap()
            .to_string(),
        "invalid input: inventory audit budget exhausted"
    );
    let mut exact = budget();
    exact.items = 3;
    assert_eq!(
        Inventory::open(&f.db(), f.profile, f.binding.clone(), exact)
            .unwrap()
            .frontier()
            .through,
        3
    );
}

#[test]
fn single_bit_blob_to_text_serial_type_damage_remains_browsable() {
    // Regression derived from independent Opus probe_b5, whose two unsuccessful
    // fixture attempts and final raw probe remain in the preserved review.
    for profile in [Profile::Admitted, Profile::Copied] {
        let t = tempfile::tempdir().unwrap();
        let f = fixture(t.path(), profile);
        let c = rusqlite::Connection::open(f.db()).unwrap();
        c.execute_batch("PRAGMA journal_mode=DELETE; VACUUM;")
            .unwrap();
        drop(c);
        let id = f.id(1);
        let n = f.requests[1].len() as u64;
        let varint = |v: u64| {
            assert!(v < 16384);
            if v >= 128 {
                vec![0x80 | (v >> 7) as u8, (v & 0x7f) as u8]
            } else {
                vec![v as u8]
            }
        };
        let mut pattern = varint(2 * id.len() as u64 + 13);
        pattern.extend(varint(2 * n + 12));
        let serial_end = pattern.len();
        pattern.extend(id.as_bytes());
        let original = std::fs::read(f.db()).unwrap();
        let mut damaged = original.clone();
        let hits: Vec<_> = damaged
            .windows(pattern.len())
            .enumerate()
            .filter(|(_, w)| *w == pattern)
            .map(|(i, _)| i)
            .collect();
        assert_eq!(hits.len(), 1);
        damaged[hits[0] + serial_end - 1] ^= 1;
        assert_eq!(
            original
                .iter()
                .zip(&damaged)
                .filter(|(a, b)| a != b)
                .count(),
            1
        );
        std::fs::write(f.db(), &damaged).unwrap();
        let c = rusqlite::Connection::open(f.db()).unwrap();
        assert_eq!(
            c.query_row(
                "SELECT typeof(bytes) FROM objects WHERE cid=?",
                [&id],
                |r| r.get::<_, String>(0)
            )
            .unwrap(),
            "text"
        );
        drop(c);
        let a = f.open();
        let first = a
            .page(
                None,
                PageBudget {
                    rows: 1,
                    ..page_budget()
                },
                budget(),
            )
            .unwrap();
        assert_eq!(first.records[0].availability, Availability::Available);
        let rest = a
            .page(first.next.as_ref(), page_budget(), budget())
            .unwrap();
        assert_eq!(
            rest.records
                .iter()
                .map(|r| (r.record.sequence, r.availability))
                .collect::<Vec<_>>(),
            vec![(2, Availability::Corrupt), (1, Availability::Available)]
        );
        assert!(rest.next.is_none());
        assert!(matches!(
            inventory::source(
                &f.db(),
                f.profile,
                f.binding.clone(),
                &rest.records[0].selection,
                service::MAX_REQUEST,
                budget()
            )
            .unwrap(),
            Source::Unavailable(Availability::Corrupt)
        ));
        assert!(matches!(
            inventory::source(
                &f.db(),
                f.profile,
                f.binding.clone(),
                &rest.records[1].selection,
                service::MAX_REQUEST,
                budget()
            )
            .unwrap(),
            Source::Available { .. }
        ));
        drop(a);
        assert_eq!(std::fs::read(f.db()).unwrap(), damaged);
    }
}

fn legacy_payload_layout(f: &Fixture) {
    f.edit("BEGIN IMMEDIATE;
CREATE TEMP TABLE saved_objects AS SELECT * FROM objects;
DROP TABLE objects;
CREATE TABLE objects(cid TEXT PRIMARY KEY, bytes BLOB NOT NULL CHECK(length(bytes)>0 AND length(bytes)<=4194304)) WITHOUT ROWID;
INSERT INTO objects SELECT * FROM saved_objects;
DROP TABLE saved_objects;
COMMIT;");
}

#[test]
fn legacy_payload_layout_recovers_to_seekable_layout_without_changing_evidence() {
    let temp = tempfile::tempdir().unwrap();
    let f = fixture(temp.path(), Profile::Admitted);
    legacy_payload_layout(&f);
    let old = f.open().page(None, page_budget(), budget()).unwrap();
    let source = attested::Archive::open(&f.root, f.binding.clone()).unwrap();
    source.rebuild_serving_index(&identity(8)).unwrap();
    assert!(
        Inventory::open_indexed(&f.db(), f.profile, f.binding.clone(), None, None, budget())
            .is_err()
    );
    let rebuilt = temp.path().join("rebuilt");
    std::fs::create_dir(&rebuilt).unwrap();
    attested::Recovery::open(&f.db(), f.binding.clone())
        .unwrap()
        .rebuild(&rebuilt.join("archive.sqlite"))
        .unwrap();
    let destination = attested::Archive::open(&rebuilt, f.binding.clone()).unwrap();
    destination.rebuild_serving_index(&identity(8)).unwrap();
    let indexed = Inventory::open_indexed(
        &rebuilt.join("archive.sqlite"),
        f.profile,
        f.binding.clone(),
        None,
        None,
        budget(),
    )
    .unwrap();
    let page = indexed.page(None, page_budget(), budget()).unwrap();
    for (original, recovered) in old.records.iter().zip(&page.records) {
        assert_eq!(
            original.record.manifest.bytes(),
            recovered.record.manifest.bytes()
        );
        assert_eq!(original.proof.bytes(), recovered.proof.bytes());
        assert_eq!(recovered.availability, Availability::Available);
    }
    assert_eq!(source.verify().unwrap(), destination.verify().unwrap());
    assert!(f.open().page(None, page_budget(), budget()).is_ok());
    let conn = rusqlite::Connection::open(rebuilt.join("archive.sqlite")).unwrap();
    let plan: String = conn
        .query_row(
            "EXPLAIN QUERY PLAN SELECT length(bytes) FROM objects WHERE cid=?",
            [f.id(0)],
            |r| r.get(3),
        )
        .unwrap();
    assert!(plan.contains("SEARCH") && !plan.contains("SCAN"), "{plan}");
}

#[test]
fn indexed_inventory_authenticates_selected_prefixes_with_constant_record_budget() {
    let temp = tempfile::tempdir().unwrap();
    let f = fixture(temp.path(), Profile::Admitted);
    let archive = attested::Archive::open(&f.root, f.binding.clone()).unwrap();
    archive.rebuild_serving_index(&identity(8)).unwrap();
    let full = f.open().page(None, page_budget(), budget()).unwrap();
    let older = full.records[1].proof.frontier().clone();
    let mut one = budget();
    one.items = 1;
    assert!(Inventory::open(&f.db(), f.profile, f.binding.clone(), one.clone()).is_err());
    let indexed = Inventory::open_indexed(
        &f.db(),
        f.profile,
        f.binding.clone(),
        Some(&older),
        None,
        one.clone(),
    )
    .unwrap();
    let page = indexed
        .page(
            None,
            PageBudget {
                rows: 1,
                ..page_budget()
            },
            one.clone(),
        )
        .unwrap();
    assert_eq!(page.records[0].record.sequence, 2);
    assert!(page.next.is_some());
    let selected = page.records[0].selection.clone();
    drop(indexed);
    f.edit("UPDATE commits SET receipt=x'00' WHERE sequence=1");
    assert!(Inventory::open(&f.db(), f.profile, f.binding.clone(), budget()).is_err());
    let indexed = Inventory::open_indexed(
        &f.db(),
        f.profile,
        f.binding.clone(),
        Some(&older),
        None,
        one.clone(),
    )
    .unwrap();
    assert!(indexed
        .page(
            None,
            PageBudget {
                rows: 1,
                ..page_budget()
            },
            one.clone()
        )
        .is_ok());
    assert!(indexed
        .page(
            page.next.as_ref(),
            PageBudget {
                rows: 1,
                ..page_budget()
            },
            one.clone()
        )
        .is_err());
    let Source::Available { bytes, .. } = inventory::source(
        &f.db(),
        f.profile,
        f.binding.clone(),
        &selected,
        service::MAX_REQUEST,
        one.clone(),
    )
    .unwrap() else {
        panic!("available selected evidence");
    };
    assert_eq!(bytes, f.requests[1]);
    let mut forged = older.clone();
    forged.manifest = full.records[0].proof.frontier().manifest.clone();
    assert!(Inventory::open_indexed(
        &f.db(),
        f.profile,
        f.binding.clone(),
        Some(&forged),
        None,
        one
    )
    .is_err());
}

#[test]
fn indexed_source_reopens_current_bytes_and_erasure_custody() {
    let temp = tempfile::tempdir().unwrap();
    let f = fixture(temp.path(), Profile::Admitted);
    let mut archive = attested::Archive::open(&f.root, f.binding.clone()).unwrap();
    archive.rebuild_serving_index(&identity(8)).unwrap();
    let indexed =
        Inventory::open_indexed(&f.db(), f.profile, f.binding.clone(), None, None, budget())
            .unwrap();
    let page = indexed.page(None, page_budget(), budget()).unwrap();
    let selected = page.records[1].selection.clone();
    drop(indexed);
    let conn = rusqlite::Connection::open(f.db()).unwrap();
    conn.execute("UPDATE objects SET bytes=x'00' WHERE cid=?", [f.id(1)])
        .unwrap();
    assert!(matches!(
        inventory::source(
            &f.db(),
            f.profile,
            f.binding.clone(),
            &selected,
            service::MAX_REQUEST,
            budget()
        )
        .unwrap(),
        Source::Unavailable(Availability::Corrupt)
    ));
    conn.execute(
        "UPDATE objects SET bytes=? WHERE cid=?",
        rusqlite::params![&f.requests[1], f.id(1)],
    )
    .unwrap();
    let plan = archive
        .preview_erasure(&[2], service::hex(&[90; 32]), 200)
        .unwrap();
    let custody = archive
        .apply_erasure(store::erasure::Record::sign(plan, &identity(8)).unwrap())
        .unwrap();
    assert!(inventory::source(
        &f.db(),
        f.profile,
        f.binding.clone(),
        &selected,
        service::MAX_REQUEST,
        budget()
    )
    .is_err());
    archive
        .refresh_serving_custody(&identity(8), custody.tip.as_deref().unwrap())
        .unwrap();
    assert!(inventory::source(
        &f.db(),
        f.profile,
        f.binding.clone(),
        &selected,
        service::MAX_REQUEST,
        budget()
    )
    .is_err());
    let indexed = Inventory::open_indexed(
        &f.db(),
        f.profile,
        f.binding.clone(),
        None,
        custody.tip.as_deref(),
        budget(),
    )
    .unwrap();
    let page = indexed.page(None, page_budget(), budget()).unwrap();
    assert_eq!(page.records[1].availability, Availability::Erased);
    assert!(matches!(
        inventory::source(
            &f.db(),
            f.profile,
            f.binding.clone(),
            &page.records[1].selection,
            service::MAX_REQUEST,
            budget()
        )
        .unwrap(),
        Source::Unavailable(Availability::Erased)
    ));
    assert_eq!(page.records[0].availability, Availability::Available);
}

#[test]
fn copied_index_tracks_resumable_recipe_prefix_native_append_and_erasure() {
    let temp = tempfile::tempdir().unwrap();
    let complete = fixture(temp.path(), Profile::Copied);
    let source = PlannedCopy::open(
        &temp.path().join("legacy/archive.sqlite"),
        Target {
            scope: [1; 32],
            issuer: identity(8).did().to_string(),
        },
        identity(7).did().to_string(),
        [9; 32],
    )
    .unwrap();
    let f = Fixture {
        root: temp.path().join("indexed-copy"),
        binding: complete.binding.clone(),
        requests: complete.requests.clone(),
        profile: Profile::Copied,
    };
    let mut archive = copied::Archive::create(&f.root, &source, f.binding.clone()).unwrap();
    archive.rebuild_serving_index(&identity(8)).unwrap();
    let mut small = budget();
    small.items = 2;
    let open = |tip: Option<&str>| {
        Inventory::open_indexed(
            &f.db(),
            f.profile,
            f.binding.clone(),
            None,
            tip,
            small.clone(),
        )
        .unwrap()
    };
    assert_eq!(open(None).recipe_metadata_match(), Some(false));
    let first = archive
        .copy_batch(
            &source,
            &identity(8),
            1000,
            copied::Budget {
                objects: 100,
                records: 1,
                bytes: 16 * 1024 * 1024,
            },
        )
        .unwrap();
    assert!(!first.status.source_copy_complete);
    let partial = open(None);
    assert_eq!(partial.frontier().through, 1);
    assert_eq!(partial.recipe_metadata_match(), Some(false));
    assert!(archive
        .admit_indexed(&request(3, 8, None), &identity(8), &grant(), 200, None)
        .is_err());
    let old_pin = partial.frontier().clone();
    drop(partial);
    drop(archive);
    let mut archive = copied::Archive::open(&f.root, f.binding.clone()).unwrap();
    assert!(
        archive
            .copy_batch(
                &source,
                &identity(8),
                1001,
                copied::Budget {
                    objects: 100,
                    records: 100,
                    bytes: 16 * 1024 * 1024
                }
            )
            .unwrap()
            .status
            .source_copy_complete
    );
    let indexed = open(None);
    assert_eq!(indexed.frontier().through, 3);
    assert_eq!(indexed.recipe_metadata_match(), Some(true));
    assert_eq!(
        Inventory::open_indexed(
            &f.db(),
            f.profile,
            f.binding.clone(),
            Some(&old_pin),
            None,
            small.clone()
        )
        .unwrap()
        .recipe_metadata_match(),
        Some(false)
    );
    let prev = indexed.frontier().manifest.as_ref().unwrap().to_string();
    drop(indexed);
    drop(archive);
    let mut archive = copied::Archive::open_indexed(&f.root, f.binding.clone(), None).unwrap();
    archive
        .admit_indexed(
            &request(3, 8, Some(prev)),
            &identity(8),
            &grant(),
            200,
            None,
        )
        .unwrap();
    let indexed = open(None);
    assert_eq!(indexed.frontier().through, 4);
    let page = indexed
        .page(
            None,
            PageBudget {
                rows: 2,
                ..page_budget()
            },
            small.clone(),
        )
        .unwrap();
    assert_eq!(
        page.records[0].proof.purpose(),
        kan::evidence_attestation::Purpose::Admitted
    );
    assert_eq!(
        page.records[1].proof.purpose(),
        kan::evidence_attestation::Purpose::RetainedVerified
    );
    let selected = page.records[1].selection.clone();
    drop(indexed);
    assert!(matches!(
        inventory::source(
            &f.db(),
            f.profile,
            f.binding.clone(),
            &selected,
            service::MAX_REQUEST,
            small.clone()
        )
        .unwrap(),
        Source::Available { .. }
    ));
    let plan = archive
        .preview_erasure(&[3], service::hex(&[91; 32]), 2000)
        .unwrap();
    let custody = archive
        .apply_erasure(store::erasure::Record::sign(plan, &identity(8)).unwrap())
        .unwrap();
    archive
        .refresh_serving_custody(&identity(8), custody.tip.as_deref().unwrap())
        .unwrap();
    let indexed = open(custody.tip.as_deref());
    assert_eq!(indexed.recipe_metadata_match(), Some(true));
    let page = indexed
        .page(
            None,
            PageBudget {
                rows: 2,
                ..page_budget()
            },
            small.clone(),
        )
        .unwrap();
    assert_eq!(page.records[1].availability, Availability::Erased);
    let previous = page.records[0].record.manifest.cid().to_string();
    drop(indexed);
    f.edit("UPDATE commits SET receipt=x'00' WHERE sequence=1");
    assert!(copied::Archive::open(&f.root, f.binding.clone()).is_err());
    let mut bounded =
        copied::Archive::open_indexed(&f.root, f.binding.clone(), custody.tip.as_deref()).unwrap();
    bounded
        .admit_indexed(
            &request(4, 8, Some(previous)),
            &identity(8),
            &grant(),
            2001,
            custody.tip.as_deref(),
        )
        .unwrap();
    assert_eq!(open(custody.tip.as_deref()).frontier().through, 5);
    f.edit("UPDATE upgrade_plan SET envelope=x'00' WHERE singleton=1");
    assert!(Inventory::open_indexed(
        &f.db(),
        f.profile,
        f.binding.clone(),
        None,
        custody.tip.as_deref(),
        budget()
    )
    .is_err());
}
