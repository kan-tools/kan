#![cfg(feature = "v2-crypto")]
//! Reviewer probe: is the overview's memory accounting conservative for the
//! Rust heap? A counting global allocator measures peak live bytes during build.
//! SQLite's own allocator is not counted (covered by the design's 16 MiB reserve).
use kan::{
    evidence_capture::{Health, Observer, Outcome},
    evidence_operations::Journal,
    evidence_operations_collection::{
        self as collection,
        overview::{self, Failure, Limits},
    },
    evidence_spool::Spool,
    sign::Identity,
};
use std::{
    alloc::{GlobalAlloc, Layout, System},
    path::Path,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};

struct Counting;
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        let p = unsafe { System.alloc(l) };
        if !p.is_null() {
            let now = LIVE.fetch_add(l.size(), Ordering::Relaxed) + l.size();
            PEAK.fetch_max(now, Ordering::Relaxed);
        }
        p
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        unsafe { System.dealloc(p, l) };
        LIVE.fetch_sub(l.size(), Ordering::Relaxed);
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, new: usize) -> *mut u8 {
        let q = unsafe { System.realloc(p, l, new) };
        if !q.is_null() {
            if new >= l.size() {
                let now = LIVE.fetch_add(new - l.size(), Ordering::Relaxed) + new - l.size();
                PEAK.fetch_max(now, Ordering::Relaxed);
            } else {
                LIVE.fetch_sub(l.size() - new, Ordering::Relaxed);
            }
        }
        q
    }
}
#[global_allocator]
static A: Counting = Counting;

fn h(attempt: u64, n: u64) -> Health {
    Health {
        attempt: format!("{attempt:064x}"),
        observer: Observer::Collector,
        observed: n,
        locally_queued: n - 1,
        unconfirmed: 1,
        recording_gap: true,
        remote_acknowledged: false,
        status: Some(200),
        outcome: Some(Outcome::Completed),
    }
}
fn bulk(path: &Path, start: u64, n: u64, obs: u64) {
    let mut c = rusqlite::Connection::open(path).unwrap();
    let tx = c.transaction().unwrap();
    {
        let mut ins = tx
            .prepare("INSERT INTO attempts VALUES(?,?,?,?,?,?)")
            .unwrap();
        for i in start..start + n {
            let x = h(i, obs);
            ins.execute(rusqlite::params![
                x.attempt,
                1i64,
                obs as i64,
                (obs - 1) as i64,
                1i64,
                serde_json::to_string(&x).unwrap()
            ])
            .unwrap();
        }
        let mut s = tx.prepare("INSERT INTO sessions VALUES(?,1,?,0)").unwrap();
        for i in 0..1000u64 {
            s.execute(rusqlite::params![format!("session-{i}"), obs as i64])
                .unwrap();
        }
    }
    tx.commit().unwrap();
}
fn active(root: &Path) -> std::path::PathBuf {
    root.join(format!(
        "generation-{}.sqlite",
        collection::generations(root, 0, 100).unwrap().active
    ))
}

#[test]
fn pm1_rust_heap_peak_stays_within_accounted_and_configured_bounds() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("health");
    let root = dir.path().join("collection");
    let spool = dir.path().join("queue");
    let id = Identity::generate();
    Spool::create(&spool, &format!("{:064x}", 3), id.did().as_str(), id.did().as_str(), 1 << 20)
        .unwrap();
    drop(Journal::create(&source, &spool).unwrap());
    bulk(&source, 0, 30_000, 2);
    collection::adopt(&source, &root).unwrap();
    bulk(&active(&root), 15_000, 30_000, 3);
    collection::rotate(&root).unwrap();
    bulk(&active(&root), 30_000, 40_000, 4);
    // Distinct attempts: 0..70_000. Sessions: 1000 (deduplicated).
    let mut report = Vec::new();
    let mut violations = Vec::new();
    for limit in [None, Some(24usize << 20), Some(32 << 20), Some(48 << 20), Some(64 << 20)] {
        let limits = limit.map_or_else(Limits::default, |bytes| Limits {
            bytes,
            ..Limits::default()
        });
        let base = LIVE.load(Ordering::Relaxed);
        PEAK.store(base, Ordering::Relaxed);
        let r = overview::build(&root, &AtomicBool::new(false), limits);
        let peak = PEAK.load(Ordering::Relaxed) - base;
        let outcome = match &r {
            Ok(o) => {
                assert_eq!(o.totals.attempts, 70_000);
                assert_eq!(o.totals.sessions, 1000);
                format!("ok accounted={} (rows={})", o.accounted_bytes, o.accounted_bytes - (16 << 20))
            }
            Err(e) => format!(
                "err {:?}",
                e.downcast_ref::<Failure>().map(|f| f.to_string())
            ),
        };
        let line = format!("limit={} peak_rust_heap_delta={peak} {outcome}", limits.bytes);
        eprintln!("PM1 {line}");
        report.push(line.clone());
        if peak > limits.bytes {
            violations.push(format!("peak exceeds configured limit: {line}"));
        }
        if let Ok(o) = &r {
            if peak > o.accounted_bytes {
                violations.push(format!("peak exceeds accounted bytes: {line}"));
            }
        }
    }
    assert!(violations.is_empty(), "{violations:#?}\n{report:#?}");
}
