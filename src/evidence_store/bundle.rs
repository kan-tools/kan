//! Owner-pinned, bounded read-only acquisition of a KNB1 recovery bundle.
//! Successful inspection authenticates retained history, not a current output
//! file, durable mutation, or writer activation. No standalone fallback exists.
use super::{private_file, same_existing_file, sqlite_paths, Connection, Path, PathBuf};
use crate::{
    evidence_recovery_commitment::Limits,
    evidence_recovery_member::{Input, Membership, Object, Row},
    evidence_recovery_observation::Context,
    evidence_recovery_replay::{self as replay, Checkpoint, Replay},
};
use atproto_dasl::Cid;
use rusqlite::types::ValueRef;
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

mod create;
pub use create::{create, create_observed, Creation, CreationBoundary, CreationError};

const SCHEMA: &str = include_str!("bundle.sql");
const APPLICATION_ID: i64 = 0x4b4e4231;
const MAX_SAFE: i64 = 9007199254740991;
const MAX_OBJECT: usize = 4194304;

type Result<T> = std::result::Result<T, Error>;
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Store(#[from] super::Error),
    /// Preserve SQLite's refusal code. TooBig and DatabaseCorrupt are physical
    /// format refusals; READONLY_ROLLBACK (776) refuses a hot source journal.
    /// None is missing evidence. Busy/I/O failures remain distinct SQLite codes
    /// for a later owner-job capability/error mapping.
    #[error(transparent)]
    Sql(#[from] rusqlite::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("invalid recovery bundle: {0}")]
    Invalid(&'static str),
    #[error("recovery bundle acquisition budget exhausted: {0}")]
    Budget(&'static str),
    #[error("recovery bundle inspection cancelled")]
    Cancelled,
    #[error(transparent)]
    Replay(#[from] replay::Error),
}
/// Acquisition limits apply before Rust copies each field. Encoded bytes are
/// not RSS: per-row containers, one bounded SQLite row, caches and replay working
/// state add overhead bounded by item/cell/work limits. No universal size cap.
#[derive(Clone)]
pub struct Budget {
    pub items: u64,
    pub acquired_bytes: u64,
    /// Pre-open sum of the main file and existing SQLite sidecars, not a fence
    /// against later filesystem growth or an exact SQLite heap ceiling.
    pub source_bytes: u64,
    pub replay_items: u64,
    pub replay_scan_bytes: u64,
    /// Includes acquisition and replay; cannot preempt arbitrary filesystem I/O.
    pub duration: Duration,
    pub cancelled: Arc<AtomicBool>,
}
pub struct Inspection {
    source: PathBuf,
    replay: Replay,
    acquired_bytes: u64,
    items: u64,
}
impl Inspection {
    /// Routing information only; a path may change after this snapshot closes.
    pub fn source(&self) -> &Path {
        &self.source
    }
    pub fn replay(&self) -> &Replay {
        &self.replay
    }
    pub fn acquired_bytes(&self) -> u64 {
        self.acquired_bytes
    }
    pub fn items(&self) -> u64 {
        self.items
    }
}
struct Work {
    budget: Budget,
    deadline: Instant,
    items: u64,
    bytes: u64,
}
impl Work {
    fn check(&self) -> Result<()> {
        if self.budget.cancelled.load(Ordering::Relaxed) {
            return Err(Error::Cancelled);
        }
        if Instant::now() >= self.deadline {
            return Err(Error::Budget("duration"));
        }
        Ok(())
    }
    fn charge(&mut self, items: u64, bytes: usize) -> Result<()> {
        self.check()?;
        self.items = self
            .items
            .checked_add(items)
            .ok_or(Error::Budget("items"))?;
        self.bytes = self
            .bytes
            .checked_add(bytes as u64)
            .ok_or(Error::Budget("acquired bytes"))?;
        if self.items > self.budget.items {
            return Err(Error::Budget("items"));
        }
        if self.bytes > self.budget.acquired_bytes {
            return Err(Error::Budget("acquired bytes"));
        }
        Ok(())
    }
}
fn require(ok: bool, why: &'static str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(Error::Invalid(why))
    }
}
fn integer(row: &rusqlite::Row<'_>, col: usize, min: i64, max: i64) -> Result<u64> {
    match row.get_ref(col)? {
        ValueRef::Integer(n) if (min..=max).contains(&n) => Ok(n as u64),
        _ => Err(Error::Invalid("integer storage class or bounds")),
    }
}
// Projection triple is typeof(column), length(CAST(column AS BLOB)), bounded
// substr(column...). Check type and full byte length before copying the slice.
fn cell(
    row: &rusqlite::Row<'_>,
    col: usize,
    min: usize,
    max: usize,
    text: bool,
    work: &mut Work,
) -> Result<Vec<u8>> {
    require(
        row.get_ref(col)? == ValueRef::Text(if text { b"text" } else { b"blob" }),
        "cell storage class",
    )?;
    let len = integer(row, col + 1, min as i64, max as i64)? as usize;
    let bytes = match (text, row.get_ref(col + 2)?) {
        (true, ValueRef::Text(b)) | (false, ValueRef::Blob(b)) => b,
        // SQLite substr() can return NULL for an empty BLOB. The original
        // storage class and full byte length were checked above: this does not
        // reinterpret a source NULL, TEXT, or a nonempty failed projection.
        (false, ValueRef::Null) if len == 0 => &[],
        _ => return Err(Error::Invalid("projected cell storage class")),
    };
    require(bytes.len() == len, "cell truncated")?;
    if text {
        require(bytes.is_ascii() && !bytes.contains(&0), "ASCII text")?;
    }
    work.charge(0, len)?;
    Ok(bytes.to_vec())
}
fn cid(row: &rusqlite::Row<'_>, col: usize, work: &mut Work) -> Result<Cid> {
    let b = cell(row, col, 59, 59, true, work)?;
    let text = std::str::from_utf8(&b).map_err(|_| Error::Invalid("CID text"))?;
    let value: Cid = text.parse().map_err(|_| Error::Invalid("CID"))?;
    require(value.to_string() == text, "canonical CID spelling")?;
    let raw = value.to_bytes();
    require(
        raw.len() == 36 && raw[..4] == [1, 0x55, 0x12, 0x20],
        "raw SHA256 CID",
    )?;
    Ok(value)
}
fn projection(name: &str, max: usize) -> String {
    format!("typeof({name}),length(CAST({name} AS BLOB)),substr({name},1,{max})")
}
fn schema(conn: &Connection, work: &mut Work) -> Result<()> {
    let app: i64 = conn.query_row("PRAGMA application_id", [], |r| r.get(0))?;
    let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    let encoding: String = conn.query_row("PRAGMA encoding", [], |r| r.get(0))?;
    require(app == APPLICATION_ID && version == 1, "bundle profile")?;
    require(encoding == "UTF-8", "bundle encoding")?;
    let expected = Connection::open_in_memory()?;
    expected.execute_batch(SCHEMA)?;
    let query="SELECT substr(type,1,32),length(CAST(type AS BLOB)),substr(name,1,256),length(CAST(name AS BLOB)),substr(tbl_name,1,256),length(CAST(tbl_name AS BLOB)),substr(sql,1,65536),length(CAST(sql AS BLOB)) FROM sqlite_schema ORDER BY type,name";
    let mut actual = conn.prepare(query)?;
    let mut wanted = expected.prepare(query)?;
    let mut a = actual.query([])?;
    let mut e = wanted.query([])?;
    loop {
        work.check()?;
        match (a.next()?, e.next()?) {
            (None, None) => return Ok(()),
            (Some(a), Some(e)) => {
                for c in 0..8 {
                    require(a.get_ref(c)? == e.get_ref(c)?, "bundle schema")?;
                }
            }
            _ => return Err(Error::Invalid("bundle schema")),
        }
    }
}
fn identity(conn: &Connection, context: &Context, work: &mut Work) -> Result<()> {
    let query = format!(
        "SELECT singleton,{},{},profile,{},{},{} FROM bundle_identity",
        projection("bundle", 32),
        projection("observer", 80),
        projection("archive", 32),
        projection("scope", 32),
        projection("issuer", 80)
    );
    let mut stmt = conn.prepare(&query)?;
    let mut rows = stmt.query([])?;
    let row = rows
        .next()?
        .ok_or(Error::Invalid("missing bundle identity"))?;
    work.charge(1, 16)?;
    require(integer(row, 0, 1, 1)? == 1, "identity singleton")?;
    require(
        cell(row, 1, 32, 32, false, work)? == context.bundle,
        "bundle pin",
    )?;
    require(
        cell(row, 4, 56, 80, true, work)? == context.observer.as_bytes(),
        "observer pin",
    )?;
    require(
        integer(row, 7, 2, 3)? == context.profile as u64,
        "profile pin",
    )?;
    require(
        cell(row, 8, 32, 32, false, work)? == context.archive,
        "archive pin",
    )?;
    require(
        cell(row, 11, 32, 32, false, work)? == context.scope,
        "scope pin",
    )?;
    require(
        cell(row, 14, 56, 80, true, work)? == context.issuer.as_bytes(),
        "issuer pin",
    )?;
    require(rows.next()?.is_none(), "identity cardinality")
}
struct EncodedRow {
    sequence: u64,
    manifest: Vec<u8>,
    receipt: Vec<u8>,
    proof: Vec<u8>,
}
fn objects(
    conn: &Connection,
    table: &str,
    min: usize,
    work: &mut Work,
) -> Result<Vec<(Cid, Vec<u8>)>> {
    let query = format!(
        "SELECT {},{} FROM {table} NOT INDEXED ORDER BY cid",
        projection("cid", 59),
        projection("bytes", MAX_OBJECT)
    );
    let mut stmt = conn.prepare(&query)?;
    let mut rows = stmt.query([])?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        work.charge(1, 0)?;
        out.push((
            cid(row, 0, work)?,
            cell(row, 3, min, MAX_OBJECT, false, work)?,
        ));
    }
    Ok(out)
}
/// Inspect one pinned SQLite snapshot. The owner must retain checkpoints outside
/// the file. SQLite can initialize WAL/SHM coordination files; main records are
/// never rewritten. A hot journal refuses. No output path or writer is selected.
pub fn inspect(
    path: &Path,
    context: Context,
    checkpoint: Option<&Checkpoint>,
    budget: Budget,
) -> Result<Inspection> {
    inspect_snapshot(path, context, checkpoint, budget, || {})
}
fn inspect_snapshot(
    path: &Path,
    context: Context,
    checkpoint: Option<&Checkpoint>,
    budget: Budget,
    after_identity: impl FnOnce(),
) -> Result<Inspection> {
    require(
        !budget.duration.is_zero() && budget.duration <= Duration::from_secs(3600),
        "duration",
    )?;
    let deadline = Instant::now()
        .checked_add(budget.duration)
        .ok_or(Error::Budget("duration"))?;
    let mut work = Work {
        budget,
        deadline,
        items: 0,
        bytes: 0,
    };
    work.check()?;
    private_file(path)?;
    let source = std::fs::canonicalize(path)?;
    let mut existing: Vec<PathBuf> = Vec::new();
    let mut source_bytes = 0u64;
    for path in sqlite_paths(&source) {
        work.check()?;
        let metadata = match std::fs::symlink_metadata(&path) {
            Ok(meta) => meta,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && path != source => continue,
            Err(e) => return Err(e.into()),
        };
        private_file(&path)?;
        require(
            !existing.iter().any(|p| same_existing_file(p, &path)),
            "aliased SQLite source files",
        )?;
        source_bytes = source_bytes
            .checked_add(metadata.len())
            .ok_or(Error::Budget("source bytes"))?;
        if source_bytes > work.budget.source_bytes {
            return Err(Error::Budget("source bytes"));
        }
        existing.push(path);
    }
    // surface-write: evidence-bundle-source:database-wal,evidence-bundle-source:database-shm
    let conn = crate::persistence::open_sqlite_recovery_source(
        crate::persistence::SurfaceWrite::EvidenceBundleSource,
        &source,
    )?;
    conn.set_limit(
        rusqlite::limits::Limit::SQLITE_LIMIT_LENGTH,
        5 * 1024 * 1024,
    )?;
    conn.busy_timeout(work.budget.duration.min(Duration::from_millis(250)))?;
    let cancel = work.budget.cancelled.clone();
    conn.progress_handler(
        1000,
        Some(move || cancel.load(Ordering::Relaxed) || Instant::now() >= deadline),
    )?;
    let result = (|| {
        conn.execute_batch("PRAGMA query_only=ON; PRAGMA trusted_schema=OFF; PRAGMA cache_size=-4096; PRAGMA mmap_size=0; BEGIN;")?;
        schema(&conn, &mut work)?;
        identity(&conn, &context, &mut work)?;
        after_identity();
        let mut plan = None;
        let query = format!(
            "SELECT singleton,{} FROM member_plan",
            projection("envelope", 4096)
        );
        let mut stmt = conn.prepare(&query)?;
        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            work.charge(1, 8)?;
            integer(row, 0, 1, 1)?;
            require(plan.is_none(), "plan cardinality")?;
            plan = Some(cell(row, 1, 1, 4096, false, &mut work)?);
        }
        let mut membership = Vec::new();
        let query = format!(
            "SELECT {},length FROM member_membership NOT INDEXED ORDER BY cid",
            projection("cid", 59)
        );
        let mut stmt = conn.prepare(&query)?;
        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            work.charge(1, 8)?;
            membership.push((
                cid(row, 0, &mut work)?,
                integer(row, 3, 1, MAX_OBJECT as i64)?,
            ));
        }
        let mut records = Vec::new();
        let query = format!(
            "SELECT sequence,{},{},{} FROM member_records NOT INDEXED ORDER BY sequence",
            projection("manifest", 65536),
            projection("receipt", 65536),
            projection("envelope", 16384)
        );
        let mut stmt = conn.prepare(&query)?;
        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            work.charge(1, 8)?;
            records.push(EncodedRow {
                sequence: integer(row, 0, 1, MAX_SAFE)?,
                manifest: cell(row, 1, 1, 65536, false, &mut work)?,
                receipt: cell(row, 4, 1, 65536, false, &mut work)?,
                proof: cell(row, 7, 1, 16384, false, &mut work)?,
            });
        }
        let original = objects(&conn, "member_objects", 0, &mut work)?;
        let candidates = objects(&conn, "restored_objects", 1, &mut work)?;
        let mut observations = Vec::new();
        let query = format!(
            "SELECT sequence,{} FROM observations NOT INDEXED ORDER BY sequence",
            projection("envelope", 16384)
        );
        let mut stmt = conn.prepare(&query)?;
        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            work.charge(1, 8)?;
            require(
                integer(row, 0, 1, MAX_SAFE)? == observations.len() as u64 + 1,
                "observation coordinate",
            )?;
            observations.push(cell(row, 1, 1, 16384, false, &mut work)?);
        }
        work.check()?;
        let membership: Vec<_> = membership
            .iter()
            .map(|(cid, length)| Membership {
                cid,
                length: *length,
            })
            .collect();
        let records: Vec<_> = records
            .iter()
            .map(|r| Row {
                sequence: r.sequence,
                manifest: &r.manifest,
                receipt: &r.receipt,
                proof: &r.proof,
            })
            .collect();
        let original: Vec<_> = original
            .iter()
            .map(|(cid, bytes)| Object { cid, bytes })
            .collect();
        let candidates: Vec<_> = candidates
            .iter()
            .map(|(cid, bytes)| Object { cid, bytes })
            .collect();
        let observations: Vec<_> = observations.iter().map(Vec::as_slice).collect();
        let input = Input {
            context: &context,
            plan: plan.as_deref(),
            membership: &membership,
            records: &records,
            objects: &original,
        };
        let limits = Limits {
            items: work.budget.replay_items,
            bytes: work.budget.replay_scan_bytes,
            duration: deadline.saturating_duration_since(Instant::now()),
            cancelled: work.budget.cancelled.clone(),
        };
        let replay = replay::verify(input, &candidates, &observations, checkpoint, limits)?;
        work.check()?;
        Ok(Inspection {
            source,
            replay,
            acquired_bytes: work.bytes,
            items: work.items,
        })
    })();
    // Normalize VM interruption after deadline/cancellation; do not conceal an
    // independent schema/data error when neither condition has occurred.
    work.check()?;
    result
}

#[cfg(test)]
mod snapshot_tests {
    use super::*;
    #[test]
    fn empty_blob_projection_does_not_admit_source_null_text_or_empty_candidates() {
        let conn = Connection::open_in_memory().unwrap();
        let mut work = Work {
            budget: Budget {
                items: 10,
                acquired_bytes: 10,
                source_bytes: 1000,
                replay_items: 10,
                replay_scan_bytes: 1000,
                duration: Duration::from_secs(10),
                cancelled: Arc::new(AtomicBool::new(false)),
            },
            deadline: Instant::now() + Duration::from_secs(10),
            items: 0,
            bytes: 0,
        };
        for (value, min, accept) in [
            (rusqlite::types::Value::Blob(vec![]), 0, true),
            (rusqlite::types::Value::Null, 0, false),
            (rusqlite::types::Value::Text(String::new()), 0, false),
            (rusqlite::types::Value::Blob(vec![]), 1, false),
        ] {
            let mut stmt = conn
                .prepare("SELECT typeof(?1),length(CAST(?1 AS BLOB)),substr(?1,1,4194304)")
                .unwrap();
            let mut rows = stmt.query([value]).unwrap();
            let result = cell(
                rows.next().unwrap().unwrap(),
                0,
                min,
                MAX_OBJECT,
                false,
                &mut work,
            );
            assert_eq!(result.is_ok(), accept);
            if accept {
                assert_eq!(result.unwrap(), Vec::<u8>::new());
            }
        }
    }
    fn fixture() -> (tempfile::TempDir, PathBuf, Context, Budget) {
        let dir = tempfile::tempdir().unwrap();
        let name = "profile2-restored-failure-observed";
        let out = std::process::Command::new(
            std::env::var_os("KAN_TLS_ORACLE_PYTHON").unwrap_or_else(|| "python3".into()),
        )
        .args([
            ".design/tools/recovery_bundle_files.py",
            dir.path().to_str().unwrap(),
            "--case",
            name,
        ])
        .output()
        .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let values: serde_json::Value = serde_json::from_str(include_str!(
            "../../.design/fixtures/recovery-replay-v1.json"
        ))
        .unwrap();
        let value = values["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|v| v["name"] == name)
            .unwrap();
        let c = &value["member"]["context"];
        let bytes = |name: &str| {
            crate::evidence_service::unhex(c[name].as_str().unwrap(), 32)
                .unwrap()
                .try_into()
                .unwrap()
        };
        let context = Context {
            bundle: bytes("bundle"),
            profile: 2,
            archive: bytes("archive"),
            scope: bytes("scope"),
            issuer: c["issuer"].as_str().unwrap().into(),
            observer: c["observer"].as_str().unwrap().into(),
        };
        let budget = Budget {
            items: 10000,
            acquired_bytes: 32 * 1024 * 1024,
            source_bytes: 64 * 1024 * 1024,
            replay_items: 10000,
            replay_scan_bytes: 128 * 1024 * 1024,
            duration: Duration::from_secs(10),
            cancelled: Arc::new(AtomicBool::new(false)),
        };
        let path = dir.path().join(format!("{name}.sqlite"));
        (dir, path, context, budget)
    }
    #[test]
    fn later_wal_changes_cannot_mix_into_the_pinned_snapshot() {
        let (_dir, path, context, budget) = fixture();
        let writer = Connection::open(&path).unwrap();
        writer.execute_batch("PRAGMA journal_mode=WAL;").unwrap();
        let inspected = inspect_snapshot(&path, context.clone(), None, budget.clone(), || {
            writer
                .execute("INSERT INTO observations VALUES(8,?)", [vec![0u8]])
                .unwrap();
        })
        .unwrap();
        assert_eq!(inspected.replay().latest().sequence, 7);
        assert!(inspect(&path, context, None, budget).is_err());
    }
    #[test]
    fn cancellation_after_identity_stops_before_replay() {
        let (_dir, path, context, budget) = fixture();
        let cancel = budget.cancelled.clone();
        let result = inspect_snapshot(&path, context, None, budget, || {
            cancel.store(true, Ordering::Relaxed)
        });
        assert!(matches!(result, Err(Error::Cancelled)));
    }
}
