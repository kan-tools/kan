//! Private operational observations. Never an evidence-completeness certificate.
pub(crate) mod projection;
use crate::{
    evidence_capture::Health,
    evidence_delivery,
    evidence_spool::{Spool, Status},
};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    hash::{Hash, Hasher},
    path::Path,
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        mpsc, Arc, Mutex,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
const PROFILE: i64 = 0x4b4f5001;
const SCHEMA: &str = "
PRAGMA application_id=1263489025;
PRAGMA user_version=1;
CREATE TABLE binding(singleton INTEGER PRIMARY KEY CHECK(singleton=1), spool TEXT NOT NULL, writer TEXT NOT NULL, scope TEXT NOT NULL, audience TEXT NOT NULL);
CREATE TABLE attempts(attempt TEXT PRIMARY KEY, updated INTEGER NOT NULL, observed INTEGER NOT NULL, queued INTEGER NOT NULL, unconfirmed INTEGER NOT NULL, body TEXT NOT NULL);
CREATE TABLE sessions(id TEXT PRIMARY KEY, updated INTEGER NOT NULL, dropped INTEGER NOT NULL, clean INTEGER NOT NULL);
CREATE TABLE worker(singleton INTEGER PRIMARY KEY CHECK(singleton=1), body TEXT NOT NULL);
";
const CAPACITY_SCHEMA: &str = "
PRAGMA user_version=2;
CREATE TABLE control(singleton INTEGER PRIMARY KEY CHECK(singleton=1), last_success INTEGER NOT NULL, exhausted INTEGER NOT NULL, reason TEXT NOT NULL);
CREATE TABLE reserve(id INTEGER PRIMARY KEY, bytes BLOB NOT NULL);
";
const ATTEMPT_LIMIT: u64 = 100_000;
const SESSION_LIMIT: u64 = 1024;
#[derive(Debug, thiserror::Error)]
#[error("operations capacity exhausted: {0}")]
struct CapacityLimit(&'static str);
#[derive(Debug, Serialize, Deserialize)]
pub struct JournalCapacity {
    pub schema: u8,
    pub pages_used: u64,
    pub pages_limit: u64,
    pub free_pages: u64,
    pub page_size: u64,
    pub attempts_used: u64,
    pub attempts_limit: u64,
    pub sessions_used: u64,
    pub sessions_limit: Option<u64>,
    pub reserve_bytes: u64,
    pub exhausted_observed: Option<bool>,
    pub exhaustion_reason: Option<String>,
    pub last_success_at: Option<u64>,
    pub loss_count_certainty: String,
    pub scope: String,
}
fn successful(conn: &Connection, schema: u8) -> Result<()> {
    if schema == 2 {
        conn.execute(
            "UPDATE control SET last_success=? WHERE singleton=1",
            [now() as i64],
        )?;
    }
    Ok(())
}
pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
fn invalid() -> Box<dyn std::error::Error + Send + Sync> {
    "operations journal unavailable or invalid".into()
}
fn unsigned(r: &rusqlite::Row<'_>, i: usize) -> rusqlite::Result<u64> {
    let n: i64 = r.get(i)?;
    u64::try_from(n).map_err(|_| rusqlite::Error::IntegralValueOutOfRange(i, n))
}
pub struct Journal {
    conn: Connection,
    schema: u8,
    read_only: bool,
    _file_lock: std::fs::File,
    pub(crate) collection_lock: Option<std::fs::File>,
    pub(crate) scope: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerStatus {
    pub sampled_at: u64,
    pub state: String,
    pub queue: Option<Status>,
    pub nonempty_since: Option<u64>,
    pub last_ack_at: Option<u64>,
    pub last_ack_position: Option<u64>,
    pub consecutive_failures: u32,
    pub retry_seconds: u64,
    #[serde(default)]
    pub telemetry_failures: u64,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct Snapshot {
    pub version: u8,
    pub read_at: u64,
    pub coverage: String,
    pub worker: Option<WorkerStatus>,
    pub attempts: u64,
    pub observed: u64,
    pub locally_queued: u64,
    pub unconfirmed: u64,
    pub telemetry_dropped: u64,
    pub unclosed_sessions: u64,
    pub recent: Vec<serde_json::Value>,
    pub reporters: Vec<serde_json::Value>,
    pub journal: JournalCapacity,
}
impl Journal {
    pub fn create(path: &Path, spool_path: &Path) -> Result<Self> {
        let st = Spool::open(spool_path)?.status()?;
        let spool = spool_path.canonicalize()?;
        for suffix in ["-journal", "-wal", "-shm", ".lock"] {
            let mut name = path.as_os_str().to_os_string();
            name.push(suffix);
            match std::fs::symlink_metadata(Path::new(&name)) {
                Ok(_) => return Err(invalid()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
        }
        // surface-write: evidence-operations:database
        crate::persistence::write_new_owner_only(
            crate::persistence::SurfaceWrite::EvidenceOperations,
            path,
            &[],
        )?;
        let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
        conn.execute_batch("PRAGMA synchronous=FULL; PRAGMA fullfsync=ON; PRAGMA journal_mode=DELETE; PRAGMA max_page_count=8192;")?;
        conn.execute_batch(SCHEMA)?;
        conn.execute_batch(CAPACITY_SCHEMA)?;
        let initialization = conn.unchecked_transaction()?;
        initialization.execute("INSERT INTO control VALUES(1,0,0,'')", [])?;
        for i in 0..64 {
            initialization.execute("INSERT INTO reserve VALUES(?,zeroblob(4096))", [i])?;
        }
        initialization.execute(
            "INSERT INTO binding VALUES(1,?,?,?,?)",
            params![
                spool.to_str().ok_or_else(invalid)?,
                st.writer,
                st.scope,
                st.audience
            ],
        )?;
        initialization.commit()?;
        std::fs::File::open(
            path.parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new(".")),
        )?
        .sync_all()?;
        Self::open_file(path, false, false)
    }
    pub fn open(path: &Path) -> Result<Self> {
        let meta = std::fs::symlink_metadata(path)?;
        if meta.file_type().is_symlink() {
            return Err(invalid());
        }
        if meta.is_dir() {
            return crate::evidence_operations_collection::open(path);
        }
        crate::evidence_operations_collection::check_standalone(path)?;
        Self::open_file(path, false, false)
    }
    pub(crate) fn open_file(path: &Path, exclusive: bool, read_only: bool) -> Result<Self> {
        let meta = std::fs::symlink_metadata(path)?;
        if !meta.is_file() || meta.file_type().is_symlink() || meta.len() > 32 * 1024 * 1024 {
            return Err(invalid());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            if meta.permissions().mode() & 0o077 != 0 || meta.nlink() != 1 {
                return Err(invalid());
            }
        }
        // This profile owns rollback-journal files only. A WAL-mode header can
        // make even read-only SQLite access create -wal/-shm files, and copied
        // WAL headers cannot serve as standalone sealed history. Refuse before
        // SQLite opens the file; do not repair or rewrite an existing journal.
        let mut header = [0u8; 20];
        std::io::Read::read_exact(&mut std::fs::File::open(path)?, &mut header)?;
        if &header[..16] != b"SQLite format 3\0" || header[18..20] != [1, 1] {
            return Err(invalid());
        }
        // flock and SQLite fcntl locks can interact on macOS. Lifetime
        // maintenance coordination must use a separate inode.
        let mut lock_name = path.as_os_str().to_os_string();
        lock_name.push(".lock");
        let lock_path = Path::new(&lock_name);
        match std::fs::symlink_metadata(lock_path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // surface-write: evidence-operations:database-lock
                match crate::persistence::write_new_owner_only(
                    crate::persistence::SurfaceWrite::EvidenceOperations,
                    lock_path,
                    &[],
                ) {
                    Ok(()) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(e) => return Err(e.into()),
                }
            }
            Err(e) => return Err(e.into()),
            Ok(_) => {}
        }
        let lock_meta = std::fs::symlink_metadata(lock_path)?;
        if !lock_meta.is_file() || lock_meta.file_type().is_symlink() || lock_meta.len() != 0 {
            return Err(invalid());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            if lock_meta.permissions().mode() & 0o077 != 0 || lock_meta.nlink() != 1 {
                return Err(invalid());
            }
        }
        let file_lock = std::fs::File::open(lock_path)?;
        if exclusive {
            fs4::FileExt::try_lock(&file_lock).map_err(|_| invalid())?;
        } else {
            fs4::FileExt::try_lock_shared(&file_lock).map_err(|_| invalid())?;
        }
        let conn = Connection::open_with_flags(
            path,
            if read_only {
                OpenFlags::SQLITE_OPEN_READ_ONLY
            } else {
                OpenFlags::SQLITE_OPEN_READ_WRITE
            },
        )?;
        conn.busy_timeout(Duration::from_millis(100))?;
        conn.set_limit(rusqlite::limits::Limit::SQLITE_LIMIT_LENGTH, 32768)?;
        let schema_version: u8 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        if conn.query_row("PRAGMA application_id", [], |r| r.get::<_, i64>(0))? != PROFILE
            || !matches!(schema_version, 1 | 2)
        {
            return Err(invalid());
        }
        if !read_only {
            conn.execute_batch(
                "PRAGMA synchronous=FULL; PRAGMA fullfsync=ON; PRAGMA max_page_count=8192;",
            )?;
        }
        if conn.query_row("PRAGMA page_size", [], |r| r.get::<_, i64>(0))? != 4096 {
            return Err(invalid());
        }
        let expected = Connection::open_in_memory()?;
        expected.execute_batch(SCHEMA)?;
        if schema_version == 2 {
            expected.execute_batch(CAPACITY_SCHEMA)?;
        }
        fn schema(c: &Connection) -> rusqlite::Result<Vec<(String, String)>> {
            c.prepare("SELECT name,coalesce(sql,'') FROM sqlite_schema ORDER BY name")?
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
                .collect()
        }
        if schema(&conn)? != schema(&expected)? {
            return Err(invalid());
        }
        if schema_version == 2 {
            let (rows, exhausted, reason, reserved, valid): (i64,i64,String,u64,u64) = conn.query_row(
                "SELECT count(*),exhausted,reason,(SELECT count(*) FROM reserve),(SELECT coalesce(sum(id>=0 AND id<64 AND length(bytes)=4096),0) FROM reserve) FROM control WHERE singleton=1",
                [], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,unsigned(r,3)?,unsigned(r,4)?)),
            )?;
            if rows != 1
                || (exhausted == 0 && (!reason.is_empty() || reserved != 64 || valid != 64))
                || (exhausted == 1
                    && match reason.as_str() {
                        "session_limit" => !(reserved == 0 || (reserved == 64 && valid == 64)),
                        "sqlite_full" | "attempt_limit" => reserved != 0,
                        _ => true,
                    })
                || !matches!(exhausted, 0 | 1)
            {
                return Err(invalid());
            }
        }
        Ok(Self {
            conn,
            schema: schema_version,
            read_only,
            _file_lock: file_lock,
            collection_lock: None,
            scope: "selected standalone journal only".into(),
        })
    }
    pub(crate) fn binding(&self) -> Result<(String, String, String, String)> {
        Ok(self.conn.query_row(
            "SELECT spool,writer,scope,audience FROM binding WHERE singleton=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )?)
    }
    pub(crate) fn frozen_bytes(&mut self, path: &Path) -> Result<Vec<u8>> {
        let tx = self
            .conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Exclusive)?;
        let bytes = std::fs::read(path)?;
        tx.commit()?;
        Ok(bytes)
    }
    pub(crate) fn seed_worker(&mut self, old: &Journal) -> Result<()> {
        let body: Option<String> = old
            .conn
            .query_row("SELECT body FROM worker WHERE singleton=1", [], |r| {
                r.get(0)
            })
            .optional()?;
        if let Some(body) = body {
            let checked: WorkerCheckpoint = serde_json::from_str(&body)?;
            if let Some(queue) = &checked.status.queue {
                self.check_queue(queue)?;
            }
            self.conn
                .execute("INSERT INTO worker VALUES(1,?)", [body])?;
        }
        Ok(())
    }
    pub fn check_binding(&self, spool: &Path, writer: Option<&str>) -> Result<()> {
        let (stored, owner): (String, String) = self.conn.query_row(
            "SELECT spool,writer FROM binding WHERE singleton=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        let selected = match spool.canonicalize() {
            Ok(path) => path,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => spool
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new("."))
                .canonicalize()?
                .join(spool.file_name().ok_or_else(invalid)?),
            Err(e) => return Err(e.into()),
        };
        if selected.to_str() != Some(&stored) || writer.is_some_and(|w| w != owner) {
            return Err(invalid());
        }
        Ok(())
    }
    fn check_queue(&self, status: &Status) -> Result<()> {
        let bound: (String, String, String) = self.conn.query_row(
            "SELECT writer,scope,audience FROM binding WHERE singleton=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )?;
        if bound
            != (
                status.writer.clone(),
                status.scope.clone(),
                status.audience.clone(),
            )
        {
            return Err(invalid());
        }
        Ok(())
    }
    // A finite reserve preserves the exhaustion observation; it cannot make a
    // failed whole-device write durable. Failed markers leave freshness unknown.
    fn note_capacity_failure<T>(&mut self, result: &Result<T>) {
        if self.schema != 2 {
            return;
        }
        let reason = result.as_ref().err().and_then(|e| {
            if let Some(limit) = e.downcast_ref::<CapacityLimit>() { Some(limit.0) }
            else if e.downcast_ref::<rusqlite::Error>().is_some_and(|e| matches!(e, rusqlite::Error::SqliteFailure(code, _) if code.code == rusqlite::ErrorCode::DiskFull)) { Some("sqlite_full") }
            else { None }
        });
        if let Some(reason) = reason.filter(|reason| *reason != "sealed_for_capacity") {
            let mark = || -> Result<()> {
                let tx = self.conn.unchecked_transaction()?;
                let (exhausted, prior): (bool, String) = tx.query_row(
                    "SELECT exhausted,reason FROM control WHERE singleton=1",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )?;
                // Session exhaustion is a sticky coverage warning. Escalate it
                // when attempt/page capacity also fails, but never fsync an
                // unchanged exhaustion observation on every refused update.
                if exhausted
                    && !(prior == "session_limit"
                        && matches!(reason, "attempt_limit" | "sqlite_full"))
                {
                    return Ok(());
                }
                if reason != "session_limit" {
                    tx.execute("DELETE FROM reserve", [])?;
                }
                tx.execute(
                    "UPDATE control SET exhausted=1, reason=? WHERE singleton=1",
                    [reason],
                )?;
                tx.commit()?;
                Ok(())
            };
            let _ = mark(); // The original write failure remains the caller's result.
        }
    }
    pub fn record(&mut self, h: &Health) -> Result<()> {
        let result = self.record_inner(h);
        self.note_capacity_failure(&result);
        result
    }
    fn record_inner(&mut self, h: &Health) -> Result<()> {
        if !valid_health(h) {
            return Err(invalid());
        }
        let tx = self.conn.transaction()?;
        if self.schema == 2 {
            let (exhausted, reason): (bool, String) = tx.query_row(
                "SELECT exhausted,reason FROM control WHERE singleton=1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?;
            if exhausted && reason != "session_limit" {
                return Err(Box::new(CapacityLimit("sealed_for_capacity")));
            }
        }
        let count = tx.query_row("SELECT count(*) FROM attempts", [], |r| unsigned(r, 0))?;
        let old: Option<String> = tx
            .query_row(
                "SELECT body FROM attempts WHERE attempt=?",
                [&h.attempt],
                |r| r.get(0),
            )
            .optional()?;
        if old.is_none() && count >= ATTEMPT_LIMIT {
            return Err(Box::new(CapacityLimit("attempt_limit")));
        }
        if let Some(old) = old {
            let old: Health = serde_json::from_str(&old)?;
            if !dominates(h, &old) {
                return Err(invalid());
            }
        }
        tx.execute("INSERT INTO attempts VALUES(?,?,?,?,?,?) ON CONFLICT(attempt) DO UPDATE SET updated=excluded.updated, observed=excluded.observed,queued=excluded.queued,unconfirmed=excluded.unconfirmed,body=excluded.body",params![h.attempt,now() as i64,i64::try_from(h.observed)?,i64::try_from(h.locally_queued)?,i64::try_from(h.unconfirmed)?,serde_json::to_string(h)?])?;
        successful(&tx, self.schema)?;
        tx.commit()?;
        Ok(())
    }
    fn session(&mut self, id: &str, dropped: u64, clean: bool) -> Result<()> {
        let write = || -> Result<()> {
            let tx = rusqlite::Transaction::new_unchecked(
                &self.conn,
                rusqlite::TransactionBehavior::Immediate,
            )?;
            let (count, existing): (u64, bool) = tx.query_row(
                "SELECT count(*),coalesce(sum(id=?),0)>0 FROM sessions",
                [id],
                |r| Ok((unsigned(r, 0)?, r.get(1)?)),
            )?;
            if self.schema == 2 && count >= SESSION_LIMIT && !existing {
                return Err(Box::new(CapacityLimit("session_limit")));
            }
            tx.execute("INSERT INTO sessions VALUES(?,?,?,?) ON CONFLICT(id) DO UPDATE SET updated=excluded.updated,dropped=max(dropped,excluded.dropped),clean=excluded.clean",params![id,now() as i64,i64::try_from(dropped)?,clean])?;
            successful(&tx, self.schema)?;
            tx.commit()?;
            Ok(())
        };
        let result = write();
        self.note_capacity_failure(&result);
        result
    }
    pub fn save_worker(&mut self, status: &WorkerStatus) -> Result<()> {
        let result = self.save_worker_inner(status);
        self.note_capacity_failure(&result);
        result
    }
    fn save_worker_inner(&mut self, status: &WorkerStatus) -> Result<()> {
        if let Some(st) = &status.queue {
            self.check_queue(st)?;
        }
        let tx = self.conn.transaction()?;
        tx.execute("INSERT INTO worker VALUES(1,?) ON CONFLICT(singleton) DO UPDATE SET body=excluded.body",[serde_json::to_string(status)?])?;
        successful(&tx, self.schema)?;
        tx.commit()?;
        Ok(())
    }
    pub fn snapshot(&mut self) -> Result<Snapshot> {
        let tx = self.conn.transaction()?;
        let body: Option<String> = tx
            .query_row("SELECT body FROM worker", [], |r| r.get(0))
            .optional()?;
        let (attempts,observed,locally_queued,unconfirmed)=tx.query_row("SELECT count(*),coalesce(sum(observed),0),coalesce(sum(queued),0),coalesce(sum(unconfirmed),0) FROM attempts",[],|r|Ok((unsigned(r,0)?,unsigned(r,1)?,unsigned(r,2)?,unsigned(r,3)?)))?;
        let (telemetry_dropped, unclosed_sessions) = tx.query_row(
            "SELECT coalesce(sum(dropped),0),coalesce(sum(clean=0),0) FROM sessions",
            [],
            |r| Ok((unsigned(r, 0)?, unsigned(r, 1)?)),
        )?;
        let mut recent = Vec::new();
        {
            let mut query = tx.prepare(
                "SELECT updated,body FROM attempts ORDER BY updated DESC,attempt DESC LIMIT 100",
            )?;
            for row in query.query_map([], |r| Ok((unsigned(r, 0)?, r.get::<_, String>(1)?)))? {
                let (at, body) = row?;
                recent.push(serde_json::json!({"updated_at":at,"capture":serde_json::from_str::<serde_json::Value>(&body)?}));
            }
        }
        let reporters = {
            let mut query=tx.prepare("SELECT updated,dropped,clean FROM sessions ORDER BY updated DESC,id DESC LIMIT 100")?;
            let values=query.query_map([],|r|Ok(serde_json::json!({"updated_at":unsigned(r,0)?,"dropped":unsigned(r,1)?,"clean":r.get::<_,bool>(2)?})))?.collect::<rusqlite::Result<Vec<_>>>()?;
            values
        };
        let (reserve_bytes, exhausted_observed, exhaustion_reason, last_success_at) =
            if self.schema == 2 {
                let (at, full, reason): (u64, bool, String) = tx.query_row(
                    "SELECT last_success,exhausted,reason FROM control WHERE singleton=1",
                    [],
                    |r| Ok((unsigned(r, 0)?, r.get(1)?, r.get(2)?)),
                )?;
                let reserve = tx.query_row(
                    "SELECT coalesce(sum(length(bytes)),0) FROM reserve",
                    [],
                    |r| unsigned(r, 0),
                )?;
                (
                    reserve,
                    Some(full),
                    (!reason.is_empty()).then_some(reason),
                    (at > 0).then_some(at),
                )
            } else {
                (0, None, None, None)
            };
        let journal = JournalCapacity {
            schema: self.schema,
            pages_used: tx.query_row("PRAGMA page_count", [], |r| unsigned(r, 0))?,
            pages_limit: if self.read_only {
                8192
            } else {
                tx.query_row("PRAGMA max_page_count", [], |r| unsigned(r, 0))?
            },
            free_pages: tx.query_row("PRAGMA freelist_count", [], |r| unsigned(r, 0))?,
            page_size: 4096,
            attempts_used: attempts,
            attempts_limit: ATTEMPT_LIMIT,
            sessions_used: tx.query_row("SELECT count(*) FROM sessions", [], |r| unsigned(r, 0))?,
            sessions_limit: (self.schema == 2).then_some(SESSION_LIMIT),
            reserve_bytes,
            exhausted_observed,
            exhaustion_reason,
            last_success_at,
            loss_count_certainty: "lower_bound".into(),
            scope: self.scope.clone(),
        };
        tx.commit()?;
        Ok(Snapshot {
            version: 2,
            read_at: now(),
            coverage: "observations-only; silence does not prove capture completeness".into(),
            worker: body.map(|s| serde_json::from_str(&s)).transpose()?,
            attempts,
            observed,
            locally_queued,
            unconfirmed,
            telemetry_dropped,
            unclosed_sessions,
            recent,
            reporters,
            journal,
        })
    }
}

fn valid_health(h: &Health) -> bool {
    h.attempt.len() == 64
        && h.attempt.bytes().all(|c| c.is_ascii_hexdigit())
        && h.locally_queued.checked_add(h.unconfirmed) == Some(h.observed)
        && h.recording_gap == (h.unconfirmed > 0)
        && !h.remote_acknowledged
}
// Replace with a whole observation, never independently maximize its fields.
pub(crate) fn dominates(new: &Health, old: &Health) -> bool {
    valid_health(new)
        && valid_health(old)
        && new.attempt == old.attempt
        && new.observer == old.observer
        && new.observed >= old.observed
        && new.locally_queued >= old.locally_queued
        && new.unconfirmed >= old.unconfirmed
        && old.status.is_none_or(|s| new.status == Some(s))
        && old.outcome.is_none_or(|o| new.outcome == Some(o))
}
fn reserve_attempt(count: &AtomicUsize) -> bool {
    reserve_attempt_observed(count, |current| {
        count.compare_exchange_weak(current, current + 1, Ordering::Relaxed, Ordering::Relaxed)
    })
}
fn reserve_attempt_observed(
    count: &AtomicUsize,
    mut compare: impl FnMut(usize) -> std::result::Result<usize, usize>,
) -> bool {
    let mut current = count.load(Ordering::Relaxed);
    for _ in 0..64 {
        if current >= 256 {
            return false;
        }
        match compare(current) {
            Ok(_) => return true,
            Err(observed) => {
                current = observed;
                std::hint::spin_loop();
            }
        }
    }
    false
}
#[derive(Default)]
struct PendingHealth {
    revision: u64,
    entries: BTreeMap<String, (u64, Arc<Health>)>,
}
impl PendingHealth {
    fn offer(&mut self, health: &Health, count: &AtomicUsize) -> bool {
        if !valid_health(health) {
            return false;
        }
        if let Some((_, old)) = self.entries.get(&health.attempt) {
            if !dominates(health, old) {
                return false;
            }
        }
        let Some(revision) = self.revision.checked_add(1) else {
            return false;
        };
        if !self.entries.contains_key(health.attempt.as_str()) && !reserve_attempt(count) {
            return false;
        }
        self.revision = revision;
        self.entries
            .insert(health.attempt.clone(), (revision, Arc::new(health.clone())));
        true
    }
    fn batch(&self) -> Vec<(u64, Arc<Health>)> {
        self.entries.values().cloned().collect()
    }
    fn finish(&mut self, attempt: &str, revision: u64, count: &AtomicUsize) {
        if self
            .entries
            .get(attempt)
            .is_some_and(|(current, _)| *current == revision)
        {
            self.entries.remove(attempt);
            count.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

struct HealthBuffer {
    shards: [Mutex<PendingHealth>; 64],
    count: AtomicUsize,
}
impl Default for HealthBuffer {
    fn default() -> Self {
        Self {
            shards: std::array::from_fn(|_| Mutex::new(PendingHealth::default())),
            count: AtomicUsize::new(0),
        }
    }
}
impl HealthBuffer {
    fn shard(&self, h: &Health) -> usize {
        let mut hash = std::collections::hash_map::DefaultHasher::new();
        h.attempt.hash(&mut hash);
        hash.finish() as usize % self.shards.len()
    }
    fn batch(&self) -> Vec<(usize, u64, Arc<Health>)> {
        self.shards
            .iter()
            .enumerate()
            .flat_map(|(i, p)| {
                p.lock()
                    .expect("health buffer poisoned")
                    .batch()
                    .into_iter()
                    .map(move |(r, h)| (i, r, h))
            })
            .collect()
    }
    fn finish(&self, shard: usize, attempt: &str, revision: u64) {
        self.shards[shard]
            .lock()
            .expect("health buffer poisoned")
            .finish(attempt, revision, &self.count);
    }
}

// Bounded CPU work only: never wait for a lock holder to be scheduled. Shared
// observations keep the writer's batch copy short. A stalled holder still causes
// one visible lost-telemetry observation after the finite admission budget.
const ADMISSION_TRIES: usize = 512;
fn offer_pending(pending: &HealthBuffer, h: &Health) -> bool {
    offer_pending_observed(pending, h, || {})
}
fn offer_pending_observed(pending: &HealthBuffer, h: &Health, mut contended: impl FnMut()) -> bool {
    if !valid_health(h) {
        return false;
    }
    let shard = &pending.shards[pending.shard(h)];
    bounded_admission(|| match shard.try_lock() {
        Ok(mut p) => Some(p.offer(h, &pending.count)),
        Err(std::sync::TryLockError::Poisoned(_)) => Some(false),
        Err(std::sync::TryLockError::WouldBlock) => {
            contended();
            None
        }
    })
}
fn bounded_admission(mut attempt: impl FnMut() -> Option<bool>) -> bool {
    for _ in 0..ADMISSION_TRIES {
        if let Some(result) = attempt() {
            return result;
        }
        std::hint::spin_loop();
    }
    false
}

fn admit_or_count_loss(pending: &HealthBuffer, dropped: &AtomicU64, h: &Health) -> bool {
    if offer_pending(pending, h) {
        true
    } else {
        dropped.fetch_add(1, Ordering::Relaxed);
        false
    }
}

/// Guard joins only after every reporter clone has been dropped.
pub struct ReporterGuard(std::thread::JoinHandle<()>);
impl ReporterGuard {
    pub fn join(self) {
        let _ = self.0.join();
    }
}
/// Bounded nonblocking capture callback; a separate writer persists summaries.
pub fn reporter(
    journal: Journal,
) -> Result<(crate::evidence_gateway::HealthReporter, ReporterGuard)> {
    reporter_inner(Some(journal), None)
}
/// Proxy startup performs no journal I/O. Unavailable, locked, full or invalid
/// journals remain visibly unknown; the dedicated writer retries opening them.
pub fn reporter_at(
    path: std::path::PathBuf,
    spool: std::path::PathBuf,
    writer: String,
) -> Result<(crate::evidence_gateway::HealthReporter, ReporterGuard)> {
    reporter_inner(None, Some((path, spool, writer)))
}
fn reporter_inner(
    mut journal: Option<Journal>,
    selection: Option<(std::path::PathBuf, std::path::PathBuf, String)>,
) -> Result<(crate::evidence_gateway::HealthReporter, ReporterGuard)> {
    let id = crate::evidence_service::hex(&rand::random::<[u8; 16]>());
    // Even initial session admission is best effort: capacity cannot stop inference.
    let initial_loss = u64::from(
        journal
            .as_mut()
            .is_some_and(|j| j.session(&id, 0, false).is_err()),
    );
    let (tx, rx) = mpsc::sync_channel::<()>(1);
    let pending = Arc::new(HealthBuffer::default());
    let writer_pending = pending.clone();
    let dropped = Arc::new(AtomicU64::new(initial_loss));
    let losses = dropped.clone();
    let mut heartbeat = std::time::Instant::now();
    let thread = std::thread::Builder::new()
        .name("kan-health".into())
        .spawn(move || loop {
            let disconnected = matches!(
                rx.recv_timeout(Duration::from_millis(500)),
                Err(mpsc::RecvTimeoutError::Disconnected)
            );
            if journal.is_none() {
                if let Some((path, spool, writer)) = &selection {
                    journal = Journal::open(path)
                        .and_then(|j| {
                            j.check_binding(spool, Some(writer))?;
                            Ok(j)
                        })
                        .ok();
                }
            }
            // Snapshot one bounded batch through separate short shard locks.
            // Database I/O never holds an admission lock.
            let batch = writer_pending.batch();
            for (shard, revision, h) in batch {
                if journal.as_mut().is_none_or(|j| j.record(&h).is_err()) {
                    losses.fetch_add(1, Ordering::Relaxed);
                }
                writer_pending.finish(shard, &h.attempt, revision);
                if heartbeat.elapsed() >= Duration::from_millis(500) {
                    if let Some(j) = &mut journal {
                        let _ = j.session(&id, losses.load(Ordering::Relaxed), false);
                    }
                    heartbeat = std::time::Instant::now();
                }
            }
            if let Some(j) = &mut journal {
                let _ = j.session(&id, losses.load(Ordering::Relaxed), disconnected);
            }
            if disconnected {
                break;
            }
        })?;
    let callback = Arc::new(move |h: &Health| {
        if !admit_or_count_loss(&pending, &dropped, h) {
            return;
        }
        // A full wake channel already guarantees a pending wake, not lost data.
        if matches!(tx.try_send(()), Err(mpsc::TrySendError::Disconnected(_))) {
            dropped.fetch_add(1, Ordering::Relaxed);
        }
    });
    Ok((callback, ReporterGuard(thread)))
}

// A watermark belongs to one drain invocation. There is still one supervised
// worker per spool, as in the original delivery contract; this is not election.
#[derive(Serialize, Deserialize)]
struct WorkerCheckpoint {
    #[serde(flatten)]
    status: WorkerStatus,
    #[serde(default)]
    run: String,
    #[serde(default)]
    run_failures: u64,
}
struct WorkerRun {
    id: String,
    failures: u64,
    committed: bool,
}
impl WorkerRun {
    fn new() -> Self {
        Self {
            id: crate::evidence_service::hex(&rand::random::<[u8; 16]>()),
            failures: 0,
            committed: false,
        }
    }
}
fn save_worker_run(
    journal: &mut Journal,
    status: &mut WorkerStatus,
    run: &mut WorkerRun,
) -> Result<()> {
    if let Some(queue) = &status.queue {
        journal.check_queue(queue)?;
    }
    let tx = journal
        .conn
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let prior: Option<String> = tx
        .query_row("SELECT body FROM worker WHERE singleton=1", [], |r| {
            r.get(0)
        })
        .optional()?;
    let prior: Option<WorkerCheckpoint> =
        prior.map(|body| serde_json::from_str(&body)).transpose()?;
    // If another run took over after our checkpoint, do not overwrite it. A
    // supervisor must stop the previous worker before starting its successor.
    if run.committed && prior.as_ref().is_some_and(|p| p.run != run.id) {
        return Err(invalid());
    }
    let mut merged = status.clone();
    let prior_total = prior
        .as_ref()
        .map(|p| &p.status)
        .map_or(0, |s| s.telemetry_failures);
    let watermark = prior
        .as_ref()
        .filter(|p| p.run == run.id)
        .map_or(0, |p| p.run_failures);
    if watermark > run.failures {
        return Err(invalid());
    }
    merged.telemetry_failures = prior_total.saturating_add(run.failures - watermark);
    if let Some(old) = prior.as_ref().map(|p| &p.status) {
        let queue = status.queue.as_ref().ok_or_else(invalid)?;
        if old.queue.as_ref().is_some_and(|q| {
            q.writer != queue.writer
                || q.scope != queue.scope
                || q.audience != queue.audience
                || q.next > queue.next
                || (q.next == queue.next && q.previous != queue.previous)
        }) || old
            .last_ack_position
            .is_some_and(|p| p >= queue.next.saturating_sub(queue.pending))
        {
            return Err(invalid());
        }
        if old.last_ack_position > merged.last_ack_position {
            // Preserve the timestamp paired with the greatest position; clocks
            // are not a monotone progress cursor.
            merged.last_ack_position = old.last_ack_position;
            merged.last_ack_at = old.last_ack_at;
        }
    }
    let checkpoint = WorkerCheckpoint {
        status: merged.clone(),
        run: run.id.clone(),
        run_failures: run.failures,
    };
    tx.execute(
        "INSERT INTO worker VALUES(1,?) ON CONFLICT(singleton) DO UPDATE SET body=excluded.body",
        [serde_json::to_string(&checkpoint)?],
    )?;
    successful(&tx, journal.schema)?;
    tx.commit()?;
    *status = merged;
    run.committed = true;
    Ok(())
}
fn persist_worker(
    journal: &mut Option<Journal>,
    status: &mut WorkerStatus,
    run: &mut WorkerRun,
    load: &impl Fn() -> Result<Journal>,
    next_open: &mut std::time::Instant,
) {
    if journal.is_none() && std::time::Instant::now() >= *next_open {
        *next_open = std::time::Instant::now() + Duration::from_secs(1);
        *journal = load().ok();
    }
    if journal.as_mut().is_none_or(|j| {
        let result = save_worker_run(j, status, run);
        j.note_capacity_failure(&result);
        result.is_err()
    }) {
        run.failures = run.failures.saturating_add(1);
    }
}

/// Independent archive worker. Cancellation may leave a remote commit unknown;
/// retained request bytes are the only retry. Never invokes an inference route.
pub async fn drain(spool_path: &Path, journal_path: &Path, endpoint: &str) -> Result<()> {
    let mut spool = Spool::open(spool_path)?;
    let binding = spool.status()?;
    let load_journal = || -> Result<Journal> {
        let j = Journal::open(journal_path)?;
        j.check_binding(spool_path, None)?;
        j.check_queue(&binding)?;
        Ok(j)
    };
    let mut journal = load_journal().ok();
    let mut run = WorkerRun::new();
    let mut next_open = std::time::Instant::now() + Duration::from_secs(1);
    let mut status = WorkerStatus {
        sampled_at: now(),
        state: "starting".into(),
        queue: Some(binding.clone()),
        nonempty_since: None,
        last_ack_at: None,
        last_ack_position: None,
        telemetry_failures: 0,
        consecutive_failures: 0,
        retry_seconds: 0,
    };
    persist_worker(
        &mut journal,
        &mut status,
        &mut run,
        &load_journal,
        &mut next_open,
    );
    loop {
        status.sampled_at = now();
        status.queue = Some(spool.status()?);
        let queue = status.queue.as_ref().expect("sample");
        if queue.pending == 0 {
            status.nonempty_since = None;
            status.state = "idle".into();
            status.consecutive_failures = 0;
            status.retry_seconds = 1;
            persist_worker(
                &mut journal,
                &mut status,
                &mut run,
                &load_journal,
                &mut next_open,
            );
            tokio::time::sleep(Duration::from_secs(1)).await;
            continue;
        }
        status.nonempty_since.get_or_insert(now());
        status.state = "delivering".into();
        status.retry_seconds = 0;
        persist_worker(
            &mut journal,
            &mut status,
            &mut run,
            &load_journal,
            &mut next_open,
        );
        match evidence_delivery::deliver_one(&mut spool, endpoint).await {
            Ok(Some(ack)) => {
                status.last_ack_at = Some(now());
                status.last_ack_position = Some(ack.position);
                status.consecutive_failures = 0;
            }
            Ok(None) => {}
            Err(_) => {
                status.state = "retrying".into();
                status.sampled_at = now();
                status.consecutive_failures = status.consecutive_failures.saturating_add(1);
                status.retry_seconds = (1u64 << status.consecutive_failures.min(5)).min(30);
                persist_worker(
                    &mut journal,
                    &mut status,
                    &mut run,
                    &load_journal,
                    &mut next_open,
                );
                tokio::time::sleep(Duration::from_secs(status.retry_seconds)).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn burst_keeps_final_cumulative_summary_and_terminal_gap() {
        use std::sync::atomic::AtomicBool;
        static BLOCKED: AtomicBool = AtomicBool::new(false);
        static RELEASE: AtomicBool = AtomicBool::new(false);
        static RECORD: AtomicBool = AtomicBool::new(false);
        static HEARTBEAT: AtomicBool = AtomicBool::new(false);
        fn hold_writer(_: i32) -> bool {
            if !RECORD.load(Ordering::SeqCst) {
                HEARTBEAT.store(true, Ordering::SeqCst);
                return false;
            }
            BLOCKED.store(true, Ordering::SeqCst);
            while !RELEASE.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(1));
            }
            true
        }
        struct ReleaseOnDrop;
        impl Drop for ReleaseOnDrop {
            fn drop(&mut self) {
                RELEASE.store(true, Ordering::SeqCst);
            }
        }
        let _release = ReleaseOnDrop;
        BLOCKED.store(false, Ordering::SeqCst);
        RELEASE.store(false, Ordering::SeqCst);
        RECORD.store(false, Ordering::SeqCst);
        HEARTBEAT.store(false, Ordering::SeqCst);
        let dir = tempfile::tempdir().unwrap();
        let spool = dir.path().join("queue");
        let path = dir.path().join("health");
        let id = crate::sign::Identity::generate();
        Spool::create(
            &spool,
            &crate::evidence_service::hex(&[3; 32]),
            id.did().as_str(),
            id.did().as_str(),
            10000,
        )
        .unwrap();
        let journal = Journal::create(&path, &spool).unwrap();
        journal.conn.trace_v2(
            rusqlite::trace::TraceEventCodes::SQLITE_TRACE_STMT,
            Some(|event| {
                if let rusqlite::trace::TraceEvent::Stmt(_, "BEGIN DEFERRED") = event {
                    RECORD.store(true, Ordering::SeqCst);
                }
            }),
        );
        journal.conn.busy_handler(Some(hold_writer)).unwrap();
        let (report, guard) = reporter(journal).unwrap();
        let lock = Connection::open(&path).unwrap();
        lock.execute_batch("BEGIN EXCLUSIVE").unwrap();
        // Force the timeout heartbeat to encounter the lock first. It must not
        // satisfy the record barrier, even if the caller is descheduled.
        let heartbeat_deadline = std::time::Instant::now() + Duration::from_secs(3);
        while !HEARTBEAT.load(Ordering::SeqCst) && std::time::Instant::now() < heartbeat_deadline {
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(HEARTBEAT.load(Ordering::SeqCst));
        assert!(!BLOCKED.load(Ordering::SeqCst));
        let mut h = Health {
            attempt: format!("{:064x}", 0),
            observer: crate::evidence_capture::Observer::Collector,
            observed: 1,
            locally_queued: 0,
            unconfirmed: 1,
            recording_gap: true,
            remote_acknowledged: false,
            status: Some(200),
            outcome: None,
        };
        report(&h);
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        while !BLOCKED.load(Ordering::SeqCst) && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(1));
        }
        let blocked = BLOCKED.load(Ordering::SeqCst);
        // SQLite itself signals the writer is inside I/O; callback offers are
        // uncontended and completion of the older revision is still pending.
        for n in 2..1003 {
            h.observed = n;
            h.locally_queued = n - 1;
            report(&h);
        }
        h.outcome = Some(crate::evidence_capture::Outcome::Completed);
        report(&h);
        let mut contradiction = h.clone();
        contradiction.outcome = None;
        report(&contradiction);
        lock.execute_batch("ROLLBACK").unwrap();
        RELEASE.store(true, Ordering::SeqCst);
        drop(report);
        guard.join();
        assert!(blocked, "test did not establish the I/O barrier");
        let snapshot = Journal::open(&path).unwrap().snapshot().unwrap();
        assert_eq!(
            (
                snapshot.observed,
                snapshot.locally_queued,
                snapshot.unconfirmed
            ),
            (1002, 1001, 1)
        );
        assert_eq!(snapshot.recent[0]["capture"]["outcome"], "completed");
        assert_eq!(snapshot.recent[0]["capture"]["recording_gap"], true);
        assert_eq!(
            snapshot.telemetry_dropped, 1,
            "only the contradiction is lost; coalescing is not dropped evidence"
        );
    }
    #[test]
    fn actual_shard_contention_retries_after_release_without_loss() {
        let pending = HealthBuffer::default();
        let health = Health {
            attempt: format!("{:064x}", 1),
            observer: crate::evidence_capture::Observer::Collector,
            observed: 1,
            locally_queued: 0,
            unconfirmed: 1,
            recording_gap: true,
            remote_acknowledged: false,
            status: None,
            outcome: None,
        };
        let mut held = Some(pending.shards[pending.shard(&health)].lock().unwrap());
        let mut contentions = 0;
        assert!(
            offer_pending_observed(&pending, &health, || {
                contentions += 1;
                if contentions == 3 {
                    drop(held.take());
                }
            }),
            "real WouldBlock must retry and admit after release"
        );
        assert_eq!(contentions, 3);
        assert_eq!(pending.count.load(Ordering::Relaxed), 1);
        assert_eq!(
            pending.shards[pending.shard(&health)]
                .lock()
                .unwrap()
                .entries[&health.attempt]
                .1
                .observed,
            1
        );
    }
    #[test]
    fn reservation_retries_spurious_failure_and_stops_at_its_finite_budget() {
        let count = AtomicUsize::new(0);
        let mut calls = 0;
        assert!(reserve_attempt_observed(&count, |current| {
            calls += 1;
            if calls < 4 {
                Err(current)
            } else {
                count.compare_exchange(current, current + 1, Ordering::Relaxed, Ordering::Relaxed)
            }
        }));
        assert_eq!(calls, 4);
        assert_eq!(count.load(Ordering::Relaxed), 1);
        calls = 0;
        assert!(!reserve_attempt_observed(&count, |current| {
            calls += 1;
            Err(current)
        }));
        assert_eq!(calls, 64, "CAS retry budget must be finite and explicit");
        assert_eq!(
            count.load(Ordering::Relaxed),
            1,
            "failed reservation must not leak capacity"
        );
        count.store(256, Ordering::Relaxed);
        assert!(!reserve_attempt_observed(&count, |_| panic!(
            "full capacity must not attempt a reservation"
        )));
    }
    #[test]
    fn admission_retries_transient_contention_but_stops_at_budget() {
        let mut calls = 0;
        assert!(bounded_admission(|| {
            calls += 1;
            (calls == 4).then_some(true)
        }));
        assert_eq!(calls, 4, "brief contention must be retried");
        calls = 0;
        assert!(!bounded_admission(|| {
            calls += 1;
            None
        }));
        assert_eq!(
            calls, 512,
            "admission must stop at its documented finite budget"
        );
        calls = 0;
        assert!(!bounded_admission(|| {
            calls += 1;
            Some(false)
        }));
        assert_eq!(calls, 1, "a semantic refusal must not be retried");
    }
    #[test]
    fn contended_admission_is_bounded_and_counts_one_summary() {
        let pending = HealthBuffer::default();
        let dropped = AtomicU64::new(7);
        let h = Health {
            attempt: format!("{:064x}", 9),
            observer: crate::evidence_capture::Observer::Collector,
            observed: 1,
            locally_queued: 1,
            unconfirmed: 0,
            recording_gap: false,
            remote_acknowledged: false,
            status: Some(200),
            outcome: Some(crate::evidence_capture::Outcome::Completed),
        };
        let held = pending.shards[pending.shard(&h)].lock().unwrap();
        let start = std::time::Instant::now();
        assert!(!admit_or_count_loss(&pending, &dropped, &h));
        assert!(start.elapsed() < Duration::from_millis(100));
        assert_eq!(dropped.load(Ordering::Relaxed), 8);
        drop(held);
        assert!(admit_or_count_loss(&pending, &dropped, &h));
        assert_eq!(dropped.load(Ordering::Relaxed), 8);
        assert_eq!(pending.batch()[0].2.outcome, h.outcome);
    }
    #[test]
    fn sharded_admission_is_independent_and_globally_bounded() {
        let buffer = HealthBuffer::default();
        let make = |i| Health {
            attempt: format!("{i:064x}"),
            observer: crate::evidence_capture::Observer::Collector,
            observed: 1,
            locally_queued: 1,
            unconfirmed: 0,
            recording_gap: false,
            remote_acknowledged: false,
            status: None,
            outcome: None,
        };
        let first = make(0);
        let held = buffer.shards[buffer.shard(&first)].lock().unwrap();
        let different = (1..256)
            .map(make)
            .find(|h| buffer.shard(h) != buffer.shard(&first))
            .unwrap();
        assert!(
            offer_pending(&buffer, &different),
            "another attempt's held shard must not block admission"
        );
        drop(held);
        for i in 0..256 {
            assert!(offer_pending(&buffer, &make(i)));
        }
        assert_eq!(buffer.count.load(Ordering::Relaxed), 256);
        assert!(!offer_pending(&buffer, &make(1001)));
        let (shard, old, mut h) = buffer
            .batch()
            .into_iter()
            .find(|(_, _, h)| h.attempt == first.attempt)
            .unwrap();
        Arc::make_mut(&mut h).observed += 1;
        Arc::make_mut(&mut h).locally_queued += 1;
        assert!(offer_pending(&buffer, &h));
        buffer.finish(shard, &h.attempt, old);
        assert_eq!(buffer.count.load(Ordering::Relaxed), 256);
        let current = buffer
            .batch()
            .into_iter()
            .find(|(_, _, item)| item.attempt == h.attempt)
            .unwrap()
            .1;
        buffer.finish(shard, &h.attempt, current);
        assert_eq!(buffer.count.load(Ordering::Relaxed), 255);
        assert!(offer_pending(&buffer, &make(1001)));
    }
    #[test]
    fn worker_checkpoint_retry_is_idempotent_after_uncertain_commit() {
        let dir = tempfile::tempdir().unwrap();
        let spool = dir.path().join("queue");
        let path = dir.path().join("health");
        let id = crate::sign::Identity::generate();
        let queue = Spool::create(
            &spool,
            &crate::evidence_service::hex(&[3; 32]),
            id.did().as_str(),
            id.did().as_str(),
            10000,
        )
        .unwrap()
        .status()
        .unwrap();
        let mut journal = Journal::create(&path, &spool).unwrap();
        let mut status = WorkerStatus {
            sampled_at: now(),
            state: "idle".into(),
            queue: Some(queue),
            nonempty_since: None,
            last_ack_at: None,
            last_ack_position: None,
            consecutive_failures: 0,
            retry_seconds: 1,
            telemetry_failures: 7,
        };
        journal.save_worker(&status).unwrap();
        let mut run = WorkerRun::new();
        run.failures = 3;
        save_worker_run(&mut journal, &mut status, &mut run).unwrap();
        assert_eq!(status.telemetry_failures, 10);
        // Simulate commit reaching storage without the caller advancing memory.
        run.committed = false;
        status.telemetry_failures = 0;
        save_worker_run(&mut journal, &mut status, &mut run).unwrap();
        assert_eq!(status.telemetry_failures, 10);
        run.failures += 1;
        save_worker_run(&mut journal, &mut status, &mut run).unwrap();
        assert_eq!(status.telemetry_failures, 11);
        let mut successor = WorkerRun::new();
        successor.failures = 2;
        save_worker_run(&mut journal, &mut status, &mut successor).unwrap();
        assert_eq!(status.telemetry_failures, 13);
        assert!(
            save_worker_run(&mut journal, &mut status, &mut run).is_err(),
            "superseded run must not overwrite a successor"
        );
    }
    #[test]
    fn physical_full_keeps_prior_health_and_rejects_new_record() {
        let dir = tempfile::tempdir().unwrap();
        let spool = dir.path().join("queue");
        let path = dir.path().join("health");
        let id = crate::sign::Identity::generate();
        Spool::create(
            &spool,
            &crate::evidence_service::hex(&[3; 32]),
            id.did().as_str(),
            id.did().as_str(),
            10000,
        )
        .unwrap();
        let mut journal = Journal::create(&path, &spool).unwrap();
        drop(journal);
        journal = Journal::open(&path).unwrap();
        assert_eq!(
            journal
                .conn
                .query_row("PRAGMA max_page_count", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            8192,
            "reopened writer must enforce the physical page cap"
        );
        let mut health = Health {
            attempt: crate::evidence_service::hex(&[1; 32]),
            observer: crate::evidence_capture::Observer::Collector,
            observed: 1,
            locally_queued: 0,
            unconfirmed: 1,
            recording_gap: true,
            remote_acknowledged: false,
            status: None,
            outcome: None,
        };
        journal.record(&health).unwrap();
        let pages: i64 = journal
            .conn
            .query_row("PRAGMA page_count", [], |r| r.get(0))
            .unwrap();
        journal
            .conn
            .execute_batch(&format!("PRAGMA max_page_count={pages}"))
            .unwrap();
        let mut failed = false;
        for i in 2..2000u64 {
            health.attempt = format!("{i:064x}");
            if let Err(e) = journal.record(&health) {
                assert!(e.to_string().contains("full"), "{e}");
                failed = true;
                break;
            }
        }
        assert!(failed, "SQLite capacity control must actually fail a write");
        let before = journal.snapshot().unwrap();
        assert!(before.unconfirmed > 0);
        assert_eq!(before.journal.exhausted_observed, Some(true));
        assert_eq!(
            before.journal.exhaustion_reason.as_deref(),
            Some("sqlite_full")
        );
        assert_eq!(before.journal.reserve_bytes, 0);
        journal.session("reserved-control-probe", 9, true).unwrap();
        assert!(
            journal.record(&health).is_err(),
            "capacity exhaustion stays sticky after control writes"
        );
        drop(journal);
        let after = Journal::open(&path).unwrap().snapshot().unwrap();
        assert_eq!(after.unconfirmed, before.unconfirmed);
        assert_eq!(after.attempts, before.attempts);
        assert_eq!(after.telemetry_dropped, 9);
        assert_eq!(after.journal.exhausted_observed, Some(true));
        assert_eq!(after.journal.loss_count_certainty, "lower_bound");
    }
    #[test]
    fn worker_full_failure_marks_capacity_and_retains_recovery_space() {
        let dir = tempfile::tempdir().unwrap();
        let spool = dir.path().join("queue");
        let path = dir.path().join("health");
        let id = crate::sign::Identity::generate();
        Spool::create(
            &spool,
            &crate::evidence_service::hex(&[3; 32]),
            id.did().as_str(),
            id.did().as_str(),
            10000,
        )
        .unwrap();
        let journal = Journal::create(&path, &spool).unwrap();
        let pages: i64 = journal
            .conn
            .query_row("PRAGMA page_count", [], |r| r.get(0))
            .unwrap();
        journal
            .conn
            .execute_batch(&format!("PRAGMA max_page_count={pages}"))
            .unwrap();
        let mut journal = Some(journal);
        // A synthetic oversized checkpoint requires new pages at the actual
        // SQLite page ceiling. No device-wide ENOSPC is claimed by this test.
        let mut status = WorkerStatus {
            sampled_at: now(),
            state: "x".repeat(20000),
            queue: None,
            nonempty_since: None,
            last_ack_at: None,
            last_ack_position: None,
            consecutive_failures: 0,
            retry_seconds: 0,
            telemetry_failures: 0,
        };
        let mut run = WorkerRun::new();
        let mut next_open = std::time::Instant::now();
        let load = || -> Result<Journal> { panic!("existing journal should not reopen") };
        persist_worker(&mut journal, &mut status, &mut run, &load, &mut next_open);
        assert_eq!(run.failures, 1);
        let failed = journal.as_mut().unwrap().snapshot().unwrap();
        assert_eq!(
            failed.journal.exhaustion_reason.as_deref(),
            Some("sqlite_full")
        );
        assert_eq!(failed.journal.reserve_bytes, 0);
        assert_eq!(failed.journal.last_success_at, None);
        status.state = "idle".into();
        persist_worker(&mut journal, &mut status, &mut run, &load, &mut next_open);
        assert_eq!(run.failures, 1);
        assert!(run.committed);
        let recovered = journal.as_mut().unwrap().snapshot().unwrap();
        assert_eq!(recovered.journal.exhausted_observed, Some(true));
        assert!(recovered.journal.last_success_at.is_some());
        assert_eq!(recovered.worker.unwrap().telemetry_failures, 1);
    }
    #[test]
    fn successful_write_is_observed_only_after_commit() {
        let dir = tempfile::tempdir().unwrap();
        let spool = dir.path().join("queue");
        let path = dir.path().join("health");
        let id = crate::sign::Identity::generate();
        Spool::create(
            &spool,
            &crate::evidence_service::hex(&[3; 32]),
            id.did().as_str(),
            id.did().as_str(),
            10000,
        )
        .unwrap();
        let mut journal = Journal::create(&path, &spool).unwrap();
        assert_eq!(journal.snapshot().unwrap().journal.last_success_at, None);
        let mut health = Health {
            attempt: format!("{:064x}", 1),
            observer: crate::evidence_capture::Observer::Collector,
            observed: 2,
            locally_queued: 0,
            unconfirmed: 1,
            recording_gap: true,
            remote_acknowledged: false,
            status: None,
            outcome: None,
        };
        assert!(journal.record(&health).is_err());
        assert_eq!(journal.snapshot().unwrap().journal.last_success_at, None);
        health.observed = 1;
        journal.record(&health).unwrap();
        assert!(journal
            .snapshot()
            .unwrap()
            .journal
            .last_success_at
            .is_some());
        journal
            .conn
            .execute("UPDATE control SET last_success=0", [])
            .unwrap();
        journal.conn.execute_batch("CREATE TEMP TRIGGER refuse_control BEFORE UPDATE ON control BEGIN SELECT RAISE(ABORT,'synthetic control write failure'); END").unwrap();
        health.observed = 2;
        health.unconfirmed = 2;
        assert!(journal.record(&health).is_err());
        let rolled_back = journal.snapshot().unwrap();
        assert_eq!(
            rolled_back.observed, 1,
            "failed control write must roll back the attempt transaction"
        );
        assert_eq!(rolled_back.journal.last_success_at, None);
        journal
            .conn
            .execute_batch("DROP TRIGGER refuse_control")
            .unwrap();
        journal.session("freshness-session", 0, false).unwrap();
        assert!(journal
            .snapshot()
            .unwrap()
            .journal
            .last_success_at
            .is_some());
        journal
            .conn
            .execute("UPDATE control SET last_success=0", [])
            .unwrap();
        journal
            .save_worker(&WorkerStatus {
                sampled_at: now(),
                state: "idle".into(),
                queue: None,
                nonempty_since: None,
                last_ack_at: None,
                last_ack_position: None,
                consecutive_failures: 0,
                retry_seconds: 0,
                telemetry_failures: 0,
            })
            .unwrap();
        assert!(journal
            .snapshot()
            .unwrap()
            .journal
            .last_success_at
            .is_some());
    }
    #[test]
    fn legacy_snapshot_does_not_rewrite_or_invent_control_evidence() {
        use sha2::{Digest, Sha256};
        let dir = tempfile::tempdir().unwrap();
        let spool = dir.path().join("queue");
        let path = dir.path().join("health");
        let id = crate::sign::Identity::generate();
        Spool::create(
            &spool,
            &crate::evidence_service::hex(&[3; 32]),
            id.did().as_str(),
            id.did().as_str(),
            10000,
        )
        .unwrap();
        let journal = Journal::create(&path, &spool).unwrap();
        journal
            .conn
            .execute_batch("DROP TABLE control; DROP TABLE reserve; PRAGMA user_version=1")
            .unwrap();
        drop(journal);
        let before = Sha256::digest(std::fs::read(&path).unwrap());
        let snapshot = Journal::open(&path).unwrap().snapshot().unwrap();
        assert_eq!(snapshot.version, 2);
        assert_eq!(snapshot.journal.schema, 1);
        assert_eq!(snapshot.journal.exhausted_observed, None);
        assert_eq!(snapshot.journal.last_success_at, None);
        assert_eq!(snapshot.journal.sessions_limit, None);
        assert_eq!(Sha256::digest(std::fs::read(&path).unwrap()), before);
    }
    #[test]
    fn attempt_count_exhaustion_retains_existing_rows_and_marks_once() {
        let dir = tempfile::tempdir().unwrap();
        let spool = dir.path().join("queue");
        let path = dir.path().join("health");
        let id = crate::sign::Identity::generate();
        Spool::create(
            &spool,
            &crate::evidence_service::hex(&[3; 32]),
            id.did().as_str(),
            id.did().as_str(),
            10000,
        )
        .unwrap();
        let mut journal = Journal::create(&path, &spool).unwrap();
        // Compact synthetic rows reach the logical count before the page limit.
        // The selected new health remains a valid production observation.
        journal.conn.execute_batch("WITH RECURSIVE n(i) AS (VALUES(0) UNION ALL SELECT i+1 FROM n WHERE i<99999) INSERT INTO attempts SELECT printf('%064x',i),0,0,0,0,'{}' FROM n").unwrap();
        let health = Health {
            attempt: format!("{:064x}", 100_000),
            observer: crate::evidence_capture::Observer::Collector,
            observed: 1,
            locally_queued: 0,
            unconfirmed: 1,
            recording_gap: true,
            remote_acknowledged: false,
            status: None,
            outcome: None,
        };
        let error = journal.record(&health).unwrap_err();
        assert_eq!(
            error.downcast_ref::<CapacityLimit>().unwrap().0,
            "attempt_limit"
        );
        let (count, exhausted, reason, reserve): (u64, bool, String, u64) = journal.conn.query_row("SELECT (SELECT count(*) FROM attempts),exhausted,reason,(SELECT count(*) FROM reserve) FROM control", [], |r| Ok((unsigned(r,0)?,r.get(1)?,r.get(2)?,unsigned(r,3)?))).unwrap();
        assert_eq!(count, 100_000);
        assert!(exhausted);
        assert_eq!(reason, "attempt_limit");
        assert_eq!(reserve, 0);
        journal
            .session("control-after-attempt-limit", 1, true)
            .unwrap();
        assert_eq!(
            journal
                .record(&health)
                .unwrap_err()
                .downcast_ref::<CapacityLimit>()
                .unwrap()
                .0,
            "sealed_for_capacity"
        );
        drop(journal);
        let reopened = Journal::open(&path).unwrap();
        assert_eq!(
            reopened
                .conn
                .query_row("SELECT reason FROM control", [], |r| r.get::<_, String>(0))
                .unwrap(),
            "attempt_limit"
        );
    }
    #[test]
    fn session_capacity_is_sticky_and_existing_control_still_updates() {
        let dir = tempfile::tempdir().unwrap();
        let spool = dir.path().join("queue");
        let path = dir.path().join("health");
        let id = crate::sign::Identity::generate();
        Spool::create(
            &spool,
            &crate::evidence_service::hex(&[3; 32]),
            id.did().as_str(),
            id.did().as_str(),
            10000,
        )
        .unwrap();
        let mut journal = Journal::create(&path, &spool).unwrap();
        // Seed the bounded session table without thousands of separate fsyncs.
        journal.conn.execute_batch("WITH RECURSIVE n(i) AS (VALUES(0) UNION ALL SELECT i+1 FROM n WHERE i<1023) INSERT INTO sessions SELECT printf('%032x',i),0,0,1 FROM n").unwrap();
        assert!(journal.session("new-session", 1, false).is_err());
        journal.session(&format!("{:032x}", 0), 12, true).unwrap();
        let s = journal.snapshot().unwrap();
        assert_eq!(s.journal.sessions_used, 1024);
        assert_eq!(
            s.journal.exhaustion_reason.as_deref(),
            Some("session_limit")
        );
        assert_eq!(s.telemetry_dropped, 12);
        assert_eq!(s.journal.reserve_bytes, 256 * 1024);
        drop(journal);
        assert_eq!(
            Journal::open(&path)
                .unwrap()
                .snapshot()
                .unwrap()
                .journal
                .reserve_bytes,
            256 * 1024
        );
        // Accept older v2 journals that had already released this reserve.
        let conn = Connection::open(&path).unwrap();
        conn.execute("DELETE FROM reserve", []).unwrap();
        drop(conn);
        assert_eq!(
            Journal::open(&path)
                .unwrap()
                .snapshot()
                .unwrap()
                .journal
                .reserve_bytes,
            0
        );
    }
}
