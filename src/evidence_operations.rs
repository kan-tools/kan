//! Private operational observations. Never an evidence-completeness certificate.
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
}
impl Journal {
    pub fn create(path: &Path, spool_path: &Path) -> Result<Self> {
        let st = Spool::open(spool_path)?.status()?;
        let spool = spool_path.canonicalize()?;
        for suffix in ["-journal", "-wal", "-shm"] {
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
        conn.execute(
            "INSERT INTO binding VALUES(1,?,?,?,?)",
            params![
                spool.to_str().ok_or_else(invalid)?,
                st.writer,
                st.scope,
                st.audience
            ],
        )?;
        std::fs::File::open(
            path.parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new(".")),
        )?
        .sync_all()?;
        Self::open(path)
    }
    pub fn open(path: &Path) -> Result<Self> {
        let meta = std::fs::symlink_metadata(path)?;
        if !meta.is_file() || meta.file_type().is_symlink() || meta.len() > 32 * 1024 * 1024 {
            return Err(invalid());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if meta.permissions().mode() & 0o077 != 0 {
                return Err(invalid());
            }
        }
        let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
        conn.busy_timeout(Duration::from_millis(100))?;
        conn.set_limit(rusqlite::limits::Limit::SQLITE_LIMIT_LENGTH, 32768)?;
        if conn.query_row("PRAGMA application_id", [], |r| r.get::<_, i64>(0))? != PROFILE
            || conn.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))? != 1
        {
            return Err(invalid());
        }
        conn.execute_batch(
            "PRAGMA synchronous=FULL; PRAGMA fullfsync=ON; PRAGMA max_page_count=8192;",
        )?;
        if conn.query_row("PRAGMA page_size", [], |r| r.get::<_, i64>(0))? != 4096 {
            return Err(invalid());
        }
        let expected = Connection::open_in_memory()?;
        expected.execute_batch(SCHEMA)?;
        fn schema(c: &Connection) -> rusqlite::Result<Vec<(String, String)>> {
            c.prepare("SELECT name,coalesce(sql,'') FROM sqlite_schema ORDER BY name")?
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
                .collect()
        }
        if schema(&conn)? != schema(&expected)? {
            return Err(invalid());
        }
        Ok(Self { conn })
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
    pub fn record(&mut self, h: &Health) -> Result<()> {
        if !valid_health(h) {
            return Err(invalid());
        }
        let tx = self.conn.transaction()?;
        let count = tx.query_row("SELECT count(*) FROM attempts", [], |r| unsigned(r, 0))?;
        let old: Option<String> = tx
            .query_row(
                "SELECT body FROM attempts WHERE attempt=?",
                [&h.attempt],
                |r| r.get(0),
            )
            .optional()?;
        if old.is_none() && count >= 100_000 {
            return Err(invalid());
        }
        if let Some(old) = old {
            let old: Health = serde_json::from_str(&old)?;
            if !dominates(h, &old) {
                return Err(invalid());
            }
        }
        tx.execute("INSERT INTO attempts VALUES(?,?,?,?,?,?) ON CONFLICT(attempt) DO UPDATE SET updated=excluded.updated, observed=excluded.observed,queued=excluded.queued,unconfirmed=excluded.unconfirmed,body=excluded.body",params![h.attempt,now() as i64,i64::try_from(h.observed)?,i64::try_from(h.locally_queued)?,i64::try_from(h.unconfirmed)?,serde_json::to_string(h)?])?;
        tx.commit()?;
        Ok(())
    }
    fn session(&self, id: &str, dropped: u64, clean: bool) -> Result<()> {
        self.conn.execute("INSERT INTO sessions VALUES(?,?,?,?) ON CONFLICT(id) DO UPDATE SET updated=excluded.updated,dropped=max(dropped,excluded.dropped),clean=excluded.clean",params![id,now() as i64,i64::try_from(dropped)?,clean])?;
        Ok(())
    }
    pub fn save_worker(&self, status: &WorkerStatus) -> Result<()> {
        if let Some(st) = &status.queue {
            self.check_queue(st)?;
        }
        self.conn.execute("INSERT INTO worker VALUES(1,?) ON CONFLICT(singleton) DO UPDATE SET body=excluded.body",[serde_json::to_string(status)?])?;
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
        tx.commit()?;
        Ok(Snapshot {
            version: 1,
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
fn dominates(new: &Health, old: &Health) -> bool {
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
    let mut current = count.load(Ordering::Relaxed);
    for _ in 0..64 {
        if current >= 256 {
            return false;
        }
        match count.compare_exchange_weak(
            current,
            current + 1,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
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
// one visible lost-summary observation after the finite admission budget.
const ADMISSION_TRIES: usize = 512;
fn offer_pending(pending: &HealthBuffer, h: &Health) -> bool {
    if !valid_health(h) {
        return false;
    }
    let shard = &pending.shards[pending.shard(h)];
    bounded_admission(|| match shard.try_lock() {
        Ok(mut p) => Some(p.offer(h, &pending.count)),
        Err(std::sync::TryLockError::Poisoned(_)) => Some(false),
        Err(std::sync::TryLockError::WouldBlock) => None,
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
            .as_ref()
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
                    if let Some(j) = &journal {
                        let _ = j.session(&id, losses.load(Ordering::Relaxed), false);
                    }
                    heartbeat = std::time::Instant::now();
                }
            }
            if let Some(j) = &journal {
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
    if journal
        .as_mut()
        .is_none_or(|j| save_worker_run(j, status, run).is_err())
    {
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
        drop(journal);
        let after = Journal::open(&path).unwrap().snapshot().unwrap();
        assert_eq!(after.unconfirmed, before.unconfirmed);
        assert_eq!(after.attempts, before.attempts);
    }
}
