//! Private operational observations. Never an evidence-completeness certificate.
use crate::{
    evidence_capture::Health,
    evidence_delivery,
    evidence_spool::{Spool, Status},
};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::{
    path::Path,
    sync::{
        atomic::{AtomicU64, Ordering},
        mpsc, Arc,
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
        if h.attempt.len() != 64
            || !h.attempt.bytes().all(|c| c.is_ascii_hexdigit())
            || h.observed != h.locally_queued.saturating_add(h.unconfirmed)
            || h.recording_gap != (h.unconfirmed > 0)
            || h.remote_acknowledged
        {
            return Err(invalid());
        }
        let tx = self.conn.transaction()?;
        let count = tx.query_row("SELECT count(*) FROM attempts", [], |r| unsigned(r, 0))?;
        let old: Option<(u64, u64, u64)> = tx
            .query_row(
                "SELECT observed,queued,unconfirmed FROM attempts WHERE attempt=?",
                [&h.attempt],
                |r| Ok((unsigned(r, 0)?, unsigned(r, 1)?, unsigned(r, 2)?)),
            )
            .optional()?;
        if old.is_none() && count >= 100_000 {
            return Err(invalid());
        }
        if old.is_some_and(|(o, q, u)| h.observed < o || h.locally_queued < q || h.unconfirmed < u)
        {
            return Err(invalid());
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
    let (tx, rx) = mpsc::sync_channel::<Health>(256);
    let dropped = Arc::new(AtomicU64::new(initial_loss));
    let losses = dropped.clone();
    let thread = std::thread::Builder::new()
        .name("kan-health".into())
        .spawn(move || loop {
            let message = rx.recv_timeout(Duration::from_millis(500));
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
            let disconnected = match message {
                Ok(h) => {
                    if journal.as_mut().is_none_or(|j| j.record(&h).is_err()) {
                        losses.fetch_add(1, Ordering::Relaxed);
                    }
                    false
                }
                Err(mpsc::RecvTimeoutError::Timeout) => false,
                Err(mpsc::RecvTimeoutError::Disconnected) => true,
            };
            if let Some(j) = &journal {
                let _ = j.session(&id, losses.load(Ordering::Relaxed), disconnected);
            }
            if disconnected {
                break;
            }
        })?;
    let callback = Arc::new(move |h: &Health| {
        if tx.try_send(h.clone()).is_err() {
            dropped.fetch_add(1, Ordering::Relaxed);
        }
    });
    Ok((callback, ReporterGuard(thread)))
}

fn persist_worker(
    journal: &mut Option<Journal>,
    status: &mut WorkerStatus,
    load: &impl Fn() -> Result<Journal>,
    next_open: &mut std::time::Instant,
) {
    if journal.is_none() && std::time::Instant::now() >= *next_open {
        *next_open = std::time::Instant::now() + Duration::from_secs(1);
        *journal = load().ok();
    }
    if journal
        .as_ref()
        .is_none_or(|j| j.save_worker(status).is_err())
    {
        status.telemetry_failures = status.telemetry_failures.saturating_add(1);
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
    let prior = journal
        .as_mut()
        .and_then(|j| j.snapshot().ok())
        .and_then(|s| s.worker);
    let mut next_open = std::time::Instant::now() + Duration::from_secs(1);
    let mut status = WorkerStatus {
        sampled_at: now(),
        state: "starting".into(),
        queue: None,
        nonempty_since: None,
        last_ack_at: prior.as_ref().and_then(|s| s.last_ack_at),
        last_ack_position: prior.as_ref().and_then(|s| s.last_ack_position),
        telemetry_failures: prior.map(|s| s.telemetry_failures).unwrap_or(0),
        consecutive_failures: 0,
        retry_seconds: 0,
    };
    persist_worker(&mut journal, &mut status, &load_journal, &mut next_open);
    loop {
        status.sampled_at = now();
        status.queue = Some(spool.status()?);
        let queue = status.queue.as_ref().expect("sample");
        if queue.pending == 0 {
            status.nonempty_since = None;
            status.state = "idle".into();
            status.consecutive_failures = 0;
            status.retry_seconds = 1;
            persist_worker(&mut journal, &mut status, &load_journal, &mut next_open);
            tokio::time::sleep(Duration::from_secs(1)).await;
            continue;
        }
        status.nonempty_since.get_or_insert(now());
        status.state = "delivering".into();
        status.retry_seconds = 0;
        persist_worker(&mut journal, &mut status, &load_journal, &mut next_open);
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
                persist_worker(&mut journal, &mut status, &load_journal, &mut next_open);
                tokio::time::sleep(Duration::from_secs(status.retry_seconds)).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
