//! Durable exact-byte send queue. No plaintext, keys, inferred remote state or erasure.
use crate::evidence_service::{self as service, Command, SignedReply, SignedRequest, MAX_REQUEST};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use std::{path::Path, time::Duration};

const PROFILE: i64 = 0x4b535002;
const SCHEMA: &str = "
CREATE TABLE state(singleton INTEGER PRIMARY KEY CHECK(singleton=1), scope TEXT NOT NULL, writer TEXT NOT NULL, audience TEXT NOT NULL, budget INTEGER NOT NULL CHECK(budget>0), next INTEGER NOT NULL CHECK(next>=0), previous TEXT, acknowledged_request BLOB, acknowledged_reply BLOB);
CREATE TABLE operations(position INTEGER PRIMARY KEY CHECK(position>=0), operation TEXT NOT NULL UNIQUE, manifest TEXT NOT NULL UNIQUE);
CREATE TABLE pending(position INTEGER PRIMARY KEY CHECK(position>=0), operation TEXT NOT NULL UNIQUE, manifest TEXT NOT NULL UNIQUE, request BLOB NOT NULL CHECK(length(request)>0 AND length(request)<=2101248));
PRAGMA application_id=1263751170;
PRAGMA user_version=2;
";
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("spool I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("spool SQLite: {0}")]
    Sql(rusqlite::Error),
    #[error("spool storage unavailable")]
    Unavailable,
    #[error("invalid spool or request: {0}")]
    Invalid(&'static str),
    #[error("spool capacity exhausted")]
    Full,
    #[error("operation identifier already retained")]
    ReusedOperation,
    #[error("spool frontier conflict")]
    Conflict,
    #[error("service proof rejected: {0}")]
    Proof(#[from] service::Failure),
}
impl From<rusqlite::Error> for Error {
    fn from(error: rusqlite::Error) -> Self {
        if let rusqlite::Error::SqliteFailure(code, _) = &error {
            use rusqlite::ErrorCode::*;
            match code.code {
                DiskFull => return Self::Full,
                DatabaseBusy
                | DatabaseLocked
                | SystemIoFailure
                | CannotOpen
                | ReadOnly
                | PermissionDenied
                | OperationInterrupted
                | FileLockingProtocolFailed
                | OutOfMemory => return Self::Unavailable,
                _ => {}
            }
        }
        Self::Sql(error)
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Enqueue {
    Queued,
    AlreadyPending,
    AlreadyAcknowledged,
}
type Result<T> = std::result::Result<T, Error>;
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frontier {
    pub next: u64,
    pub previous: Option<String>,
}
#[derive(Debug, Clone, serde::Serialize)]
pub struct Status {
    pub scope: String,
    pub writer: String,
    pub audience: String,
    pub budget: u64,
    pub next: u64,
    pub previous: Option<String>,
    pub pending: u64,
    pub pending_bytes: u64,
}
#[derive(Debug, Clone, serde::Serialize)]
pub struct Operation {
    pub position: u64,
    pub manifest: String,
    pub pending: bool,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Boundary {
    BeforeCommit,
    AfterCommit,
}
pub struct Spool {
    conn: Connection,
}
#[derive(Clone)]
struct State {
    scope: String,
    writer: String,
    audience: String,
    budget: u64,
    next: u64,
    previous: Option<String>,
    request: Option<Vec<u8>>,
    reply: Option<Vec<u8>>,
}
fn unsigned(row: &rusqlite::Row<'_>, index: usize) -> rusqlite::Result<u64> {
    let value: i64 = row.get(index)?;
    u64::try_from(value).map_err(|_| rusqlite::Error::IntegralValueOutOfRange(index, value))
}
fn state(conn: &Connection) -> Result<State> {
    if conn.query_row("SELECT count(*) FROM state", [], |r| unsigned(r, 0))? != 1 {
        return Err(Error::Invalid("state cardinality"));
    }
    Ok(conn.query_row("SELECT scope,writer,audience,budget,next,previous,acknowledged_request,acknowledged_reply FROM state WHERE singleton=1",[],|r|Ok(State{scope:r.get(0)?,writer:r.get(1)?,audience:r.get(2)?,budget:unsigned(r,3)?,next:unsigned(r,4)?,previous:r.get(5)?,request:r.get(6)?,reply:r.get(7)?}))?)
}
fn schema(conn: &Connection) -> Result<Vec<(String, String, String, String)>> {
    Ok(conn
        .prepare(
            "SELECT type,name,tbl_name,coalesce(sql,'') FROM sqlite_schema ORDER BY type,name",
        )?
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?
        .collect::<std::result::Result<_, _>>()?)
}
fn connection(path: &Path, wait: Duration) -> Result<Connection> {
    let meta = std::fs::symlink_metadata(path)?;
    if !meta.is_file() || meta.file_type().is_symlink() {
        return Err(Error::Invalid("regular file required"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o077 != 0 {
            return Err(Error::Invalid("owner-only file required"));
        }
    }
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    conn.busy_timeout(wait)?;
    conn.set_limit(
        rusqlite::limits::Limit::SQLITE_LIMIT_LENGTH,
        (2 * MAX_REQUEST + 65536) as i32,
    )?;
    Ok(conn)
}
fn coordinates(bytes: &[u8], st: &State) -> Result<(u64, Option<String>, String, String)> {
    let signed = SignedRequest::decode(bytes)?;
    if signed.request.scope != st.scope
        || signed.request.principal != st.writer
        || signed.request.audience != st.audience
    {
        return Err(Error::Invalid("destination or writer binding"));
    }
    let Command::Append {
        id,
        position,
        previous,
        ..
    } = signed.request.command
    else {
        return Err(Error::Invalid("append required"));
    };
    let cid = service::append_manifest(bytes)?.cid().to_string();
    Ok((position, previous, id, cid))
}
fn durability(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "PRAGMA synchronous=FULL; PRAGMA fullfsync=ON; PRAGMA checkpoint_fullfsync=ON;",
    )?;
    Ok(())
}
fn configure(conn: &Connection) -> Result<()> {
    durability(conn)?;
    if conn.query_row("PRAGMA journal_mode=WAL", [], |r| r.get::<_, String>(0))? != "wal" {
        return Err(Error::Invalid("WAL unavailable"));
    }
    Ok(())
}
impl Spool {
    /// Consistent metadata snapshot; this does not reserve the writer frontier.
    pub fn status(&mut self) -> Result<Status> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Deferred)?;
        let st = state(&tx)?;
        let (pending, pending_bytes) = tx.query_row(
            "SELECT count(*),coalesce(sum(length(request)),0) FROM pending",
            [],
            |r| Ok((unsigned(r, 0)?, unsigned(r, 1)?)),
        )?;
        tx.commit()?;
        Ok(Status {
            scope: st.scope,
            writer: st.writer,
            audience: st.audience,
            budget: st.budget,
            next: st.next,
            previous: st.previous,
            pending,
            pending_bytes,
        })
    }
    /// Retained local operation identity, not a proof of source-content equivalence.
    pub fn operation(&self, id: &str) -> Result<Option<Operation>> {
        if service::unhex(id, 16)?.len() != 16 {
            return Err(Error::Invalid("operation identifier"));
        }
        Ok(self.conn.query_row(
            "SELECT o.position,o.manifest,p.position IS NOT NULL FROM operations o LEFT JOIN pending p ON p.position=o.position WHERE o.operation=?", [id],
            |r| Ok(Operation { position: unsigned(r, 0)?, manifest: r.get(1)?, pending: r.get(2)? }),
        ).optional()?)
    }
    /// New namespace only. Interrupted initialization is retained for explicit recovery.
    pub fn create(
        path: &Path,
        scope: &str,
        writer: &str,
        audience: &str,
        budget: u64,
    ) -> Result<Self> {
        if service::unhex(scope, 32)?.len() != 32 || budget == 0 || budget > 1 << 40 {
            return Err(Error::Invalid("scope or budget"));
        }
        service::validate_shape(&service::Request {
            version: 1,
            scope: scope.into(),
            principal: writer.into(),
            audience: audience.into(),
            expires: Some(0),
            command: Command::Snapshot,
        })?;
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        if !parent.is_dir() {
            return Err(Error::Invalid("existing parent required"));
        }
        let name = path
            .file_name()
            .ok_or(Error::Invalid("filename required"))?
            .to_str()
            .ok_or(Error::Invalid("UTF-8 filename required"))?;
        for suffix in ["", "-wal", "-shm", "-journal"] {
            let candidate = parent.join(format!("{name}{suffix}"));
            match std::fs::symlink_metadata(candidate) {
                Ok(_) => return Err(Error::Invalid("namespace exists")),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
        }
        // surface-write: evidence-spool:database
        crate::persistence::write_new_owner_only(
            crate::persistence::SurfaceWrite::EvidenceSpool,
            path,
            &[],
        )?;
        let mut conn = connection(path, Duration::from_secs(5))?;
        durability(&conn)?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute_batch(SCHEMA)?;
        tx.execute(
            "INSERT INTO state VALUES(1,?,?,?,?,0,NULL,NULL,NULL)",
            params![scope, writer, audience, budget as i64],
        )?;
        tx.commit()?;
        std::fs::File::open(parent)?.sync_all()?;
        configure(&conn)?;
        Ok(Self { conn })
    }
    pub fn open(path: &Path) -> Result<Self> {
        Self::open_with_wait(path, Duration::from_secs(5))
    }
    /// Capture tolerates brief SQLite contention, including initial WAL setup.
    /// Filesystem I/O and the audit itself are not hard real-time operations.
    pub fn open_for_capture(path: &Path) -> Result<Self> {
        Self::open_with_wait(path, Duration::from_millis(100))
    }
    pub(crate) fn with_capture_wait<T, E: From<Error>>(
        &mut self,
        wait: Duration,
        operation: impl FnOnce(&mut Self) -> std::result::Result<T, E>,
    ) -> (std::result::Result<T, E>, Duration) {
        let mut spent = Duration::ZERO;
        let result = (|| {
            let previous: u32 = self
                .conn
                .query_row("PRAGMA busy_timeout", [], |r| r.get(0))
                .map_err(Error::from)?;
            self.conn
                .busy_handler(Some(capture_busy))
                .map_err(Error::from)?;
            let prior = CAPTURE_WAIT.with(|state| {
                state.replace(Some(CaptureWait {
                    remaining: wait.min(Duration::from_millis(100)),
                    spent: Duration::ZERO,
                }))
            });
            // The operation is synchronous and cannot move threads. Restore both
            // the thread-local callback state and caller policy even on unwind.
            let outcome =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| operation(self)));
            spent = CAPTURE_WAIT
                .with(|state| state.replace(prior).expect("capture wait installed").spent);
            let restored = self
                .conn
                .busy_timeout(Duration::from_millis(u64::from(previous)))
                .map_err(Error::from);
            match outcome {
                Err(panic) => std::panic::resume_unwind(panic),
                Ok(result) => {
                    restored?;
                    result
                }
            }
        })();
        (result, spent)
    }
    fn open_with_wait(path: &Path, wait: Duration) -> Result<Self> {
        let mut conn = connection(path, wait)?;
        let expected = Connection::open_in_memory()?;
        expected.execute_batch(SCHEMA)?;
        if conn.query_row("PRAGMA application_id", [], |r| r.get::<_, i64>(0))? != PROFILE
            || conn.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))? != 2
            || schema(&conn)? != schema(&expected)?
        {
            return Err(Error::Invalid("unrecognized schema"));
        }
        // One consistent audit, including when another process enqueues concurrently.
        let tx = conn.transaction_with_behavior(TransactionBehavior::Deferred)?;
        audit(&tx)?;
        tx.commit()?;
        configure(&conn)?;
        Ok(Self { conn })
    }
    pub fn frontier(&self) -> Result<Frontier> {
        let st = state(&self.conn)?;
        Ok(Frontier {
            next: st.next,
            previous: st.previous,
        })
    }
    pub fn pending_bytes(&self) -> Result<u64> {
        Ok(self.conn.query_row(
            "SELECT coalesce(sum(length(request)),0) FROM pending",
            [],
            |r| unsigned(r, 0),
        )?)
    }
    pub fn head(&self) -> Result<Option<Vec<u8>>> {
        Ok(self
            .conn
            .query_row(
                "SELECT request FROM pending ORDER BY position LIMIT 1",
                [],
                |r| r.get(0),
            )
            .optional()?)
    }
    /// Distinguishes new, pending and acknowledged exact retries; never regenerates bytes.
    pub fn enqueue(&mut self, bytes: &[u8]) -> Result<Enqueue> {
        self.enqueue_observed(bytes, &mut |_| {})
    }
    pub fn enqueue_observed(
        &mut self,
        bytes: &[u8],
        observe: &mut dyn FnMut(Boundary),
    ) -> Result<Enqueue> {
        if bytes.len() > MAX_REQUEST {
            return Err(Error::Invalid("request size"));
        }
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let result = enqueue_in(&tx, bytes, None)?;
        if result != Enqueue::Queued {
            return Ok(result);
        }
        observe(Boundary::BeforeCommit);
        tx.commit()?;
        observe(Boundary::AfterCommit);
        Ok(Enqueue::Queued)
    }
    /// Reserve the writer before deriving its next request. The crate-local
    /// preparer runs once, synchronously, under the same transaction as enqueue.
    #[cfg(feature = "v2-crypto")]
    pub(crate) fn enqueue_generated<T, E: From<Error>>(
        &mut self,
        operation: &str,
        prepare: impl FnOnce(Status) -> std::result::Result<(Vec<u8>, T), E>,
    ) -> std::result::Result<T, E> {
        service::unhex(operation, 16).map_err(Error::from)?;
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(Error::from)?;
        let st = state(&tx)?;
        let exists: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM operations WHERE operation=?)",
                [operation],
                |r| r.get(0),
            )
            .map_err(Error::from)?;
        if exists {
            return Err(Error::ReusedOperation.into());
        }
        let (pending, pending_bytes) = tx
            .query_row(
                "SELECT count(*),coalesce(sum(length(request)),0) FROM pending",
                [],
                |r| Ok((unsigned(r, 0)?, unsigned(r, 1)?)),
            )
            .map_err(Error::from)?;
        let (bytes, value) = prepare(Status {
            scope: st.scope,
            writer: st.writer,
            audience: st.audience,
            budget: st.budget,
            next: st.next,
            previous: st.previous,
            pending,
            pending_bytes,
        })?;
        if enqueue_in(&tx, &bytes, Some(operation))? != Enqueue::Queued {
            return Err(Error::ReusedOperation.into());
        }
        tx.commit().map_err(Error::from)?;
        Ok(value)
    }
    /// Only a verified reply for the current head can release queued bytes.
    pub fn acknowledge(&mut self, reply: &[u8]) -> Result<()> {
        self.acknowledge_observed(reply, &mut |_| {})
    }
    pub fn acknowledge_observed(
        &mut self,
        reply: &[u8],
        observe: &mut dyn FnMut(Boundary),
    ) -> Result<()> {
        if reply.len() > 65536 {
            return Err(Error::Invalid("reply size"));
        }
        let signed: SignedReply =
            serde_json::from_slice(reply).map_err(|_| Error::Invalid("reply JSON"))?;
        if signed.bytes()? != reply {
            return Err(Error::Invalid("canonical reply required"));
        }
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let st = state(&tx)?;
        let request: Vec<u8> = tx
            .query_row(
                "SELECT request FROM pending ORDER BY position LIMIT 1",
                [],
                |r| r.get(0),
            )
            .optional()?
            .ok_or(Error::Invalid("empty queue"))?;
        let (position, _, _, _) = coordinates(&request, &st)?;
        service::admitted_manifest(&request, &signed, &st.audience)?;
        tx.execute(
            "UPDATE state SET acknowledged_request=?,acknowledged_reply=? WHERE singleton=1",
            params![request, reply],
        )?;
        tx.execute("DELETE FROM pending WHERE position=?", [position as i64])?;
        observe(Boundary::BeforeCommit);
        tx.commit()?;
        observe(Boundary::AfterCommit);
        Ok(())
    }
}
fn enqueue_in(
    tx: &rusqlite::Transaction<'_>,
    bytes: &[u8],
    expected_operation: Option<&str>,
) -> Result<Enqueue> {
    if bytes.len() > MAX_REQUEST {
        return Err(Error::Invalid("request size"));
    }
    let st = state(tx)?;
    let (position, previous, id, cid) = coordinates(bytes, &st)?;
    if expected_operation.is_some_and(|expected| expected != id) {
        return Err(Error::Invalid("prepared operation binding"));
    }
    let old: Option<(u64, String)> = tx
        .query_row(
            "SELECT position,manifest FROM operations WHERE operation=?",
            [&id],
            |r| Ok((unsigned(r, 0)?, r.get(1)?)),
        )
        .optional()?;
    if let Some((old_position, old_cid)) = old {
        if old_position != position || old_cid != cid {
            return Err(Error::Conflict);
        }
        let pending: Option<Vec<u8>> = tx
            .query_row(
                "SELECT request FROM pending WHERE position=?",
                [position as i64],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(pending) = pending {
            return if pending == bytes {
                Ok(Enqueue::AlreadyPending)
            } else {
                Err(Error::Invalid("pending commitment"))
            };
        }
        if let Some(acknowledged) = &st.request {
            if coordinates(acknowledged, &st)?.0 >= position {
                return Ok(Enqueue::AlreadyAcknowledged);
            }
        }
        return Err(Error::Invalid(
            "operation lacks pending bytes or acknowledgment",
        ));
    }
    if position != st.next || previous != st.previous {
        return Err(Error::Conflict);
    }
    let used: u64 = tx.query_row(
        "SELECT coalesce(sum(length(request)),0) FROM pending",
        [],
        |r| unsigned(r, 0),
    )?;
    if used.checked_add(bytes.len() as u64).ok_or(Error::Full)? > st.budget {
        return Err(Error::Full);
    }
    tx.execute(
        "INSERT INTO operations VALUES(?,?,?)",
        params![position as i64, id, cid],
    )?;
    tx.execute(
        "INSERT INTO pending VALUES(?,?,?,?)",
        params![position as i64, id, cid, bytes],
    )?;
    let next = position
        .checked_add(1)
        .filter(|n| *n <= crate::evidence::MAX_SAFE_INTEGER as u64)
        .ok_or(Error::Invalid("frontier exhausted"))?;
    tx.execute(
        "UPDATE state SET next=?,previous=? WHERE singleton=1",
        params![next as i64, cid],
    )?;
    Ok(Enqueue::Queued)
}

fn audit(conn: &Connection) -> Result<()> {
    let st = state(conn)?;
    service::validate_shape(&service::Request {
        version: 1,
        scope: st.scope.clone(),
        principal: st.writer.clone(),
        audience: st.audience.clone(),
        expires: Some(0),
        command: Command::Snapshot,
    })?;
    let mut count = 0u64;
    let mut operations =
        conn.prepare("SELECT position,operation,manifest FROM operations ORDER BY position")?;
    let mut entries = operations.query([])?;
    while let Some(row) = entries.next()? {
        let id: String = row.get(1)?;
        let raw = service::unhex(&id, 16)?;
        let cid: String = row.get(2)?;
        if unsigned(row, 0)? != count
            || raw.len() != 16
            || service::hex(&raw) != id
            || cid.parse::<atproto_dasl::Cid>().is_err()
        {
            return Err(Error::Invalid("operation registry"));
        }
        count += 1;
    }
    if count != st.next {
        return Err(Error::Invalid("operation registry frontier"));
    }
    if st.budget == 0 || st.budget > 1 << 40 {
        return Err(Error::Invalid("budget"));
    }
    let (mut next, mut previous) = match (&st.request, &st.reply) {
        (None, None) => (0, None),
        (Some(request), Some(reply)) => {
            let (position, _, id, cid) = coordinates(request, &st)?;
            let registered: (String, String) = conn.query_row(
                "SELECT operation,manifest FROM operations WHERE position=?",
                [position as i64],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?;
            if registered != (id, cid.clone()) {
                return Err(Error::Invalid("acknowledged operation registry"));
            }
            let signed: SignedReply =
                serde_json::from_slice(reply).map_err(|_| Error::Invalid("retained reply"))?;
            if signed.bytes()? != *reply {
                return Err(Error::Invalid("retained canonical reply"));
            }
            service::admitted_manifest(request, &signed, &st.audience)?;
            (position + 1, Some(cid))
        }
        _ => return Err(Error::Invalid("partial acknowledgment")),
    };
    let mut used = 0u64;
    let mut stmt =
        conn.prepare("SELECT p.position,p.operation,p.manifest,p.request,o.operation,o.manifest FROM pending p LEFT JOIN operations o ON o.position=p.position ORDER BY p.position")?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        let bytes: Vec<u8> = row.get(3)?;
        let (position, prev, id, cid) = coordinates(&bytes, &st)?;
        if position != next
            || prev != previous
            || position != unsigned(row, 0)?
            || id != row.get::<_, String>(1)?
            || cid != row.get::<_, String>(2)?
            || Some(id.clone()) != row.get::<_, Option<String>>(4)?
            || Some(cid.clone()) != row.get::<_, Option<String>>(5)?
        {
            return Err(Error::Invalid("queue chain"));
        }
        next += 1;
        previous = Some(cid);
        used = used.checked_add(bytes.len() as u64).ok_or(Error::Full)?;
    }
    if next != st.next || previous != st.previous || used > st.budget {
        return Err(Error::Invalid("frontier or capacity"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn capture_wait_restores_policy_and_thread_state_after_unwind() {
        let conn = Connection::open_in_memory().unwrap();
        conn.busy_timeout(Duration::from_secs(5)).unwrap();
        let mut spool = Spool { conn };
        let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _: (Result<()>, Duration) =
                spool.with_capture_wait(Duration::from_millis(20), |_| panic!("fixture unwind"));
        }));
        assert!(panicked.is_err());
        let wait: u32 = spool
            .conn
            .query_row("PRAGMA busy_timeout", [], |r| r.get(0))
            .unwrap();
        assert_eq!(wait, 5000);
        assert!(CAPTURE_WAIT.with(|s| s.borrow().is_none()));
        let (result, spent): (Result<()>, Duration) =
            spool.with_capture_wait(Duration::ZERO, |_| Ok(()));
        assert!(result.is_ok());
        assert_eq!(spent, Duration::ZERO);
    }
    #[test]
    fn physical_sqlite_full_is_explicit_and_atomic() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("spool.sqlite");
        let writer = crate::sign::Identity::generate();
        let server = crate::sign::Identity::generate();
        let mut spool = Spool::create(
            &path,
            &service::hex(&[1; 32]),
            writer.did().as_str(),
            server.did().as_str(),
            10_000_000,
        )
        .unwrap();
        let pages: i64 = spool
            .conn
            .pragma_query_value(None, "page_count", |r| r.get(0))
            .unwrap();
        spool
            .conn
            .pragma_update(None, "max_page_count", pages)
            .unwrap();
        let raw = SignedRequest::sign(
            service::Request {
                version: 1,
                scope: service::hex(&[1; 32]),
                principal: writer.did().to_string(),
                audience: server.did().to_string(),
                expires: None,
                command: Command::Append {
                    id: service::hex(&[2; 16]),
                    position: 0,
                    previous: None,
                    ciphertext: service::hex(&vec![7; 100_000]),
                },
            },
            &writer,
        )
        .unwrap()
        .bytes()
        .unwrap();
        assert!(matches!(spool.enqueue(&raw), Err(Error::Full)));
        assert_eq!(spool.frontier().unwrap().next, 0);
        assert!(spool.head().unwrap().is_none());
        drop(spool);
        assert_eq!(Spool::open(&path).unwrap().frontier().unwrap().next, 0);
    }
}

// rusqlite's busy callback accepts a function pointer. Thread-local state scopes
// its budget to one synchronous capture admission without unsafe FFI or shared
// process-global mutable state. The callback never calls SQLite.
struct CaptureWait {
    remaining: Duration,
    spent: Duration,
}
thread_local! { static CAPTURE_WAIT:std::cell::RefCell<Option<CaptureWait>>=const {std::cell::RefCell::new(None)}; }
fn capture_busy(_: i32) -> bool {
    CAPTURE_WAIT.with(|state| {
        let mut state = state.borrow_mut();
        let Some(wait) = state.as_mut() else {
            return false;
        };
        if wait.remaining.is_zero() {
            return false;
        }
        let started = std::time::Instant::now();
        std::thread::sleep(wait.remaining.min(Duration::from_millis(2)));
        let elapsed = started.elapsed();
        wait.remaining = wait.remaining.saturating_sub(elapsed);
        wait.spent = wait.spent.saturating_add(elapsed);
        true
    })
}
