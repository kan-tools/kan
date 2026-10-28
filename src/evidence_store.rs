//! Experimental opaque ledger. See `.design/kan-v2-storage.md` and RFC 4.
//! This layer assumes its caller has authenticated admission. It cannot decrypt.

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    time::Duration,
};

use atproto_dasl::{Cid, Ipld};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use sha2::{Digest, Sha256};

use crate::evidence::{self, Decoded, Kind, Record};

pub const MAX_CHUNK: usize = 4 * 1024 * 1024;
const APPLICATION_ID: i64 = 0x4b563201;
// Two range probes use the existing scope-leading indexes, including when every
// retained row has the requested scope. `scope != ?` scans that entire index.
const FOREIGN_SCOPE: &str = "SELECT EXISTS(SELECT 1 FROM commits WHERE scope < ?1) OR EXISTS(SELECT 1 FROM commits WHERE scope > ?1)";
const SCHEMA: &str = "
CREATE TABLE objects(cid TEXT PRIMARY KEY, bytes BLOB NOT NULL CHECK(length(bytes)>0 AND length(bytes)<=4194304)) WITHOUT ROWID;
CREATE TABLE commits(
 sequence INTEGER PRIMARY KEY, cid TEXT NOT NULL UNIQUE, scope BLOB NOT NULL, writer TEXT NOT NULL,
 operation BLOB NOT NULL, position INTEGER NOT NULL, previous TEXT,
 manifest BLOB NOT NULL CHECK(length(manifest)>0 AND length(manifest)<=65536),
 receipt BLOB NOT NULL CHECK(length(receipt)>0 AND length(receipt)<=65536),
 UNIQUE(scope,writer,operation), UNIQUE(scope,writer,position));
CREATE TABLE bindings(
 scope BLOB NOT NULL, writer TEXT NOT NULL, slot BLOB NOT NULL, ciphertext TEXT NOT NULL REFERENCES objects(cid),
 length INTEGER NOT NULL, first_manifest TEXT NOT NULL REFERENCES commits(cid),
 PRIMARY KEY(scope,writer,slot)) WITHOUT ROWID;
PRAGMA application_id=1263940097;
PRAGMA user_version=1;
";

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Sql(#[from] rusqlite::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Record(#[from] evidence::Error),
    #[error("invalid input: {0}")]
    Invalid(&'static str),
    #[error("conflict: {0}")]
    Conflict(&'static str),
    #[error("missing object: {0}")]
    Missing(String),
    #[error("missing commit: {0}")]
    MissingCommit(u64),
    #[error("corrupt evidence: {0}")]
    Corrupt(String),
}

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    pub through: u64,
    pub tip: Option<Cid>,
}

#[derive(Debug)]
pub struct Committed {
    pub sequence: u64,
    pub manifest: Record,
    pub receipt: Record,
    pub duplicate: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Boundary {
    ObjectInserted,
    ObjectDurable,
    ManifestInserted,
    BindingsInserted,
    BeforeCommit,
    AfterCommit,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Verification {
    pub objects: u64,
    pub commits: u64,
    pub bytes: u64,
    pub snapshot: Snapshot,
}

/// Owns one connection. SQLite serializes concurrent writers, including processes.
/// `tests/evidence_store.rs` exercises commit, crash recovery and independent reads.
pub struct Ledger {
    conn: Connection,
}

/// Read-only, pinned raw evidence view. Does not certify archive completeness or
/// derived indexes. Drop promptly: a live source may retain WAL history meanwhile.
pub struct RecoveryReader {
    ledger: Ledger,
    source: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryBoundary {
    ObjectCopied,
    CommitCopied,
    Verified,
    Committed,
}

/// Fault harness boundaries; observers do not establish durability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitializationBoundary {
    FileCreated,
    SchemaWritten,
    SchemaCommitted,
    Ready,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackupBoundary {
    Copied,
    Normalized,
}

// Bound SQLite's own value/row materialization, not just returned Rust buffers.
// Legitimate objects need 4 MiB plus their key; manifest rows are much smaller.
const RECOVERY_SQLITE_LENGTH_LIMIT: i32 = (MAX_CHUNK * 2) as i32;

// Output bounds supplement the connection's SQLite allocation limit, including
// damaged rows written with CHECK constraints disabled.
const RAW_COMMITS: &str = "SELECT sequence,length(manifest),substr(manifest,1,65536),length(receipt),substr(receipt,1,65536) FROM commits NOT INDEXED";

fn raw_commit(row: &rusqlite::Row<'_>) -> Result<Committed> {
    let sequence = u64::try_from(row.get::<_, i64>(0)?)
        .ok()
        .filter(|n| *n > 0)
        .ok_or_else(|| Error::Corrupt("sequence".into()))?;
    for column in [1, 3] {
        if !(1..=65536).contains(&row.get::<_, i64>(column)?) {
            return Err(Error::Corrupt(format!(
                "record length at sequence {sequence}"
            )));
        }
    }
    let manifest = known(&row.get::<_, Vec<u8>>(2)?, Kind::Manifest)?;
    let receipt = known(&row.get::<_, Vec<u8>>(4)?, Kind::Receipt)?;
    if !evidence::binds(&receipt, &manifest) {
        return Err(Error::Corrupt(format!("receipt at sequence {sequence}")));
    }
    Ok(Committed {
        sequence,
        manifest,
        receipt,
        duplicate: false,
    })
}

impl RecoveryReader {
    /// Open a database FILE, including a standalone backup, without consulting
    /// derived fields. SQLite must still be able to read its schema/raw tables.
    /// WAL mode may initialize coordination sidecars; read-only media without
    /// usable sidecars and hot rollback journals fail closed. Preserve all source
    /// media together and perform any crash recovery on a separate writable copy.
    pub fn open(path: &Path) -> Result<Self> {
        private_file(path)?;
        let source = std::fs::canonicalize(path)?;
        let ledger = Ledger {
            // surface-write: evidence-recovery-source:database-wal,evidence-recovery-source:database-shm
            conn: crate::persistence::open_sqlite_recovery_source(
                crate::persistence::SurfaceWrite::EvidenceRecoverySource,
                &source,
            )?,
        };
        ledger.conn.set_limit(
            rusqlite::limits::Limit::SQLITE_LIMIT_LENGTH,
            RECOVERY_SQLITE_LENGTH_LIMIT,
        )?;
        ledger.conn.busy_timeout(Duration::from_secs(5))?;
        ledger.conn.execute_batch("PRAGMA query_only=ON; BEGIN;")?;
        // Reading the profile pins the transaction before the handle escapes.
        ledger.check_schema()?;
        Ok(Self { ledger, source })
    }

    pub fn record(&self, sequence: u64) -> Result<Committed> {
        let n = i64::try_from(sequence).map_err(|_| Error::Invalid("sequence overflow"))?;
        if n == 0 {
            return Err(Error::Invalid("sequence starts at one"));
        }
        let mut stmt = self
            .ledger
            .conn
            .prepare(&format!("{RAW_COMMITS} WHERE sequence=?"))?;
        let mut rows = stmt.query([n])?;
        raw_commit(rows.next()?.ok_or(Error::MissingCommit(sequence))?)
    }

    pub fn read_object(&self, id: &Cid) -> Result<Vec<u8>> {
        // WITHOUT ROWID key seeks can materialize an entire corrupt object row
        // before SQLITE_LIMIT_LENGTH applies. This offline recovery path scans
        // keys instead; NOT INDEXED/+cid prohibit an index seek. Ordinary Ledger
        // reads retain their indexed path. Memory is bounded; recovery I/O is not
        // a constant-time point lookup.
        let row: Option<(i64, Vec<u8>)> = self
            .ledger
            .conn
            .query_row(
                "SELECT length(bytes),substr(bytes,1,4194304) FROM objects NOT INDEXED WHERE +cid=?",
                [id.to_string()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let (length, bytes) = row.ok_or_else(|| Error::Missing(id.to_string()))?;
        if !(1..=MAX_CHUNK as i64).contains(&length) || ciphertext_cid(&bytes) != *id {
            return Err(Error::Corrupt(id.to_string()));
        }
        Ok(bytes)
    }

    /// Build a NEW standalone SQLite file. Failure may retain an incomplete file
    /// or a complete file after a post-commit error; retry with a fresh destination.
    /// Never rewrites source evidence or automatically promotes the output.
    pub fn rebuild(&self, destination: &Path) -> Result<Verification> {
        self.rebuild_observed(destination, &mut |_| {})
    }

    /// Fault-injection hooks do not certify durability.
    pub fn rebuild_observed(
        &self,
        destination: &Path,
        observe: &mut dyn FnMut(RecoveryBoundary),
    ) -> Result<Verification> {
        let destination = sqlite_destination(&self.source, destination)?;
        // surface-write: evidence-recovery:archive.sqlite
        crate::persistence::write_new_owner_only(
            crate::persistence::SurfaceWrite::EvidenceRecovery,
            &destination,
            &[],
        )?;
        let target = Ledger {
            conn: Connection::open_with_flags(&destination, OpenFlags::SQLITE_OPEN_READ_WRITE)?,
        };
        target.conn.execute_batch("PRAGMA journal_mode=DELETE; PRAGMA foreign_keys=ON; PRAGMA synchronous=FULL; PRAGMA fullfsync=ON;")?;
        let tx = target.conn.unchecked_transaction()?;
        tx.execute_batch(SCHEMA)?;
        {
            let mut stmt = self.ledger.conn.prepare(
                "SELECT cid,length(bytes),substr(bytes,1,4194304) FROM objects ORDER BY cid",
            )?;
            let mut rows = stmt.query([])?;
            while let Some(row) = rows.next()? {
                let id: String = row.get(0)?;
                let length: i64 = row.get(1)?;
                let bytes: Vec<u8> = row.get(2)?;
                if !(1..=MAX_CHUNK as i64).contains(&length)
                    || ciphertext_cid(&bytes).to_string() != id
                {
                    return Err(Error::Corrupt(id));
                }
                tx.execute("INSERT INTO objects VALUES(?,?)", params![id, bytes])?;
                observe(RecoveryBoundary::ObjectCopied);
            }
        }
        {
            let mut stmt = self
                .ledger
                .conn
                .prepare(&format!("{RAW_COMMITS} ORDER BY sequence"))?;
            let mut rows = stmt.query([])?;
            let mut expected = 1;
            while let Some(row) = rows.next()? {
                let raw = raw_commit(row)?;
                if raw.sequence != expected {
                    return Err(Error::Corrupt("sequence gap".into()));
                }
                expected += 1;
                let m = &raw.manifest;
                let b = m.body();
                let id = m.cid().to_string();
                tx.execute(
                    "INSERT INTO commits VALUES(?,?,?,?,?,?,?,?,?)",
                    params![
                        raw.sequence as i64,
                        id,
                        blob(&b["scopeToken"]),
                        writer(m),
                        blob(&b["operation"]),
                        number(&b["position"]),
                        optional_cid(&b["previous"]),
                        m.bytes(),
                        raw.receipt.bytes()
                    ],
                )?;
                for e in entries(m) {
                    tx.execute("INSERT INTO bindings VALUES(?,?,?,?,?,?) ON CONFLICT(scope,writer,slot) DO NOTHING",
                        params![blob(&b["scopeToken"]), writer(m), blob(&e["slot"]), cid(&e["ciphertext"]), number(&e["length"]), id])?;
                }
                observe(RecoveryBoundary::CommitCopied);
            }
        }
        // Verify before publishing even the profile marker. This also rejects
        // raw histories with missing predecessors or conflicting slot reuse.
        let expected = target.verify_contents()?;
        observe(RecoveryBoundary::Verified);
        tx.commit()?;
        observe(RecoveryBoundary::Committed);
        drop(target);
        std::fs::File::open(&destination)?.sync_all()?;
        std::fs::File::open(parent_directory(&destination))?.sync_all()?;
        let actual = Ledger::verify_file(&destination)?;
        if actual != expected {
            return Err(Error::Corrupt("rebuild verification changed".into()));
        }
        Ok(actual)
    }
}

fn sqlite_paths(path: &Path) -> Vec<PathBuf> {
    let mut paths = vec![path.to_path_buf()];
    for suffix in ["-journal", "-wal", "-shm"] {
        let mut name = path.as_os_str().to_os_string();
        name.push(suffix);
        paths.push(PathBuf::from(name));
    }
    paths
}

fn same_existing_file(a: &Path, b: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        matches!((std::fs::metadata(a), std::fs::metadata(b)), (Ok(a), Ok(b)) if a.dev() == b.dev() && a.ino() == b.ino())
    }
    #[cfg(not(unix))]
    {
        matches!((std::fs::canonicalize(a), std::fs::canonicalize(b)), (Ok(a), Ok(b)) if a == b)
    }
}

fn sqlite_destination(source: &Path, destination: &Path) -> Result<PathBuf> {
    let parent = std::fs::canonicalize(parent_directory(destination))?;
    let name = destination
        .file_name()
        .ok_or(Error::Invalid("destination filename"))?;
    let destination = parent.join(name);
    let target_paths = sqlite_paths(&destination);
    let source_paths = sqlite_paths(source);
    // Conservative ASCII case comparison also protects case-insensitive volumes.
    if target_paths.iter().any(|target| {
        source_paths.iter().any(|source| {
            target
                .as_os_str()
                .as_encoded_bytes()
                .eq_ignore_ascii_case(source.as_os_str().as_encoded_bytes())
        })
    }) {
        return Err(Error::Invalid("destination overlaps source SQLite files"));
    }
    // Resolve an existing base through filesystem aliases (including Unicode
    // spelling/case aliases on macOS and hard links on Unix), before a sidecar
    // that does not exist yet can be created under that base's name.
    if let Some(name) = name.to_str() {
        for suffix in ["-journal", "-wal", "-shm"] {
            if name.len() >= suffix.len()
                && name.as_bytes()[name.len() - suffix.len()..]
                    .eq_ignore_ascii_case(suffix.as_bytes())
            {
                let base = parent.join(&name[..name.len() - suffix.len()]);
                if same_existing_file(&base, source) {
                    return Err(Error::Invalid("destination aliases source SQLite sidecar"));
                }
            }
        }
    }
    unused_sqlite_sidecars(&destination)?;
    Ok(destination)
}

fn unused_sqlite_sidecars(destination: &Path) -> Result<()> {
    // A new main filename alone is insufficient: SQLite owns these sibling names.
    for path in sqlite_paths(destination).iter().skip(1) {
        match std::fs::symlink_metadata(path) {
            Ok(_) => return Err(Error::Invalid("destination SQLite sidecar already exists")),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

pub fn ciphertext_cid(bytes: &[u8]) -> Cid {
    let mut raw = vec![1, 0x55, 0x12, 0x20];
    raw.extend(Sha256::digest(bytes));
    Cid::from_bytes(&raw).expect("fixed raw SHA256 CID")
}

fn known(bytes: &[u8], kind: Kind) -> Result<Record> {
    match evidence::decode(bytes)? {
        Decoded::Known(r) if r.kind() == kind => Ok(r),
        _ => Err(Error::Invalid("wrong or unsupported record kind")),
    }
}

fn blob(value: &Ipld) -> &[u8] {
    value.as_bytes().expect("validated bytes")
}
fn number(value: &Ipld) -> i64 {
    match value {
        Ipld::Integer(n) => *n as i64,
        _ => unreachable!("validated integer"),
    }
}
fn text(value: &Ipld) -> &str {
    match value {
        Ipld::String(s) => s,
        _ => unreachable!("validated string"),
    }
}
fn cid(value: &Ipld) -> String {
    match value {
        Ipld::Link(c) => c.to_string(),
        _ => unreachable!("validated link"),
    }
}
fn optional_cid(value: &Ipld) -> Option<String> {
    if matches!(value, Ipld::Null) {
        None
    } else {
        Some(cid(value))
    }
}
fn writer(record: &Record) -> &str {
    let Ipld::Map(author) = &record.body()["writer"] else {
        unreachable!("validated author")
    };
    text(&author["principal"])
}
fn entries(record: &Record) -> impl Iterator<Item = &BTreeMap<String, Ipld>> {
    let Ipld::List(entries) = &record.body()["entries"] else {
        unreachable!("validated entries")
    };
    entries.iter().map(|entry| match entry {
        Ipld::Map(e) => e,
        _ => unreachable!("validated entry"),
    })
}

fn parent_directory(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn private_file(path: &Path) -> Result<()> {
    let meta = std::fs::symlink_metadata(path)?;
    if !meta.is_file() || meta.file_type().is_symlink() {
        return Err(Error::Invalid("expected regular database file"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o077 != 0 {
            return Err(Error::Invalid("database must be owner-only"));
        }
    }
    Ok(())
}

fn configure(conn: &Connection) -> Result<()> {
    conn.busy_timeout(Duration::from_secs(5))?;
    conn.execute_batch("PRAGMA foreign_keys=ON; PRAGMA synchronous=FULL; PRAGMA fullfsync=ON; PRAGMA checkpoint_fullfsync=ON;")?;
    let mode: String = conn.query_row("PRAGMA journal_mode=WAL", [], |r| r.get(0))?;
    if mode != "wal" {
        return Err(Error::Invalid("WAL unavailable"));
    }
    Ok(())
}

impl Ledger {
    pub fn create(root: &Path) -> Result<Self> {
        Self::create_observed(root, &mut |_| {})
    }

    pub fn create_observed(
        root: &Path,
        observe: &mut dyn FnMut(InitializationBoundary),
    ) -> Result<Self> {
        if !root.exists() {
            if !parent_directory(root).is_dir() {
                return Err(Error::Invalid("archive parent must already exist"));
            }
            // surface-write: evidence-db:archive.sqlite
            crate::persistence::create_dir_all(
                crate::persistence::SurfaceWrite::EvidenceArchive,
                root,
            )?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                // surface-write: evidence-db:archive.sqlite
                crate::persistence::set_permissions(
                    crate::persistence::SurfaceWrite::EvidenceArchive,
                    root,
                    std::fs::Permissions::from_mode(0o700),
                )?;
            }
        }
        let meta = std::fs::symlink_metadata(root)?;
        if !meta.is_dir() || meta.file_type().is_symlink() {
            return Err(Error::Invalid("expected archive directory"));
        }
        let path = root.join("archive.sqlite");
        unused_sqlite_sidecars(&path)?;
        // surface-write: evidence-db:archive.sqlite
        crate::persistence::write_new_owner_only(
            crate::persistence::SurfaceWrite::EvidenceArchive,
            &path,
            &[],
        )?;
        observe(InitializationBoundary::FileCreated);
        Self::initialize_empty(root, &path, observe)
    }

    /// Explicitly adopt an empty interrupted SQLite initialization, or reopen a
    /// recognized archive after a lost initialization acknowledgment. SQLite may
    /// recover its journal/WAL; this is not a forensic read-only operation.
    /// Empty foreign SQLite files are indistinguishable and require this opt-in.
    pub fn resume_initialization(root: &Path) -> Result<Self> {
        let path = root.join("archive.sqlite");
        private_file(&path)?;
        let conn = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
        let app: i64 = conn.query_row("PRAGMA application_id", [], |r| r.get(0))?;
        let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        drop(conn);
        if app == APPLICATION_ID && version == 1 {
            let ledger = Self::open(root)?;
            // A lost acknowledgment may precede the original directory syncs.
            std::fs::File::open(root)?.sync_all()?;
            std::fs::File::open(parent_directory(root))?.sync_all()?;
            return Ok(ledger);
        }
        Self::initialize_empty(root, &path, &mut |_| {})
    }

    fn initialize_empty(
        root: &Path,
        path: &Path,
        observe: &mut dyn FnMut(InitializationBoundary),
    ) -> Result<Self> {
        let mut conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
        conn.busy_timeout(Duration::from_secs(5))?;
        conn.execute_batch("PRAGMA synchronous=FULL; PRAGMA fullfsync=ON;")?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let app: i64 = tx.query_row("PRAGMA application_id", [], |r| r.get(0))?;
        let version: i64 = tx.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        let tables: i64 = tx.query_row("SELECT count(*) FROM sqlite_schema", [], |r| r.get(0))?;
        if app != 0 || version != 0 || tables != 0 {
            return Err(Error::Invalid(
                "resume requires an empty unversioned database or a recognized archive",
            ));
        }
        let integrity: String = tx.query_row("PRAGMA integrity_check", [], |r| r.get(0))?;
        if integrity != "ok" {
            return Err(Error::Corrupt(integrity));
        }
        tx.execute_batch(SCHEMA)?;
        observe(InitializationBoundary::SchemaWritten);
        tx.commit()?;
        observe(InitializationBoundary::SchemaCommitted);
        configure(&conn)?;
        std::fs::File::open(root)?.sync_all()?;
        std::fs::File::open(parent_directory(root))?.sync_all()?;
        let ledger = Self { conn };
        ledger.check_schema()?;
        observe(InitializationBoundary::Ready);
        Ok(ledger)
    }

    pub fn open(root: &Path) -> Result<Self> {
        let path = root.join("archive.sqlite");
        private_file(&path)?;
        let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
        let ledger = Self { conn };
        ledger.check_schema()?;
        ledger.check_write_schema()?;
        // Reject malformed profile-marked files before changing journal mode.
        // SQLite may still recover/checkpoint preexisting journal/WAL media.
        // Audit once on opening; keep this connection for bounded hot-path writes.
        // Corrupt derived bindings cannot silently become a new empty namespace.
        ledger.verify()?;
        configure(&ledger.conn)?;
        Ok(ledger)
    }

    fn check_schema(&self) -> Result<()> {
        let app: i64 = self
            .conn
            .query_row("PRAGMA application_id", [], |r| r.get(0))?;
        let version: i64 = self
            .conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))?;
        if app != APPLICATION_ID || version != 1 {
            return Err(Error::Invalid("unknown database profile"));
        }
        Ok(())
    }

    /// Writable admission is stricter than raw recovery: even an empty archive
    /// must have exactly the constraints/indexes we rely on and no extra triggers.
    fn check_write_schema(&self) -> Result<()> {
        let expected = Connection::open_in_memory()?;
        expected.execute_batch(SCHEMA)?;
        let query = "SELECT type,name,tbl_name,sql FROM main.sqlite_schema ORDER BY type,name";
        let mut expected_stmt = expected.prepare(query)?;
        let mut actual_stmt = self.conn.prepare(query)?;
        let mut expected_rows = expected_stmt.query([])?;
        let mut actual_rows = actual_stmt.query([])?;
        loop {
            match (expected_rows.next()?, actual_rows.next()?) {
                (None, None) => return Ok(()),
                (Some(expected), Some(actual)) => {
                    for column in 0..4 {
                        if expected.get::<_, Option<String>>(column)?
                            != actual.get::<_, Option<String>>(column)?
                        {
                            return Err(Error::Invalid("unsupported writable archive schema"));
                        }
                    }
                }
                _ => return Err(Error::Invalid("unsupported writable archive schema")),
            }
        }
    }

    pub fn stage(&mut self, bytes: &[u8]) -> Result<Cid> {
        self.stage_observed(bytes, &mut |_| {})
    }

    /// Observer exists for external fault harnesses; it cannot certify durability.
    pub fn stage_observed(
        &mut self,
        bytes: &[u8],
        observe: &mut dyn FnMut(Boundary),
    ) -> Result<Cid> {
        if bytes.is_empty() || bytes.len() > MAX_CHUNK {
            return Err(Error::Invalid("chunk length"));
        }
        let id = ciphertext_cid(bytes);
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let prior: Option<Vec<u8>> = tx
            .query_row(
                "SELECT bytes FROM objects WHERE cid=?",
                [id.to_string()],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(prior) = prior {
            if prior != bytes {
                return Err(Error::Corrupt(id.to_string()));
            }
        } else {
            tx.execute(
                "INSERT INTO objects VALUES(?,?)",
                params![id.to_string(), bytes],
            )?;
            observe(Boundary::ObjectInserted);
        }
        tx.commit()?;
        observe(Boundary::ObjectDurable);
        Ok(id)
    }

    pub fn read_object(&self, id: &Cid) -> Result<Vec<u8>> {
        let bytes: Vec<u8> = self
            .conn
            .query_row(
                "SELECT bytes FROM objects WHERE cid=?",
                [id.to_string()],
                |r| r.get(0),
            )
            .optional()?
            .ok_or_else(|| Error::Missing(id.to_string()))?;
        if bytes.is_empty() || bytes.len() > MAX_CHUNK || ciphertext_cid(&bytes) != *id {
            return Err(Error::Corrupt(id.to_string()));
        }
        Ok(bytes)
    }

    pub fn commit(&mut self, manifest: &[u8], receipt: &[u8]) -> Result<Committed> {
        self.commit_observed(manifest, receipt, &mut |_| {})
    }

    pub fn commit_observed(
        &mut self,
        manifest: &[u8],
        receipt: &[u8],
        observe: &mut dyn FnMut(Boundary),
    ) -> Result<Committed> {
        self.commit_inner(manifest, receipt, observe, false, None)
    }

    /// Service partition admission: serialized with all other writers. The first
    /// commit binds an empty partition; later service commits cannot mix scopes.
    pub fn commit_partition(&mut self, manifest: &[u8], receipt: &[u8]) -> Result<Committed> {
        self.commit_inner(manifest, receipt, &mut |_| {}, true, None)
    }

    /// Admit only if no commit has arrived since the caller audited `expected`.
    /// The comparison is serialized with insertion, including exact retries.
    /// This is an optimistic concurrency fence, not a service-profile validator.
    pub fn commit_partition_at(
        &mut self,
        manifest: &[u8],
        receipt: &[u8],
        expected: &Snapshot,
    ) -> Result<Committed> {
        self.commit_inner(manifest, receipt, &mut |_| {}, true, Some(expected))
    }

    fn commit_inner(
        &mut self,
        manifest: &[u8],
        receipt: &[u8],
        observe: &mut dyn FnMut(Boundary),
        single_scope: bool,
        expected_snapshot: Option<&Snapshot>,
    ) -> Result<Committed> {
        let manifest = known(manifest, Kind::Manifest)?;
        let receipt = known(receipt, Kind::Receipt)?;
        if !evidence::binds(&receipt, &manifest) {
            return Err(Error::Invalid("receipt does not bind manifest"));
        }
        let b = manifest.body();
        let scope = blob(&b["scopeToken"]);
        let writer = writer(&manifest);
        let operation = blob(&b["operation"]);
        let position = number(&b["position"]);
        let previous = optional_cid(&b["previous"]);
        let id = manifest.cid().to_string();
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(expected) = expected_snapshot {
            let current: Option<(i64, String)> = tx
                .query_row(
                    "SELECT sequence,cid FROM commits ORDER BY sequence DESC LIMIT 1",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()?;
            let matches = match current {
                None => expected.through == 0 && expected.tip.is_none(),
                Some((sequence, cid)) => {
                    u64::try_from(sequence).ok() == Some(expected.through)
                        && expected.tip.as_ref().map(ToString::to_string).as_ref() == Some(&cid)
                }
            };
            if !matches {
                return Err(Error::Conflict("service audit frontier"));
            }
        }
        if single_scope && tx.query_row(FOREIGN_SCOPE, [scope], |row| row.get::<_, bool>(0))? {
            return Err(Error::Conflict("service partition scope"));
        }
        let prior: Option<(i64,String,Vec<u8>,Vec<u8>)> = tx.query_row(
            "SELECT sequence,cid,manifest,receipt FROM commits WHERE scope=? AND writer=? AND operation=?",
            params![scope, writer, operation], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).optional()?;
        if let Some((sequence, old_id, old_manifest, old_receipt)) = prior {
            if old_id != id {
                return Err(Error::Conflict("operation reused for different manifest"));
            }
            let stored = known(&old_manifest, Kind::Manifest)?;
            let acknowledgment = known(&old_receipt, Kind::Receipt)?;
            if stored.cid() != manifest.cid() || !evidence::binds(&acknowledgment, &stored) {
                return Err(Error::Corrupt(id));
            }
            return Ok(Committed {
                sequence: u64::try_from(sequence).map_err(|_| Error::Corrupt("sequence".into()))?,
                manifest: stored,
                receipt: acknowledgment,
                duplicate: true,
            });
        }
        let head: Option<(i64, String)> = tx.query_row(
            "SELECT position,cid FROM commits WHERE scope=? AND writer=? ORDER BY position DESC LIMIT 1",
            params![scope,writer], |r| Ok((r.get(0)?,r.get(1)?))).optional()?;
        let expected = head.as_ref().map_or(0, |(p, _)| p + 1);
        if position != expected || previous.as_ref() != head.as_ref().map(|(_, c)| c) {
            return Err(Error::Conflict("writer frontier"));
        }
        for e in entries(&manifest) {
            let object = cid(&e["ciphertext"]);
            let bytes: Vec<u8> = tx
                .query_row("SELECT bytes FROM objects WHERE cid=?", [&object], |r| {
                    r.get(0)
                })
                .optional()?
                .ok_or_else(|| Error::Missing(object.clone()))?;
            if bytes.len() as i64 != number(&e["length"])
                || ciphertext_cid(&bytes).to_string() != object
            {
                return Err(Error::Corrupt(object));
            }
            let binding: Option<(String, i64)> = tx
                .query_row(
                    "SELECT ciphertext,length FROM bindings WHERE scope=? AND writer=? AND slot=?",
                    params![scope, writer, blob(&e["slot"])],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            if binding.is_some_and(|v| v != (object, number(&e["length"]))) {
                return Err(Error::Conflict("slot rebound"));
            }
        }
        tx.execute("INSERT INTO commits(cid,scope,writer,operation,position,previous,manifest,receipt) VALUES(?,?,?,?,?,?,?,?)",
            params![id,scope,writer,operation,position,previous,manifest.bytes(),receipt.bytes()])?;
        let sequence = tx.last_insert_rowid() as u64;
        observe(Boundary::ManifestInserted);
        for e in entries(&manifest) {
            tx.execute(
                "INSERT OR IGNORE INTO bindings VALUES(?,?,?,?,?,?)",
                params![
                    scope,
                    writer,
                    blob(&e["slot"]),
                    cid(&e["ciphertext"]),
                    number(&e["length"]),
                    id
                ],
            )?;
        }
        observe(Boundary::BindingsInserted);
        observe(Boundary::BeforeCommit);
        tx.commit()?;
        observe(Boundary::AfterCommit);
        Ok(Committed {
            sequence,
            manifest,
            receipt,
            duplicate: false,
        })
    }

    pub fn snapshot(&self) -> Result<Snapshot> {
        let row: Option<(i64, String)> = self
            .conn
            .query_row(
                "SELECT sequence,cid FROM commits ORDER BY sequence DESC LIMIT 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        match row {
            None => Ok(Snapshot {
                through: 0,
                tip: None,
            }),
            Some((through, c)) => Ok(Snapshot {
                through: u64::try_from(through).map_err(|_| Error::Corrupt("sequence".into()))?,
                tip: Some(c.parse().map_err(|_| Error::Corrupt(c))?),
            }),
        }
    }

    pub fn page(&self, snapshot: &Snapshot, after: u64, limit: usize) -> Result<Vec<Committed>> {
        if limit == 0 || limit > 128 || after > snapshot.through {
            return Err(Error::Invalid("page bounds"));
        }
        let through =
            i64::try_from(snapshot.through).map_err(|_| Error::Invalid("snapshot overflow"))?;
        let tip: Option<String> = self
            .conn
            .query_row("SELECT cid FROM commits WHERE sequence=?", [through], |r| {
                r.get(0)
            })
            .optional()?;
        if (snapshot.through == 0 && snapshot.tip.is_some())
            || (snapshot.through > 0 && tip.is_none())
            || tip != snapshot.tip.as_ref().map(ToString::to_string)
        {
            return Err(Error::Invalid("unknown snapshot"));
        }
        let mut stmt = self.conn.prepare("SELECT sequence,cid,manifest,receipt FROM commits WHERE sequence>? AND sequence<=? ORDER BY sequence LIMIT ?")?;
        let mut rows = stmt.query(params![after as i64, through, limit as i64])?;
        let mut out = Vec::new();
        while let Some(row) = rows.next()? {
            let stored_id: String = row.get(1)?;
            let manifest = known(&row.get::<_, Vec<u8>>(2)?, Kind::Manifest)?;
            let receipt = known(&row.get::<_, Vec<u8>>(3)?, Kind::Receipt)?;
            if manifest.cid().to_string() != stored_id || !evidence::binds(&receipt, &manifest) {
                return Err(Error::Corrupt(stored_id));
            }
            out.push(Committed {
                sequence: u64::try_from(row.get::<_, i64>(0)?)
                    .map_err(|_| Error::Corrupt("sequence".into()))?,
                manifest,
                receipt,
                duplicate: false,
            });
        }
        Ok(out)
    }

    pub fn verify(&self) -> Result<Verification> {
        // A read transaction pins all scans even while another process appends.
        let tx = self.conn.unchecked_transaction()?;
        let verified = self.verify_contents()?;
        tx.commit()?;
        Ok(verified)
    }

    // Caller owns a transaction (read-only audit or unpublished recovery output).
    fn verify_contents(&self) -> Result<Verification> {
        let tx = &self.conn;
        let integrity: String = tx.query_row("PRAGMA integrity_check", [], |r| r.get(0))?;
        if integrity != "ok" {
            return Err(Error::Corrupt(integrity));
        }
        let foreign_keys: i64 =
            tx.query_row("SELECT count(*) FROM pragma_foreign_key_check", [], |r| {
                r.get(0)
            })?;
        if foreign_keys != 0 {
            return Err(Error::Corrupt("foreign keys".into()));
        }
        let snapshot = self.snapshot()?;
        let (mut objects, mut bytes, mut commits) = (0, 0, 0);
        let mut stmt = tx.prepare("SELECT cid,bytes FROM objects ORDER BY cid")?;
        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            let id: String = row.get(0)?;
            let payload: Vec<u8> = row.get(1)?;
            if payload.is_empty()
                || payload.len() > MAX_CHUNK
                || ciphertext_cid(&payload).to_string() != id
            {
                return Err(Error::Corrupt(id));
            }
            objects += 1;
            bytes += payload.len() as u64;
        }
        drop(rows);
        drop(stmt);
        let mut stmt = tx.prepare("SELECT sequence,cid,scope,writer,operation,position,previous,manifest,receipt FROM commits ORDER BY sequence")?;
        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            let seq: i64 = row.get(0)?;
            let id: String = row.get(1)?;
            let m = known(&row.get::<_, Vec<u8>>(7)?, Kind::Manifest)?;
            let r = known(&row.get::<_, Vec<u8>>(8)?, Kind::Receipt)?;
            let b = m.body();
            if seq != commits as i64 + 1
                || m.cid().to_string() != id
                || !evidence::binds(&r, &m)
                || row.get::<_, Vec<u8>>(2)? != blob(&b["scopeToken"])
                || row.get::<_, String>(3)? != writer(&m)
                || row.get::<_, Vec<u8>>(4)? != blob(&b["operation"])
                || row.get::<_, i64>(5)? != number(&b["position"])
                || row.get::<_, Option<String>>(6)? != optional_cid(&b["previous"])
            {
                return Err(Error::Corrupt(id));
            }
            let previous: Option<String> = tx.query_row("SELECT cid FROM commits WHERE scope=? AND writer=? AND position=? AND sequence<?",
                params![blob(&b["scopeToken"]),writer(&m),number(&b["position"])-1,seq], |r| r.get(0)).optional()?;
            if previous != optional_cid(&b["previous"])
                || (number(&b["position"]) > 0 && previous.is_none())
            {
                return Err(Error::Corrupt("predecessor".into()));
            }
            for e in entries(&m) {
                let actual: Option<(String, i64, i64)> = tx.query_row("SELECT b.ciphertext,b.length,c.sequence FROM bindings b JOIN commits c ON c.cid=b.first_manifest WHERE b.scope=? AND b.writer=? AND b.slot=?",
                    params![blob(&b["scopeToken"]),writer(&m),blob(&e["slot"])], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional()?;
                if !actual.is_some_and(|(object, length, first_sequence)| {
                    object == cid(&e["ciphertext"])
                        && length == number(&e["length"])
                        && first_sequence <= seq
                }) {
                    return Err(Error::Corrupt("binding".into()));
                }
                let payload = self.read_object(
                    &cid(&e["ciphertext"])
                        .parse()
                        .map_err(|_| Error::Corrupt("CID".into()))?,
                )?;
                if payload.len() as i64 != number(&e["length"]) {
                    return Err(Error::Corrupt("object length".into()));
                }
            }
            commits += 1;
        }
        drop(rows);
        drop(stmt);
        // Reject extra derived bindings as well as missing ones.
        let mut stmt = tx.prepare("SELECT b.scope,b.writer,b.slot,b.ciphertext,b.length,c.manifest FROM bindings b JOIN commits c ON c.cid=b.first_manifest")?;
        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            let m = known(&row.get::<_, Vec<u8>>(5)?, Kind::Manifest)?;
            let slot: Vec<u8> = row.get(2)?;
            let object: String = row.get(3)?;
            let len: i64 = row.get(4)?;
            if row.get::<_, Vec<u8>>(0)? != blob(&m.body()["scopeToken"])
                || row.get::<_, String>(1)? != writer(&m)
                || !entries(&m).any(|e| {
                    blob(&e["slot"]) == slot
                        && cid(&e["ciphertext"]) == object
                        && number(&e["length"]) == len
                })
            {
                return Err(Error::Corrupt("extra binding".into()));
            }
        }
        drop(rows);
        drop(stmt);
        Ok(Verification {
            objects,
            commits,
            bytes,
            snapshot,
        })
    }

    pub fn backup(&self, destination: &Path) -> Result<Verification> {
        self.backup_observed(destination, &mut |_| {})
    }

    pub fn backup_observed(
        &self,
        destination: &Path,
        observe: &mut dyn FnMut(BackupBoundary),
    ) -> Result<Verification> {
        let source = std::fs::canonicalize(
            self.conn
                .path()
                .ok_or(Error::Invalid("backup source filename unavailable"))?,
        )?;
        let destination = sqlite_destination(&source, destination)?;
        // surface-write: evidence-backup:archive.sqlite,evidence-backup:archive.sqlite-journal,evidence-backup:archive.sqlite-wal,evidence-backup:archive.sqlite-shm
        crate::persistence::write_new_owner_only(
            crate::persistence::SurfaceWrite::EvidenceBackup,
            &destination,
            &[],
        )?;
        let mut target =
            Connection::open_with_flags(&destination, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
        target.execute_batch("PRAGMA synchronous=FULL; PRAGMA fullfsync=ON;")?;
        {
            let backup = rusqlite::backup::Backup::new(&self.conn, &mut target)?;
            loop {
                match backup.step(256)? {
                    rusqlite::backup::StepResult::Done => break,
                    rusqlite::backup::StepResult::More => {}
                    _ => return Err(Error::Invalid("backup busy; destination incomplete")),
                }
            }
        }
        observe(BackupBoundary::Copied);
        target.execute_batch("PRAGMA journal_mode=DELETE;")?;
        observe(BackupBoundary::Normalized);
        drop(target);
        std::fs::File::open(&destination)?.sync_all()?;
        std::fs::File::open(parent_directory(&destination))?.sync_all()?;
        Self::verify_file(&destination)
    }

    pub fn verify_file(path: &Path) -> Result<Verification> {
        private_file(path)?;
        let ledger = Self {
            conn: Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?,
        };
        ledger.check_schema()?;
        ledger.verify()
    }
}

#[cfg(test)]
mod admission_tests {
    use super::*;

    #[test]
    fn scope_guard_uses_bounded_index_probes() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(SCHEMA).unwrap();
        let tx = conn.transaction().unwrap();
        for position in 0..20_000i64 {
            // Query-planner fixture only, not purported canonical evidence.
            tx.execute("INSERT INTO commits(cid,scope,writer,operation,position,manifest,receipt) VALUES(?,?,?,?,?,x'01',x'01')",
                params![position.to_string(),[128u8;32].as_slice(),"writer",position.to_be_bytes().as_slice(),position]).unwrap();
        }
        tx.commit().unwrap();
        let mut plan = conn
            .prepare(&format!("EXPLAIN QUERY PLAN {FOREIGN_SCOPE}"))
            .unwrap();
        let details: Vec<String> = plan
            .query_map([[128u8; 32].as_slice()], |row| row.get(3))
            .unwrap()
            .collect::<std::result::Result<_, _>>()
            .unwrap();
        assert_eq!(
            details
                .iter()
                .filter(|s| s.contains("SEARCH commits") && s.contains("scope"))
                .count(),
            2,
            "{details:?}"
        );
        assert!(
            !details.iter().any(|s| s.contains("SCAN commits")),
            "{details:?}"
        );
        for (scope, foreign) in [(128u8, false), (127, true), (129, true)] {
            let mut statement = conn.prepare(FOREIGN_SCOPE).unwrap();
            assert_eq!(
                statement
                    .query_row([[scope; 32].as_slice()], |row| row.get::<_, bool>(0))
                    .unwrap(),
                foreign
            );
            let steps = statement.get_status(rusqlite::StatementStatus::VmStep);
            assert!(
                steps < 100,
                "scope guard used {steps} VM steps for scope {scope}"
            );
        }
    }
}
