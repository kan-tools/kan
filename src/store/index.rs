//! The disposable SQLite index (`docs/SPEC.md` §10, ADR-3's
//! `.kan/index.sqlite`): a pure projection of the log's claims. Delete the
//! file and `rebuild` reconstructs it from `Log::iter_all` — nothing here is
//! a second source of truth (AC-6).

use std::path::{Path, PathBuf};

use atproto_dasl::Cid;
use rusqlite::OptionalExtension;
use sha2::Digest;

use crate::claim::v1::AuthorId;
use crate::store::log::StoredClaim;

/// The projection's table, **named by schema version**, and the meta key
/// recording what that table was built from.
///
/// **Why the version is in the name rather than in a row.** The index is
/// disposable, so a shape change needs no migration — but it does need two
/// kan binaries sharing one `.kan/` to stay out of each other's way, and
/// that is not hypothetical: `day` shells out to the *installed* `kan`
/// (ADR-42) while a checkout builds its own, so one workspace routinely sees
/// both. A single `claims` table cannot serve both, and the failure is not
/// subtle — v0.9.2 against a v0.11-written index dies with
/// `NOT NULL constraint failed: claims.origin` on its next write, because
/// `CREATE TABLE IF NOT EXISTS` leaves the newer table in place and the older
/// binary's `INSERT` names no `origin`. Reproduced against the released
/// binary before choosing this, rather than reasoned about.
///
/// Disjoint names mean each binary maintains its own projection and neither
/// can corrupt or block the other. `built_from_root` is versioned with it for
/// the same reason: a shared freshness key would have each binary trusting a
/// projection the other built.
///
/// The cost is a stale table per superseded version, which is disk in a file
/// that can be deleted at any time. Cleaning them up would reintroduce
/// exactly the breakage this avoids.
const CLAIMS_TABLE: &str = "claims_v2";
const BUILT_FROM_ROOT_KEY: &str = "built_from_root_v2";
const PROJECTION_DIGEST_KEY: &str = "projection_digest_v2";

/// Which store a projected claim came from.
///
/// The distinction is load-bearing rather than bookkeeping: `Local` (the
/// default trust base) is *every author with a claim in `.kan/log`*, and the
/// log is what was written **through** this workspace where the overlay is
/// what **arrived at** it as a committed `.claims/` file
/// (`.design/identity-surface.md` RQ-2). Those are different acts, and the
/// difference is the trust-relevant one -- without it a merged pull request
/// carrying a claims file would inject a STRANGER's claims into the
/// maintainer's default view.
///
/// It stops there, and the limit is worth stating where the column is
/// defined: origin decides `Local`'s MEMBERSHIP and nothing else. The fold
/// never sees it, so a claims file from an author who has already written
/// here still folds in. #164 gives the fold origin per row in v0.12.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    /// This workspace's own log — the one medium kan writes, signs and ships.
    Log,
    /// The tracked `.claims/` tree (`transport::git_tree`).
    GitTree,
}

impl Origin {
    /// Named for the **medium**, not for the store it currently lands in.
    ///
    /// `.kan/overlay` is on its way out (#164): the index becomes the
    /// aggregate and each row carries the medium it arrived from, which is
    /// what `fold(⋃ readable media, trust)` actually needs and what a single
    /// conflated overlay erases. Spelling it `git-tree` now costs nothing --
    /// the index is disposable, so this value can change at any time with no
    /// migration -- and saves renaming it under a milestone that is already
    /// churning this code.
    fn as_str(self) -> &'static str {
        match self {
            Origin::Log => "log",
            Origin::GitTree => "git-tree",
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("DAG-CBOR encode error: {0}")]
    Encode(#[from] atproto_dasl::EncodeError),
    /// A stored claim could not be decoded.
    ///
    /// The message distinguishes the *only* two shapes this realistically
    /// takes, because they call for opposite responses and the raw serde
    /// text names neither. An unknown field or variant means this binary is
    /// older than the log it is reading — `docs/SPEC.md` §7.1's honest
    /// failure, working as designed — and the fix is to upgrade. Anything
    /// else is a genuinely damaged record.
    ///
    /// Without that distinction the raw text ("unknown field `recorded_at`,
    /// expected one of ...") reads as corruption. It was mistaken for
    /// exactly that during this release's development, minutes after a real
    /// data-loss incident and against a freshly restored log — an operator
    /// with less context could reasonably have concluded the backup was bad
    /// and discarded it. Third time the stale-binary class caused a false
    /// alarm in one session (ADR-48).
    #[error("{}", decode_message(.0))]
    Decode(#[from] atproto_dasl::DecodeError),
    #[error("stored CID is not valid: {0}")]
    InvalidCid(#[from] atproto_dasl::DaslCidError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Turns a decode failure into something an operator can act on.
fn decode_message(e: &atproto_dasl::DecodeError) -> String {
    let raw = e.to_string();
    if raw.contains("unknown field") || raw.contains("unknown variant") {
        format!(
            "this kan is older than the log it is reading.\n\n{raw}\n\n\
             The log is not damaged: a claim in it uses a field or claim kind this build \
             does not know about, and kan reports that rather than silently dropping it \
             (docs/SPEC.md 7.1). Upgrade kan -- `cargo install kan` for a release, or \
             `cargo install --path .` from a checkout -- and read it again."
        )
    } else {
        format!("DAG-CBOR decode error: {raw}")
    }
}

pub struct Index {
    conn: rusqlite::Connection,
    path: Option<PathBuf>,
}

impl Index {
    /// A projection with nowhere to live — for reading a repo that has no
    /// `.kan/` at all.
    ///
    /// AC-3: `kan status` in a git repo with no workspace reports no subjects
    /// and **creates nothing**. Opening a file-backed index would create the
    /// file and the directory holding it, which is the vivification #149 is
    /// about, arriving through the back door.
    pub fn open_in_memory() -> Result<Self, Error> {
        Self::with_connection(rusqlite::Connection::open_in_memory()?, None)
    }

    pub fn open(path: &Path) -> Result<Self, Error> {
        if let Some(parent) = path.parent() {
            // surface-write: sqlite:meta
            crate::persistence::create_dir_all(crate::persistence::SurfaceWrite::Sqlite, parent)?;
        }
        let connection = match rusqlite::Connection::open(path) {
            Ok(connection) => connection,
            Err(_) => {
                // The projection path itself can be unusable even while the
                // authoritative log is intact: a directory, broken symlink,
                // or permissions failure prevents SQLite from opening a file.
                // Do not delete an object we could not identify safely. Read
                // through a recomputed in-memory projection instead; a later
                // open can return to the file once the path is usable again.
                return Self::open_in_memory();
            }
        };
        match Self::with_connection(connection, Some(path.to_path_buf())) {
            Ok(index) => Ok(index),
            Err(_) => {
                // A structurally corrupt current projection may make even
                // CREATE INDEX IF NOT EXISTS fail before Workspace can
                // compare it with the authoritative reference. Reopen the
                // disposable database and recreate only this binary's schema.
                // If cleanup or recreation is denied, bypass the disposable
                // file: projection damage must not control authoritative read
                // availability.
                // surface-write: sqlite:meta
                if crate::persistence::remove_file(crate::persistence::SurfaceWrite::Sqlite, path)
                    .is_err()
                {
                    return Self::open_in_memory();
                }
                let Ok(connection) = rusqlite::Connection::open(path) else {
                    return Self::open_in_memory();
                };
                Self::with_connection(connection, Some(path.to_path_buf()))
                    .or_else(|_| Self::open_in_memory())
            }
        }
    }

    fn with_connection(conn: rusqlite::Connection, path: Option<PathBuf>) -> Result<Self, Error> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS meta (
                key   TEXT PRIMARY KEY,
                value TEXT
             );",
        )?;

        // An older kan's `claims` table is left exactly where it is. It costs
        // disk and nothing else, and dropping it is what would break the
        // other binary.
        conn.execute_batch(&format!(
            "CREATE TABLE IF NOT EXISTS {CLAIMS_TABLE} (
                content_cid  TEXT PRIMARY KEY,
                rev          TEXT NOT NULL,
                author_did   TEXT NOT NULL,
                author_agent BLOB,
                origin       TEXT NOT NULL,
                subject_key  TEXT NOT NULL,
                kind         TEXT NOT NULL,
                raw          BLOB NOT NULL
             );
             CREATE INDEX IF NOT EXISTS {CLAIMS_TABLE}_by_rev
                ON {CLAIMS_TABLE}(rev);
             CREATE INDEX IF NOT EXISTS {CLAIMS_TABLE}_by_subject
                ON {CLAIMS_TABLE}(subject_key);
             CREATE INDEX IF NOT EXISTS {CLAIMS_TABLE}_by_origin
                ON {CLAIMS_TABLE}(origin);"
        ))?;
        Ok(Self { conn, path })
    }

    /// Recreate this binary's disposable schema after structural corruption.
    /// No authoritative data lives here. Older versioned claim tables are
    /// deliberately retained; `meta` is shared but contains only disposable
    /// freshness hints, so recreating it merely makes other binaries rebuild.
    pub fn recreate_current_schema(&mut self) -> Result<(), Error> {
        if let Some(path) = self.path.clone() {
            // Establish a complete in-memory projection before touching the
            // disposable file. If its parent is read-only, removal or
            // recreation can fail even though the authoritative log is
            // perfectly readable; in that case the in-memory index remains
            // the recovery target for the rebuild below.
            let fallback = Self::open_in_memory()?;
            let old = std::mem::replace(self, fallback);
            drop(old);
            // surface-write: sqlite:meta
            if crate::persistence::remove_file(crate::persistence::SurfaceWrite::Sqlite, &path)
                .is_err()
            {
                return Ok(());
            }
            if let Ok(recreated) = Self::open(&path) {
                *self = recreated;
            }
            return Ok(());
        }
        self.conn.execute_batch(&format!(
            "DROP TABLE IF EXISTS {CLAIMS_TABLE};
             DROP TABLE IF EXISTS meta;"
        ))?;
        self.conn.execute_batch(
            "CREATE TABLE meta (
                key   TEXT PRIMARY KEY,
                value TEXT
             );",
        )?;
        self.conn.execute_batch(&format!(
            "CREATE TABLE {CLAIMS_TABLE} (
                content_cid  TEXT PRIMARY KEY,
                rev          TEXT NOT NULL,
                author_did   TEXT NOT NULL,
                author_agent BLOB,
                origin       TEXT NOT NULL,
                subject_key  TEXT NOT NULL,
                kind         TEXT NOT NULL,
                raw          BLOB NOT NULL
             );
             CREATE INDEX {CLAIMS_TABLE}_by_rev ON {CLAIMS_TABLE}(rev);
             CREATE INDEX {CLAIMS_TABLE}_by_subject ON {CLAIMS_TABLE}(subject_key);
             CREATE INDEX {CLAIMS_TABLE}_by_origin ON {CLAIMS_TABLE}(origin);"
        ))?;
        Ok(())
    }

    /// Wipe and repopulate the index from `claims` (the full contents of a
    /// `Log`, via `Log::iter_all`) — the disposable-projection guarantee.
    /// `built_from_root` (`Log::current_root` at the time `claims` was
    /// read) is stored in the same transaction as the claims themselves
    /// (`.design/v0.4-milestone.md` REQ-4) — meta and claims always commit
    /// atomically together, so a crash mid-rebuild can never leave a
    /// half-updated claims table read back as "fresh" by
    /// `built_from_root`'s caller.
    pub fn rebuild(
        &mut self,
        log_claims: &[(Cid, StoredClaim)],
        foreign_claims: &[(Cid, StoredClaim)],
        built_from_root: Option<&Cid>,
    ) -> Result<(), Error> {
        match self.rebuild_once(log_claims, foreign_claims, built_from_root) {
            Ok(()) => Ok(()),
            Err(_) => {
                // Projection failures are never allowed to turn an already
                // committed authoritative append into a reported failure.
                // Discard the derived schema/file and retry from inputs.
                self.recreate_current_schema()?;
                self.rebuild_once(log_claims, foreign_claims, built_from_root)
            }
        }
    }

    fn rebuild_once(
        &mut self,
        log_claims: &[(Cid, StoredClaim)],
        foreign_claims: &[(Cid, StoredClaim)],
        built_from_root: Option<&Cid>,
    ) -> Result<(), Error> {
        let tx = self.conn.transaction()?;
        tx.execute(&format!("DELETE FROM {CLAIMS_TABLE}"), [])?;
        let sources = [(Origin::Log, log_claims), (Origin::GitTree, foreign_claims)];
        for (origin, claims) in sources {
            for (cid, stored) in claims {
                let subject_key = format!("{:?}", stored.claim.content.subject);
                let kind = format!("{:?}", stored.claim.content.body.kind());
                let raw = atproto_dasl::to_vec(stored)?;
                tx.execute(
                    &format!(
                        "INSERT INTO {CLAIMS_TABLE}
                            (content_cid, rev, author_did, author_agent, origin, subject_key,
                             kind, raw)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)"
                    ),
                    rusqlite::params![
                        cid.to_string(),
                        stored.rev,
                        stored.claim.content.author.did,
                        stored.claim.content.author.agent,
                        origin.as_str(),
                        subject_key,
                        kind,
                        raw,
                    ],
                )?;
            }
        }
        let projection_digest = Self::projection_digest(&tx)?;
        tx.execute(
            &format!(
                "INSERT INTO meta (key, value) VALUES ('{BUILT_FROM_ROOT_KEY}', ?1)
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value"
            ),
            rusqlite::params![built_from_root.map(|c| c.to_string())],
        )?;
        tx.execute(
            &format!(
                "INSERT INTO meta (key, value) VALUES ('{PROJECTION_DIGEST_KEY}', ?1)
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value"
            ),
            [projection_digest],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// The log root CID this index was last `rebuild`t from, if any —
    /// `None` for a freshly created index (no `meta` row yet) or if the
    /// log itself had no commits at rebuild time. `Workspace::open`
    /// compares this against `Log::current_root()`: an exact match proves
    /// (via content-addressing, not a heuristic) that nothing has changed
    /// since this index was built, so the full rebuild can be skipped.
    pub fn built_from_root(&self) -> Result<Option<Cid>, Error> {
        let value: Option<String> = self
            .conn
            .query_row(
                &format!("SELECT value FROM meta WHERE key = '{BUILT_FROM_ROOT_KEY}'"),
                [],
                |r| r.get::<_, Option<String>>(0),
            )
            .optional()?
            .flatten();
        Ok(match value {
            Some(v) => Some(v.parse()?),
            None => None,
        })
    }

    /// All claims currently projected, in chronological (`rev`, then
    /// `content_cid`) order — the practical input to `crate::fold::fold`.
    ///
    /// The `content_cid` tiebreak matches `fold`'s own `(rev, cid)` sort, so
    /// two claims sharing a `rev` (possible once `.claims/` ingestion mixes
    /// authors' clocks) order identically here and in the fold rather than by
    /// whatever order SQLite returned (review/full-pass-v0.12 F9).
    pub fn all_stored_claims(&self) -> Result<Vec<(Cid, StoredClaim)>, Error> {
        let mut stmt = self.conn.prepare(&format!(
            "SELECT content_cid, raw FROM {CLAIMS_TABLE} ORDER BY rev ASC, content_cid ASC"
        ))?;
        let rows = stmt.query_map([], |row| {
            let cid_str: String = row.get(0)?;
            let raw: Vec<u8> = row.get(1)?;
            Ok((cid_str, raw))
        })?;

        let mut out = Vec::new();
        for row in rows {
            let (cid_str, raw) = row?;
            let cid: Cid = cid_str.parse()?;
            let stored: StoredClaim = atproto_dasl::from_slice(&raw)?;
            out.push((cid, stored));
        }
        Ok(out)
    }

    /// Whether the persisted projection still has the exact schema and row
    /// bytes committed by `rebuild`. This is a cheap corruption detector, not
    /// an authority claim: a mismatch causes full reference recomputation from
    /// the log and published records. Keeping the seal beside the disposable
    /// rows avoids signature-verifying the whole authoritative log on every
    /// ordinary CLI open while still detecting valid-CBOR substitution and
    /// corruption of denormalized query columns.
    pub fn projection_is_consistent(&self) -> Result<bool, Error> {
        let stored: Option<String> = self
            .conn
            .query_row(
                &format!("SELECT value FROM meta WHERE key = '{PROJECTION_DIGEST_KEY}'"),
                [],
                |row| row.get(0),
            )
            .optional()?;
        let Some(stored) = stored else {
            return Ok(false);
        };
        let expected_schema = Self::open_in_memory()?;
        Ok(stored == Self::projection_digest(&self.conn)?
            && Self::schema_objects(&self.conn)? == Self::schema_objects(&expected_schema.conn)?)
    }

    fn projection_digest(conn: &rusqlite::Connection) -> Result<String, Error> {
        fn add(hasher: &mut sha2::Sha256, bytes: &[u8]) {
            hasher.update((bytes.len() as u64).to_be_bytes());
            hasher.update(bytes);
        }

        let mut stmt = conn.prepare(&format!(
            "SELECT content_cid, rev, author_did, author_agent, origin, subject_key, kind, raw
             FROM {CLAIMS_TABLE} ORDER BY content_cid"
        ))?;
        let mapped = stmt.query_map([], |row| {
            Ok(ProjectionRow {
                content_cid: row.get(0)?,
                rev: row.get(1)?,
                author_did: row.get(2)?,
                author_agent: row.get(3)?,
                origin: row.get(4)?,
                subject_key: row.get(5)?,
                kind: row.get(6)?,
                raw: row.get(7)?,
            })
        })?;
        let mut hasher = sha2::Sha256::new();
        for row in mapped {
            let row = row?;
            add(&mut hasher, row.content_cid.as_bytes());
            add(&mut hasher, row.rev.as_bytes());
            add(&mut hasher, row.author_did.as_bytes());
            match row.author_agent {
                Some(agent) => {
                    hasher.update([1]);
                    add(&mut hasher, &agent);
                }
                None => hasher.update([0]),
            }
            add(&mut hasher, row.origin.as_bytes());
            add(&mut hasher, row.subject_key.as_bytes());
            add(&mut hasher, row.kind.as_bytes());
            add(&mut hasher, &row.raw);
        }
        Ok(format!("{:x}", hasher.finalize()))
    }

    fn schema_objects(conn: &rusqlite::Connection) -> Result<Vec<SchemaObject>, Error> {
        let mut stmt = conn.prepare(
            "SELECT type, name, tbl_name, sql
             FROM sqlite_master
             WHERE name = 'meta' OR name = ?1 OR tbl_name = ?1
             ORDER BY type, name",
        )?;
        let mapped = stmt.query_map([CLAIMS_TABLE], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })?;
        mapped.collect::<Result<_, _>>().map_err(Error::from)
    }

    /// Every distinct `AuthorId` with a claim in `.kan/log` — the membership
    /// of `TrustBase::Local`, and the reason a default read needs no identity
    /// (`.design/identity-surface.md` REQ-1).
    ///
    /// **Answered from the projection rather than from the log.** The log is
    /// the source of truth, but walking it means verifying a signature per
    /// claim — ADR-13's dominant cost, and the thing the index exists to
    /// avoid paying on every read. The projection is rebuilt from the log
    /// whenever the log's root moves, so this cannot drift from it.
    ///
    /// **`agent` is carried, not collapsed to the DID.** A v0.2–v0.6 claim
    /// written with `KAN_AGENT` set has `AuthorId { did, agent: Some(h) }`,
    /// and it is a member here on exactly the same footing as any other —
    /// it is in the log. That is REQ-7 with no DID-matching special case:
    /// the legacy author is trusted because it wrote here, not because its
    /// DID resembles somebody's.
    pub fn log_authors(&self) -> Result<Vec<AuthorId>, Error> {
        let mut stmt = self.conn.prepare(&format!(
            "SELECT DISTINCT author_did, author_agent FROM {CLAIMS_TABLE} \
                 WHERE origin = 'log'"
        ))?;
        let rows = stmt.query_map([], |row| {
            Ok(AuthorId {
                did: row.get(0)?,
                agent: row.get(1)?,
            })
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    pub fn len(&self) -> Result<usize, Error> {
        let count: i64 =
            self.conn
                .query_row(&format!("SELECT COUNT(*) FROM {CLAIMS_TABLE}"), [], |r| {
                    r.get(0)
                })?;
        Ok(count as usize)
    }

    pub fn is_empty(&self) -> Result<bool, Error> {
        Ok(self.len()? == 0)
    }
}

#[derive(Debug, PartialEq, Eq)]
struct ProjectionRow {
    content_cid: String,
    rev: String,
    author_did: String,
    author_agent: Option<Vec<u8>>,
    origin: String,
    subject_key: String,
    kind: String,
    raw: Vec<u8>,
}

type SchemaObject = (String, String, String, Option<String>);
