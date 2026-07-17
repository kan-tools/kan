//! The disposable SQLite index (`docs/SPEC.md` §10, ADR-3's
//! `.kan/index.sqlite`): a pure projection of the log's claims. Delete the
//! file and `rebuild` reconstructs it from `Log::iter_all` — nothing here is
//! a second source of truth (AC-6).

use std::path::Path;

use atproto_dasl::Cid;

use crate::store::log::StoredClaim;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("DAG-CBOR encode error: {0}")]
    Encode(#[from] atproto_dasl::EncodeError),
    #[error("DAG-CBOR decode error: {0}")]
    Decode(#[from] atproto_dasl::DecodeError),
    #[error("stored CID is not valid: {0}")]
    InvalidCid(#[from] atproto_dasl::DaslCidError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

pub struct Index {
    conn: rusqlite::Connection,
}

impl Index {
    pub fn open(path: &Path) -> Result<Self, Error> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let conn = rusqlite::Connection::open(path)?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS claims (
                content_cid TEXT PRIMARY KEY,
                rev         TEXT NOT NULL,
                author_did  TEXT NOT NULL,
                subject_key TEXT NOT NULL,
                kind        TEXT NOT NULL,
                raw         BLOB NOT NULL
             );
             CREATE INDEX IF NOT EXISTS claims_by_rev ON claims(rev);
             CREATE INDEX IF NOT EXISTS claims_by_subject ON claims(subject_key);",
        )?;
        Ok(Self { conn })
    }

    /// Wipe and repopulate the index from `claims` (the full contents of a
    /// `Log`, via `Log::iter_all`) — the disposable-projection guarantee.
    pub fn rebuild(&mut self, claims: &[(Cid, StoredClaim)]) -> Result<(), Error> {
        let tx = self.conn.transaction()?;
        tx.execute("DELETE FROM claims", [])?;
        for (cid, stored) in claims {
            let subject_key = format!("{:?}", stored.claim.content.subject);
            let kind = format!("{:?}", stored.claim.content.body.kind());
            let raw = atproto_dasl::to_vec(stored)?;
            tx.execute(
                "INSERT INTO claims (content_cid, rev, author_did, subject_key, kind, raw)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                rusqlite::params![
                    cid.to_string(),
                    stored.rev,
                    stored.claim.content.author.did,
                    subject_key,
                    kind,
                    raw,
                ],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    /// All claims currently projected, in chronological (`rev`) order — the
    /// practical input to `crate::fold::fold`.
    pub fn all_stored_claims(&self) -> Result<Vec<(Cid, StoredClaim)>, Error> {
        let mut stmt = self
            .conn
            .prepare("SELECT content_cid, raw FROM claims ORDER BY rev ASC")?;
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

    pub fn len(&self) -> Result<usize, Error> {
        let count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM claims", [], |r| r.get(0))?;
        Ok(count as usize)
    }

    pub fn is_empty(&self) -> Result<bool, Error> {
        Ok(self.len()? == 0)
    }
}
