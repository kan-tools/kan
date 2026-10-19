//! Complete typed rows for disposable projections, separate from recent samples.
use super::*;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub(crate) enum Observation {
    Attempt {
        updated: u64,
        health: Health,
    },
    Session {
        id: String,
        updated: u64,
        dropped: u64,
        clean: bool,
    },
}
#[derive(Debug, Clone, Serialize)]
pub struct Scan {
    pub started_at: u64,
    pub finished_at: u64,
    pub digest: String,
    pub worker: Option<WorkerStatus>,
    pub exhausted_observed: Option<bool>,
}
fn hash<T: Serialize>(digest: &mut Sha256, value: &T) -> Result<()> {
    let bytes = serde_json::to_vec(value)?;
    digest.update((bytes.len() as u64).to_be_bytes());
    digest.update(bytes);
    Ok(())
}
impl Journal {
    /// Copy a bounded active database into memory using short SQLite backup
    /// steps. Parsing/deduplication then holds no read lock on the live journal.
    /// A constantly changing or busy source can refuse refresh after five seconds.
    pub(crate) fn projection_copy(
        mut self,
        check: &mut dyn FnMut() -> Result<()>,
    ) -> Result<(Self, (u64, u64))> {
        let start = now();
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        self.conn.busy_timeout(Duration::ZERO)?;
        let mut memory = Connection::open_in_memory()?;
        memory.execute_batch(
            "PRAGMA page_size=4096; PRAGMA max_page_count=8192; PRAGMA temp_store=MEMORY;",
        )?;
        memory.set_limit(rusqlite::limits::Limit::SQLITE_LIMIT_LENGTH, 32768)?;
        {
            let backup = rusqlite::backup::Backup::new(&self.conn, &mut memory)?;
            loop {
                check()?;
                if std::time::Instant::now() >= deadline {
                    return Err("active snapshot copy timed out; source may be busy".into());
                }
                let step = backup.step(64)?;
                if !(0..=8192).contains(&backup.progress().pagecount) {
                    return Err(invalid());
                }
                match step {
                    rusqlite::backup::StepResult::Done => break,
                    rusqlite::backup::StepResult::More => std::thread::yield_now(),
                    rusqlite::backup::StepResult::Busy | rusqlite::backup::StepResult::Locked => {
                        std::thread::sleep(Duration::from_millis(1));
                    }
                    _ => return Err(invalid()),
                }
            }
        }
        let end = now();
        self.schema = Self::validate_connection(&memory)?;
        self.conn = memory;
        self.read_only = true;
        Ok((self, (start, end)))
    }
    /// One pinned read transaction; callbacks must do bounded CPU/memory work and
    /// must not wait for another source or browser. Cancellation is checked per row.
    pub(crate) fn scan_projection(
        &self,
        expected_binding: &(String, String, String, String),
        visit: &mut dyn FnMut(Observation) -> Result<()>,
    ) -> Result<Scan> {
        let started_at = now();
        let tx = self.conn.unchecked_transaction()?;
        if &self.binding()? != expected_binding {
            return Err(invalid());
        }
        let count: i64 = tx.query_row("SELECT count(*) FROM binding", [], |r| r.get(0))?;
        if count != 1 {
            return Err(invalid());
        }
        let mut digest = Sha256::new();
        hash(
            &mut digest,
            &(
                "kan.operations.projection.v1",
                self.schema,
                expected_binding,
            ),
        )?;
        {
            let mut query=tx.prepare("SELECT attempt,updated,observed,queued,unconfirmed,body FROM attempts ORDER BY attempt")?;
            let mut rows = query.query([])?;
            while let Some(row) = rows.next()? {
                let id: String = row.get(0)?;
                let updated = unsigned(row, 1)?;
                let health: Health = serde_json::from_str(&row.get::<_, String>(5)?)?;
                if !valid_health(&health)
                    || health.attempt != id
                    || health.observed != unsigned(row, 2)?
                    || health.locally_queued != unsigned(row, 3)?
                    || health.unconfirmed != unsigned(row, 4)?
                {
                    return Err(invalid());
                }
                let value = Observation::Attempt { updated, health };
                hash(&mut digest, &value)?;
                visit(value)?;
            }
        }
        {
            let mut query =
                tx.prepare("SELECT id,updated,dropped,clean FROM sessions ORDER BY id")?;
            let mut rows = query.query([])?;
            while let Some(row) = rows.next()? {
                let id: String = row.get(0)?;
                let clean: i64 = row.get(3)?;
                if id.is_empty() || id.len() > 4096 || !matches!(clean, 0 | 1) {
                    return Err(invalid());
                }
                let value = Observation::Session {
                    id,
                    updated: unsigned(row, 1)?,
                    dropped: unsigned(row, 2)?,
                    clean: clean == 1,
                };
                hash(&mut digest, &value)?;
                visit(value)?;
            }
        }
        let worker: Option<WorkerStatus> = tx
            .query_row("SELECT body FROM worker WHERE singleton=1", [], |r| {
                r.get::<_, String>(0)
            })
            .optional()?
            .map(|s| serde_json::from_str(&s))
            .transpose()?;
        if tx.query_row("SELECT count(*) FROM worker", [], |r| r.get::<_, i64>(0))?
            != i64::from(worker.is_some())
        {
            return Err(invalid());
        }
        if let Some(queue) = worker.as_ref().and_then(|w| w.queue.as_ref()) {
            self.check_queue(queue)?;
        }
        hash(&mut digest, &worker)?;
        let exhausted_observed = if self.schema == 2 {
            if tx.query_row("SELECT count(*) FROM control", [], |r| r.get::<_, i64>(0))? != 1 {
                return Err(invalid());
            }
            let control: (u64, i64, String) = tx.query_row(
                "SELECT last_success,exhausted,reason FROM control WHERE singleton=1",
                [],
                |r| Ok((unsigned(r, 0)?, r.get(1)?, r.get(2)?)),
            )?;
            if !matches!(control.1, 0 | 1) {
                return Err(invalid());
            }
            hash(&mut digest, &control)?;
            Some(control.1 == 1)
        } else {
            None
        };
        tx.commit()?;
        Ok(Scan {
            started_at,
            finished_at: now(),
            digest: crate::evidence_service::hex(&digest.finalize()),
            worker,
            exhausted_observed,
        })
    }
}
