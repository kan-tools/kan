//! Independently configured freshness gates for managed reader workspaces.
use super::*;
use crate::evidence_erasure_history::{Access, Snapshot};
impl Workspace {
    /// Keep this enrollment configuration independently of database backups.
    /// The database never chooses its own acceptable current custody.
    pub fn with_erasure_histories(mut self, histories: Vec<Access>) -> Result<Self> {
        if histories.len() > 16 || self.erasure_maintenance {
            return Err(Failure::Invalid);
        }
        let mut seen = BTreeSet::new();
        for history in &histories {
            history.validate()?;
            if !seen.insert(serde_json::to_vec(&history.binding).map_err(invalid)?) {
                return Err(Failure::Invalid);
            }
        }
        self.erasure_histories = histories;
        {
            let conn = self.conn.lock().map_err(invalid)?;
            let tx = conn.unchecked_transaction().map_err(invalid)?;
            self.check_erasure_histories(&tx)?;
        }
        Ok(self)
    }
    /// Keep independently current source custody across an external publication.
    /// SQLite state is checked in a read transaction, but no database lock is
    /// held while awaiting the network. Workspace maintenance has its own lease.
    pub(crate) fn publication_lease(&self) -> Result<Vec<Snapshot>> {
        let conn = self.conn.lock().map_err(invalid)?;
        let tx = conn.unchecked_transaction().map_err(invalid)?;
        let current = self.check_erasure_histories(&tx)?;
        tx.commit().map_err(invalid)?;
        Ok(current)
    }
    pub(in crate::evidence_workspace) fn audit_erasure_snapshots(
        &self,
        conn: &Connection,
        current: &[Snapshot],
    ) -> Result<()> {
        if current.len() != self.erasure_histories.len() {
            return Err(Failure::Invalid);
        }
        for (history, snapshot) in self.erasure_histories.iter().zip(current) {
            for record in &snapshot.history {
                if let Some(erasure) = &record.change.erasure {
                    if !self
                        .erasure_dependency_ids(conn, &history.binding, erasure)?
                        .is_empty()
                    {
                        return Err(Failure::AccessLimited);
                    }
                }
            }
        }
        Ok(())
    }
    /// Caller must already hold a SQLite transaction. Establish its read
    /// snapshot before checking data_version so a cached proof and returned row
    /// cannot straddle an external commit. Hold custody until that transaction ends.
    pub(in crate::evidence_workspace) fn check_erasure_histories(
        &self,
        conn: &Connection,
    ) -> Result<Vec<Snapshot>> {
        if self.erasure_histories.is_empty() {
            return Ok(Vec::new());
        }
        let held = self
            .erasure_histories
            .iter()
            .map(Access::current)
            .collect::<Result<Vec<_>>>()?;
        let tips = held
            .iter()
            .map(|s| s.tip.clone().ok_or(Failure::AccessLimited))
            .collect::<Result<Vec<_>>>()?;
        conn.query_row("SELECT count(*) FROM entries", [], |r| r.get::<_, i64>(0))
            .map_err(invalid)?;
        let version = conn
            .query_row("PRAGMA data_version", [], |r| r.get::<_, i64>(0))
            .map_err(invalid)?;
        let mut cached = self.erasure_audit.lock().map_err(invalid)?;
        if cached.as_ref() != Some(&(version, tips.clone())) {
            self.audit_erasure_snapshots(conn, &held)?;
            *cached = Some((version, tips));
        }
        Ok(held)
    }
}
