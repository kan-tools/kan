//! Atomic compatibility-record batches in the existing encrypted annotation
//! journal. Operation identity is separate from claim CID and append order.
use super::*;
impl Workspace {
    pub(crate) fn append_authored(
        &self,
        id: &str,
        source: &str,
        operation: &crate::evidence_library::RecordOperation,
        intent: &str,
        build: impl FnOnce(u64) -> Result<Value>,
    ) -> Result<Value> {
        let key = Self::id("annotation", id);
        let mut conn = self.conn.lock().map_err(invalid)?;
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(invalid)?;
        let custody = self.check_erasure_histories(&tx)?;
        if erasure::erased(self, &tx, "annotation", &key)? {
            return Err(Failure::AccessLimited);
        }
        let prior: Option<Vec<u8>> = tx
            .query_row(
                "SELECT body FROM entries WHERE kind='annotation' AND id=?",
                [&key],
                |r| r.get(0),
            )
            .optional()
            .map_err(invalid)?;
        if let Some(bytes) = prior {
            let value = self.unseal("annotation", &key, &bytes)?;
            let batch = &value["draft"]["authored"];
            if value["id"] != id
                || batch["source"] != source
                || batch["intent_hash"] != intent
                || batch["operation"] != serde_json::to_value(operation).map_err(invalid)?
            {
                return Err(Failure::Invalid);
            }
            return Ok(value);
        }
        let mut order = 0u64;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
        {
            let mut q = tx
                .prepare("SELECT id,body FROM entries WHERE kind='annotation'")
                .map_err(invalid)?;
            let mut rows = q.query([]).map_err(invalid)?;
            while let Some(row) = rows.next().map_err(invalid)? {
                let key: String = row.get(0).map_err(invalid)?;
                if erasure::erased(self, &tx, "annotation", &key)? {
                    continue;
                }
                let body: Vec<u8> = row.get(1).map_err(invalid)?;
                if std::time::Instant::now() >= deadline {
                    return Err(Failure::Unavailable);
                }
                let value = self.unseal("annotation", &key, &body)?;
                if value["draft"]["authored"]["source"] == source {
                    order = order.max(
                        value["draft"]["authored"]["order"]
                            .as_u64()
                            .ok_or(Failure::Corrupt)?,
                    );
                }
            }
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(invalid)?
            .as_micros();
        let now: u64 = now.try_into().map_err(invalid)?;
        let next = now.max(order.checked_add(4).ok_or(Failure::Invalid)?);
        let value = build(next)?;
        if value["id"] != id
            || value["author"] != self.author()
            || value["draft"]["authored"]["order"] != next
        {
            return Err(Failure::Invalid);
        }
        if serde_json::to_vec(&value).map_err(invalid)?.len() > 262144 {
            return Err(Failure::Invalid);
        }
        let bytes = self.seal("annotation", &key, value.clone())?;
        // surface-write: evidence-workspace:annotation (existing encrypted journal capability)
        tx.execute(
            "INSERT INTO entries VALUES('annotation',?,?)",
            params![key, bytes],
        )
        .map_err(invalid)?;
        *self.annotation_lookup.lock().map_err(invalid)? = None;
        *self.erasure_audit.lock().map_err(invalid)? = None;
        self.audit_erasure_snapshots(&tx, &custody)?;
        tx.commit().map_err(invalid)?;
        Ok(value)
    }
}
