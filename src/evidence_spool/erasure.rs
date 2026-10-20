//! Admission-preserving retirement of explicitly erased spool operations. The
//! issuer-signed erasure plan binds exact manifest bytes without retaining raw
//! request ciphertext. Unpublished cancellation is a separate protocol.
use super::*;
use crate::{
    evidence::{self, Decoded},
    evidence_erasure_history::{Access, Record},
    evidence_proof_service::Profile,
    evidence_store::erasure::Target,
};
use atproto_dasl::Ipld;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
pub(crate) const SCHEMA:&str="CREATE TABLE erasure_authorizations(id TEXT PRIMARY KEY NOT NULL,body BLOB NOT NULL CHECK(length(body)>0 AND length(body)<=1052672));
CREATE TABLE erased_operations(position INTEGER PRIMARY KEY CHECK(position>=0),authorization TEXT NOT NULL,manifest BLOB CHECK(manifest IS NULL OR (length(manifest)>0 AND length(manifest)<=65536)));
PRAGMA user_version=3;";
fn invalid() -> Error {
    Error::Invalid("spool erasure proof or cursor")
}
pub(super) fn exists(conn: &Connection) -> Result<bool> {
    Ok(conn.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name='erased_operations')",[],|r|r.get(0))?)
}
pub(super) fn contains(conn: &Connection, position: u64) -> Result<bool> {
    if !exists(conn)? {
        return Ok(false);
    }
    Ok(conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM erased_operations WHERE position=?)",
        [position as i64],
        |r| r.get(0),
    )?)
}
fn validate(record: &Record, st: &State) -> Result<()> {
    record.verify_signature()?;
    let c = &record.change;
    if c.version != 1
        || c.binding.profile != Profile::Admitted
        || c.binding.scope != st.scope
        || c.binding.issuer != st.audience
    {
        return Err(invalid());
    }
    let erasure = c.erasure.as_ref().ok_or_else(invalid)?;
    erasure
        .validate(&c.binding.owner_binding()?, &erasure.plan.previous)
        .map_err(service::Failure::from)?;
    Ok(())
}
fn manifest(
    bytes: &[u8],
    position: u64,
    operation: &str,
    cid: &str,
    target: &Target,
    st: &State,
    conn: &Connection,
) -> Result<()> {
    let Decoded::Known(m) = evidence::decode(bytes).map_err(|_| invalid())? else {
        return Err(invalid());
    };
    let previous = if position == 0 {
        Ipld::Null
    } else {
        let value: String = conn.query_row(
            "SELECT manifest FROM operations WHERE position=?",
            [(position - 1) as i64],
            |r| r.get(0),
        )?;
        Ipld::Link(value.parse().map_err(|_| invalid())?)
    };
    let id = service::unhex(operation, 16)?;
    let entries = Ipld::List(vec![Ipld::Map(BTreeMap::from([
        ("slot".into(), Ipld::Bytes(Sha256::digest(&id).to_vec())),
        (
            "ciphertext".into(),
            Ipld::Link(target.object.parse().map_err(|_| invalid())?),
        ),
        ("length".into(), Ipld::Integer(target.length as i128)),
    ]))]);
    if m.kind() != evidence::Kind::Manifest
        || m.cid().to_string() != cid
        || cid != target.manifest
        || m.body()["writer"] != service::author(&st.writer)?
        || m.body()["scopeToken"] != Ipld::Bytes(service::unhex(&st.scope, 32)?)
        || m.body()["operation"] != Ipld::Bytes(id)
        || m.body()["position"] != Ipld::Integer(i128::from(position))
        || m.body()["previous"] != previous
        || m.body()["entries"] != entries
    {
        return Err(invalid());
    }
    Ok(())
}
/// Authenticate every retirement. Only full canonical manifests can advance a
/// cursor; metadata-only old markers must be covered by an authenticated cursor.
pub(super) fn frontier(conn: &Connection, st: &State) -> Result<Option<(u64, String)>> {
    if !exists(conn)? {
        return Ok(None);
    }
    let mut records = BTreeMap::new();
    let mut total = 0usize;
    let mut q =
        conn.prepare("SELECT id,body FROM erasure_authorizations ORDER BY id LIMIT 1025")?;
    for row in q.query_map([], |r| {
        Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?))
    })? {
        let (id, bytes) = row?;
        total += bytes.len();
        if records.len() >= 1024 || total > 18 * 1024 * 1024 {
            return Err(invalid());
        }
        let record: Record = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
        if serde_json::to_vec(&record).map_err(|_| invalid())? != bytes || record.id()? != id {
            return Err(invalid());
        }
        validate(&record, st)?;
        let targets = record
            .change
            .erasure
            .as_ref()
            .ok_or_else(invalid)?
            .plan
            .targets
            .iter()
            .map(|t| (t.manifest.clone(), t.clone()))
            .collect::<BTreeMap<_, _>>();
        records.insert(id, targets);
    }
    let mut maximum = None;
    let mut partial = Vec::new();
    let mut used = BTreeSet::new();
    let mut q=conn.prepare("SELECT e.position,e.authorization,e.manifest,o.operation,o.manifest FROM erased_operations e LEFT JOIN operations o ON o.position=e.position ORDER BY e.position LIMIT 32769")?;
    let mut rows = q.query([])?;
    let mut count = 0;
    while let Some(row) = rows.next()? {
        count += 1;
        if count > 32768 {
            return Err(invalid());
        }
        let position = unsigned(row, 0)?;
        let authorization: String = row.get(1)?;
        let body: Option<Vec<u8>> = row.get(2)?;
        let operation: String = row.get(3)?;
        let cid: String = row.get(4)?;
        let targets = records.get(&authorization).ok_or_else(invalid)?;
        let target = targets.get(&cid).ok_or_else(invalid)?;
        if let Some(bytes) = body {
            manifest(&bytes, position, &operation, &cid, target, st, conn)?;
            maximum = Some((position, cid));
        } else {
            partial.push(position);
        }
        used.insert(authorization);
    }
    if used.len() != records.len() {
        return Err(invalid());
    }
    let acknowledged = match (&st.request, &st.reply) {
        (Some(raw), Some(reply)) => {
            let signed: SignedReply = serde_json::from_slice(reply).map_err(|_| invalid())?;
            if signed.bytes()? != *reply {
                return Err(invalid());
            }
            service::admitted_manifest(raw, &signed, &st.audience)?;
            Some(coordinates(raw, st)?.0)
        }
        (None, None) => None,
        _ => return Err(invalid()),
    };
    let covered = acknowledged
        .into_iter()
        .chain(maximum.as_ref().map(|(p, _)| *p))
        .max();
    if partial.iter().any(|p| covered.is_none_or(|n| n < *p)) {
        return Err(invalid());
    }
    Ok(maximum)
}
impl Spool {
    /// Reconcile only independently authorized, actually admitted erasures. A
    /// selected head prefix may retire while later selected requests wait behind
    /// an unaffected head. No progress across such a gap is ever fabricated.
    pub fn reconcile_erasure(&mut self, history: &Access) -> Result<serde_json::Value> {
        let current = history.current()?;
        let st = state(&self.conn)?;
        if history.binding.profile != Profile::Admitted
            || history.binding.scope != st.scope
            || history.binding.issuer != st.audience
        {
            return Err(invalid());
        }
        self.conn.execute_batch("PRAGMA secure_delete=ON;")?;
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        audit(&tx)?;
        if exists(&tx)? {
            let ids = current
                .history
                .iter()
                .map(Record::id)
                .collect::<std::result::Result<BTreeSet<_>, _>>()?;
            let mut q = tx.prepare("SELECT id FROM erasure_authorizations")?;
            for id in q.query_map([], |r| r.get::<_, String>(0))? {
                if !ids.contains(&id?) {
                    return Err(Error::Proof(service::Failure::AccessLimited));
                }
            }
        }
        let st = state(&tx)?;
        let mut selected = BTreeMap::new();
        for record in &current.history {
            if let Some(erasure) = &record.change.erasure {
                for target in &erasure.plan.targets {
                    selected
                        .entry(target.manifest.clone())
                        .or_insert((record, target));
                }
            }
        }
        let mut pending = tx.prepare("SELECT position,manifest FROM pending ORDER BY position")?;
        let mut blocked = false;
        let mut deferred = BTreeSet::new();
        for row in pending.query_map([], |r| Ok((unsigned(r, 0)?, r.get::<_, String>(1)?)))? {
            let (position, cid) = row?;
            if selected.contains_key(&cid) {
                if blocked {
                    deferred.insert(position);
                }
            } else {
                blocked = true;
            }
        }
        drop(pending);
        let acknowledged = st
            .request
            .as_ref()
            .map(|r| coordinates(r, &st))
            .transpose()?;
        let mut changes = Vec::new();
        for (cid, (record, target)) in &selected {
            let operation: Option<(u64, String)> = tx
                .query_row(
                    "SELECT position,operation FROM operations WHERE manifest=?",
                    [cid],
                    |r| Ok((unsigned(r, 0)?, r.get(1)?)),
                )
                .optional()?;
            let Some((position, id)) = operation else {
                continue;
            };
            if contains(&tx, position)? || deferred.contains(&position) {
                continue;
            }
            let pending: Option<Vec<u8>> = tx
                .query_row(
                    "SELECT request FROM pending WHERE position=?",
                    [position as i64],
                    |r| r.get(0),
                )
                .optional()?;
            let raw = pending.as_ref().or_else(|| {
                acknowledged
                    .as_ref()
                    .filter(|a| a.0 == position)
                    .and(st.request.as_ref())
            });
            let body = if let Some(raw) = raw {
                if crate::evidence_store::ciphertext_cid(raw).to_string() != target.object
                    || raw.len() != target.length
                {
                    return Err(invalid());
                }
                let m = service::append_manifest(raw)?;
                manifest(m.bytes(), position, &id, cid, target, &st, &tx)?;
                Some(m.bytes().to_vec())
            } else {
                None
            };
            changes.push((
                position,
                *record,
                body,
                acknowledged.as_ref().is_some_and(|a| a.0 == position),
            ));
        }
        if changes.is_empty() && !deferred.is_empty() {
            return Err(Error::Conflict);
        }
        if !changes.is_empty() {
            if !exists(&tx)? {
                // surface-write: evidence-spool:database
                crate::persistence::initialize_spool_erasure(
                    crate::persistence::SurfaceWrite::EvidenceSpool,
                    &tx,
                )?;
            }
            for (position, record, body, clear_ack) in &changes {
                let id = record.id()?;
                let bytes = serde_json::to_vec(record).map_err(|_| invalid())?;
                let existing: Option<Vec<u8>> = tx
                    .query_row(
                        "SELECT body FROM erasure_authorizations WHERE id=?",
                        [&id],
                        |r| r.get(0),
                    )
                    .optional()?;
                if let Some(old) = existing {
                    if old != bytes {
                        return Err(invalid());
                    }
                } else {
                    // surface-write: evidence-spool:database
                    crate::persistence::insert_spool_erasure_authorization(
                        crate::persistence::SurfaceWrite::EvidenceSpool,
                        &tx,
                        &id,
                        &bytes,
                    )?;
                }
                // surface-write: evidence-spool:database
                crate::persistence::insert_spool_erasure_operation(
                    crate::persistence::SurfaceWrite::EvidenceSpool,
                    &tx,
                    *position,
                    &id,
                    body.as_deref(),
                )?;
                // surface-write: evidence-spool:database
                crate::persistence::erase_spool_payload(
                    crate::persistence::SurfaceWrite::EvidenceSpool,
                    &tx,
                    *position,
                    *clear_ack,
                )?;
            }
            audit(&tx)?;
        }
        tx.commit()?;
        Ok(
            serde_json::json!({"state":if deferred.is_empty(){"admitted-erasure-reconciled"}else{"partial-admitted-erasure"},"deferred_pending_operations":deferred.len(),"owner_checkpoint":current.tip,"retired_operations":changes.len(),"page_reclamation":"pending","unpublished_cancellation":"not-performed","backup_purge":"not-performed"}),
        )
    }
    pub fn reclaim_erased_pages(&self) -> Result<bool> {
        audit(&self.conn)?;
        self.conn.execute_batch("PRAGMA secure_delete=ON;")?;
        let busy: i64 = self
            .conn
            .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| r.get(0))?;
        if busy != 0 {
            return Ok(false);
        }
        self.conn.execute_batch("VACUUM;")?;
        let busy: i64 = self
            .conn
            .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| r.get(0))?;
        Ok(busy == 0)
    }
}
