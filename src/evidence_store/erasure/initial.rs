//! Commitment-only admission of an owner-cancelled unpublished request. The
//! normal writer/slot chain and issuer proof are committed, but payload bytes
//! are never staged. An initial-erasure record identifies this disposition.
use super::*;

fn target_matches(record: &Record, manifest: &evidence::Record) -> Result<()> {
    let t = record.plan.targets.first().ok_or_else(corrupt)?;
    let es: Vec<_> = entries(manifest).collect();
    if record.plan.initial_erasure.is_none()
        || record.plan.targets.len() != 1
        || record.plan.tip != manifest.cid().to_string()
        || t.manifest != manifest.cid().to_string()
        || es.len() != 1
        || cid(&es[0]["ciphertext"]) != t.object
        || number(&es[0]["length"]) != t.length as i64
    {
        return Err(corrupt());
    }
    Ok(())
}
pub(in crate::evidence_store) fn check_initial_request(
    conn: &Connection,
    binding: &attested::Binding,
    record: &Record,
    raw: &[u8],
) -> Result<()> {
    record.validate(binding, &record.plan.previous)?;
    let manifest = service::append_manifest(raw).map_err(|_| corrupt())?;
    target_matches(record, &manifest)?;
    let t = &record.plan.targets[0];
    if t.object != ciphertext_cid(raw).to_string() || t.length != raw.len() {
        return Err(corrupt());
    }
    let history = load(conn)?;
    let installed = history
        .records
        .iter()
        .any(|r| r.id().ok() == record.id().ok());
    if !installed && history.tip != record.plan.previous {
        return Err(Error::Conflict("initial erasure history changed"));
    }
    let committed: Option<i64> = conn
        .query_row(
            "SELECT sequence FROM commits WHERE cid=?",
            [&t.manifest],
            |r| r.get(0),
        )
        .optional()?;
    if let Some(sequence) = committed {
        if !installed || u64::try_from(sequence).ok() != Some(t.sequence) {
            return Err(Error::Conflict(
                "request was admitted without initial erasure",
            ));
        }
        check_marker(conn, &t.object)?;
    }
    Ok(())
}
/// Runs after the ordinary writer-frontier check and inside the same transaction
/// as metadata/attestation insertion. No raw request reaches this write surface.
pub(in crate::evidence_store) fn install_initial(
    tx: &rusqlite::Transaction<'_>,
    record: &Record,
    manifest: &evidence::Record,
) -> Result<()> {
    let owner = binding(tx)?;
    record.validate(&owner, &record.plan.previous)?;
    target_matches(record, manifest)?;
    let current: Option<(i64, String)> = tx
        .query_row(
            "SELECT sequence,cid FROM commits ORDER BY sequence DESC LIMIT 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let next = current.as_ref().map_or(1, |(n, _)| (*n as u64) + 1);
    if record.plan.through != next
        || record
            .plan
            .initial_erasure
            .as_ref()
            .ok_or_else(corrupt)?
            .previous
            != current.map(|(_, cid)| cid)
    {
        return Err(Error::Conflict("initial erasure preview is stale"));
    }
    let history = load(tx)?;
    let id = record.id()?;
    if history
        .records
        .iter()
        .any(|r| r.id().ok().as_ref() == Some(&id))
    {
        // An old restore may have installed current custody before metadata.
        // Newer plans cannot be bypassed to admit unrelated bytes.
        if history.tip.as_ref() != Some(&id) {
            return Err(Error::Conflict("initial erasure is not current"));
        }
    } else {
        record.validate(&owner, &history.tip)?;
        install(tx, &history, std::slice::from_ref(record))?;
    }
    // surface-write: evidence-erasure-sqlite:objects
    crate::persistence::insert_erased_evidence_object(
        crate::persistence::SurfaceWrite::EvidenceErasure,
        tx,
        &record.plan.targets[0].object,
    )?;
    Ok(())
}
impl attested::Archive {
    /// Select the exact signed request, whether still unpublished or admitted
    /// during a coordinator's earlier scan. The caller must fence enrolled
    /// admission while preparing and publishing its owner authorization.
    pub(crate) fn preview_request_erasure(
        &self,
        raw: &[u8],
        nonce: String,
        now: u64,
    ) -> Result<Plan> {
        let manifest = service::append_manifest(raw).map_err(|_| corrupt())?;
        let sequence: Option<i64> = self
            .ledger
            .conn
            .query_row(
                "SELECT sequence FROM commits WHERE cid=?",
                [manifest.cid().to_string()],
                |row| row.get(0),
            )
            .optional()?;
        match sequence {
            Some(sequence) => self.preview_erasure(
                &[u64::try_from(sequence).map_err(|_| corrupt())?],
                nonce,
                now,
            ),
            None => self.preview_erased_admission(raw, nonce, now),
        }
    }
    /// Preview exact commitment-only admission. The coordinating owner must
    /// establish derivative membership and sign/publish independent consent.
    /// Only an actually next, not-yet-committed writer operation is eligible.
    pub fn preview_erased_admission(&self, raw: &[u8], nonce: String, now: u64) -> Result<Plan> {
        if self.copy.is_some() {
            return Err(Error::Invalid("copied archive"));
        }
        let manifest = service::append_manifest(raw).map_err(|_| corrupt())?;
        let signed = service::SignedRequest::decode(raw).map_err(|_| corrupt())?;
        if signed.request.scope != service::hex(&self.binding.scope)
            || signed.request.audience != self.binding.issuer
        {
            return Err(Error::Invalid("erased admission binding"));
        }
        let verified = self.verify()?;
        let tx = self.ledger.conn.unchecked_transaction()?;
        let snap = self.ledger.snapshot()?;
        if snap.through != verified.through || snap.tip != verified.manifest {
            return Err(Error::Conflict(
                "archive advanced during erased admission preview",
            ));
        }
        let b = manifest.body();
        let head: Option<(i64,String)> = tx.query_row(
            "SELECT position,cid FROM commits WHERE scope=? AND writer=? ORDER BY position DESC LIMIT 1",
            params![blob(&b["scopeToken"]),writer(&manifest)],|r|Ok((r.get(0)?,r.get(1)?)),
        ).optional()?;
        if number(&b["position"]) != head.as_ref().map_or(0, |(n, _)| n + 1)
            || optional_cid(&b["previous"]) != head.map(|(_, cid)| cid)
        {
            return Err(Error::Conflict("writer frontier"));
        }
        let history = load(&tx)?;
        if history
            .records
            .iter()
            .any(|r| r.plan.through > snap.through)
        {
            return Err(Error::Conflict("missing erased admission metadata"));
        }
        let sequence = snap
            .through
            .checked_add(1)
            .filter(|n| *n <= evidence::MAX_SAFE_INTEGER as u64)
            .ok_or_else(corrupt)?;
        let cid = manifest.cid().to_string();
        let plan = Plan {
            version: 1,
            archive: service::hex(&self.binding.archive),
            scope: service::hex(&self.binding.scope),
            issuer: self.binding.issuer.clone(),
            through: sequence,
            tip: cid.clone(),
            previous: history.tip,
            nonce,
            recorded_at: now,
            targets: vec![Target {
                sequence,
                manifest: cid,
                object: ciphertext_cid(raw).to_string(),
                length: raw.len(),
            }],
            initial_erasure: Some(InitialErasure {
                previous: snap.tip.map(|c| c.to_string()),
            }),
        };
        tx.commit()?;
        Ok(plan)
    }
}
