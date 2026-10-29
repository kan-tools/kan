//! Owner-selected read-only proof inventory. Never an admission or remote grant API.
use super::*;
use crate::{
    evidence_attestation::{self as proof, Frontier, Purpose, Verified},
    evidence_copy_plan::Plan,
    evidence_service as service,
};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::Instant;

const METADATA_LIMIT: i32 = 256 * 1024;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    Admitted,
    Copied,
}
impl Profile {
    pub fn number(self) -> i64 {
        match self {
            Self::Admitted => 2,
            Self::Copied => 3,
        }
    }
}
#[derive(Clone)]
pub struct Budget {
    /// Records plus original-membership rows, not just returned rows.
    pub items: u64,
    pub metadata_bytes: u64,
    pub duration: Duration,
    pub cancelled: Arc<AtomicBool>,
}
impl Budget {
    fn deadline(&self) -> Result<Instant> {
        if self.duration.is_zero() || self.duration > Duration::from_secs(3600) {
            return Err(Error::Invalid("inventory duration budget"));
        }
        Instant::now()
            .checked_add(self.duration)
            .ok_or(Error::Invalid("inventory deadline"))
    }
    fn check(&self, deadline: Instant) -> Result<()> {
        if self.cancelled.load(Ordering::Relaxed) || Instant::now() >= deadline {
            return Err(Error::Invalid("inventory cancelled or timed out"));
        }
        Ok(())
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Availability {
    Available,
    Erased,
    Missing,
    Corrupt,
}
#[derive(Clone, Debug)]
pub struct Selection {
    index_custody: Option<Option<String>>,
    profile: Profile,
    binding: attested::Binding,
    snapshot: Frontier,
    frontier: Frontier,
}
impl Selection {
    pub fn frontier(&self) -> &Frontier {
        &self.frontier
    }
    pub fn snapshot(&self) -> &Frontier {
        &self.snapshot
    }
}
#[derive(Clone, Debug)]
pub struct Cursor {
    snapshot: Frontier,
    next: Frontier,
    profile: Profile,
    binding: attested::Binding,
}
pub struct Occurrence {
    pub record: Committed,
    pub proof: Verified,
    pub availability: Availability,
    pub selection: Selection,
}
pub struct Page {
    pub records: Vec<Occurrence>,
    pub next: Option<Cursor>,
    pub payload_budget_used: usize,
}
#[derive(Clone, Copy)]
pub struct PageBudget {
    pub rows: usize,
    /// Sum of canonical manifest, receipt and proof bytes; not an RPC wire limit.
    pub record_bytes: usize,
    pub payload_bytes: usize,
}
pub enum Source {
    Available { bytes: Vec<u8>, writer: String },
    Unavailable(Availability),
}

fn corrupt(message: &str) -> Error {
    Error::Corrupt(message.into())
}
fn configure_read(conn: &Connection, budget: &Budget, deadline: Instant) -> Result<()> {
    conn.set_limit(rusqlite::limits::Limit::SQLITE_LIMIT_LENGTH, METADATA_LIMIT)?;
    conn.busy_timeout(budget.duration.min(Duration::from_secs(5)))?;
    let cancelled = budget.cancelled.clone();
    conn.progress_handler(
        1000,
        Some(move || cancelled.load(Ordering::Relaxed) || Instant::now() >= deadline),
    )?;
    budget.check(deadline)
}
fn schema(conn: &Connection, profile: Profile) -> Result<()> {
    let expected = Connection::open_in_memory()?;
    expected_base_schema(conn, &expected)?;
    expected.execute_batch(attested::SCHEMA)?;
    if profile == Profile::Copied {
        expected.execute_batch(copied::SCHEMA)?;
    }
    erasure::extend_schema(conn, &expected)?;
    serving::extend_schema(conn, &expected)?;
    // Bound every variable schema field; the SQLite allocation limit is separate.
    let query="SELECT substr(type,1,32),length(type),substr(name,1,256),length(name),substr(tbl_name,1,256),length(tbl_name),substr(sql,1,65536),length(sql) FROM sqlite_schema ORDER BY type,name";
    let mut a = conn.prepare(query)?;
    let mut e = expected.prepare(query)?;
    let mut actual = a.query([])?;
    let mut wanted = e.query([])?;
    loop {
        match (actual.next()?, wanted.next()?) {
            (None, None) => return Ok(()),
            (Some(a), Some(e)) => {
                for c in 0..8 {
                    if a.get_ref(c)? != e.get_ref(c)? {
                        return Err(Error::Invalid("unsupported inventory schema"));
                    }
                }
            }
            _ => return Err(Error::Invalid("unsupported inventory schema")),
        }
    }
}
fn plan(
    reader: &RecoveryReader,
    profile: Profile,
    binding: &attested::Binding,
) -> Result<Option<Plan>> {
    schema(&reader.ledger.conn, profile)?;
    attested::check_binding(&reader.ledger.conn, binding)?;
    if profile == Profile::Copied {
        Ok(Some(copied::stored_plan(&reader.ledger.conn, binding)?))
    } else {
        Ok(None)
    }
}
fn purpose(record: &Committed, proof: &Verified, plan: Option<&Plan>) -> Result<()> {
    match proof.purpose() {
        Purpose::Admitted => {
            if plan.is_some_and(|p| record.sequence <= p.source().through) {
                return Err(corrupt("admission inside planned retained prefix"));
            }
        }
        Purpose::RetainedVerified => {
            let p =
                plan.ok_or_else(|| corrupt("retained-verified prefix requires copy profile"))?;
            if record.sequence > p.source().through {
                return Err(corrupt("retained-verified row after planned prefix"));
            }
            let historical = service::author(&p.source().historical_issuer)
                .map_err(|_| corrupt("historical issuer"))?;
            if record.receipt.body()["issuer"] != historical {
                return Err(corrupt(
                    "retained-verified historical issuer differs from copy plan",
                ));
            }
        }
    }
    let es: Vec<_> = entries(&record.manifest).collect();
    if es.len() != 1 {
        return Err(corrupt("inventory requires one service request entry"));
    }
    if number(&es[0]["length"]) as u64 > service::MAX_REQUEST as u64 {
        return Err(corrupt("inventory request bound"));
    }
    Ok(())
}
fn cost(record: &Committed, bytes: &[u8]) -> u64 {
    (record.manifest.bytes().len() + record.receipt.bytes().len() + bytes.len()) as u64
}
fn add_spent(spent: &mut u64, amount: u64, maximum: u64) -> Result<()> {
    *spent = spent
        .checked_add(amount)
        .ok_or(Error::Invalid("inventory budget overflow"))?;
    if *spent > maximum {
        return Err(Error::Invalid("inventory audit budget exhausted"));
    }
    Ok(())
}

pub struct Inventory {
    indexed: Option<serving::Checkpoint>,
    erasures: erasure::History,
    reader: RecoveryReader,
    binding: attested::Binding,
    profile: Profile,
    plan: Option<Plan>,
    frontier: Frontier,
    recipe_metadata_match: Option<bool>,
}
impl Inventory {
    /// Full metadata startup audit; no payload bytes are read here. The duration
    /// bounds checked work/SQLite VM execution, not arbitrary filesystem stalls.
    pub fn open(
        path: &Path,
        profile: Profile,
        binding: attested::Binding,
        budget: Budget,
    ) -> Result<Self> {
        Self::open_selected(path, profile, binding, None, budget)
    }
    /// Reopen a retained older prefix without holding a transaction between
    /// human page requests. The whole current metadata chain is still audited;
    /// the requested frontier must occur in that same verified chain.
    /// This is owner-selected metadata, not a grant or a wire-pin verifier.
    pub fn open_at(
        path: &Path,
        profile: Profile,
        binding: attested::Binding,
        selected: &Frontier,
        budget: Budget,
    ) -> Result<Self> {
        Self::open_selected(path, profile, binding, Some(selected), budget)
    }
    /// Bounded selected metadata opening. Requires explicit index initialization
    /// and the seekable payload layout; never silently performs a lifetime scan.
    pub fn open_indexed(
        path: &Path,
        profile: Profile,
        binding: attested::Binding,
        selected: Option<&Frontier>,
        current_erasure_tip: Option<&str>,
        budget: Budget,
    ) -> Result<Self> {
        binding.validate()?;
        let deadline = budget.deadline()?;
        budget.check(deadline)?;
        let reader = RecoveryReader::open_profile_configured(path, profile.number(), |conn| {
            configure_read(conn, &budget, deadline)
        })?;
        let conn = &reader.ledger.conn;
        let plan = plan(&reader, profile, &binding)?;
        if !rowid_objects(conn)? {
            return Err(Error::Invalid(
                "indexed reads require seekable payload layout; recover to a new archive",
            ));
        }
        let checkpoint = serving::checkpoint(conn, &binding, current_erasure_tip)?;
        let current = checkpoint.validate(&binding)?;
        let frontier = selected.unwrap_or(&current).clone();
        if frontier.through > current.through
            || (frontier.through == 0 && frontier != Frontier::default())
        {
            return Err(Error::Invalid("indexed prefix outside archive"));
        }
        if frontier.through > 0 {
            if budget.items == 0 {
                return Err(Error::Invalid("inventory audit budget exhausted"));
            }
            let metadata =
                serving::selected_metadata(conn, &binding, &checkpoint, frontier.through)?;
            if metadata.proof.frontier() != &frontier {
                return Err(corrupt("indexed prefix mismatch"));
            }
            if cost(&metadata.record, metadata.proof.bytes()) > budget.metadata_bytes {
                return Err(Error::Invalid("inventory audit budget exhausted"));
            }
        }
        budget.check(deadline)?;
        conn.progress_handler(0, None::<fn() -> bool>)?;
        let recipe_metadata_match = checkpoint.recipe_metadata_match().map(|matches| {
            matches
                && plan
                    .as_ref()
                    .is_some_and(|p| frontier.through >= p.source().through)
        });
        Ok(Self {
            indexed: Some(checkpoint),
            erasures: Default::default(),
            reader,
            binding,
            profile,
            plan,
            frontier,
            recipe_metadata_match,
        })
    }
    fn open_selected(
        path: &Path,
        profile: Profile,
        binding: attested::Binding,
        selected: Option<&Frontier>,
        budget: Budget,
    ) -> Result<Self> {
        binding.validate()?;
        let deadline = budget.deadline()?;
        budget.check(deadline)?;
        let reader = RecoveryReader::open_profile_configured(path, profile.number(), |conn| {
            configure_read(conn, &budget, deadline)
        })?;
        let plan = plan(&reader, profile, &binding)?;
        let erasures = erasure::load(&reader.ledger.conn)?;
        let mut query = reader
            .ledger
            .conn
            .prepare(&format!("{RAW_COMMITS} ORDER BY sequence"))?;
        let mut rows = query.query([])?;
        let mut frontier = Frontier::default();
        let mut selected_found = selected.is_none_or(|pin| *pin == Frontier::default());
        let mut items = 0;
        let mut bytes = 0;
        let mut hash = Sha256::new();
        hash.update(copy_upgrade::SOURCE_DOMAIN);
        copy_upgrade::frame(&mut hash, b"commits");
        if let Some(plan) = &plan {
            hash.update(plan.source().through.to_be_bytes());
        }
        while let Some(row) = rows.next()? {
            budget.check(deadline)?;
            add_spent(&mut items, 1, budget.items)?;
            let record = raw_commit(row)?;
            if record.sequence != frontier.through + 1 {
                return Err(corrupt("noncontiguous inventory metadata"));
            }
            let envelope = attested::envelope(&reader.ledger.conn, record.sequence)?;
            add_spent(&mut bytes, cost(&record, &envelope), budget.metadata_bytes)?;
            let verified = proof::verify(
                &envelope,
                &binding.context(),
                &record.manifest,
                &record.receipt,
                &frontier,
            )
            .map_err(|_| corrupt("invalid inventory proof chain"))?;
            purpose(&record, &verified, plan.as_ref())?;
            if let Some(plan) = &plan {
                if record.sequence <= plan.source().through {
                    hash.update(record.sequence.to_be_bytes());
                    copy_upgrade::frame(&mut hash, record.manifest.bytes());
                    copy_upgrade::frame(&mut hash, record.receipt.bytes());
                    let es: Vec<_> = entries(&record.manifest).collect();
                    let request: Cid = cid(&es[0]["ciphertext"])
                        .parse()
                        .map_err(|_| corrupt("request CID"))?;
                    copy_upgrade::frame(&mut hash, &request.to_bytes());
                    if record.sequence == plan.source().through
                        && Some(record.manifest.cid()) != plan.source().tip.as_ref()
                    {
                        return Err(corrupt("copy source tip"));
                    }
                }
            }
            frontier = verified.frontier().clone();
            if selected == Some(&frontier) {
                selected_found = true;
            }
        }
        drop(rows);
        drop(query);
        let proof_count: i64 = reader.ledger.conn.query_row(
            "SELECT count(*) FROM attestations NOT INDEXED",
            [],
            |r| r.get(0),
        )?;
        if u64::try_from(proof_count).ok() != Some(frontier.through) {
            return Err(corrupt("inventory proof cardinality"));
        }
        let recipe_metadata_match = if let Some(plan) = &plan {
            let count: i64 = reader.ledger.conn.query_row(
                "SELECT count(*) FROM upgrade_objects NOT INDEXED",
                [],
                |r| r.get(0),
            )?;
            copy_upgrade::frame(&mut hash, b"objects");
            hash.update(
                u64::try_from(count)
                    .map_err(|_| corrupt("original inventory count"))?
                    .to_be_bytes(),
            );
            let mut q=reader.ledger.conn.prepare("SELECT substr(cid,1,128),length(cid),length FROM upgrade_objects NOT INDEXED ORDER BY cid")?;
            let mut rs = q.query([])?;
            while let Some(row) = rs.next()? {
                budget.check(deadline)?;
                add_spent(&mut items, 1, budget.items)?;
                let text: String = row.get(0)?;
                let size: i64 = row.get(1)?;
                let length: i64 = row.get(2)?;
                let id: Cid = text.parse().map_err(|_| corrupt("original object CID"))?;
                if size != text.len() as i64
                    || text != id.to_string()
                    || !(1..=MAX_CHUNK as i64).contains(&length)
                {
                    return Err(corrupt("original inventory coordinate"));
                }
                add_spent(&mut bytes, text.len() as u64 + 8, budget.metadata_bytes)?;
                copy_upgrade::frame(&mut hash, &id.to_bytes());
                hash.update((length as u64).to_be_bytes());
            }
            let digest: [u8; 32] = hash.finalize().into();
            let matches =
                frontier.through >= plan.source().through && digest == plan.source().digest;
            if !matches
                && (frontier.through > plan.source().through
                    || (plan.source().through > 0 && frontier.through == plan.source().through))
            {
                return Err(corrupt(
                    "complete retained prefix does not match recipe metadata",
                ));
            }
            Some(matches)
        } else {
            None
        };
        if !selected_found {
            return Err(corrupt("selected inventory frontier not retained"));
        }
        if let Some(selected) = selected {
            frontier = selected.clone();
        }
        // The current source may have completed copying after this selected
        // prefix. Do not report that later completion as a property of the pin.
        let recipe_metadata_match = recipe_metadata_match.map(|matches| {
            matches
                && plan
                    .as_ref()
                    .is_some_and(|p| frontier.through >= p.source().through)
        });
        budget.check(deadline)?;
        reader
            .ledger
            .conn
            .progress_handler(0, None::<fn() -> bool>)?;
        Ok(Self {
            indexed: None,
            erasures,
            reader,
            binding,
            profile,
            plan,
            frontier,
            recipe_metadata_match,
        })
    }
    pub fn frontier(&self) -> &Frontier {
        &self.frontier
    }
    /// Transfer the same pinned, metadata-audited transaction to offline restore.
    /// This is not payload verification or permission to modify its source.
    pub(crate) fn into_recovery(self) -> Result<RecoveryReader> {
        // The audit uses a tighter metadata allocation bound. Payload recovery
        // must accept valid objects up to MAX_CHUNK, without reopening the
        // source or losing the audited transaction. Keep recovery's existing
        // finite SQLite bound and its independent length/CID checks.
        self.reader.ledger.conn.set_limit(
            rusqlite::limits::Limit::SQLITE_LIMIT_LENGTH,
            RECOVERY_SQLITE_LENGTH_LIMIT,
        )?;
        Ok(self.reader)
    }
    /// Metadata/inventory commitment only; not payload completeness or admission readiness.
    pub fn recipe_metadata_match(&self) -> Option<bool> {
        self.recipe_metadata_match
    }
    /// The canonical copy recipe, not evidence of payload availability or a grant.
    pub fn copy_plan(&self) -> Option<&Plan> {
        self.plan.as_ref()
    }
    /// Stateless descending continuation. Only this method constructs a cursor
    /// from caller coordinates; page() verifies its first proof against `next`
    /// before returning any occurrence. The current opening already audited the
    /// full chain, so a checked row at/below the pin belongs to that prefix.
    pub fn page_from(&self, next: &Frontier, limit: PageBudget, work: Budget) -> Result<Page> {
        if next.through > self.frontier.through
            || (next.through == 0 && *next != Frontier::default())
        {
            return Err(Error::Invalid(
                "inventory continuation outside selected prefix",
            ));
        }
        self.page(
            Some(&Cursor {
                snapshot: self.frontier.clone(),
                next: next.clone(),
                profile: self.profile,
                binding: self.binding.clone(),
            }),
            limit,
            work,
        )
    }
    pub fn page(&self, cursor: Option<&Cursor>, limit: PageBudget, work: Budget) -> Result<Page> {
        if limit.rows == 0
            || limit.rows > 40
            || limit.record_bytes == 0
            || limit.record_bytes > 8 * 1024 * 1024
            || limit.payload_bytes > 40 * MAX_CHUNK
        {
            return Err(Error::Invalid("inventory page budget"));
        }
        let deadline = work.deadline()?;
        configure_read(&self.reader.ledger.conn, &work, deadline)?;
        let mut expected = if let Some(cursor) = cursor {
            if cursor.profile != self.profile
                || cursor.binding != self.binding
                || cursor.snapshot != self.frontier
            {
                return Err(Error::Invalid("inventory cursor differs from snapshot"));
            }
            cursor.next.clone()
        } else {
            self.frontier.clone()
        };
        let mut records = Vec::new();
        let mut record_bytes = 0;
        let mut sampled_bytes = 0;
        let mut consumed = 0;
        while expected.through > 0 && records.len() < limit.rows {
            work.check(deadline)?;
            add_spent(&mut consumed, 1, work.items)?;
            let (record, verified) = if let Some(checkpoint) = &self.indexed {
                let metadata = serving::selected_metadata(
                    &self.reader.ledger.conn,
                    &self.binding,
                    checkpoint,
                    expected.through,
                )?;
                if metadata.proof.frontier() != &expected {
                    return Err(corrupt("indexed page coordinate mismatch"));
                }
                (metadata.record, metadata.proof)
            } else {
                let record = attested::record(&self.reader.ledger.conn, expected.through)?;
                let envelope = attested::envelope(&self.reader.ledger.conn, expected.through)?;
                let verified = proof::verify_at(
                    &envelope,
                    &self.binding.context(),
                    &record.manifest,
                    &record.receipt,
                    &expected,
                )
                .map_err(|_| corrupt("invalid inventory page proof"))?;
                (record, verified)
            };
            purpose(&record, &verified, self.plan.as_ref())?;
            let size = cost(&record, verified.bytes()) as usize;
            let (id, length) = request_coordinate(&record)?;
            if size > limit.record_bytes - record_bytes
                || (record_bytes as u64 + size as u64) > work.metadata_bytes
                || length > limit.payload_bytes - sampled_bytes
            {
                if records.is_empty() {
                    return Err(Error::Invalid("inventory row exceeds page budget"));
                }
                break;
            }
            let erased = if let Some(checkpoint) = &self.indexed {
                serving::erased(&self.reader.ledger.conn, checkpoint, &id)?
            } else {
                self.erasures.objects.contains_key(&id.to_string())
            };
            let (availability, _) = payload(&self.reader.ledger.conn, &id, length, erased)?;
            sampled_bytes += length;
            record_bytes += size;
            let selection = Selection {
                index_custody: self
                    .indexed
                    .as_ref()
                    .map(|c| c.erasure_tip().map(str::to_owned)),
                profile: self.profile,
                binding: self.binding.clone(),
                snapshot: self.frontier.clone(),
                frontier: verified.frontier().clone(),
            };
            expected = verified.previous().clone();
            records.push(Occurrence {
                record,
                proof: verified,
                availability,
                selection,
            });
        }
        work.check(deadline)?;
        let next = (expected.through > 0).then(|| Cursor {
            snapshot: self.frontier.clone(),
            next: expected,
            profile: self.profile,
            binding: self.binding.clone(),
        });
        Ok(Page {
            records,
            next,
            payload_budget_used: sampled_bytes,
        })
    }
}
fn request_coordinate(record: &Committed) -> Result<(Cid, usize)> {
    let es: Vec<_> = entries(&record.manifest).collect();
    if es.len() != 1 {
        return Err(corrupt("inventory requires one service request entry"));
    }
    let id = cid(&es[0]["ciphertext"])
        .parse()
        .map_err(|_| corrupt("request CID"))?;
    let length =
        usize::try_from(number(&es[0]["length"])).map_err(|_| corrupt("request length"))?;
    if length == 0 || length > service::MAX_REQUEST {
        return Err(corrupt("inventory request bound"));
    }
    Ok((id, length))
}
fn payload(
    conn: &Connection,
    id: &Cid,
    expected: usize,
    erased: bool,
) -> Result<(Availability, Option<Vec<u8>>)> {
    if erased {
        return Ok((Availability::Erased, None));
    }
    // New rowid archives seek through a separate CID index. Historical WITHOUT
    // ROWID rows require the old safe scan: a key seek can materialize an entire
    // oversized corrupt payload before SQLite's value limit applies.
    // Check the stored SQLite type before computing length: TEXT length can
    // materialize an oversized corrupt cell and counts characters, not bytes.
    // A wrong payload storage class is local payload corruption, not a page error.
    let indexed = rowid_objects(conn)?;
    let length_query = if indexed {
        "SELECT CASE WHEN typeof(bytes)='blob' THEN length(bytes) ELSE -1 END FROM objects WHERE cid=?"
    } else {
        "SELECT CASE WHEN typeof(bytes)='blob' THEN length(bytes) ELSE -1 END FROM objects NOT INDEXED WHERE +cid=?"
    };
    let length: Option<i64> = conn
        .query_row(length_query, [id.to_string()], |r| r.get(0))
        .optional()?;
    let Some(length) = length else {
        return Ok((Availability::Missing, None));
    };
    if length != expected as i64 {
        return Ok((Availability::Corrupt, None));
    }
    let old = conn.set_limit(
        rusqlite::limits::Limit::SQLITE_LIMIT_LENGTH,
        RECOVERY_SQLITE_LENGTH_LIMIT,
    )?;
    let result = conn.query_row(
        if indexed {
            "SELECT substr(bytes,1,?2) FROM objects WHERE cid=?1"
        } else {
            "SELECT substr(bytes,1,?2) FROM objects NOT INDEXED WHERE +cid=?1"
        },
        params![id.to_string(), service::MAX_REQUEST as i64],
        |r| r.get::<_, Vec<u8>>(0),
    );
    conn.set_limit(rusqlite::limits::Limit::SQLITE_LIMIT_LENGTH, old)?;
    let bytes = result?;
    if bytes.len() != expected || ciphertext_cid(&bytes) != *id {
        Ok((Availability::Corrupt, None))
    } else {
        Ok((Availability::Available, Some(bytes)))
    }
}
/// No grant is inferred from selection. The service/reader must authorize first.
/// This fresh read never reuses the inventory transaction's old payload snapshot.
pub fn source(
    path: &Path,
    profile: Profile,
    binding: attested::Binding,
    selection: &Selection,
    max_payload_bytes: usize,
    budget: Budget,
) -> Result<Source> {
    if selection.profile != profile || selection.binding != binding {
        return Err(Error::Invalid(
            "source selection differs from owner binding",
        ));
    }
    binding.validate()?;
    let deadline = budget.deadline()?;
    budget.check(deadline)?;
    let reader = RecoveryReader::open_profile_configured(path, profile.number(), |conn| {
        configure_read(conn, &budget, deadline)
    })?;
    let plan = plan(&reader, profile, &binding)?;
    let mut pin_cost = 0;
    let mut pin_items = 0;
    let indexed = if let Some(custody) = &selection.index_custody {
        if !rowid_objects(&reader.ledger.conn)? {
            return Err(Error::Invalid("indexed source layout changed"));
        }
        let checkpoint = serving::checkpoint(&reader.ledger.conn, &binding, custody.as_deref())?;
        if selection.snapshot.through != selection.frontier.through {
            let pin = serving::selected_metadata(
                &reader.ledger.conn,
                &binding,
                &checkpoint,
                selection.snapshot.through,
            )?;
            if pin.proof.frontier() != &selection.snapshot {
                return Err(corrupt("indexed source prefix changed"));
            }
            pin_cost = cost(&pin.record, pin.proof.bytes());
            pin_items = 1;
        }
        let metadata = serving::selected_metadata(
            &reader.ledger.conn,
            &binding,
            &checkpoint,
            selection.frontier.through,
        )?;
        if metadata.proof.frontier() != &selection.frontier {
            return Err(corrupt("indexed source coordinate changed"));
        }
        Some(checkpoint)
    } else {
        None
    };
    let record = attested::record(&reader.ledger.conn, selection.frontier.through)?;
    let envelope = attested::envelope(&reader.ledger.conn, record.sequence)?;
    if budget.items < 1 + pin_items || cost(&record, &envelope) + pin_cost > budget.metadata_bytes {
        return Err(Error::Invalid("inventory audit budget exhausted"));
    }
    let verified = proof::verify_at(
        &envelope,
        &binding.context(),
        &record.manifest,
        &record.receipt,
        &selection.frontier,
    )
    .map_err(|_| corrupt("selected proof changed"))?;
    purpose(&record, &verified, plan.as_ref())?;
    let (id, length) = request_coordinate(&record)?;
    if length > max_payload_bytes {
        return Err(Error::Invalid("selected payload exceeds source budget"));
    }
    let erased = if let Some(checkpoint) = &indexed {
        serving::erased(&reader.ledger.conn, checkpoint, &id)?
    } else {
        erasure::load(&reader.ledger.conn)?
            .objects
            .contains_key(&id.to_string())
    };
    let (availability, bytes) = payload(&reader.ledger.conn, &id, length, erased)?;
    budget.check(deadline)?;
    let Some(bytes) = bytes else {
        return Ok(Source::Unavailable(availability));
    };
    let signed = service::verify_retained_request(&record, &bytes)
        .map_err(|_| corrupt("selected writer request"))?;
    if signed.request.scope != service::hex(&binding.scope) {
        return Err(corrupt("selected request scope"));
    }
    budget.check(deadline)?;
    Ok(Source::Available {
        bytes,
        writer: signed.request.principal,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sqlite_vm_deadline_and_cancel_interrupt_unyielding_queries() {
        for cancel in [false, true] {
            let conn = Connection::open_in_memory().unwrap();
            let cancelled = Arc::new(AtomicBool::new(false));
            let budget = Budget {
                items: 1,
                metadata_bytes: 1,
                duration: if cancel {
                    Duration::from_secs(60)
                } else {
                    Duration::from_millis(20)
                },
                cancelled: cancelled.clone(),
            };
            configure_read(&conn, &budget, budget.deadline().unwrap()).unwrap();
            let interrupt = conn.get_interrupt_handle();
            let (done, wait) = std::sync::mpsc::channel();
            // Bound a broken callback without counting that watchdog as success.
            let watchdog = std::thread::spawn(move || {
                if wait.recv_timeout(Duration::from_secs(3)).is_err() {
                    interrupt.interrupt();
                    true
                } else {
                    false
                }
            });
            let cancellation = cancel.then(|| {
                std::thread::spawn(move || {
                    std::thread::sleep(Duration::from_millis(20));
                    cancelled.store(true, Ordering::Relaxed);
                })
            });
            let result = conn.query_row("WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<1000000000) SELECT sum(x) FROM n", [], |r| r.get::<_,i64>(0));
            let _ = done.send(());
            let fallback = watchdog.join().unwrap();
            if let Some(thread) = cancellation {
                thread.join().unwrap();
            }
            assert!(
                !fallback,
                "watchdog, not the production VM callback, interrupted SQL"
            );
            assert!(
                matches!(result, Err(rusqlite::Error::SqliteFailure(e,_)) if e.code == rusqlite::ErrorCode::OperationInterrupted)
            );
        }
    }

    #[test]
    fn page_installs_vm_limits_after_startup_removes_its_handler() {
        let temp = tempfile::tempdir().unwrap();
        let issuer = crate::sign::Identity::generate();
        let writer = crate::sign::Identity::generate();
        let binding = attested::Binding {
            archive: [2; 32],
            scope: [1; 32],
            issuer: issuer.did().to_string(),
        };
        let root = temp.path().join("archive");
        let mut archive = attested::Archive::create(&root, binding.clone()).unwrap();
        let bytes = service::SignedRequest::sign(
            service::Request {
                version: 1,
                scope: service::hex(&binding.scope),
                principal: writer.did().to_string(),
                audience: issuer.did().to_string(),
                expires: None,
                command: service::Command::Append {
                    id: service::hex(&[1; 16]),
                    position: 0,
                    previous: None,
                    ciphertext: service::hex(b"fixture"),
                },
            },
            &writer,
        )
        .unwrap()
        .bytes()
        .unwrap();
        archive
            .admit(
                &bytes,
                &issuer,
                &service::Grant {
                    principal: writer.did().to_string(),
                    append: true,
                    inventory: true,
                },
                100,
            )
            .unwrap();
        drop(archive);
        let work = || Budget {
            items: 100,
            metadata_bytes: 1024 * 1024,
            duration: Duration::from_secs(60),
            cancelled: Arc::new(AtomicBool::new(false)),
        };
        let a = Inventory::open(
            &root.join("archive.sqlite"),
            Profile::Admitted,
            binding,
            work(),
        )
        .unwrap();
        // Test-only in-memory workload injection after successful real startup:
        // no main database mutation or millions of fixture rows on disk. The
        // recursive view makes the ordinary page payload lookup unyielding.
        let conn = &a.reader.ledger.conn;
        conn.execute_batch("PRAGMA query_only=OFF; CREATE TEMP VIEW objects AS WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<1000000000) SELECT 'probe-'||x AS cid,x'01' AS bytes FROM n; PRAGMA query_only=ON;").unwrap();
        for cancel in [false, true] {
            let mut budget = work();
            if !cancel {
                budget.duration = Duration::from_millis(20);
            }
            let flag = budget.cancelled.clone();
            let interrupt = conn.get_interrupt_handle();
            let (done, wait) = std::sync::mpsc::channel();
            let watchdog = std::thread::spawn(move || {
                if wait.recv_timeout(Duration::from_secs(3)).is_err() {
                    interrupt.interrupt();
                    true
                } else {
                    false
                }
            });
            let cancellation = cancel.then(|| {
                std::thread::spawn(move || {
                    std::thread::sleep(Duration::from_millis(20));
                    flag.store(true, Ordering::Relaxed);
                })
            });
            let result = a.page(
                None,
                PageBudget {
                    rows: 1,
                    record_bytes: 1024 * 1024,
                    payload_bytes: MAX_CHUNK,
                },
                budget,
            );
            let _ = done.send(());
            let fallback = watchdog.join().unwrap();
            if let Some(t) = cancellation {
                t.join().unwrap();
            }
            assert!(!fallback, "page did not install its production VM callback");
            assert!(
                matches!(result,Err(Error::Sql(rusqlite::Error::SqliteFailure(e,_))) if e.code==rusqlite::ErrorCode::OperationInterrupted)
            );
        }
        conn.progress_handler(0, None::<fn() -> bool>).unwrap();
        conn.execute_batch("PRAGMA query_only=OFF; DROP VIEW temp.objects; PRAGMA query_only=ON;")
            .unwrap();
        let page = a
            .page(
                None,
                PageBudget {
                    rows: 1,
                    record_bytes: 1024 * 1024,
                    payload_bytes: MAX_CHUNK,
                },
                work(),
            )
            .unwrap();
        assert_eq!(page.records[0].availability, Availability::Available);
    }
}
