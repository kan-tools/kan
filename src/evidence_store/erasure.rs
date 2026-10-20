//! Signed storage erasure, separate from semantic retraction. A one-byte marker
//! preserves object/binding identity; only a verified issuer authorization can
//! excuse the absent payload. Historical backup/key copies remain recoverable.
use super::*;
use crate::{evidence_service as service, sign::Identity};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub(crate) const SCHEMA: &str = "CREATE TABLE erasures(ordinal INTEGER PRIMARY KEY, id TEXT NOT NULL UNIQUE, body BLOB NOT NULL CHECK(length(body)>0 AND length(body)<=1048576));";
const DOMAIN: &[u8] = b"tools.kan.storage.erasure.v1\0";
const MAX_BYTES: usize = 16 * 1024 * 1024;
const MAX_RECORD: usize = 1024 * 1024;
const MAX_TARGETS: usize = 4096;
pub(super) const MARKER: &[u8] = &[0];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Target {
    pub sequence: u64,
    pub manifest: String,
    pub object: String,
    pub length: usize,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    pub version: u8,
    pub archive: String,
    pub scope: String,
    pub issuer: String,
    pub through: u64,
    pub tip: String,
    pub previous: Option<String>,
    pub nonce: String,
    pub recorded_at: u64,
    pub targets: Vec<Target>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub plan: Plan,
    pub signature: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Package {
    pub version: u8,
    pub records: Vec<Record>,
    pub tip: Option<String>,
}
#[derive(Default)]
pub(super) struct History {
    pub records: Vec<Record>,
    pub objects: BTreeMap<String, Target>,
    pub tip: Option<String>,
}
fn corrupt() -> Error {
    Error::Corrupt("erasure authority or coordinates".into())
}
fn bytes(value: &impl Serialize) -> Result<Vec<u8>> {
    serde_json::to_vec(value).map_err(|_| corrupt())
}
fn hash(value: &impl Serialize) -> Result<String> {
    Ok(service::hex(&Sha256::digest(bytes(value)?)))
}
fn link(value: &str) -> Result<()> {
    let id: Cid = value.parse().map_err(|_| corrupt())?;
    if id.to_string() != value {
        return Err(corrupt());
    }
    Ok(())
}
impl Plan {
    pub fn digest(&self) -> Result<String> {
        hash(self)
    }
    fn preimage(&self) -> Result<Vec<u8>> {
        Ok([DOMAIN, &bytes(self)?].concat())
    }
}
impl Record {
    pub fn sign(plan: Plan, signer: &Identity) -> Result<Self> {
        if signer.did().as_str() != plan.issuer {
            return Err(Error::Invalid("erasure signer"));
        }
        let signature = signer.sign(&plan.preimage()?).map_err(|_| corrupt())?;
        Ok(Self {
            plan,
            signature: service::hex(&signature),
        })
    }
    pub fn id(&self) -> Result<String> {
        hash(self)
    }
    pub(crate) fn validate(
        &self,
        binding: &attested::Binding,
        previous: &Option<String>,
    ) -> Result<()> {
        let p = &self.plan;
        if p.version != 1
            || p.archive != service::hex(&binding.archive)
            || p.scope != service::hex(&binding.scope)
            || p.issuer != binding.issuer
            || &p.previous != previous
            || p.through == 0
            || p.through > evidence::MAX_SAFE_INTEGER as u64
            || p.recorded_at > evidence::MAX_SAFE_INTEGER as u64
            || p.targets.is_empty()
            || p.targets.len() > MAX_TARGETS
            || p.nonce.len() != 64
            || service::unhex(&p.nonce, 32).map_err(|_| corrupt())?.len() != 32
            || bytes(self)?.len() > MAX_RECORD
        {
            return Err(corrupt());
        }
        link(&p.tip)?;
        let sig = service::unhex(&self.signature, 64).map_err(|_| corrupt())?;
        if sig.len() != 64 || !crate::sign::verify(&p.issuer, &p.preimage()?, &sig) {
            return Err(corrupt());
        }
        let mut last = 0;
        let mut objects = BTreeSet::new();
        for t in &p.targets {
            if t.sequence <= last
                || t.sequence > p.through
                || t.length == 0
                || t.length > service::MAX_REQUEST
                || !objects.insert(&t.object)
            {
                return Err(corrupt());
            }
            link(&t.manifest)?;
            link(&t.object)?;
            last = t.sequence;
        }
        Ok(())
    }
}
pub(super) fn exists(conn: &Connection) -> Result<bool> {
    Ok(conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name='erasures')",
        [],
        |r| r.get(0),
    )?)
}
pub(super) fn extend_schema(source: &Connection, expected: &Connection) -> Result<()> {
    if exists(source)? {
        expected.execute_batch(SCHEMA)?;
    }
    Ok(())
}
fn binding(conn: &Connection) -> Result<attested::Binding> {
    let (a, s, i): (Vec<u8>, Vec<u8>, String) = conn.query_row(
        "SELECT archive,scope,issuer FROM archive_identity WHERE singleton=1",
        [],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    )?;
    let b = attested::Binding {
        archive: a.try_into().map_err(|_| corrupt())?,
        scope: s.try_into().map_err(|_| corrupt())?,
        issuer: i,
    };
    b.validate()?;
    attested::check_binding(conn, &b)?;
    Ok(b)
}
fn coordinate(conn: &Connection, t: &Target, through: u64) -> Result<()> {
    if t.sequence > through {
        return Ok(());
    } // Newer independently signed history on an older restore.
    let record = attested::record(conn, t.sequence)?;
    let es: Vec<_> = entries(&record.manifest).collect();
    if record.manifest.cid().to_string() != t.manifest
        || es.len() != 1
        || cid(&es[0]["ciphertext"]) != t.object
        || number(&es[0]["length"]) != t.length as i64
    {
        return Err(corrupt());
    }
    Ok(())
}
impl History {
    fn add(
        &mut self,
        conn: &Connection,
        binding: &attested::Binding,
        through: u64,
        r: Record,
    ) -> Result<()> {
        r.validate(binding, &self.tip)?;
        if r.plan.through <= through
            && attested::record(conn, r.plan.through)?
                .manifest
                .cid()
                .to_string()
                != r.plan.tip
        {
            return Err(corrupt());
        }
        for t in &r.plan.targets {
            coordinate(conn, t, through)?;
            if let Some(old) = self.objects.insert(t.object.clone(), t.clone()) {
                if old != *t {
                    return Err(corrupt());
                }
            }
        }
        if self.objects.len() > 32768 {
            return Err(Error::Invalid("erasure history capacity"));
        }
        self.tip = Some(r.id()?);
        self.records.push(r);
        Ok(())
    }
    pub fn package(&self) -> Package {
        Package {
            version: 1,
            records: self.records.clone(),
            tip: self.tip.clone(),
        }
    }
}
pub(super) fn load(conn: &Connection) -> Result<History> {
    if !exists(conn)? {
        return Ok(History::default());
    }
    let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    if version != 2 && version != 3 {
        return Err(Error::Invalid("erasure requires proof storage"));
    }
    let old = conn.set_limit(
        rusqlite::limits::Limit::SQLITE_LIMIT_LENGTH,
        RECOVERY_SQLITE_LENGTH_LIMIT,
    )?;
    let result = load_inner(conn);
    conn.set_limit(rusqlite::limits::Limit::SQLITE_LIMIT_LENGTH, old)?;
    result
}
fn load_inner(conn: &Connection) -> Result<History> {
    let mut history = History::default();
    if !exists(conn)? {
        return Ok(history);
    }
    let binding = binding(conn)?;
    let through: i64 =
        conn.query_row("SELECT COALESCE(MAX(sequence),0) FROM commits", [], |r| {
            r.get(0)
        })?;
    let through = u64::try_from(through).map_err(|_| corrupt())?;
    let mut stmt = conn.prepare(
        "SELECT ordinal,id,length(body),substr(body,1,1048576) FROM erasures ORDER BY ordinal",
    )?;
    let mut rows = stmt.query([])?;
    let mut total = 0;
    while let Some(row) = rows.next()? {
        let ordinal: i64 = row.get(0)?;
        let id: String = row.get(1)?;
        let length: i64 = row.get(2)?;
        let body: Vec<u8> = row.get(3)?;
        total += body.len();
        if ordinal != history.records.len() as i64
            || !(1..=MAX_RECORD as i64).contains(&length)
            || length as usize != body.len()
            || total > MAX_BYTES
            || history.records.len() >= 1024
        {
            return Err(corrupt());
        }
        let r: Record = serde_json::from_slice(&body).map_err(|_| corrupt())?;
        if bytes(&r)? != body || r.id()? != id {
            return Err(corrupt());
        }
        history.add(conn, &binding, through, r)?;
    }
    Ok(history)
}
/// Safe for raw storage readers too: only a fully verified erasure excuses bytes.
pub(super) fn erased(conn: &Connection, id: &str) -> Result<bool> {
    Ok(load(conn)?.objects.contains_key(id))
}
pub(super) fn stage_allowed(conn: &Connection, id: &str) -> Result<()> {
    let history = load(conn)?;
    if history.objects.contains_key(id) {
        return Err(Error::Erased(id.to_owned()));
    }
    if let Some(required) = history.records.iter().map(|r| r.plan.through).max() {
        let through: i64 =
            conn.query_row("SELECT COALESCE(MAX(sequence),0) FROM commits", [], |r| {
                r.get(0)
            })?;
        if required > through as u64 {
            return Err(Error::Conflict(
                "restore is behind erasure history; recover missing metadata before admission",
            ));
        }
    }
    Ok(())
}
pub(super) fn check_marker(conn: &Connection, id: &str) -> Result<()> {
    let body: Option<Vec<u8>> = conn
        .query_row("SELECT bytes FROM objects WHERE cid=?", [id], |r| r.get(0))
        .optional()?;
    if body.as_deref() != Some(MARKER) {
        return Err(Error::Corrupt(
            "erased object retains bytes or marker is missing".into(),
        ));
    }
    Ok(())
}
pub(super) fn copy_history(source: &Connection, target: &rusqlite::Transaction<'_>) -> Result<()> {
    let history = load(source)?;
    if !exists(source)? {
        return Ok(());
    }
    // surface-write: evidence-erasure-sqlite:erasures
    crate::persistence::initialize_evidence_erasure(
        crate::persistence::SurfaceWrite::EvidenceErasure,
        target,
    )?;
    for (i, r) in history.records.iter().enumerate() {
        // surface-write: evidence-erasure-sqlite:erasures
        crate::persistence::insert_evidence_erasure(
            crate::persistence::SurfaceWrite::EvidenceErasure,
            target,
            i as i64,
            &r.id()?,
            &bytes(r)?,
        )?;
    }
    Ok(())
}
impl attested::Archive {
    /// Low-level exact-object plan. Human callers must resolve a complete logical
    /// capture and its derivative/copy cascade before using this storage API.
    pub fn preview_erasure(&self, sequences: &[u64], nonce: String, now: u64) -> Result<Plan> {
        if sequences.is_empty() || sequences.len() > MAX_TARGETS {
            return Err(Error::Invalid("erasure selection bound"));
        }
        let verified = self.verify()?;
        let tx = self.ledger.conn.unchecked_transaction()?;
        let snap = self.ledger.snapshot()?;
        if snap.through != verified.through || snap.tip != verified.manifest {
            return Err(Error::Conflict("archive advanced during erasure preview"));
        }
        let history = load(&tx)?;
        let mut unique = BTreeSet::new();
        let mut targets = Vec::new();
        for seq in sequences {
            if !unique.insert(*seq) {
                return Err(Error::Invalid("duplicate erasure selection"));
            }
            let r = attested::record(&tx, *seq)?;
            let es: Vec<_> = entries(&r.manifest).collect();
            if es.len() != 1 {
                return Err(corrupt());
            }
            let object = cid(&es[0]["ciphertext"]);
            if history.objects.contains_key(&object) {
                return Err(Error::Conflict("already erased"));
            }
            targets.push(Target {
                sequence: *seq,
                manifest: r.manifest.cid().to_string(),
                object,
                length: usize::try_from(number(&es[0]["length"])).map_err(|_| corrupt())?,
            });
        }
        targets.sort_by_key(|t| t.sequence);
        let plan = Plan {
            version: 1,
            archive: service::hex(&self.binding.archive),
            scope: service::hex(&self.binding.scope),
            issuer: self.binding.issuer.clone(),
            through: snap.through,
            tip: snap.tip.ok_or_else(corrupt)?.to_string(),
            previous: history.tip,
            nonce,
            recorded_at: now,
            targets,
        };
        if bytes(&plan)?.len() > MAX_RECORD - 256 {
            return Err(Error::Invalid("erasure plan capacity"));
        }
        tx.commit()?;
        Ok(plan)
    }
    pub fn erasure_history(&self) -> Result<Package> {
        Ok(load(&self.ledger.conn)?.package())
    }
    /// Commit authorization and logical payload removal in one transaction.
    /// SQLite page/WAL reclamation and other destinations are separate statuses.
    pub fn apply_erasure(&mut self, record: Record) -> Result<Package> {
        self.verify()?;
        self.ledger.conn.execute_batch("PRAGMA secure_delete=ON;")?;
        let tx = self
            .ledger
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let history = load(&tx)?;
        if history
            .records
            .iter()
            .any(|r| r.id().ok() == record.id().ok())
        {
            return Ok(history.package());
        }
        let through: i64 =
            tx.query_row("SELECT COALESCE(MAX(sequence),0) FROM commits", [], |r| {
                r.get(0)
            })?;
        if record.plan.through != through as u64 || record.plan.previous != history.tip {
            return Err(Error::Conflict("erasure preview is stale"));
        }
        record.validate(&self.binding, &history.tip)?;
        if attested::record(&tx, record.plan.through)?
            .manifest
            .cid()
            .to_string()
            != record.plan.tip
        {
            return Err(Error::Conflict("erasure preview tip"));
        }
        for t in &record.plan.targets {
            coordinate(&tx, t, through as u64)?;
        }
        install(&tx, &history, &[record])?;
        tx.commit()?;
        self.audit_cache.replace(Default::default());
        self.erasure_history()
    }
    /// Apply a CURRENT independently retained history before exposing an older
    /// restore. Caller pins its expected tip; the backup's own tip is insufficient.
    pub fn reconcile_erasure(&mut self, package: &Package, expected_tip: &str) -> Result<Package> {
        if package.version != 1
            || package.tip.as_deref() != Some(expected_tip)
            || bytes(package)?.len() > MAX_BYTES
            || package.records.len() > 1024
        {
            return Err(Error::Invalid("current erasure checkpoint required"));
        }
        self.verify()?;
        self.ledger.conn.execute_batch("PRAGMA secure_delete=ON;")?;
        let tx = self
            .ledger
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let old = load(&tx)?;
        let through: i64 =
            tx.query_row("SELECT COALESCE(MAX(sequence),0) FROM commits", [], |r| {
                r.get(0)
            })?;
        let mut wanted = History::default();
        for r in &package.records {
            wanted.add(&tx, &self.binding, through as u64, r.clone())?;
        }
        if wanted.tip != package.tip
            || old.records.len() > wanted.records.len()
            || old
                .records
                .iter()
                .zip(&wanted.records)
                .any(|(a, b)| a.id().ok() != b.id().ok())
        {
            return Err(Error::Conflict("erasure history rollback or fork"));
        }
        install(&tx, &old, &wanted.records[old.records.len()..])?;
        // Also scrub any payloads from the restored checkpoint covered by history.
        for id in wanted.objects.keys() {
            redact(&tx, id)?;
        }
        tx.commit()?;
        self.audit_cache.replace(Default::default());
        self.erasure_history()
    }
    /// Best-effort SQLite reclamation, never a promise about filesystem snapshots
    /// or storage hardware. Busy readers leave purge visibly pending.
    pub fn reclaim_erased_pages(&self) -> Result<bool> {
        self.verify()?;
        self.ledger.conn.execute_batch("PRAGMA secure_delete=ON;")?;
        let (busy, _, _): (i64, i64, i64) =
            self.ledger
                .conn
                .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| {
                    Ok((r.get(0)?, r.get(1)?, r.get(2)?))
                })?;
        if busy != 0 {
            return Ok(false);
        }
        self.ledger.conn.execute_batch("VACUUM;")?;
        let (busy, _, _): (i64, i64, i64) =
            self.ledger
                .conn
                .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| {
                    Ok((r.get(0)?, r.get(1)?, r.get(2)?))
                })?;
        Ok(busy == 0)
    }
}
fn install(tx: &rusqlite::Transaction<'_>, old: &History, records: &[Record]) -> Result<()> {
    let extra: usize = records
        .iter()
        .map(|r| bytes(r).map(|b| b.len()))
        .collect::<Result<Vec<_>>>()?
        .iter()
        .sum();
    let used: usize = old
        .records
        .iter()
        .map(|r| bytes(r).map(|b| b.len()))
        .collect::<Result<Vec<_>>>()?
        .iter()
        .sum();
    let mut objects = old.objects.keys().cloned().collect::<BTreeSet<_>>();
    for r in records {
        objects.extend(r.plan.targets.iter().map(|t| t.object.clone()));
    }
    if used + extra > MAX_BYTES || old.records.len() + records.len() > 1024 || objects.len() > 32768
    {
        return Err(Error::Invalid("erasure history capacity"));
    }
    if !exists(tx)? {
        // surface-write: evidence-erasure-sqlite:erasures
        crate::persistence::initialize_evidence_erasure(
            crate::persistence::SurfaceWrite::EvidenceErasure,
            tx,
        )?;
    }
    for (i, r) in records.iter().enumerate() {
        // surface-write: evidence-erasure-sqlite:erasures
        crate::persistence::insert_evidence_erasure(
            crate::persistence::SurfaceWrite::EvidenceErasure,
            tx,
            (old.records.len() + i) as i64,
            &r.id()?,
            &bytes(r)?,
        )?;
        for t in &r.plan.targets {
            redact(tx, &t.object)?;
        }
    }
    Ok(())
}
fn redact(tx: &rusqlite::Transaction<'_>, id: &str) -> Result<()> {
    // surface-write: evidence-erasure-sqlite:objects
    crate::persistence::redact_evidence_object(
        crate::persistence::SurfaceWrite::EvidenceErasure,
        tx,
        id,
    )?;
    Ok(())
}

/// A capture identity is scoped to this archive and observed writer. Observer
/// and attempt claims never merge different writers or archives implicitly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Capture {
    pub writer: String,
    pub observer: String,
    pub attempt: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapturePreview {
    pub capture: Capture,
    pub plan: Plan,
    pub recording_gap: bool,
    pub coverage: String,
}
#[cfg(feature = "v2-crypto")]
impl attested::Archive {
    /// Scan the full pinned archive for a closed capture, retaining only exact
    /// coordinates. A page/window selection cannot establish this closure.
    pub fn preview_capture_erasure(
        &self,
        capture: Capture,
        keys: &[[u8; 32]],
        nonce: String,
        now: u64,
    ) -> Result<CapturePreview> {
        use crate::{
            evidence_capture::Event,
            evidence_reconstruction::{self as reconstruction, Decoded},
        };
        if keys.is_empty()
            || keys.len() > 64
            || capture.attempt.len() != 64
            || service::unhex(&capture.attempt, 32)
                .map_err(|_| corrupt())?
                .len()
                != 32
            || !matches!(capture.observer.as_str(), "collector" | "gateway")
        {
            return Err(Error::Invalid("capture selection or keys"));
        }
        service::author(&capture.writer).map_err(|_| Error::Invalid("capture writer"))?;
        let verified = self.verify()?;
        if verified.through > 100_000 {
            return Err(Error::Invalid("capture erasure scan limit"));
        }
        let deadline = std::time::Instant::now() + Duration::from_secs(120);
        let tx = self.ledger.conn.unchecked_transaction()?;
        let snap = self.ledger.snapshot()?;
        if snap.through != verified.through || snap.tip != verified.manifest {
            return Err(Error::Conflict("archive advanced during erasure scan"));
        }
        let history = load(&tx)?;
        let mut found = BTreeMap::new();
        let mut spent = 0usize;
        let mut gap = false;
        let mut started = false;
        let mut terminal = None;
        for sequence in 1..=snap.through {
            if std::time::Instant::now() >= deadline {
                return Err(Error::Invalid("capture erasure scan deadline"));
            }
            let row = attested::record(&tx, sequence)?;
            if writer(&row.manifest) != capture.writer {
                continue;
            }
            let object = cid(&entries(&row.manifest).next().ok_or_else(corrupt)?["ciphertext"]);
            if history.objects.contains_key(&object) {
                continue;
            }
            let signed_bytes = self
                .ledger
                .retained_object(&object.parse().map_err(|_| corrupt())?)?;
            spent = spent.checked_add(signed_bytes.len()).ok_or_else(corrupt)?;
            if spent > 256 * 1024 * 1024 {
                return Err(Error::Invalid("capture erasure scan byte limit"));
            }
            let signed =
                service::verify_retained_request(&row, &signed_bytes).map_err(|_| corrupt())?;
            let service::Command::Append { ciphertext, .. } = signed.request.command else {
                return Err(corrupt());
            };
            let ciphertext =
                service::unhex(&ciphertext, service::MAX_PAYLOAD).map_err(|_| corrupt())?;
            let recipient =
                crate::evidence_crypto::recipient_id(&ciphertext).map_err(|_| corrupt())?;
            let mut plaintext = None;
            for key in keys {
                let public = crate::evidence_crypto::public_key(key).map_err(|_| corrupt())?;
                if Sha256::digest(public).as_slice() == recipient {
                    plaintext = Some(
                        crate::evidence_crypto::open(key, &self.binding.scope, &ciphertext)
                            .map_err(|_| corrupt())?,
                    );
                    break;
                }
            }
            let plaintext = plaintext.ok_or(Error::Invalid(
                "capture scan has unavailable keys; completeness unknown",
            ))?;
            let frame = match reconstruction::decode(&plaintext) {
                Ok(Decoded::Opaque) => continue,
                Ok(Decoded::Capture(frame)) => frame,
                _ => {
                    return Err(Error::Invalid(
                        "capture scan contains unrecognized capture framing",
                    ))
                }
            };
            let observer = match frame.header.observer {
                crate::evidence_capture::Observer::Collector => "collector",
                crate::evidence_capture::Observer::Gateway => "gateway",
            };
            if frame.header.attempt != capture.attempt || observer != capture.observer {
                continue;
            }
            if found.len() >= MAX_TARGETS || found.insert(frame.header.ordinal, sequence).is_some()
            {
                return Err(Error::Invalid(
                    "capture duplicate ordinal or selection limit",
                ));
            }
            gap |= frame.header.unconfirmed_before != 0;
            match frame.header.event {
                Event::Started { .. } => {
                    if frame.header.ordinal != 0 || started {
                        return Err(Error::Invalid("capture start"));
                    }
                    started = true;
                }
                Event::Terminal { .. } => {
                    let previous_terminal = terminal.replace(frame.header.ordinal);
                    if previous_terminal.is_some() {
                        return Err(Error::Invalid("capture terminal"));
                    }
                }
                _ => (),
            }
        }
        let terminal = terminal.ok_or(Error::Invalid(
            "capture still active or terminal unavailable",
        ))?;
        if !started || found.keys().next_back().copied() != Some(terminal) {
            return Err(Error::Invalid("capture closure unavailable"));
        }
        gap |= found.len() as u64
            != terminal
                .checked_add(1)
                .ok_or(Error::Invalid("capture ordinal overflow"))?;
        let sequences: Vec<_> = found.into_values().collect();
        tx.commit()?;
        let plan = self.preview_erasure(&sequences, nonce, now)?;
        if plan.through != snap.through
            || Some(&plan.tip) != snap.tip.as_ref().map(|id| id.to_string()).as_ref()
        {
            return Err(Error::Conflict("archive advanced after capture scan"));
        }
        Ok(CapturePreview {capture,plan,recording_gap:gap,coverage:"All retained records of this closed writer/observer/attempt in the pinned archive. Recording gaps remain disclosed. Other archives, spools, derivatives and backups require coordinated cleanup; this is a storage plan only.".into()})
    }
}

/// Read current signed erasure metadata without requiring payload availability.
/// The caller supplies the owner-pinned profile and archive identity.
pub fn read_history(
    path: &Path,
    profile: inventory::Profile,
    expected: attested::Binding,
) -> Result<Package> {
    expected.validate()?;
    let reader = RecoveryReader::open_profile(path, profile.number())?;
    attested::check_binding(&reader.ledger.conn, &expected)?;
    Ok(load(&reader.ledger.conn)?.package())
}
