//! Bounded, disposable collection totals. Never an evidence completeness proof.
use super::*;
use crate::evidence_operations::{
    self as operations,
    projection::{Observation, Scan},
};
use std::{
    collections::BTreeMap,
    io::Read,
    sync::atomic::{AtomicBool, Ordering},
};

const SOURCE_LIMIT: u64 = 32 * 1024 * 1024;
const WORKING_RESERVE: usize = 16 * 1024 * 1024; // SQLite, manifest, hashing and bounded row buffers.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub attempts: usize,
    pub sessions: usize,
    pub bytes: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            attempts: 250_000,
            sessions: 65_536,
            bytes: 128 * 1024 * 1024,
        }
    }
}
#[derive(Debug, thiserror::Error)]
pub enum Failure {
    #[error("collection overview cancelled")]
    Cancelled,
    #[error("collection overview capacity reached: {0}")]
    Capacity(&'static str),
    #[error("collection observations conflict")]
    Conflict,
    #[error("collection overview arithmetic overflow")]
    Overflow,
}
#[derive(Debug, Clone, Serialize)]
pub struct Source {
    pub generation: String,
    pub sealed_sha256: Option<String>,
    pub snapshot: Scan,
}
fn decimal<S: serde::Serializer>(
    value: &u64,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error> {
    serializer.serialize_str(&value.to_string())
}
#[derive(Debug, Clone, Serialize)]
pub struct Totals {
    #[serde(serialize_with = "decimal")]
    pub attempts: u64,
    #[serde(serialize_with = "decimal")]
    pub sessions: u64,
    #[serde(serialize_with = "decimal")]
    pub observed: u64,
    #[serde(serialize_with = "decimal")]
    pub locally_queued: u64,
    #[serde(serialize_with = "decimal")]
    pub unconfirmed: u64,
    #[serde(serialize_with = "decimal")]
    pub attempts_with_gaps: u64,
    #[serde(serialize_with = "decimal")]
    pub telemetry_dropped_lower_bound: u64,
    #[serde(serialize_with = "decimal")]
    pub unclosed_sessions: u64,
}
#[derive(Debug, Clone, Serialize)]
pub struct Overview {
    pub version: u8,
    pub coverage: &'static str,
    pub capture_completeness: &'static str,
    pub built_at: u64,
    pub manifest_sha256: String,
    pub active: String,
    pub sources: Vec<Source>,
    pub totals: Totals,
    pub accounted_bytes: usize,
    pub memory_limit: usize,
}
fn cancel(flag: &AtomicBool) -> Result<()> {
    if flag.load(Ordering::Relaxed) {
        Err(Box::new(Failure::Cancelled))
    } else {
        Ok(())
    }
}
fn cost(row: &Observation) -> Result<usize> {
    // Includes serialized strings, map nodes, duplicated identity keys, allocator
    // slack and fixed row storage. Refuse before retaining a new row.
    serde_json::to_vec(row)?
        .len()
        .checked_add(1024)
        .ok_or_else(|| Box::new(Failure::Overflow) as _)
}
struct Budget {
    used: usize,
    limit: usize,
}
impl Budget {
    fn add(&mut self, n: usize) -> Result<()> {
        let next = self.used.checked_add(n).ok_or(Failure::Overflow)?;
        if next > self.limit {
            return Err(Box::new(Failure::Capacity("memory")));
        }
        self.used = next;
        Ok(())
    }
}
struct Selected {
    row: Observation,
    cost: usize,
}
struct Aggregate {
    attempts: BTreeMap<String, Selected>,
    sessions: BTreeMap<String, Selected>,
    limits: Limits,
}
impl Aggregate {
    fn new(limits: Limits) -> Self {
        Self {
            attempts: BTreeMap::new(),
            sessions: BTreeMap::new(),
            limits,
        }
    }
    fn add(&mut self, row: Observation, budget: &mut Budget) -> Result<()> {
        let n = cost(&row)?;
        let (key, map, limit, label) = match &row {
            Observation::Attempt { health, .. } => (
                health.attempt.clone(),
                &mut self.attempts,
                self.limits.attempts,
                "attempts",
            ),
            Observation::Session { id, .. } => (
                id.clone(),
                &mut self.sessions,
                self.limits.sessions,
                "sessions",
            ),
        };
        if let Some(old) = map.get(&key) {
            let dominates = match (&row, &old.row) {
                (
                    Observation::Attempt { health: new, .. },
                    Observation::Attempt { health: old, .. },
                ) => operations::dominates(new, old),
                (
                    Observation::Session {
                        dropped: new,
                        clean: nc,
                        ..
                    },
                    Observation::Session {
                        dropped: old,
                        clean: oc,
                        ..
                    },
                ) => new >= old && (!oc || *nc),
                _ => false,
            };
            if !dominates {
                return Err(Box::new(Failure::Conflict));
            }
            budget.used -= old.cost;
        } else if map.len() >= limit {
            return Err(Box::new(Failure::Capacity(label)));
        }
        budget.add(n)?;
        map.insert(key, Selected { row, cost: n });
        Ok(())
    }
    fn totals(&self) -> Result<Totals> {
        let mut t = Totals {
            attempts: self.attempts.len() as u64,
            sessions: self.sessions.len() as u64,
            observed: 0,
            locally_queued: 0,
            unconfirmed: 0,
            attempts_with_gaps: 0,
            telemetry_dropped_lower_bound: 0,
            unclosed_sessions: 0,
        };
        fn add(dst: &mut u64, n: u64) -> Result<()> {
            *dst = dst.checked_add(n).ok_or(Failure::Overflow)?;
            Ok(())
        }
        for selected in self.attempts.values() {
            let Observation::Attempt { health, .. } = &selected.row else {
                unreachable!()
            };
            add(&mut t.observed, health.observed)?;
            add(&mut t.locally_queued, health.locally_queued)?;
            add(&mut t.unconfirmed, health.unconfirmed)?;
            add(&mut t.attempts_with_gaps, u64::from(health.recording_gap))?;
        }
        for selected in self.sessions.values() {
            let Observation::Session { dropped, clean, .. } = &selected.row else {
                unreachable!()
            };
            add(&mut t.telemetry_dropped_lower_bound, *dropped)?;
            add(&mut t.unclosed_sessions, u64::from(!clean))?;
        }
        Ok(t)
    }
}
// Bounded streaming hash, no 32-MiB plaintext file copy. The shared collection
// lock protects membership/rotation; a sealed file must match its committed hash.
fn sealed_hash(path: &Path, flag: &AtomicBool) -> Result<String> {
    let mut file = File::open(path)?;
    let mut digest = Sha256::new();
    let mut bytes = 0u64;
    let mut buffer = [0; 65536];
    loop {
        cancel(flag)?;
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        bytes += n as u64;
        if bytes > SOURCE_LIMIT {
            return Err(invalid());
        }
        digest.update(&buffer[..n]);
    }
    Ok(crate::evidence_service::hex(&digest.finalize()))
}
fn source(
    root: &Path,
    g: &Generation,
    binding: &Binding,
    flag: &AtomicBool,
    visit: &mut dyn FnMut(Observation) -> Result<()>,
) -> Result<Source> {
    cancel(flag)?;
    let path = generation_path(root, &g.id);
    private(&path, false, SOURCE_LIMIT)?;
    // All collection generations have an existing lifetime lock. Refuse missing
    // coordination files rather than letting a read projection create one.
    let mut lock_path = path.as_os_str().to_os_string();
    lock_path.push(".lock");
    private(Path::new(&lock_path), false, 0)?;
    if let Some(expected) = &g.sealed_sha256 {
        sidecars_absent(&path)?;
        if &sealed_hash(&path, flag)? != expected {
            return Err(invalid());
        }
    }
    let journal = Journal::open_file(&path, false, true)?;
    let expected = (
        binding.spool.clone(),
        binding.writer.clone(),
        binding.scope.clone(),
        binding.audience.clone(),
    );
    let mut snapshot = journal.scan_projection(&expected, &mut |row| {
        cancel(flag)?;
        visit(row)
    })?;
    // Recheck sealed bytes after the SQLite read so a changed source is never
    // promoted merely because it passed a pre-open hash.
    if let Some(expected) = &g.sealed_sha256 {
        if &sealed_hash(&path, flag)? != expected {
            return Err(invalid());
        }
    }
    if g.sealed_sha256.is_some() {
        snapshot.worker = None;
    }
    Ok(Source {
        generation: g.id.clone(),
        sealed_sha256: g.sealed_sha256.clone(),
        snapshot,
    })
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Boundary {
    MembershipPinned,
    ActiveRead,
    GenerationRead,
    BeforePublish,
}
/// Explicit, synchronous, owner-side refresh. Ordinary status polling must not
/// call this function. The hook is a deterministic test seam outside SQLite reads.
pub fn build(root: &Path, flag: &AtomicBool, limits: Limits) -> Result<Overview> {
    build_observed(root, flag, limits, &mut |_| Ok(()))
}
pub fn build_observed(
    root: &Path,
    flag: &AtomicBool,
    limits: Limits,
    hook: &mut dyn FnMut(Boundary) -> Result<()>,
) -> Result<Overview> {
    cancel(flag)?;
    let max = Limits::default();
    if limits.attempts > max.attempts || limits.sessions > max.sessions || limits.bytes > max.bytes
    {
        return Err(Box::new(Failure::Capacity("configured bound")));
    }
    let _held = lock(root, false)?;
    let (m, manifest_sha256) = manifest_snapshot(root)?;
    hook(Boundary::MembershipPinned)?;
    let mut budget = Budget {
        used: 0,
        limit: limits.bytes,
    };
    budget.add(WORKING_RESERVE)?;
    let mut active_rows = Vec::new();
    let active = m.generations.last().ok_or_else(invalid)?;
    let mut attempt_count = 0usize;
    let mut session_count = 0usize;
    let active_source = source(root, active, &m.binding, flag, &mut |row| {
        match &row {
            Observation::Attempt { .. } => {
                attempt_count += 1;
                if attempt_count > limits.attempts {
                    return Err(Box::new(Failure::Capacity("attempts")));
                }
            }
            Observation::Session { .. } => {
                session_count += 1;
                if session_count > limits.sessions {
                    return Err(Box::new(Failure::Capacity("sessions")));
                }
            }
        }
        budget.add(cost(&row)?)?;
        active_rows.push(row);
        Ok(())
    })?;
    hook(Boundary::ActiveRead)?;
    let mut aggregate = Aggregate::new(limits);
    let mut sources = Vec::new();
    budget.add(serde_json::to_vec(&active_source)?.len() + 1024)?;
    for g in &m.generations[..m.generations.len() - 1] {
        let sampled = source(root, g, &m.binding, flag, &mut |row| {
            aggregate.add(row, &mut budget)
        })?;
        budget.add(serde_json::to_vec(&sampled)?.len() + 1024)?;
        sources.push(sampled);
        hook(Boundary::GenerationRead)?;
    }
    // Apply the pinned active snapshot last, so every chronological cumulative
    // transition is checked, even if an eventual larger value dominates both.
    for row in active_rows {
        cancel(flag)?;
        budget.used -= cost(&row)?;
        aggregate.add(row, &mut budget)?;
    }
    sources.push(active_source);
    let totals = aggregate.totals()?;
    hook(Boundary::BeforePublish)?;
    cancel(flag)?;
    if manifest_snapshot(root)?.1 != manifest_sha256 {
        return Err(invalid());
    }
    Ok(Overview {
        version: 1,
        coverage: "observations-only",
        capture_completeness: "unknown",
        built_at: operations::now(),
        manifest_sha256,
        active: m.active,
        sources,
        totals,
        accounted_bytes: budget.used,
        memory_limit: limits.bytes,
    })
}

/// Published memory only. A prior result stays explicitly associated with its
/// original job/snapshot while a new refresh runs, fails or is cancelled.
#[derive(Debug, Clone, Serialize)]
pub struct Published {
    pub version: u8,
    pub state: &'static str,
    pub job: u64,
    pub reason: Option<String>,
    pub last_job: Option<u64>,
    pub last: Option<Overview>,
}
struct Control {
    handle: Option<std::thread::JoinHandle<()>>,
    cancel: std::sync::Arc<AtomicBool>,
    next: u64,
}
pub struct Manager {
    published: std::sync::Arc<std::sync::Mutex<Published>>,
    control: std::sync::Mutex<Control>,
}
impl Default for Manager {
    fn default() -> Self {
        Self::new()
    }
}
impl Manager {
    pub fn new() -> Self {
        Self {
            published: std::sync::Arc::new(std::sync::Mutex::new(Published {
                version: 1,
                state: "unavailable",
                job: 0,
                reason: None,
                last_job: None,
                last: None,
            })),
            control: std::sync::Mutex::new(Control {
                handle: None,
                cancel: std::sync::Arc::new(AtomicBool::new(false)),
                next: 0,
            }),
        }
    }
    pub fn status(&self) -> Published {
        self.published.lock().unwrap().clone()
    }
    pub fn refresh(&self, root: PathBuf) -> Result<Published> {
        self.refresh_observed(root, Limits::default(), |_| Ok(()))
    }
    /// Deterministic test seam. Hooks execute only outside SQLite snapshots.
    pub fn refresh_observed(
        &self,
        root: PathBuf,
        limits: Limits,
        mut hook: impl FnMut(Boundary) -> Result<()> + Send + 'static,
    ) -> Result<Published> {
        let mut control = self.control.lock().unwrap();
        if control.handle.as_ref().is_some_and(|h| !h.is_finished()) {
            return Ok(self.status());
        }
        if let Some(previous) = control.handle.take() {
            let _ = previous.join();
        }
        control.next = control.next.checked_add(1).ok_or(Failure::Overflow)?;
        let job = control.next;
        let cancel = std::sync::Arc::new(AtomicBool::new(false));
        control.cancel = cancel.clone();
        {
            let mut state = self.published.lock().unwrap();
            state.state = "building";
            state.job = job;
            state.reason = None;
        }
        let published = self.published.clone();
        match std::thread::Builder::new()
            .name("kan-operations-overview".into())
            .spawn(move || {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    build_observed(&root, &cancel, limits, &mut hook)
                }));
                let mut state = published.lock().unwrap();
                if cancel.load(Ordering::Relaxed) {
                    state.state = "cancelled";
                    state.reason = None;
                } else {
                    match result {
                        Ok(Ok(overview)) => {
                            state.state = "completed";
                            state.last_job = Some(job);
                            state.last = Some(overview);
                            state.reason = None;
                        }
                        Ok(Err(error)) => {
                            state.state = if matches!(
                                error.downcast_ref::<Failure>(),
                                Some(Failure::Capacity(_))
                            ) {
                                "capacity-limited"
                            } else {
                                "failed"
                            };
                            state.reason = Some(match error.downcast_ref::<Failure>() {
                                Some(Failure::Capacity(bound)) => format!("{bound} bound reached"),
                                Some(Failure::Conflict) => {
                                    "conflicting cumulative observations".into()
                                }
                                Some(Failure::Overflow) => "counter overflow".into(),
                                _ => "source invalid or unavailable".into(),
                            });
                        }
                        Err(_) => {
                            state.state = "failed";
                            state.reason = Some("overview worker failed".into());
                        }
                    }
                }
            }) {
            Ok(handle) => control.handle = Some(handle),
            Err(error) => {
                let mut state = self.published.lock().unwrap();
                state.state = "failed";
                state.reason = Some("overview worker unavailable".into());
                return Err(error.into());
            }
        }
        Ok(self.status())
    }
    pub fn cancel(&self) -> Published {
        let control = self.control.lock().unwrap();
        if control.handle.as_ref().is_some_and(|h| !h.is_finished()) {
            control.cancel.store(true, Ordering::Relaxed);
            let mut state = self.published.lock().unwrap();
            if state.state == "building" {
                state.state = "cancelling";
            }
        }
        self.status()
    }
}
impl Drop for Manager {
    fn drop(&mut self) {
        let control = self.control.get_mut().unwrap();
        control.cancel.store(true, Ordering::Relaxed);
        if let Some(handle) = control.handle.take() {
            let _ = handle.join();
        }
    }
}
