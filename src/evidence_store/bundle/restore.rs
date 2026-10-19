//! Checkpointed append-only restoration into an existing retained KNB1 bundle.
use super::*;
use crate::{evidence_recovery_observation as observation, sign::Identity};
use atproto_dasl::Ipld;

pub struct Restoration<'a> {
    pub path: &'a Path,
    pub expected: &'a Checkpoint,
    pub observer: &'a Identity,
    pub candidate: Object<'a>,
    pub sampled_at: u64,
    pub budget: Budget,
    /// Main-file page ceiling; rollback journal and memory require separate room.
    pub output_bytes: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RestorationBoundary {
    Acquired,
    CandidateVerified,
    CandidateInserted,
    ObservationInserted,
    BeforeCommit,
    AfterCommit,
    Synced,
    Reopened,
}
pub struct Restored {
    pub inspection: Inspection,
    pub observation: observation::Authenticated,
    pub duplicate: bool,
}
#[derive(Debug, thiserror::Error)]
pub enum RestorationError {
    #[error(transparent)]
    Refused(#[from] Error),
    #[error("bundle restoration outcome uncertain; retain {path:?}: {cause}")]
    Uncertain {
        path: PathBuf,
        checkpoint: Box<Checkpoint>,
        cause: Box<Error>,
    },
}

pub fn restore(request: Restoration<'_>) -> std::result::Result<Restored, RestorationError> {
    restore_observed(request, |_| {})
}
pub fn restore_observed(
    request: Restoration<'_>,
    mut observe: impl FnMut(RestorationBoundary),
) -> std::result::Result<Restored, RestorationError> {
    let context = &request.expected.context;
    let mut attempted = None;
    let mut actual_path = request.path.to_path_buf();
    let result = (|| -> Result<Restored> {
        require(request.observer.did() == context.observer, "observer pin")?;
        require(request.sampled_at <= MAX_SAFE as u64, "sample time")?;
        require(
            !request.budget.duration.is_zero()
                && request.budget.duration <= Duration::from_secs(3600),
            "duration",
        )?;
        require(
            request.output_bytes / 4096 >= 8 && request.output_bytes / 4096 <= u32::MAX as u64,
            "output page bound",
        )?;
        let deadline = Instant::now()
            .checked_add(request.budget.duration)
            .ok_or(Error::Budget("duration"))?;
        let mut work = Work {
            budget: request.budget.clone(),
            deadline,
            items: 0,
            bytes: 0,
        };
        work.check()?;
        let path = create::source_path(request.path, &work)?;
        actual_path = path.clone();
        // Read-only preflight refuses damaged/hot-journal inputs before opening a
        // writer. Its result is not the mutation authority: replay again under
        // BEGIN IMMEDIATE below, including the independently supplied checkpoint.
        inspect(
            &path,
            context.clone(),
            Some(request.expected),
            request.budget.clone(),
        )?;
        work.check()?;
        create::source_path(&path, &work)?;
        // Refuse unsupported journal/page modes on a read-only connection, before
        // the mutation opener could initialize coordination files.
        // surface-write: evidence-bundle-source:database-wal,evidence-bundle-source:database-shm
        let preflight = crate::persistence::open_sqlite_recovery_source(
            crate::persistence::SurfaceWrite::EvidenceBundleSource,
            &path,
        )?;
        let mode: String = preflight.query_row("PRAGMA journal_mode", [], |r| r.get(0))?;
        let page: i64 = preflight.query_row("PRAGMA page_size", [], |r| r.get(0))?;
        require(
            mode.eq_ignore_ascii_case("delete") && page == 4096,
            "restoration journal/page mode",
        )?;
        drop(preflight);
        work.check()?;
        // surface-write: evidence-bundle:database,evidence-bundle:database-journal
        let mut conn = crate::persistence::open_sqlite_bundle_mutation(
            crate::persistence::SurfaceWrite::EvidenceBundle,
            &path,
        )?;
        conn.set_limit(
            rusqlite::limits::Limit::SQLITE_LIMIT_LENGTH,
            5 * 1024 * 1024,
        )?;
        conn.busy_timeout(
            deadline
                .saturating_duration_since(Instant::now())
                .min(Duration::from_millis(250)),
        )?;
        let cancel = work.budget.cancelled.clone();
        conn.progress_handler(
            1000,
            Some(move || cancel.load(Ordering::Relaxed) || Instant::now() >= deadline),
        )?;
        let mode: String = conn.query_row("PRAGMA journal_mode", [], |r| r.get(0))?;
        require(
            mode.eq_ignore_ascii_case("delete"),
            "restoration requires DELETE journal",
        )?;
        let page: i64 = conn.query_row("PRAGMA page_size", [], |r| r.get(0))?;
        require(page == 4096, "restoration page size")?;
        let pages = request.output_bytes / 4096;
        let applied: i64 =
            conn.query_row(&format!("PRAGMA max_page_count={pages}"), [], |r| r.get(0))?;
        require(
            u64::try_from(applied).ok() == Some(pages),
            "output page limit",
        )?;
        conn.execute_batch("PRAGMA synchronous=FULL; PRAGMA fullfsync=ON; PRAGMA trusted_schema=OFF; PRAGMA cache_size=-4096; PRAGMA mmap_size=0;")?;
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        schema(&tx, &mut work)?;
        identity(&tx, context, &mut work)?;
        let mut data = acquire(&tx, &mut work)?;
        let before = data.with_input(context, |input, candidates, observations| {
            replay::verify(
                input,
                candidates,
                observations,
                Some(request.expected),
                replay_limits(&work),
            )
            .map_err(Error::Replay)
        })?;
        observe(RestorationBoundary::Acquired);
        work.check()?;
        // Authenticate all retained envelopes in chain order; replay already
        // checked their semantics, including correspondence with candidate rows.
        let mut prior = None;
        let mut existing = None;
        for bytes in &data.observations {
            work.check()?;
            let auth = observation::authenticate(bytes, context, prior.as_ref())
                .map_err(|_| Error::Invalid("observation changed"))?;
            if let Ipld::Map(st) = auth.statement() {
                if st.get("event") == Some(&Ipld::String("restored".into())) {
                    if let Some(Ipld::Map(body)) = st.get("body") {
                        if body.get("cid") == Some(&Ipld::Link(request.candidate.cid.clone())) {
                            existing = Some(auth.clone());
                        }
                    }
                }
            }
            prior = Some(auth);
        }
        let duplicate = existing.is_some();
        let claim = if let Some(claim) = existing {
            require(
                data.candidates.iter().any(|(cid, bytes)| {
                    cid == request.candidate.cid && bytes == request.candidate.bytes
                }),
                "retry candidate differs",
            )?;
            claim
        } else {
            require(
                before.latest() == request.expected,
                "stale restoration checkpoint",
            )?;
            data.with_input(context, |input, _, _| {
                replay::verify_candidate(input, request.candidate, replay_limits(&work))
                    .map(|_| ())
                    .map_err(Error::Replay)
            })?;
            observe(RestorationBoundary::CandidateVerified);
            work.check()?;
            let body = Ipld::Map(
                [
                    (
                        "member".into(),
                        Ipld::Bytes(before.member().commitment().to_vec()),
                    ),
                    ("cid".into(), Ipld::Link(request.candidate.cid.clone())),
                    (
                        "candidate".into(),
                        Ipld::Link(request.candidate.cid.clone()),
                    ),
                    (
                        "length".into(),
                        Ipld::Integer(request.candidate.bytes.len() as i128),
                    ),
                ]
                .into_iter()
                .collect(),
            );
            let statement = create::statement(
                context,
                prior.as_ref(),
                request.sampled_at,
                "restored",
                body,
            );
            let encoded = create::encode(&statement)?;
            work.charge(2, request.candidate.bytes.len() + encoded.len())?;
            let claim =
                observation::sign_claim(&encoded, request.observer, context, prior.as_ref())
                    .map_err(|_| Error::Invalid("restoration observation"))?;
            data.candidates.push((
                request.candidate.cid.clone(),
                request.candidate.bytes.to_vec(),
            ));
            data.candidates.sort_by_key(|(cid, _)| cid.to_string());
            data.observations.push(claim.bytes().to_vec());
            data.with_input(context, |input, candidates, observations| {
                replay::verify(
                    input,
                    candidates,
                    observations,
                    Some(request.expected),
                    replay_limits(&work),
                )
                .map(|_| ())
                .map_err(Error::Replay)
            })?;
            work.check()?;
            tx.execute(
                "INSERT INTO restored_objects VALUES(?1,?2)",
                rusqlite::params![request.candidate.cid.to_string(), request.candidate.bytes],
            )?;
            observe(RestorationBoundary::CandidateInserted);
            work.check()?;
            tx.execute(
                "INSERT INTO observations VALUES(?1,?2)",
                rusqlite::params![create::sql_integer(claim.sequence())?, claim.bytes()],
            )?;
            observe(RestorationBoundary::ObservationInserted);
            work.check()?;
            claim
        };
        let intended = if duplicate {
            before.latest().clone()
        } else {
            Checkpoint {
                context: context.clone(),
                sequence: claim.sequence(),
                statement: claim.statement_cid().clone(),
            }
        };
        observe(RestorationBoundary::BeforeCommit);
        work.check()?;
        // An exact retry resolves a possibly lost previous completion. Sync and
        // independently reopen even though this transaction appended nothing.
        attempted = Some(intended.clone());
        tx.commit()?;
        observe(RestorationBoundary::AfterCommit);
        drop(conn);
        std::fs::File::open(&path)?.sync_all()?;
        std::fs::File::open(super::super::parent_directory(&path))?.sync_all()?;
        observe(RestorationBoundary::Synced);
        work.check()?;
        let mut budget = request.budget.clone();
        budget.duration = deadline.saturating_duration_since(Instant::now());
        budget.source_bytes = request.output_bytes;
        let inspection = inspect(&path, context.clone(), Some(&intended), budget)?;
        observe(RestorationBoundary::Reopened);
        Ok(Restored {
            inspection,
            observation: claim,
            duplicate,
        })
    })();
    result.map_err(|cause| match attempted {
        Some(checkpoint) => RestorationError::Uncertain {
            path: actual_path,
            checkpoint: Box::new(checkpoint),
            cause: Box::new(cause),
        },
        None => RestorationError::Refused(cause),
    })
}
