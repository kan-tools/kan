//! Explicit owner publication. Intent, physical output and observed completion
//! are separate durable steps; none activates a service writer.
use super::super::{attested, copied, Ledger};
use super::*;
use crate::{evidence_recovery_observation as observation, sign::Identity};
use atproto_dasl::Ipld;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PublicationMode {
    New,
    Resume,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PublicationFailureReason {
    SourceChanged,
    InvalidCandidate,
    DestinationConflict,
    Budget,
    Io,
    Verification,
}
impl PublicationFailureReason {
    fn name(self) -> &'static str {
        match self {
            Self::SourceChanged => "source-changed",
            Self::InvalidCandidate => "invalid-candidate",
            Self::DestinationConflict => "destination-conflict",
            Self::Budget => "budget",
            Self::Io => "io",
            Self::Verification => "verification",
        }
    }
}
/// An attributed unsuccessful check. This does not assert that an output is
/// absent, remove an intent, or prevent a later explicit successful resume.
pub struct PublicationFailure<'a> {
    pub path: &'a Path,
    pub expected: &'a Checkpoint,
    pub observer: &'a Identity,
    pub attempt: [u8; 16],
    pub reason: PublicationFailureReason,
    pub sampled_at: u64,
    pub budget: Budget,
    pub bundle_bytes: u64,
}
pub struct FailedPublication {
    pub inspection: Inspection,
    pub observation: observation::Authenticated,
}
#[derive(Debug, thiserror::Error)]
pub enum PublicationFailureError {
    #[error(transparent)]
    Refused(#[from] Error),
    #[error("publication failure attribution uncertain; retain {path:?}: {cause}")]
    Uncertain {
        path: PathBuf,
        checkpoint: Box<Checkpoint>,
        cause: Box<Error>,
    },
}

pub fn record_publication_failure(
    request: PublicationFailure<'_>,
) -> std::result::Result<FailedPublication, PublicationFailureError> {
    let context = &request.expected.context;
    let mut attempted = None;
    let mut path = request.path.to_path_buf();
    let result = (|| -> Result<FailedPublication> {
        require(request.observer.did() == context.observer, "observer pin")?;
        require(request.sampled_at <= MAX_SAFE as u64, "sample time")?;
        let mut work = mutation::work(request.budget.clone(), request.bundle_bytes)?;
        let (actual, mut conn) = mutation::open(
            request.path,
            request.expected,
            request.bundle_bytes,
            &mut work,
        )?;
        path = actual;
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        schema(&tx, &mut work)?;
        identity(&tx, context, &mut work)?;
        let mut data = acquire(&tx, &mut work)?;
        let replay = data.with_input(context, |input, candidates, observations| {
            replay::verify(
                input,
                candidates,
                observations,
                Some(request.expected),
                replay_limits(&work),
            )
            .map_err(Error::Replay)
        })?;
        require(
            replay.latest() == request.expected,
            "stale failure checkpoint",
        )?;
        let attempt = replay
            .attempts()
            .iter()
            .find(|a| a.id == request.attempt)
            .ok_or(Error::Invalid("publication intent missing"))?;
        require(
            attempt.observed_at_sequence.is_none(),
            "publication already observed",
        )?;
        let body = map([
            ("attempt", Ipld::Bytes(request.attempt.to_vec())),
            ("intent", Ipld::Link(attempt.intent.clone())),
            ("reason", Ipld::String(request.reason.name().into())),
        ]);
        let observation = append(
            &tx,
            &mut data,
            request.expected,
            request.observer,
            request.sampled_at,
            ("publication-failed", body),
            &mut work,
        )?;
        let pin = checkpoint(context, &observation);
        work.check()?;
        attempted = Some(pin.clone());
        tx.commit()?;
        drop(conn);
        mutation::synchronize(&path, &work)?;
        let inspection = reopen(&path, &pin, &work, request.bundle_bytes)?;
        Ok(FailedPublication {
            inspection,
            observation,
        })
    })();
    result.map_err(|cause| match attempted {
        None => PublicationFailureError::Refused(cause),
        Some(pin) => PublicationFailureError::Uncertain {
            path,
            checkpoint: Box::new(pin),
            cause: Box::new(cause),
        },
    })
}

pub struct Publication<'a> {
    pub path: &'a Path,
    pub expected: &'a Checkpoint,
    pub observer: &'a Identity,
    pub attempt: [u8; 16],
    pub destination: &'a Path,
    pub mode: PublicationMode,
    pub sampled_at: u64,
    pub budget: Budget,
    pub bundle_bytes: u64,
    pub output_bytes: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PublicationBoundary {
    Acquired,
    IntentInserted,
    BeforeIntentCommit,
    IntentCommitted,
    IntentSynced,
    IntentReopened,
    OutputReserved,
    OutputRowsInserted,
    OutputChecked,
    BeforeOutputCommit,
    OutputCommitted,
    OutputSynced,
    OutputVerified,
    ObservedInserted,
    BeforeObservedCommit,
    ObservedCommitted,
    ObservedSynced,
    Reopened,
}
pub struct Published {
    pub inspection: Inspection,
    pub intent: observation::Authenticated,
    pub observation: observation::Authenticated,
    pub output: PathBuf,
    pub duplicate: bool,
}
#[derive(Debug, thiserror::Error)]
pub enum PublicationError {
    #[error(transparent)]
    Refused(#[from] Error),
    #[error("publication interrupted at {phase:?}; retain bundle {bundle:?} and output {output:?}: {cause}")]
    Interrupted {
        phase: PublicationBoundary,
        bundle: PathBuf,
        output: PathBuf,
        /// Last attempted checkpoint; a failed COMMIT may not have retained it.
        checkpoint: Box<Checkpoint>,
        cause: Box<Error>,
    },
}
struct Selection {
    objects: Vec<(Cid, Vec<u8>)>,
    output: [u8; 32],
    restorations: [u8; 32],
    replay: Replay,
    intent: Option<observation::Authenticated>,
}
fn selection(data: &Acquired, request: &Publication<'_>, work: &mut Work) -> Result<Selection> {
    data.with_input(
        &request.expected.context,
        |input, candidates, observations| {
            let s = replay::publication_selection(
                input,
                candidates,
                observations,
                request.expected,
                (request.mode == PublicationMode::Resume).then_some(request.attempt),
                replay_limits(work),
            )?;
            let mut objects = Vec::with_capacity(s.objects.len());
            for (cid, bytes) in s.objects {
                work.charge(1, bytes.len())?;
                objects.push((cid, bytes.to_vec()));
            }
            Ok(Selection {
                objects,
                output: s.output,
                restorations: s.restorations,
                replay: s.replay,
                intent: s.intent,
            })
        },
    )
}
fn tail(data: &Acquired, context: &Context, work: &Work) -> Result<observation::Authenticated> {
    let mut prior = None;
    for raw in &data.observations {
        work.check()?;
        prior = Some(
            observation::authenticate(raw, context, prior.as_ref())
                .map_err(|_| Error::Invalid("history changed"))?,
        );
    }
    prior.ok_or(Error::Invalid("empty history"))
}
fn checkpoint(context: &Context, claim: &observation::Authenticated) -> Checkpoint {
    Checkpoint {
        context: context.clone(),
        sequence: claim.sequence(),
        statement: claim.statement_cid().clone(),
    }
}
fn map<const N: usize>(pairs: [(&str, Ipld); N]) -> Ipld {
    Ipld::Map(
        pairs
            .into_iter()
            .map(|(key, value)| (key.into(), value))
            .collect(),
    )
}
fn frontier(value: &crate::evidence_attestation::Frontier) -> Ipld {
    map([
        ("through", Ipld::Integer(value.through.into())),
        (
            "manifest",
            value.manifest.clone().map(Ipld::Link).unwrap_or(Ipld::Null),
        ),
        (
            "attestation",
            value
                .attestation
                .clone()
                .map(Ipld::Link)
                .unwrap_or(Ipld::Null),
        ),
    ])
}
fn append(
    tx: &rusqlite::Transaction<'_>,
    data: &mut Acquired,
    expected: &Checkpoint,
    observer: &Identity,
    sampled_at: u64,
    event: (&str, Ipld),
    work: &mut Work,
) -> Result<observation::Authenticated> {
    let prior = tail(data, &expected.context, work)?;
    let statement = create::statement(
        &expected.context,
        Some(&prior),
        sampled_at,
        event.0,
        event.1,
    );
    let bytes = create::encode(&statement)?;
    work.charge(1, bytes.len())?;
    let claim = observation::sign_claim(&bytes, observer, &expected.context, Some(&prior))
        .map_err(|_| Error::Invalid("publication observation"))?;
    data.observations.push(claim.bytes().to_vec());
    data.with_input(&expected.context, |input, candidates, observations| {
        replay::verify(
            input,
            candidates,
            observations,
            Some(expected),
            replay_limits(work),
        )
        .map_err(Error::Replay)
    })?;
    work.check()?;
    tx.execute(
        "INSERT INTO observations VALUES(?1,?2)",
        rusqlite::params![create::sql_integer(claim.sequence())?, claim.bytes()],
    )?;
    Ok(claim)
}
fn reopen(path: &Path, pin: &Checkpoint, work: &Work, bundle_bytes: u64) -> Result<Inspection> {
    work.check()?;
    let mut budget = work.budget.clone();
    budget.duration = work.deadline.saturating_duration_since(Instant::now());
    budget.source_bytes = bundle_bytes;
    inspect(path, pin.context.clone(), Some(pin), budget)
}
fn output_path(
    source: &Path,
    destination: &Path,
    new: bool,
    bytes: u64,
    work: &Work,
) -> Result<PathBuf> {
    let destination = super::super::sqlite_destination(source, destination)?;
    match std::fs::symlink_metadata(&destination) {
        Ok(_) => {
            require(!new, "destination already exists")?;
            let mut budget = work.budget.clone();
            budget.source_bytes = bytes;
            let output_work = Work {
                budget,
                deadline: work.deadline,
                items: 0,
                bytes: 0,
            };
            create::source_path(&destination, &output_work)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(destination),
        Err(e) => Err(e.into()),
    }
}
fn verify_output(
    ledger: &Ledger,
    context: &Context,
    output: &[u8; 32],
    work: &mut Work,
) -> Result<()> {
    // Bounded raw acquisition validates schema/types before the ordinary audit.
    let acquired = create::acquire(&ledger.conn, context.clone(), work, &mut |_| {})?;
    let actual = acquired.with_input(|input| {
        replay::published_output_commitment(input, replay_limits(work)).map_err(Error::Replay)
    })?;
    require(&actual == output, "physical publication output commitment")?;
    let binding = attested::Binding {
        archive: context.archive,
        scope: context.scope,
        issuer: context.issuer.clone(),
    };
    let base = ledger.verify_contents()?;
    if context.profile == 3 {
        let plan = copied::stored_plan(&ledger.conn, &binding)?;
        let verified = copied::full_audit(ledger, &binding, &plan)?;
        require(verified.copy.source_copy_complete, "partial published copy")?;
    } else {
        ledger.check_profile(2)?;
        ledger.check_write_profile(true)?;
        attested::verify_contents(ledger, &binding, &base)?;
    }
    work.check()
}
fn write_output(
    path: &Path,
    data: &Acquired,
    selection: &Selection,
    request: &Publication<'_>,
    work: &mut Work,
    observe: &mut impl FnMut(PublicationBoundary),
    phase: &mut PublicationBoundary,
) -> Result<()> {
    let context = &request.expected.context;
    // surface-write: evidence-publication:database,evidence-publication:database-journal
    crate::persistence::write_new_owner_only(
        crate::persistence::SurfaceWrite::EvidencePublication,
        path,
        &[],
    )?;
    *phase = PublicationBoundary::OutputReserved;
    observe(*phase);
    work.check()?;
    let conn = Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE)?;
    conn.execute_batch(
        "PRAGMA journal_mode=DELETE; PRAGMA page_size=4096; PRAGMA foreign_keys=ON;",
    )?;
    mutation::configure(&conn, work, Some(request.output_bytes))?;
    let ledger = Ledger { conn };
    let tx = rusqlite::Transaction::new_unchecked(
        &ledger.conn,
        rusqlite::TransactionBehavior::Immediate,
    )?;
    tx.execute_batch(super::super::SCHEMA)?;
    let binding = attested::Binding {
        archive: context.archive,
        scope: context.scope,
        issuer: context.issuer.clone(),
    };
    attested::initialize(&tx, &binding)?;
    if let Some(raw) = &data.plan {
        let plan =
            crate::evidence_copy_plan::Plan::decode(raw).map_err(super::super::Error::from)?;
        copied::initialize(&tx, &binding, &plan)?;
        for (cid, length) in &data.membership {
            work.check()?;
            tx.execute(
                "INSERT INTO upgrade_objects VALUES(?1,?2)",
                rusqlite::params![cid.to_string(), create::sql_integer(*length)?],
            )?;
        }
    }
    for (cid, bytes) in &selection.objects {
        work.check()?;
        tx.execute(
            "INSERT INTO objects VALUES(?1,?2)",
            rusqlite::params![cid.to_string(), bytes],
        )?;
    }
    for row in &data.records {
        work.check()?;
        let manifest = super::super::known(&row.manifest, crate::evidence::Kind::Manifest)?;
        let b = manifest.body();
        let cid = manifest.cid().to_string();
        tx.execute(
            "INSERT INTO commits VALUES(?,?,?,?,?,?,?,?,?)",
            rusqlite::params![
                create::sql_integer(row.sequence)?,
                cid,
                super::super::blob(&b["scopeToken"]),
                super::super::writer(&manifest),
                super::super::blob(&b["operation"]),
                super::super::number(&b["position"]),
                super::super::optional_cid(&b["previous"]),
                row.manifest,
                row.receipt
            ],
        )?;
        for entry in super::super::entries(&manifest) {
            tx.execute("INSERT INTO bindings VALUES(?,?,?,?,?,?) ON CONFLICT(scope,writer,slot) DO NOTHING", rusqlite::params![
                super::super::blob(&b["scopeToken"]),super::super::writer(&manifest),super::super::blob(&entry["slot"]),
                super::super::cid(&entry["ciphertext"]),super::super::number(&entry["length"]),cid])?;
        }
        tx.execute(
            "INSERT INTO attestations VALUES(?1,?2)",
            rusqlite::params![create::sql_integer(row.sequence)?, row.proof],
        )?;
    }
    *phase = PublicationBoundary::OutputRowsInserted;
    observe(*phase);
    work.check()?;
    verify_output(&ledger, context, &selection.output, work)?;
    *phase = PublicationBoundary::OutputChecked;
    observe(*phase);
    work.check()?;
    *phase = PublicationBoundary::BeforeOutputCommit;
    observe(*phase);
    work.check()?;
    tx.commit()?;
    *phase = PublicationBoundary::OutputCommitted;
    observe(*phase);
    drop(ledger);
    mutation::synchronize(path, work)
}
fn observed(
    data: &Acquired,
    context: &Context,
    sequence: u64,
    work: &Work,
) -> Result<observation::Authenticated> {
    let mut prior = None;
    for raw in &data.observations {
        work.check()?;
        let auth = observation::authenticate(raw, context, prior.as_ref())
            .map_err(|_| Error::Invalid("history changed"))?;
        if auth.sequence() == sequence {
            return Ok(auth);
        }
        prior = Some(auth);
    }
    Err(Error::Invalid("observed publication missing"))
}

pub fn publish(request: Publication<'_>) -> std::result::Result<Published, PublicationError> {
    publish_observed(request, |_| {})
}
/// Synchronous owner-side observer; it must return promptly. Deadline checks
/// cannot preempt callback code or arbitrary filesystem stalls.
pub fn publish_observed(
    request: Publication<'_>,
    mut observe: impl FnMut(PublicationBoundary),
) -> std::result::Result<Published, PublicationError> {
    let context = &request.expected.context;
    let mut phase = PublicationBoundary::Acquired;
    let mut attempted = None;
    let mut bundle_path = request.path.to_path_buf();
    let mut destination = request.destination.to_path_buf();
    let result = (|| -> Result<Published> {
        require(request.observer.did() == context.observer, "observer pin")?;
        require(request.sampled_at <= MAX_SAFE as u64, "sample time")?;
        let mut work = mutation::work(request.budget.clone(), request.bundle_bytes)?;
        require(
            request.output_bytes / 4096 >= 8 && request.output_bytes / 4096 <= u32::MAX as u64,
            "output page bound",
        )?;
        bundle_path = create::source_path(request.path, &work)?;
        destination = output_path(
            &bundle_path,
            request.destination,
            request.mode == PublicationMode::New,
            request.output_bytes,
            &work,
        )?;
        let (_, mut conn) = mutation::open(
            &bundle_path,
            request.expected,
            request.bundle_bytes,
            &mut work,
        )?;
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        schema(&tx, &mut work)?;
        identity(&tx, context, &mut work)?;
        let mut data = acquire(&tx, &mut work)?;
        let selected = selection(&data, &request, &mut work)?;
        observe(phase);
        work.check()?;
        let intent = if let Some(intent) = &selected.intent {
            intent.clone()
        } else {
            require(
                selected.replay.latest() == request.expected,
                "stale publication checkpoint",
            )?;
            require(
                !selected
                    .replay
                    .attempts()
                    .iter()
                    .any(|a| a.id == request.attempt),
                "publication attempt already exists",
            )?;
            let body = map([
                ("attempt", Ipld::Bytes(request.attempt.to_vec())),
                (
                    "member",
                    Ipld::Bytes(selected.replay.member().commitment().to_vec()),
                ),
                ("restorations", Ipld::Bytes(selected.restorations.to_vec())),
                ("output", Ipld::Bytes(selected.output.to_vec())),
                ("frontier", frontier(selected.replay.member().frontier())),
            ]);
            let intent = append(
                &tx,
                &mut data,
                request.expected,
                request.observer,
                request.sampled_at,
                ("publication-intent", body),
                &mut work,
            )?;
            phase = PublicationBoundary::IntentInserted;
            observe(phase);
            work.check()?;
            intent
        };
        let intent_pin = if selected.intent.is_some() {
            selected.replay.latest().clone()
        } else {
            checkpoint(context, &intent)
        };
        phase = PublicationBoundary::BeforeIntentCommit;
        observe(phase);
        work.check()?;
        attempted = Some(intent_pin.clone());
        tx.commit()?;
        phase = PublicationBoundary::IntentCommitted;
        observe(phase);
        drop(conn);
        mutation::synchronize(&bundle_path, &work)?;
        phase = PublicationBoundary::IntentSynced;
        observe(phase);
        work.check()?;
        reopen(&bundle_path, &intent_pin, &work, request.bundle_bytes)?;
        phase = PublicationBoundary::IntentReopened;
        observe(phase);
        work.check()?;
        // Recheck custody after releasing the bundle transaction. Never replace
        // an existing output, even if an earlier attempt left it incomplete.
        create::source_path(&bundle_path, &work)?;
        destination = output_path(
            &bundle_path,
            &destination,
            false,
            request.output_bytes,
            &work,
        )?;
        if !destination.try_exists()? {
            write_output(
                &destination,
                &data,
                &selected,
                &request,
                &mut work,
                &mut observe,
                &mut phase,
            )?;
        }
        mutation::synchronize(&destination, &work)?;
        phase = PublicationBoundary::OutputSynced;
        observe(phase);
        work.check()?;
        destination = output_path(
            &bundle_path,
            &destination,
            false,
            request.output_bytes,
            &work,
        )?;
        // Keep this DELETE-mode read transaction through observed commit. Normal
        // SQLite writers cannot change the verified output during attribution.
        // surface-write: evidence-publication-source:database-wal,evidence-publication-source:database-shm
        let output_conn = crate::persistence::open_sqlite_recovery_source(
            crate::persistence::SurfaceWrite::EvidencePublicationSource,
            &destination,
        )?;
        mutation::configure(&output_conn, &work, None)?;
        output_conn.execute_batch("PRAGMA query_only=ON; BEGIN;")?;
        let output_reader = Ledger { conn: output_conn };
        verify_output(&output_reader, context, &selected.output, &mut work)?;
        phase = PublicationBoundary::OutputVerified;
        observe(phase);
        work.check()?;
        let (_, mut conn) =
            mutation::open(&bundle_path, &intent_pin, request.bundle_bytes, &mut work)?;
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        schema(&tx, &mut work)?;
        identity(&tx, context, &mut work)?;
        let mut current = acquire(&tx, &mut work)?;
        let replay = current.with_input(context, |input, candidates, observations| {
            replay::verify(
                input,
                candidates,
                observations,
                Some(&intent_pin),
                replay_limits(&work),
            )
            .map_err(Error::Replay)
        })?;
        let attempt = replay
            .attempts()
            .iter()
            .find(|a| a.id == request.attempt)
            .ok_or(Error::Invalid("publication intent missing"))?;
        require(
            attempt.intent == *intent.statement_cid()
                && attempt.output == selected.output
                && attempt.restorations == selected.restorations,
            "publication intent changed",
        )?;
        let duplicate = attempt.observed_at_sequence.is_some();
        let observation = if let Some(sequence) = attempt.observed_at_sequence {
            observed(&current, context, sequence, &work)?
        } else {
            let body = map([
                ("attempt", Ipld::Bytes(request.attempt.to_vec())),
                ("intent", Ipld::Link(intent.statement_cid().clone())),
                ("output", Ipld::Bytes(selected.output.to_vec())),
                ("frontier", frontier(replay.member().frontier())),
            ]);
            let observation = append(
                &tx,
                &mut current,
                &intent_pin,
                request.observer,
                request.sampled_at,
                ("publication-observed", body),
                &mut work,
            )?;
            phase = PublicationBoundary::ObservedInserted;
            observe(phase);
            work.check()?;
            observation
        };
        let observed_pin = if duplicate {
            replay.latest().clone()
        } else {
            checkpoint(context, &observation)
        };
        phase = PublicationBoundary::BeforeObservedCommit;
        observe(phase);
        work.check()?;
        attempted = Some(observed_pin.clone());
        tx.commit()?;
        phase = PublicationBoundary::ObservedCommitted;
        observe(phase);
        drop(conn);
        mutation::synchronize(&bundle_path, &work)?;
        phase = PublicationBoundary::ObservedSynced;
        observe(phase);
        work.check()?;
        let inspection = reopen(&bundle_path, &observed_pin, &work, request.bundle_bytes)?;
        phase = PublicationBoundary::Reopened;
        observe(phase);
        work.check()?;
        drop(output_reader);
        Ok(Published {
            inspection,
            intent,
            observation,
            output: destination.clone(),
            duplicate,
        })
    })();
    result.map_err(|cause| match attempted {
        None => PublicationError::Refused(cause),
        Some(pin) => PublicationError::Interrupted {
            phase,
            bundle: bundle_path,
            output: destination,
            checkpoint: Box::new(pin),
            cause: Box::new(cause),
        },
    })
}
