//! Copy the complete retained bundle, including unavailable original evidence.
//! Neither mode signs observations, repairs payloads, or activates a writer.
use super::*;

pub struct BundleCopy<'a> {
    pub source: &'a Path,
    pub destination: &'a Path,
    pub expected: &'a Checkpoint,
    pub budget: Budget,
    /// Main-file ceiling; journals and bounded owned snapshots are additional.
    pub output_bytes: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CopyBoundary {
    Acquired,
    Reserved,
    RowsInserted,
    BeforeCommit,
    CopyStep,
    Committed,
    Synced,
    Reopened,
}
pub struct CopiedBundle {
    pub inspection: Inspection,
    pub captured: Checkpoint,
}
#[derive(Debug, thiserror::Error)]
pub enum BundleCopyError {
    #[error(transparent)]
    Refused(#[from] Error),
    #[error("bundle copy incomplete at {phase:?}; retain {path:?}: {cause}")]
    Incomplete {
        path: PathBuf,
        phase: CopyBoundary,
        cause: Box<Error>,
    },
    #[error("bundle copy uncertain at {phase:?}; retain {path:?}: {cause}")]
    Uncertain {
        path: PathBuf,
        phase: CopyBoundary,
        checkpoint: Box<Checkpoint>,
        cause: Box<Error>,
    },
}

pub fn backup(request: BundleCopy<'_>) -> std::result::Result<CopiedBundle, BundleCopyError> {
    backup_observed(request, |_| {})
}
pub fn rebuild(request: BundleCopy<'_>) -> std::result::Result<CopiedBundle, BundleCopyError> {
    rebuild_observed(request, |_| {})
}
/// Owner-side synchronous notification, not a remote hook. It must return promptly.
pub fn backup_observed(
    request: BundleCopy<'_>,
    observe: impl FnMut(CopyBoundary),
) -> std::result::Result<CopiedBundle, BundleCopyError> {
    copy(request, true, observe)
}
/// Owner-side synchronous notification, not a remote hook. It must return promptly.
pub fn rebuild_observed(
    request: BundleCopy<'_>,
    observe: impl FnMut(CopyBoundary),
) -> std::result::Result<CopiedBundle, BundleCopyError> {
    copy(request, false, observe)
}

fn replay_data(data: &Acquired, expected: &Checkpoint, work: &Work) -> Result<Replay> {
    data.with_input(&expected.context, |input, candidates, observations| {
        replay::verify(
            input,
            candidates,
            observations,
            Some(expected),
            replay_limits(work),
        )
        .map_err(Error::Replay)
    })
}
fn read_connection(path: &Path, work: &Work) -> Result<Connection> {
    // surface-write: evidence-bundle-copy-source:database-wal,evidence-bundle-copy-source:database-shm
    let conn = crate::persistence::open_sqlite_recovery_source(
        crate::persistence::SurfaceWrite::EvidenceBundleCopySource,
        path,
    )?;
    mutation::configure(&conn, work, None)?;
    conn.execute_batch("PRAGMA query_only=ON; BEGIN;")?;
    Ok(conn)
}
fn insert(
    tx: &rusqlite::Transaction<'_>,
    context: &Context,
    data: &Acquired,
    work: &Work,
) -> Result<()> {
    tx.execute_batch(SCHEMA)?;
    tx.execute(
        "INSERT INTO bundle_identity VALUES(1,?1,?2,?3,?4,?5,?6)",
        rusqlite::params![
            context.bundle.as_slice(),
            context.observer,
            context.profile,
            context.archive.as_slice(),
            context.scope.as_slice(),
            context.issuer
        ],
    )?;
    if let Some(plan) = &data.plan {
        tx.execute("INSERT INTO member_plan VALUES(1,?1)", [plan])?;
    }
    for (cid, length) in &data.membership {
        work.check()?;
        tx.execute(
            "INSERT INTO member_membership VALUES(?1,?2)",
            rusqlite::params![cid.to_string(), create::sql_integer(*length)?],
        )?;
    }
    for row in &data.records {
        work.check()?;
        tx.execute(
            "INSERT INTO member_records VALUES(?1,?2,?3,?4)",
            rusqlite::params![
                create::sql_integer(row.sequence)?,
                row.manifest,
                row.receipt,
                row.proof
            ],
        )?;
    }
    for (table, rows) in [
        ("member_objects", &data.original),
        ("restored_objects", &data.candidates),
    ] {
        for (cid, bytes) in rows {
            work.check()?;
            tx.execute(
                &format!("INSERT INTO {table} VALUES(?1,?2)"),
                rusqlite::params![cid.to_string(), bytes],
            )?;
        }
    }
    for (index, bytes) in data.observations.iter().enumerate() {
        work.check()?;
        tx.execute(
            "INSERT INTO observations VALUES(?1,?2)",
            rusqlite::params![create::sql_integer(index as u64 + 1)?, bytes],
        )?;
    }
    tx.execute_batch(&format!(
        "PRAGMA application_id={APPLICATION_ID}; PRAGMA user_version=1;"
    ))?;
    Ok(())
}

fn copy(
    request: BundleCopy<'_>,
    physical: bool,
    mut observe: impl FnMut(CopyBoundary),
) -> std::result::Result<CopiedBundle, BundleCopyError> {
    let mut destination = request.destination.to_path_buf();
    let mut phase = CopyBoundary::Acquired;
    let mut reserved = false;
    let mut attempted = None;
    let result = (|| -> Result<CopiedBundle> {
        let mut work = mutation::work(request.budget.clone(), request.output_bytes)?;
        let source = create::source_path(request.source, &work)?;
        destination = create::destination_path(&source, request.destination)?;
        let conn = read_connection(&source, &work)?;
        schema(&conn, &mut work)?;
        identity(&conn, &request.expected.context, &mut work)?;
        let data = acquire(&conn, &mut work)?;
        let replay = replay_data(&data, request.expected, &work)?;
        let captured = replay.latest().clone();
        // The backup API copies the source page count, including free pages.
        // Its header can replace the target's ceiling; reject before reservation.
        if physical {
            let pages: i64 = conn.query_row("PRAGMA page_count", [], |r| r.get(0))?;
            require(
                pages > 0 && pages as u64 <= request.output_bytes / 4096,
                "physical backup page bound",
            )?;
        }
        observe(phase);
        work.check()?;
        create::source_path(&source, &work)?;
        destination = create::destination_path(&source, &destination)?;
        // surface-write: evidence-bundle-copy:database,evidence-bundle-copy:database-journal
        crate::persistence::write_new_owner_only(
            crate::persistence::SurfaceWrite::EvidenceBundleCopy,
            &destination,
            &[],
        )?;
        reserved = true;
        phase = CopyBoundary::Reserved;
        observe(phase);
        work.check()?;
        let mut target =
            Connection::open_with_flags(&destination, rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE)?;
        target.execute_batch("PRAGMA journal_mode=DELETE; PRAGMA page_size=4096;")?;
        mutation::configure(&target, &work, Some(request.output_bytes))?;
        if physical {
            let backup = rusqlite::backup::Backup::new(&conn, &mut target)?;
            phase = CopyBoundary::BeforeCommit;
            observe(phase);
            work.check()?;
            // A step may commit internally, including the first step for a
            // small database. Errors after a step is attempted are uncertain.
            loop {
                phase = CopyBoundary::CopyStep;
                observe(phase);
                work.check()?;
                attempted = Some(captured.clone());
                match backup.step(64)? {
                    rusqlite::backup::StepResult::Done => break,
                    rusqlite::backup::StepResult::More => {}
                    _ => {
                        return Err(Error::Invalid(
                            "bundle backup busy; retained output incomplete",
                        ))
                    }
                }
            }
        } else {
            let tx = target.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            insert(&tx, &request.expected.context, &data, &work)?;
            phase = CopyBoundary::RowsInserted;
            observe(phase);
            work.check()?;
            // Validate both history and every retained cell before publishing
            // recognizable markers; a construction defect must roll back.
            schema(&tx, &mut work)?;
            identity(&tx, &request.expected.context, &mut work)?;
            let rebuilt = acquire(&tx, &mut work)?;
            require(rebuilt == data, "rebuilt bundle cells differ")?;
            require(
                replay_data(&rebuilt, &captured, &work)?.latest() == &captured,
                "rebuilt bundle checkpoint",
            )?;
            phase = CopyBoundary::BeforeCommit;
            observe(phase);
            work.check()?;
            attempted = Some(captured.clone());
            tx.commit()?;
        }
        phase = CopyBoundary::Committed;
        observe(phase);
        work.check()?;
        mutation::configure(&target, &work, Some(request.output_bytes))?;
        drop(target);
        // The source read transaction remains pinned until physical copying or
        // logical insertion is complete. Later source appends cannot mix in.
        drop(conn);
        mutation::synchronize(&destination, &work)?;
        phase = CopyBoundary::Synced;
        observe(phase);
        work.check()?;
        let mut output_work = Work {
            budget: Budget {
                source_bytes: request.output_bytes,
                ..work.budget.clone()
            },
            deadline: work.deadline,
            items: work.items,
            bytes: work.bytes,
        };
        create::source_path(&destination, &output_work)?;
        let reopened = read_connection(&destination, &output_work)?;
        schema(&reopened, &mut output_work)?;
        identity(&reopened, &request.expected.context, &mut output_work)?;
        let actual = acquire(&reopened, &mut output_work)?;
        require(actual == data, "copied bundle cells differ")?;
        let replay = replay_data(&actual, &captured, &output_work)?;
        require(replay.latest() == &captured, "copied bundle checkpoint")?;
        phase = CopyBoundary::Reopened;
        observe(phase);
        output_work.check()?;
        Ok(CopiedBundle {
            inspection: Inspection {
                source: destination.clone(),
                replay,
                acquired_bytes: output_work.bytes,
                items: output_work.items,
            },
            captured,
        })
    })();
    result.map_err(|cause| match attempted {
        Some(pin) => BundleCopyError::Uncertain {
            path: destination,
            phase,
            checkpoint: Box::new(pin),
            cause: Box::new(cause),
        },
        None if reserved => BundleCopyError::Incomplete {
            path: destination,
            phase,
            cause: Box::new(cause),
        },
        None => BundleCopyError::Refused(cause),
    })
}
