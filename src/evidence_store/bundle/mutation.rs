//! Shared bounded owner-side opening; mutation authority still comes from
//! reacquisition and replay under the caller's BEGIN IMMEDIATE transaction.
use super::*;

pub(super) fn work(budget: Budget, output_bytes: u64) -> Result<Work> {
    require(
        !budget.duration.is_zero() && budget.duration <= Duration::from_secs(3600),
        "duration",
    )?;
    require(
        output_bytes / 4096 >= 8 && output_bytes / 4096 <= u32::MAX as u64,
        "output page bound",
    )?;
    let deadline = Instant::now()
        .checked_add(budget.duration)
        .ok_or(Error::Budget("duration"))?;
    let work = Work {
        budget,
        deadline,
        items: 0,
        bytes: 0,
    };
    work.check()?;
    Ok(work)
}

pub(super) fn configure(conn: &Connection, work: &Work, output_bytes: Option<u64>) -> Result<()> {
    conn.set_limit(
        rusqlite::limits::Limit::SQLITE_LIMIT_LENGTH,
        5 * 1024 * 1024,
    )?;
    conn.busy_timeout(
        work.deadline
            .saturating_duration_since(Instant::now())
            .min(Duration::from_millis(250)),
    )?;
    let cancel = work.budget.cancelled.clone();
    let deadline = work.deadline;
    conn.progress_handler(
        1000,
        Some(move || cancel.load(Ordering::Relaxed) || Instant::now() >= deadline),
    )?;
    let mode: String = conn.query_row("PRAGMA journal_mode", [], |r| r.get(0))?;
    let page: i64 = conn.query_row("PRAGMA page_size", [], |r| r.get(0))?;
    require(
        mode.eq_ignore_ascii_case("delete") && page == 4096,
        "mutation journal/page mode",
    )?;
    if let Some(bytes) = output_bytes {
        let pages = bytes / 4096;
        let applied: i64 =
            conn.query_row(&format!("PRAGMA max_page_count={pages}"), [], |r| r.get(0))?;
        require(
            u64::try_from(applied).ok() == Some(pages),
            "output page limit",
        )?;
        conn.execute_batch("PRAGMA synchronous=FULL; PRAGMA fullfsync=ON;")?;
    }
    conn.execute_batch("PRAGMA trusted_schema=OFF; PRAGMA cache_size=-4096; PRAGMA mmap_size=0;")?;
    work.check()
}

pub(super) fn open(
    path: &Path,
    expected: &Checkpoint,
    output_bytes: u64,
    work: &mut Work,
) -> Result<(PathBuf, Connection)> {
    let path = create::source_path(path, work)?;
    let mut budget = work.budget.clone();
    budget.duration = work.deadline.saturating_duration_since(Instant::now());
    inspect(&path, expected.context.clone(), Some(expected), budget)?;
    work.check()?;
    create::source_path(&path, work)?;
    // Check journal/page mode before opening a writer. Read-only inspection
    // refuses hot journals rather than implicitly repairing retained evidence.
    // surface-write: evidence-bundle-source:database-wal,evidence-bundle-source:database-shm
    let preflight = crate::persistence::open_sqlite_recovery_source(
        crate::persistence::SurfaceWrite::EvidenceBundleSource,
        &path,
    )?;
    configure(&preflight, work, None)?;
    drop(preflight);
    work.check()?;
    // surface-write: evidence-bundle:database,evidence-bundle:database-journal
    let conn = crate::persistence::open_sqlite_bundle_mutation(
        crate::persistence::SurfaceWrite::EvidenceBundle,
        &path,
    )?;
    configure(&conn, work, Some(output_bytes))?;
    Ok((path, conn))
}

pub(super) fn synchronize(path: &Path, work: &Work) -> Result<()> {
    work.check()?;
    std::fs::File::open(path)?.sync_all()?;
    std::fs::File::open(super::super::parent_directory(path))?.sync_all()?;
    work.check()
}
