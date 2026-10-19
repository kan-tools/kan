//! Creation of a new retained bundle; never repairs or activates the source.
use super::*;
use crate::{
    evidence_attestation::Frontier, evidence_recovery_member as member,
    evidence_recovery_observation as observation, sign::Identity,
};
use atproto_dasl::Ipld;

/// Caller-selected owner pins and source frontier; paths confer no authority.
pub struct Creation<'a> {
    pub source: &'a Path,
    pub destination: &'a Path,
    pub context: Context,
    pub frontier: Frontier,
    pub observer: &'a Identity,
    pub sampled_at: u64,
    pub budget: Budget,
    /// SQLite main-file ceiling, rounded down to whole 4096-byte pages. Rollback
    /// journals and bounded in-memory acquisition require separate disk/RAM room.
    pub output_bytes: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CreationBoundary {
    Reserved,
    MemberInserted,
    HistoryInserted,
    MarkersSet,
    BeforeCommit,
    AfterCommit,
    Synced,
    Reopened,
}
#[derive(Debug, thiserror::Error)]
pub enum CreationError {
    #[error(transparent)]
    Refused(#[from] Error),
    #[error("bundle creation outcome uncertain; retain {path:?}: {cause}")]
    Uncertain {
        path: PathBuf,
        checkpoint: Box<Checkpoint>,
        cause: Box<Error>,
    },
}

pub(super) fn sql_integer(value: u64) -> Result<i64> {
    i64::try_from(value).map_err(|_| Error::Invalid("SQLite integer range"))
}

struct MemberBytes {
    context: Context,
    plan: Option<Vec<u8>>,
    membership: Vec<(Cid, u64)>,
    records: Vec<EncodedRow>,
    objects: Vec<(Cid, Vec<u8>)>,
}
impl MemberBytes {
    fn with_input<T>(&self, f: impl FnOnce(Input<'_>) -> Result<T>) -> Result<T> {
        let membership: Vec<_> = self
            .membership
            .iter()
            .map(|(cid, length)| Membership {
                cid,
                length: *length,
            })
            .collect();
        let records: Vec<_> = self
            .records
            .iter()
            .map(|r| Row {
                sequence: r.sequence,
                manifest: &r.manifest,
                receipt: &r.receipt,
                proof: &r.proof,
            })
            .collect();
        let objects: Vec<_> = self
            .objects
            .iter()
            .map(|(cid, bytes)| Object { cid, bytes })
            .collect();
        f(Input {
            context: &self.context,
            plan: self.plan.as_deref(),
            membership: &membership,
            records: &records,
            objects: &objects,
        })
    }
}
fn source_schema(conn: &Connection, context: &Context, work: &Work) -> Result<()> {
    require(matches!(context.profile, 2 | 3), "source profile")?;
    let app: i64 = conn.query_row("PRAGMA application_id", [], |r| r.get(0))?;
    let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    let encoding: String = conn.query_row("PRAGMA encoding", [], |r| r.get(0))?;
    require(
        app == 1263940097 && version == context.profile as i64 && encoding == "UTF-8",
        "source profile",
    )?;
    let expected = Connection::open_in_memory()?;
    expected.execute_batch(super::super::SCHEMA)?;
    expected.execute_batch(super::super::attested::SCHEMA)?;
    if context.profile == 3 {
        expected.execute_batch(super::super::copied::SCHEMA)?;
    }
    let query="SELECT substr(type,1,32),length(CAST(type AS BLOB)),substr(name,1,256),length(CAST(name AS BLOB)),substr(tbl_name,1,256),length(CAST(tbl_name AS BLOB)),substr(sql,1,65536),length(CAST(sql AS BLOB)) FROM sqlite_schema ORDER BY type,name";
    let mut a = conn.prepare(query)?;
    let mut e = expected.prepare(query)?;
    let mut actual = a.query([])?;
    let mut wanted = e.query([])?;
    loop {
        work.check()?;
        match (actual.next()?, wanted.next()?) {
            (None, None) => return Ok(()),
            (Some(a), Some(e)) => {
                for c in 0..8 {
                    require(a.get_ref(c)? == e.get_ref(c)?, "source schema")?;
                }
            }
            _ => return Err(Error::Invalid("source schema")),
        }
    }
}
fn source_identity(conn: &Connection, context: &Context, work: &mut Work) -> Result<()> {
    let query = format!(
        "SELECT singleton,{},{},{} FROM archive_identity",
        projection("archive", 32),
        projection("scope", 32),
        projection("issuer", 80)
    );
    let mut stmt = conn.prepare(&query)?;
    let mut rows = stmt.query([])?;
    let row = rows.next()?.ok_or(Error::Invalid("source identity"))?;
    work.charge(1, 8)?;
    integer(row, 0, 1, 1)?;
    require(
        cell(row, 1, 32, 32, false, work)? == context.archive,
        "source archive pin",
    )?;
    require(
        cell(row, 4, 32, 32, false, work)? == context.scope,
        "source scope pin",
    )?;
    require(
        cell(row, 7, 56, 80, true, work)? == context.issuer.as_bytes(),
        "source issuer pin",
    )?;
    require(rows.next()?.is_none(), "source identity cardinality")
}
fn acquire(conn: &Connection, context: Context, work: &mut Work) -> Result<MemberBytes> {
    source_schema(conn, &context, work)?;
    source_identity(conn, &context, work)?;
    let mut out = MemberBytes {
        context,
        plan: None,
        membership: vec![],
        records: vec![],
        objects: vec![],
    };
    if out.context.profile == 3 {
        let query = format!(
            "SELECT singleton,{} FROM upgrade_plan",
            projection("envelope", 4096)
        );
        let mut stmt = conn.prepare(&query)?;
        let mut rows = stmt.query([])?;
        let row = rows.next()?.ok_or(Error::Invalid("missing source plan"))?;
        work.charge(1, 8)?;
        integer(row, 0, 1, 1)?;
        out.plan = Some(cell(row, 1, 1, 4096, false, work)?);
        require(rows.next()?.is_none(), "source plan cardinality")?;
        let query = format!(
            "SELECT {},length FROM upgrade_objects NOT INDEXED ORDER BY cid",
            projection("cid", 59)
        );
        let mut stmt = conn.prepare(&query)?;
        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            work.charge(1, 8)?;
            out.membership
                .push((cid(row, 0, work)?, integer(row, 3, 1, MAX_OBJECT as i64)?));
        }
    }
    let query = format!(
        "SELECT sequence,{},{} FROM commits NOT INDEXED ORDER BY sequence",
        projection("manifest", 65536),
        projection("receipt", 65536)
    );
    let mut stmt = conn.prepare(&query)?;
    let mut rows = stmt.query([])?;
    let proof_query = format!(
        "SELECT sequence,{} FROM attestations NOT INDEXED ORDER BY sequence",
        projection("envelope", 16384)
    );
    let mut proofs = conn.prepare(&proof_query)?;
    let mut proof_rows = proofs.query([])?;
    loop {
        work.check()?;
        match (rows.next()?, proof_rows.next()?) {
            (None, None) => break,
            (Some(row), Some(proof)) => {
                work.charge(1, 16)?;
                let sequence = integer(row, 0, 1, MAX_SAFE)?;
                require(
                    sequence == out.records.len() as u64 + 1
                        && integer(proof, 0, 1, MAX_SAFE)? == sequence,
                    "source proof coordinates",
                )?;
                out.records.push(EncodedRow {
                    sequence,
                    manifest: cell(row, 1, 1, 65536, false, work)?,
                    receipt: cell(row, 4, 1, 65536, false, work)?,
                    proof: cell(proof, 1, 1, 16384, false, work)?,
                });
            }
            _ => return Err(Error::Invalid("source proof coordinates")),
        }
    }
    out.objects = objects(conn, "objects", 0, work)?;
    Ok(out)
}
fn map<const N: usize>(pairs: [(&str, Ipld); N]) -> Ipld {
    Ipld::Map(pairs.into_iter().map(|(k, v)| (k.into(), v)).collect())
}
pub(super) fn statement(
    context: &Context,
    previous: Option<&observation::Authenticated>,
    sampled_at: u64,
    event: &str,
    body: Ipld,
) -> Ipld {
    map([
        ("version", Ipld::Integer(1)),
        ("domain", Ipld::String(observation::DOMAIN.into())),
        ("bundle", Ipld::Bytes(context.bundle.to_vec())),
        ("profile", Ipld::Integer(context.profile.into())),
        ("archive", Ipld::Bytes(context.archive.to_vec())),
        ("scope", Ipld::Bytes(context.scope.to_vec())),
        ("issuer", Ipld::String(context.issuer.clone())),
        ("observer", Ipld::String(context.observer.clone())),
        (
            "sequence",
            Ipld::Integer(previous.map_or(1, |p| p.sequence() + 1).into()),
        ),
        (
            "previous",
            previous
                .map(|p| Ipld::Link(p.statement_cid().clone()))
                .unwrap_or(Ipld::Null),
        ),
        ("sampledAt", Ipld::Integer(sampled_at.into())),
        ("event", Ipld::String(event.into())),
        ("body", body),
    ])
}
pub(super) fn encode(value: &Ipld) -> Result<Vec<u8>> {
    atproto_dasl::to_vec(value).map_err(|_| Error::Invalid("observation encoding"))
}
fn loss(value: &member::Loss) -> Ipld {
    map([
        (
            "occurrence",
            value
                .occurrence
                .map(|n| Ipld::Integer(n.into()))
                .unwrap_or(Ipld::Null),
        ),
        ("cid", Ipld::Link(value.cid.clone())),
        (
            "expectedLength",
            value
                .expected_length
                .map(|n| Ipld::Integer(n.into()))
                .unwrap_or(Ipld::Null),
        ),
        (
            "state",
            Ipld::String(
                match value.state {
                    member::Availability::Missing => "missing",
                    member::Availability::Corrupt => "corrupt",
                    member::Availability::Available => {
                        unreachable!("verified losses exclude available")
                    }
                }
                .into(),
            ),
        ),
    ])
}
fn initial_history(
    data: &MemberBytes,
    selected: &Frontier,
    observer: &Identity,
    sampled_at: u64,
    work: &mut Work,
) -> Result<Vec<observation::Authenticated>> {
    require(observer.did() == data.context.observer, "observer pin")?;
    require(sampled_at <= MAX_SAFE as u64, "sample time")?;
    let member = data.with_input(|input| {
        member::verify(
            input,
            member::Budget {
                items: work.budget.replay_items,
                input_bytes: work.budget.replay_scan_bytes,
                duration: work.deadline.saturating_duration_since(Instant::now()),
                cancelled: work.budget.cancelled.clone(),
            },
        )
        .map_err(|e| Error::Replay(replay::Error::Member(e)))
    })?;
    require(member.frontier() == selected, "selected source frontier")?;
    let frontier = map([
        ("through", Ipld::Integer(selected.through.into())),
        (
            "manifest",
            selected
                .manifest
                .clone()
                .map(Ipld::Link)
                .unwrap_or(Ipld::Null),
        ),
        (
            "attestation",
            selected
                .attestation
                .clone()
                .map(Ipld::Link)
                .unwrap_or(Ipld::Null),
        ),
    ]);
    let created = statement(
        &data.context,
        None,
        sampled_at,
        "created",
        map([
            ("recipe", Ipld::Integer(1)),
            ("member", Ipld::Bytes(member.commitment().to_vec())),
            ("frontier", frontier),
        ]),
    );
    let bytes = encode(&created)?;
    work.charge(1, bytes.len())?;
    let mut history = vec![
        observation::sign_claim(&bytes, observer, &data.context, None)
            .map_err(|_| Error::Invalid("created observation"))?,
    ];
    let mut offset = 0;
    while offset < member.losses().len() {
        work.check()?;
        let mut entries: Vec<_> = member.losses()[offset..]
            .iter()
            .take(32)
            .map(loss)
            .collect();
        let bytes = loop {
            require(!entries.is_empty(), "unrepresentable loss")?;
            let value = statement(
                &data.context,
                history.last(),
                sampled_at,
                "unavailable",
                map([
                    ("member", Ipld::Bytes(member.commitment().to_vec())),
                    ("entries", Ipld::List(entries.clone())),
                ]),
            );
            let bytes = encode(&value)?;
            let envelope = encode(&map([
                ("statement", Ipld::Bytes(bytes.clone())),
                ("signature", Ipld::Bytes(vec![0; 64])),
            ]))?;
            if envelope.len() <= observation::MAX_ENVELOPE {
                break bytes;
            }
            entries.pop();
        };
        work.charge(1, bytes.len())?;
        let claim = observation::sign_claim(&bytes, observer, &data.context, history.last())
            .map_err(|_| Error::Invalid("unavailable observation"))?;
        history.push(claim);
        offset += entries.len();
    }
    let raw: Vec<_> = history
        .iter()
        .map(observation::Authenticated::bytes)
        .collect();
    data.with_input(|input| {
        replay::verify(
            input,
            &[],
            &raw,
            None,
            Limits {
                items: work.budget.replay_items,
                bytes: work.budget.replay_scan_bytes,
                duration: work.deadline.saturating_duration_since(Instant::now()),
                cancelled: work.budget.cancelled.clone(),
            },
        )
        .map_err(Error::Replay)
    })?;
    work.check()?;
    Ok(history)
}
pub(super) fn source_path(path: &Path, work: &Work) -> Result<PathBuf> {
    private_file(path)?;
    let source = std::fs::canonicalize(path)?;
    let mut existing: Vec<PathBuf> = vec![];
    let mut size = 0u64;
    for path in sqlite_paths(&source) {
        work.check()?;
        let metadata = match std::fs::symlink_metadata(&path) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && path != source => continue,
            Err(e) => return Err(e.into()),
        };
        private_file(&path)?;
        require(
            !existing.iter().any(|p| same_existing_file(p, &path)),
            "aliased source SQLite files",
        )?;
        size = size
            .checked_add(metadata.len())
            .ok_or(Error::Budget("source bytes"))?;
        if size > work.budget.source_bytes {
            return Err(Error::Budget("source bytes"));
        }
        existing.push(path);
    }
    Ok(source)
}
fn destination_path(source: &Path, destination: &Path) -> Result<PathBuf> {
    let target = super::super::sqlite_destination(source, destination)?;
    match std::fs::symlink_metadata(&target) {
        Ok(_) => Err(Error::Invalid("destination already exists")),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(target),
        Err(e) => Err(e.into()),
    }
}
/// A successful return follows durable commit, file/directory synchronization
/// and a fresh independent pinned inspection. Every failed reserved output is
/// retained; after COMMIT is attempted, errors report an uncertain outcome.
pub fn create(request: Creation<'_>) -> std::result::Result<Inspection, CreationError> {
    create_observed(request, &mut |_| {})
}
pub fn create_observed(
    request: Creation<'_>,
    observe: &mut dyn FnMut(CreationBoundary),
) -> std::result::Result<Inspection, CreationError> {
    let prepare = || -> Result<_> {
        require(
            request.observer.did() == request.context.observer,
            "observer pin",
        )?;
        require(request.sampled_at <= MAX_SAFE as u64, "sample time")?;
        require(matches!(request.context.profile, 2 | 3), "source profile")?;
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
        let source = source_path(request.source, &work)?;
        let destination = destination_path(&source, request.destination)?;
        // surface-write: evidence-bundle-source:database-wal,evidence-bundle-source:database-shm
        let conn = crate::persistence::open_sqlite_recovery_source(
            crate::persistence::SurfaceWrite::EvidenceBundleSource,
            &source,
        )?;
        conn.set_limit(
            rusqlite::limits::Limit::SQLITE_LIMIT_LENGTH,
            5 * 1024 * 1024,
        )?;
        conn.busy_timeout(request.budget.duration.min(Duration::from_millis(250)))?;
        let cancelled = request.budget.cancelled.clone();
        conn.progress_handler(
            1000,
            Some(move || cancelled.load(Ordering::Relaxed) || Instant::now() >= deadline),
        )?;
        conn.execute_batch("PRAGMA query_only=ON; PRAGMA trusted_schema=OFF; PRAGMA cache_size=-4096; PRAGMA mmap_size=0; BEGIN;")?;
        let data = acquire(&conn, request.context.clone(), &mut work);
        work.check()?;
        let data = data?;
        let history = initial_history(
            &data,
            &request.frontier,
            request.observer,
            request.sampled_at,
            &mut work,
        )?;
        // The read transaction pins the entire acquisition; all retained bytes
        // are now owned. Closing does not advance or repair the source.
        drop(conn);
        Ok((source, destination, data, history, work))
    };
    let (source, destination, data, history, work) = prepare()?;
    let last = history
        .last()
        .ok_or(Error::Invalid("empty created history"))?;
    let checkpoint = Checkpoint {
        context: request.context.clone(),
        sequence: last.sequence(),
        statement: last.statement_cid().clone(),
    };
    let mut commit_attempted = false;
    let result = (|| -> Result<Inspection> {
        work.check()?;
        source_path(&source, &work)?;
        destination_path(&source, &destination)?;
        // surface-write: evidence-bundle:database,evidence-bundle:database-journal
        crate::persistence::write_new_owner_only(
            crate::persistence::SurfaceWrite::EvidenceBundle,
            &destination,
            &[],
        )?;
        observe(CreationBoundary::Reserved);
        work.check()?;
        let mut conn =
            Connection::open_with_flags(&destination, rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE)?;
        conn.execute_batch("PRAGMA journal_mode=DELETE; PRAGMA page_size=4096; PRAGMA synchronous=FULL; PRAGMA fullfsync=ON; PRAGMA trusted_schema=OFF; PRAGMA cache_size=-4096; PRAGMA mmap_size=0;")?;
        conn.set_limit(
            rusqlite::limits::Limit::SQLITE_LIMIT_LENGTH,
            5 * 1024 * 1024,
        )?;
        let pages = request.output_bytes / 4096;
        let applied: i64 =
            conn.query_row(&format!("PRAGMA max_page_count={pages}"), [], |r| r.get(0))?;
        require(
            u64::try_from(applied).ok() == Some(pages),
            "output page limit",
        )?;
        let cancel = work.budget.cancelled.clone();
        let deadline = work.deadline;
        conn.progress_handler(
            1000,
            Some(move || cancel.load(Ordering::Relaxed) || Instant::now() >= deadline),
        )?;
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        tx.execute_batch(SCHEMA)?;
        tx.execute(
            "INSERT INTO bundle_identity VALUES(1,?1,?2,?3,?4,?5,?6)",
            rusqlite::params![
                data.context.bundle.as_slice(),
                data.context.observer,
                data.context.profile,
                data.context.archive.as_slice(),
                data.context.scope.as_slice(),
                data.context.issuer
            ],
        )?;
        if let Some(plan) = &data.plan {
            tx.execute("INSERT INTO member_plan VALUES(1,?1)", [plan])?;
        }
        for (cid, length) in &data.membership {
            work.check()?;
            tx.execute(
                "INSERT INTO member_membership VALUES(?1,?2)",
                rusqlite::params![cid.to_string(), sql_integer(*length)?],
            )?;
        }
        for r in &data.records {
            work.check()?;
            tx.execute(
                "INSERT INTO member_records VALUES(?1,?2,?3,?4)",
                rusqlite::params![sql_integer(r.sequence)?, r.manifest, r.receipt, r.proof],
            )?;
        }
        for (cid, bytes) in &data.objects {
            work.check()?;
            tx.execute(
                "INSERT INTO member_objects VALUES(?1,?2)",
                rusqlite::params![cid.to_string(), bytes],
            )?;
        }
        observe(CreationBoundary::MemberInserted);
        for h in &history {
            work.check()?;
            tx.execute(
                "INSERT INTO observations VALUES(?1,?2)",
                rusqlite::params![sql_integer(h.sequence())?, h.bytes()],
            )?;
        }
        observe(CreationBoundary::HistoryInserted);
        work.check()?;
        tx.execute_batch(&format!(
            "PRAGMA application_id={APPLICATION_ID}; PRAGMA user_version=1;"
        ))?;
        observe(CreationBoundary::MarkersSet);
        work.check()?;
        observe(CreationBoundary::BeforeCommit);
        work.check()?;
        commit_attempted = true;
        tx.commit()?;
        observe(CreationBoundary::AfterCommit);
        drop(conn);
        std::fs::File::open(&destination)?.sync_all()?;
        std::fs::File::open(super::super::parent_directory(&destination))?.sync_all()?;
        observe(CreationBoundary::Synced);
        work.check()?;
        let mut budget = request.budget.clone();
        budget.duration = work.deadline.saturating_duration_since(Instant::now());
        // Reopening must allow the explicitly selected output file size, not
        // silently reuse a possibly smaller source-file allowance.
        budget.source_bytes = request.output_bytes;
        let result = inspect(
            &destination,
            request.context.clone(),
            Some(&checkpoint),
            budget,
        )?;
        require(
            result.replay().latest() == &checkpoint,
            "created checkpoint",
        )?;
        observe(CreationBoundary::Reopened);
        Ok(result)
    })();
    result.map_err(|cause| {
        if commit_attempted {
            CreationError::Uncertain {
                path: destination,
                checkpoint: Box::new(checkpoint),
                cause: Box::new(cause),
            }
        } else {
            CreationError::Refused(cause)
        }
    })
}
