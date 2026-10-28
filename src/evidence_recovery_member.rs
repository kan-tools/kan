//! Pure logical-member audit over caller-acquired bounded bytes.
//! No file, publication, observation-history or durability authority is conferred.
//! Callers must acquire immutable bounded slices and reject noncanonical physical
//! CID spellings before constructing typed CIDs; this API cannot inspect spelling.
use crate::{
    evidence::{self, Decoded, Kind, Record},
    evidence_attestation::{self as proof, Frontier, Purpose},
    evidence_copy_plan::Plan,
    evidence_recovery_commitment::{Counts, Domain, Header, Limits, MemberFraming},
    evidence_recovery_observation::Context,
    evidence_service as service,
    evidence_store::Committed,
};
use atproto_dasl::{Cid, Ipld};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
const MAX_OBJECT: usize = 4 * 1024 * 1024;
type Result<T> = std::result::Result<T, Error>;
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("invalid recovery member: {0}")]
    Invalid(&'static str),
    #[error("recovery member budget exhausted")]
    Budget,
    #[error("recovery member verification cancelled")]
    Cancelled,
}
fn framing_error(error: crate::evidence_recovery_commitment::Error) -> Error {
    use crate::evidence_recovery_commitment::Error as E;
    match error {
        E::Cancelled => Error::Cancelled,
        E::Budget => Error::Budget,
        E::Shape(_) | E::Poisoned => Error::Invalid("member framing"),
    }
}
fn require(ok: bool, reason: &'static str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(Error::Invalid(reason))
    }
}
#[derive(Clone)]
pub struct Budget {
    /// Sum of supplied record, membership and original-object rows.
    pub items: u64,
    /// Sum of input metadata/plan/payload bytes and canonical membership keys + lengths.
    /// Bounds retained metadata indirectly; this is not a measured RSS ceiling.
    pub input_bytes: u64,
    pub duration: Duration,
    pub cancelled: Arc<AtomicBool>,
}
#[derive(Clone, Copy)]
pub struct Row<'a> {
    pub sequence: u64,
    pub manifest: &'a [u8],
    pub receipt: &'a [u8],
    pub proof: &'a [u8],
}
#[derive(Clone, Copy)]
pub struct Object<'a> {
    pub cid: &'a Cid,
    pub bytes: &'a [u8],
}
#[derive(Clone, Copy)]
pub struct Membership<'a> {
    pub cid: &'a Cid,
    pub length: u64,
}
#[derive(Clone, Copy)]
pub struct Input<'a> {
    pub context: &'a Context,
    pub plan: Option<&'a [u8]>,
    pub membership: &'a [Membership<'a>],
    pub records: &'a [Row<'a>],
    pub objects: &'a [Object<'a>],
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Availability {
    Available,
    Missing,
    Corrupt,
}
/// Why a loss coordinate exists. This is recomputed from the immutable member,
/// never supplied by the observer as an independent claim of authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Basis {
    IssuerMetadata,
    VerifiedCopyRecipe,
    UnverifiedMembership,
    OriginalObject,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Loss {
    pub occurrence: Option<u64>,
    pub cid: Cid,
    pub expected_length: Option<u64>,
    pub state: Availability,
    pub basis: Basis,
}
/// Verified issuer metadata and sampled originals. Unavailable writer requests
/// remain unverified. This result is NOT an authenticated recovery history.
pub struct Member {
    context: Context,
    commitment: [u8; 32],
    frontier: Frontier,
    recipe_metadata_complete: bool,
    losses: Vec<Loss>,
    verified_requests: u64,
}
impl Member {
    pub fn context(&self) -> &Context {
        &self.context
    }
    pub fn commitment(&self) -> &[u8; 32] {
        &self.commitment
    }
    pub fn frontier(&self) -> &Frontier {
        &self.frontier
    }
    pub fn recipe_metadata_complete(&self) -> bool {
        self.recipe_metadata_complete
    }
    pub fn losses(&self) -> &[Loss] {
        &self.losses
    }
    pub fn verified_requests(&self) -> u64 {
        self.verified_requests
    }
}
struct Work {
    budget: Budget,
    deadline: Instant,
    bytes: u64,
}
impl Work {
    fn new(budget: Budget, items: usize) -> Result<Self> {
        require(
            !budget.duration.is_zero() && budget.duration <= Duration::from_secs(3600),
            "duration",
        )?;
        if u64::try_from(items).map_err(|_| Error::Budget)? > budget.items {
            return Err(Error::Budget);
        }
        let deadline = Instant::now()
            .checked_add(budget.duration)
            .ok_or(Error::Budget)?;
        let s = Self {
            budget,
            deadline,
            bytes: 0,
        };
        s.check()?;
        Ok(s)
    }
    fn check(&self) -> Result<()> {
        if self.budget.cancelled.load(Ordering::Relaxed) {
            return Err(Error::Cancelled);
        }
        if Instant::now() >= self.deadline {
            return Err(Error::Budget);
        }
        Ok(())
    }
    fn input(&mut self, size: usize) -> Result<()> {
        self.check()?;
        self.bytes = self.bytes.checked_add(size as u64).ok_or(Error::Budget)?;
        if self.bytes > self.budget.input_bytes {
            return Err(Error::Budget);
        }
        Ok(())
    }
    fn hash(&self, hash: &mut Sha256, bytes: &[u8]) -> Result<()> {
        for part in bytes.chunks(65536) {
            self.check()?;
            hash.update(part)
        }
        Ok(())
    }
    fn frame(&self, hash: &mut Sha256, bytes: &[u8]) -> Result<()> {
        hash.update((bytes.len() as u64).to_be_bytes());
        self.hash(hash, bytes)
    }
}
fn key(cid: &Cid) -> Result<String> {
    let b = cid.to_bytes();
    require(b.len() == 36 && b[..4] == [1, 0x55, 0x12, 0x20], "raw CID")?;
    Ok(cid.to_string())
}
fn ordered(last: &mut Option<String>, next: &str) -> Result<()> {
    require(
        last.as_ref().is_none_or(|x| x.as_str() < next),
        "CID order or duplicate",
    )?;
    *last = Some(next.into());
    Ok(())
}
fn known(bytes: &[u8], kind: Kind) -> Result<Record> {
    match evidence::decode(bytes).map_err(|_| Error::Invalid("metadata codec"))? {
        Decoded::Known(r) if r.kind() == kind => Ok(r),
        _ => Err(Error::Invalid("metadata profile")),
    }
}
struct Coordinate {
    cid: Cid,
    length: Option<u64>,
    referenced: bool,
    member: bool,
    original: Option<usize>,
    state: Availability,
}
fn length(c: &mut Coordinate, n: u64) -> Result<()> {
    require(
        (1..=MAX_OBJECT as u64).contains(&n),
        "forensic-recovery-required",
    )?;
    require(
        c.length.is_none_or(|old| old == n),
        "conflicting expected lengths",
    )?;
    c.length = Some(n);
    Ok(())
}
fn coordinate(cid: &Cid) -> Coordinate {
    Coordinate {
        cid: cid.clone(),
        length: None,
        referenced: false,
        member: false,
        original: None,
        state: Availability::Missing,
    }
}
fn did(s: &str) -> Result<()> {
    require(
        (56..=80).contains(&s.len()) && s.is_ascii() && s.starts_with("did:key:z"),
        "issuer encoding",
    )?;
    let (a, k) = atrium_crypto::did::parse_did_key(s).map_err(|_| Error::Invalid("issuer key"))?;
    require(
        a == atrium_crypto::Algorithm::P256
            && atrium_crypto::did::format_did_key(a, &k)
                .map_err(|_| Error::Invalid("issuer point"))?
                == s,
        "issuer key",
    )
}

pub fn verify(input: Input<'_>, budget: Budget) -> Result<Member> {
    let ctx = input.context;
    require(matches!(ctx.profile, 2 | 3), "profile")?;
    did(&ctx.issuer)?;
    did(&ctx.observer)?;
    let count = input
        .records
        .len()
        .checked_add(input.membership.len())
        .and_then(|n| n.checked_add(input.objects.len()))
        .ok_or(Error::Budget)?;
    let mut work = Work::new(budget, count)?;
    let plan = match (ctx.profile, input.plan) {
        (2, None) => {
            require(input.membership.is_empty(), "profile2 membership")?;
            None
        }
        (3, Some(bytes)) => {
            work.input(bytes.len())?;
            let p = Plan::decode(bytes).map_err(|_| Error::Invalid("plan"))?;
            require(
                p.archive_id() == ctx.archive
                    && p.target().scope == ctx.scope
                    && p.target().issuer == ctx.issuer,
                "plan binding",
            )?;
            Some(p)
        }
        _ => return Err(Error::Invalid("profile plan")),
    };
    let mut keys = BTreeMap::<String, Coordinate>::new();
    let mut last = None;
    for m in input.membership {
        work.input(44)?;
        let k = key(m.cid)?;
        ordered(&mut last, &k)?;
        let mut c = coordinate(m.cid);
        length(&mut c, m.length)?;
        c.member = true;
        keys.insert(k, c);
    }
    let mut frontier = Frontier::default();
    let mut references = Vec::new();
    let mut writers = BTreeMap::<String, (u64, Cid)>::new();
    let mut operations = BTreeSet::new();
    let mut slots = BTreeMap::new();
    let mut source = Sha256::new();
    source.update(b"tools.kan.archive.copy-source.v1\0");
    work.frame(&mut source, b"commits")?;
    if let Some(p) = &plan {
        source.update(p.source().through.to_be_bytes())
    }
    for row in input.records {
        for (bytes, max) in [
            (row.manifest, 65536),
            (row.receipt, 65536),
            (row.proof, 16384),
        ] {
            require(!bytes.is_empty() && bytes.len() <= max, "metadata bounds")?;
            work.input(bytes.len())?;
        }
        require(row.sequence == frontier.through + 1, "record position")?;
        let m = known(row.manifest, Kind::Manifest)?;
        let r = known(row.receipt, Kind::Receipt)?;
        let p = proof::verify(
            row.proof,
            &proof::Context {
                issuer: &ctx.issuer,
                archive: ctx.archive,
                scope: ctx.scope,
            },
            &m,
            &r,
            &frontier,
        )
        .map_err(|_| Error::Invalid("issuer proof"))?;
        let retained = plan
            .as_ref()
            .is_some_and(|p| row.sequence <= p.source().through);
        require(
            p.purpose()
                == if retained {
                    Purpose::RetainedVerified
                } else {
                    Purpose::Admitted
                },
            "proof purpose",
        )?;
        if retained {
            let author = service::author(
                &plan
                    .as_ref()
                    .expect("retained plan")
                    .source()
                    .historical_issuer,
            )
            .map_err(|_| Error::Invalid("historical issuer"))?;
            require(r.body()["issuer"] == author, "historical receipt issuer")?;
        }
        let b = m.body();
        let wb = evidence::closed(
            &b["writer"],
            &["principal", "verificationMethod", "identityVersion"],
        )
        .map_err(|_| Error::Invalid("writer"))?;
        let writer =
            evidence::string(&wb["principal"], 80).map_err(|_| Error::Invalid("writer"))?;
        require(
            service::author(writer).map_err(|_| Error::Invalid("static writer"))? == b["writer"],
            "static writer",
        )?;
        let pos =
            evidence::uint(&b["position"]).map_err(|_| Error::Invalid("writer position"))? as u64;
        let expected = writers.get(writer);
        require(
            match expected {
                None => pos == 0 && b["previous"] == Ipld::Null,
                Some((old, cid)) => pos == old + 1 && b["previous"] == Ipld::Link(cid.clone()),
            },
            "writer predecessor",
        )?;
        let op = evidence::bytes(&b["operation"], 16).map_err(|_| Error::Invalid("operation"))?;
        require(
            operations.insert((writer.to_string(), op.to_vec())),
            "duplicate operation",
        )?;
        let Ipld::List(es) = &b["entries"] else {
            return Err(Error::Invalid("entries"));
        };
        require(es.len() == 1, "service request entry")?;
        let e = evidence::closed(&es[0], &["slot", "ciphertext", "length"])
            .map_err(|_| Error::Invalid("entry"))?;
        let cid =
            evidence::link(&e["ciphertext"], 0x55).map_err(|_| Error::Invalid("entry CID"))?;
        require(
            cid != &crate::evidence_store::ciphertext_cid(b""),
            "empty service request CID",
        )?;
        let n = evidence::uint(&e["length"]).map_err(|_| Error::Invalid("entry length"))? as u64;
        let k = key(cid)?;
        let c = keys.entry(k.clone()).or_insert_with(|| coordinate(cid));
        length(c, n)?;
        require(n <= service::MAX_REQUEST as u64, "service request length")?;
        require(!c.referenced, "reused service request CID")?;
        c.referenced = true;
        if retained {
            require(c.member, "retained reference absent from membership")?
        }
        let slot = evidence::bytes(&e["slot"], 32)
            .map_err(|_| Error::Invalid("slot"))?
            .to_vec();
        let expected_slot: [u8; 32] = Sha256::digest(op).into();
        require(slot.as_slice() == expected_slot, "service slot")?;
        let sk = (writer.to_string(), slot);
        let sv = (k.clone(), n);
        require(
            slots.get(&sk).is_none_or(|old| old == &sv),
            "conflicting slot binding",
        )?;
        slots.insert(sk, sv);
        if retained {
            source.update(row.sequence.to_be_bytes());
            work.frame(&mut source, row.manifest)?;
            work.frame(&mut source, row.receipt)?;
            work.frame(&mut source, &cid.to_bytes())?;
            let plan = plan.as_ref().expect("retained plan");
            if row.sequence == plan.source().through {
                require(plan.source().tip.as_ref() == Some(m.cid()), "source tip")?
            }
        }
        writers.insert(writer.to_string(), (pos, m.cid().clone()));
        references.push((row.sequence, k));
        frontier = p.frontier().clone();
        work.check()?;
    }
    let recipe_metadata_complete = if let Some(p) = &plan {
        work.frame(&mut source, b"objects")?;
        source.update((input.membership.len() as u64).to_be_bytes());
        for m in input.membership {
            work.check()?;
            work.frame(&mut source, &m.cid.to_bytes())?;
            source.update(m.length.to_be_bytes())
        }
        let digest: [u8; 32] = source.finalize().into();
        let full = frontier.through >= p.source().through;
        if full {
            require(digest == p.source().digest, "source metadata digest")?
        }
        full
    } else {
        true
    };
    if !recipe_metadata_complete {
        for c in keys.values_mut() {
            work.check()?;
            if !c.referenced {
                // Preserve the claimed length in M1, but do not let an
                // unauthenticated membership row classify or constrain bytes.
                c.length = None;
            }
        }
    }
    last = None;
    for (index, object) in input.objects.iter().enumerate() {
        require(
            object.bytes.len() <= MAX_OBJECT,
            "forensic-recovery-required",
        )?;
        work.input(object.bytes.len())?;
        let k = key(object.cid)?;
        ordered(&mut last, &k)?;
        let c = keys.entry(k).or_insert_with(|| coordinate(object.cid));
        if !recipe_metadata_complete {
            require(c.member, "untracked object in partial copy")?
        }
        c.original = Some(index);
        let mut hash = Sha256::new();
        work.hash(&mut hash, object.bytes)?;
        let actual: [u8; 32] = hash.finalize().into();
        let hash_valid = actual == object.cid.to_bytes()[4..];
        require(
            !hash_valid || c.length.is_none_or(|n| n == object.bytes.len() as u64),
            "hash-valid bytes contradict authenticated length",
        )?;
        let valid = !object.bytes.is_empty() && hash_valid;
        c.state = if valid {
            Availability::Available
        } else {
            Availability::Corrupt
        };
    }
    let mut losses = Vec::new();
    let mut verified_requests = 0;
    for ((sequence, k), row) in references.iter().zip(input.records) {
        work.check()?;
        let c = &keys[k];
        if c.state == Availability::Available {
            let committed = Committed {
                sequence: *sequence,
                manifest: known(row.manifest, Kind::Manifest)?,
                receipt: known(row.receipt, Kind::Receipt)?,
                duplicate: false,
            };
            service::verify_retained_request(
                &committed,
                input.objects[c.original.expect("available original")].bytes,
            )
            .map_err(|_| Error::Invalid("retained writer request"))?;
            verified_requests += 1;
        } else {
            losses.push(Loss {
                occurrence: Some(*sequence),
                cid: c.cid.clone(),
                expected_length: c.length,
                state: c.state,
                basis: Basis::IssuerMetadata,
            })
        }
    }
    for c in keys.values() {
        work.check()?;
        if !c.referenced && c.state != Availability::Available {
            losses.push(Loss {
                occurrence: None,
                cid: c.cid.clone(),
                expected_length: c.length,
                state: c.state,
                basis: if !c.member {
                    Basis::OriginalObject
                } else if recipe_metadata_complete {
                    Basis::VerifiedCopyRecipe
                } else {
                    Basis::UnverifiedMembership
                },
            })
        }
    }
    work.check()?;
    let framing_bytes = work
        .bytes
        .checked_mul(4)
        .and_then(|n| n.checked_add((count as u64).checked_mul(128)?))
        .and_then(|n| n.checked_add(1024))
        .ok_or(Error::Budget)?;
    let limits = Limits {
        items: count as u64,
        bytes: framing_bytes,
        duration: work.deadline.saturating_duration_since(Instant::now()),
        cancelled: work.budget.cancelled.clone(),
    };
    if limits.duration.is_zero() {
        return Err(Error::Budget);
    }
    let mut framing = MemberFraming::new(
        Header {
            profile: ctx.profile,
            archive: ctx.archive,
            scope: ctx.scope,
            issuer: &ctx.issuer,
            plan: input.plan,
        },
        Counts {
            membership: input.membership.len() as u64,
            records: input.records.len() as u64,
            objects: input.objects.len() as u64,
        },
        Domain::Member,
        limits,
    )
    .map_err(framing_error)?;
    for m in input.membership {
        framing.membership(m.cid, m.length).map_err(framing_error)?
    }
    framing.begin_records().map_err(framing_error)?;
    for r in input.records {
        framing
            .record(r.sequence, r.manifest, r.receipt, r.proof)
            .map_err(framing_error)?
    }
    framing.begin_objects().map_err(framing_error)?;
    for o in input.objects {
        framing
            .original_object(o.cid, o.bytes)
            .map_err(framing_error)?
    }
    let commitment = framing.finish().map_err(framing_error)?;
    work.check()?;
    Ok(Member {
        context: ctx.clone(),
        commitment,
        frontier,
        recipe_metadata_complete,
        losses,
        verified_requests,
    })
}
