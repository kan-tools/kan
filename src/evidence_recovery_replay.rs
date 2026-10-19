//! Pure recovery-history replay. Verified claims are not a current output file,
//! durable mutation acknowledgment, standalone schema or writer activation.
use crate::{
    evidence::{self, Decoded},
    evidence_recovery_commitment::{
        self as commitment, Counts, Domain, Header, Limits, MemberFraming, RestorationFraming,
    },
    evidence_recovery_member::{self as member, Availability, Input, Member, Object},
    evidence_recovery_observation::{self as observation, Authenticated, Context},
};
use atproto_dasl::{Cid, Ipld};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    sync::atomic::Ordering,
    time::{Duration, Instant},
};
type Result<T> = std::result::Result<T, Error>;
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("invalid recovery history: {0}")]
    Invalid(&'static str),
    #[error("recovery replay budget exhausted")]
    Budget,
    #[error("recovery replay cancelled")]
    Cancelled,
    #[error("invalid recovery member: {0}")]
    Member(#[from] member::Error),
}
fn require(ok: bool, reason: &'static str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(Error::Invalid(reason))
    }
}
fn member_error(e: member::Error) -> Error {
    match e {
        member::Error::Budget => Error::Budget,
        member::Error::Cancelled => Error::Cancelled,
        e => Error::Member(e),
    }
}
fn commitment_error(e: commitment::Error) -> Error {
    match e {
        commitment::Error::Budget => Error::Budget,
        commitment::Error::Cancelled => Error::Cancelled,
        _ => Error::Invalid("commitment framing"),
    }
}
/// Supply only from owner configuration retained independently of this bundle.
/// None at verify means no externally checkpointed rollback protection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Checkpoint {
    pub context: Context,
    pub sequence: u64,
    pub statement: Cid,
}
#[derive(Clone, Debug)]
pub struct Attempt {
    pub id: [u8; 16],
    pub intent: Cid,
    pub output: [u8; 32],
    pub restorations: [u8; 32],
    pub failure_count: u64,
    /// The observer's attributed claim; not proof of current physical output.
    pub observed_at_sequence: Option<u64>,
}
pub struct Replay {
    member: Member,
    checkpoint: Checkpoint,
    external: Option<Checkpoint>,
    restored: u64,
    attempts: Vec<Attempt>,
}
impl Replay {
    pub fn member(&self) -> &Member {
        &self.member
    }
    pub fn latest(&self) -> &Checkpoint {
        &self.checkpoint
    }
    pub fn external(&self) -> Option<&Checkpoint> {
        self.external.as_ref()
    }
    pub fn restored(&self) -> u64 {
        self.restored
    }
    pub fn attempts(&self) -> &[Attempt] {
        &self.attempts
    }
}
struct Work {
    limits: Limits,
    deadline: Instant,
    items: u64,
    bytes: u64,
}
impl Work {
    fn new(limits: Limits) -> Result<Self> {
        require(
            !limits.duration.is_zero() && limits.duration <= Duration::from_secs(3600),
            "duration",
        )?;
        let deadline = Instant::now()
            .checked_add(limits.duration)
            .ok_or(Error::Budget)?;
        let s = Self {
            limits,
            deadline,
            items: 0,
            bytes: 0,
        };
        s.check()?;
        Ok(s)
    }
    fn check(&self) -> Result<()> {
        if self.limits.cancelled.load(Ordering::Relaxed) {
            return Err(Error::Cancelled);
        }
        if Instant::now() >= self.deadline {
            return Err(Error::Budget);
        }
        Ok(())
    }
    fn charge(&mut self, items: u64, bytes: u64) -> Result<()> {
        self.check()?;
        self.items = self.items.checked_add(items).ok_or(Error::Budget)?;
        self.bytes = self.bytes.checked_add(bytes).ok_or(Error::Budget)?;
        if self.items > self.limits.items || self.bytes > self.limits.bytes {
            return Err(Error::Budget);
        }
        Ok(())
    }
    fn remaining(&self) -> Result<Duration> {
        self.check()?;
        let d = self.deadline.saturating_duration_since(Instant::now());
        if d.is_zero() {
            Err(Error::Budget)
        } else {
            Ok(d)
        }
    }
    fn hash(&self, bytes: &[u8]) -> Result<[u8; 32]> {
        let mut h = Sha256::new();
        for part in bytes.chunks(65536) {
            self.check()?;
            h.update(part)
        }
        Ok(h.finalize().into())
    }
    fn framing_limits(&self, items: u64, input_bytes: u64) -> Result<Limits> {
        // Framing overhead is bounded by each local field/item ceiling. Scan
        // accounting counts encoded inputs; the framing layer counts hash work.
        let bytes = input_bytes
            .checked_mul(4)
            .and_then(|n| n.checked_add(items.checked_mul(128)?))
            .and_then(|n| n.checked_add(1024))
            .ok_or(Error::Budget)?;
        Ok(Limits {
            items,
            bytes,
            duration: self.remaining()?,
            cancelled: self.limits.cancelled.clone(),
        })
    }
}
fn map<const N: usize>(fields: [(&str, Ipld); N]) -> Ipld {
    Ipld::Map(fields.into_iter().map(|(k, v)| (k.into(), v)).collect())
}
fn fields(v: &Ipld) -> Result<&BTreeMap<String, Ipld>> {
    match v {
        Ipld::Map(m) => Ok(m),
        _ => Err(Error::Invalid("map")),
    }
}
fn bytes<const N: usize>(v: &Ipld) -> Result<[u8; N]> {
    match v {
        Ipld::Bytes(b) => b
            .as_slice()
            .try_into()
            .map_err(|_| Error::Invalid("byte width")),
        _ => Err(Error::Invalid("bytes")),
    }
}
fn link(v: &Ipld) -> Result<&Cid> {
    match v {
        Ipld::Link(c) => Ok(c),
        _ => Err(Error::Invalid("link")),
    }
}
fn integer(v: &Ipld) -> Result<u64> {
    evidence::uint(v)
        .map(|n| n as u64)
        .map_err(|_| Error::Invalid("integer"))
}
fn frontier(m: &Member) -> Ipld {
    let f = m.frontier();
    map([
        ("through", Ipld::Integer(f.through.into())),
        (
            "manifest",
            f.manifest.clone().map(Ipld::Link).unwrap_or(Ipld::Null),
        ),
        (
            "attestation",
            f.attestation.clone().map(Ipld::Link).unwrap_or(Ipld::Null),
        ),
    ])
}
fn loss(l: &member::Loss) -> Ipld {
    map([
        (
            "occurrence",
            l.occurrence
                .map(|n| Ipld::Integer(n.into()))
                .unwrap_or(Ipld::Null),
        ),
        ("cid", Ipld::Link(l.cid.clone())),
        (
            "expectedLength",
            l.expected_length
                .map(|n| Ipld::Integer(n.into()))
                .unwrap_or(Ipld::Null),
        ),
        (
            "state",
            Ipld::String(
                match l.state {
                    Availability::Missing => "missing",
                    Availability::Corrupt => "corrupt",
                    Availability::Available => unreachable!("member losses exclude available"),
                }
                .into(),
            ),
        ),
    ])
}
/// Charge acquisition-sized passes; does not acquire or duplicate payloads.
fn input_cost(input: Input<'_>, work: &mut Work) -> Result<(u64, u64)> {
    let n = input
        .records
        .len()
        .checked_add(input.membership.len())
        .and_then(|n| n.checked_add(input.objects.len()))
        .ok_or(Error::Budget)? as u64;
    work.charge(n, 0)?;
    let before = work.bytes;
    if let Some(p) = input.plan {
        work.charge(0, p.len() as u64)?
    }
    for r in input.records {
        for b in [r.manifest, r.receipt, r.proof] {
            work.charge(0, b.len() as u64)?
        }
    }
    for _ in input.membership {
        work.charge(0, 44)?
    }
    for o in input.objects {
        work.charge(0, o.bytes.len() as u64)?
    }
    Ok((n, work.bytes - before))
}
fn audit(input: Input<'_>, work: &mut Work) -> Result<Member> {
    let (items, size) = input_cost(input, work)?;
    // The member audit also computes M1 over the same input collection.
    work.charge(0, size)?;
    let m = member::verify(
        input,
        member::Budget {
            items,
            input_bytes: size,
            duration: work.remaining()?,
            cancelled: work.limits.cancelled.clone(),
        },
    )
    .map_err(member_error)?;
    work.check()?;
    Ok(m)
}
struct Key<'a> {
    cid: Cid,
    length: Option<u64>,
    original: Option<&'a [u8]>,
}
fn keys<'a>(input: Input<'a>, work: &Work) -> Result<BTreeMap<String, Key<'a>>> {
    let mut out = BTreeMap::new();
    for m in input.membership {
        work.check()?;
        out.insert(
            m.cid.to_string(),
            Key {
                cid: m.cid.clone(),
                length: Some(m.length),
                original: None,
            },
        );
    }
    for row in input.records {
        work.check()?;
        let Decoded::Known(record) =
            evidence::decode(row.manifest).map_err(|_| Error::Invalid("member changed"))?
        else {
            return Err(Error::Invalid("member changed"));
        };
        let Ipld::List(es) = &record.body()["entries"] else {
            return Err(Error::Invalid("member entries"));
        };
        let e = fields(es.first().ok_or(Error::Invalid("member entries"))?)?;
        let cid = link(&e["ciphertext"])?;
        let length = integer(&e["length"])?;
        out.entry(cid.to_string()).or_insert_with(|| Key {
            cid: cid.clone(),
            length: Some(length),
            original: None,
        });
    }
    for o in input.objects {
        work.check()?;
        out.entry(o.cid.to_string())
            .or_insert_with(|| Key {
                cid: o.cid.clone(),
                length: None,
                original: None,
            })
            .original = Some(o.bytes);
    }
    Ok(out)
}
fn expected_partition(auth: &Authenticated, losses: &[member::Loss]) -> Result<Vec<Ipld>> {
    let mut entries: Vec<_> = losses.iter().take(32).map(loss).collect();
    while !entries.is_empty() {
        let mut st = auth.statement().clone();
        let Ipld::Map(s) = &mut st else {
            unreachable!()
        };
        let Ipld::Map(body) = s.get_mut("body").expect("authenticated body") else {
            unreachable!()
        };
        body.insert("entries".into(), Ipld::List(entries.clone()));
        let raw = atproto_dasl::to_vec(&st).map_err(|_| Error::Invalid("partition encoding"))?;
        let envelope = atproto_dasl::to_vec(&map([
            ("statement", Ipld::Bytes(raw)),
            ("signature", Ipld::Bytes(vec![0; 64])),
        ]))
        .map_err(|_| Error::Invalid("partition encoding"))?;
        if envelope.len() <= observation::MAX_ENVELOPE {
            return Ok(entries);
        }
        entries.pop();
    }
    Err(Error::Invalid("unrepresentable loss"))
}
fn output_commitments<'a>(
    input: Input<'a>,
    original: &Member,
    keys: &BTreeMap<String, Key<'a>>,
    selected: &BTreeMap<String, &'a [u8]>,
    work: &mut Work,
) -> Result<([u8; 32], [u8; 32])> {
    require(
        original.recipe_metadata_complete(),
        "partial copy publication",
    )?;
    let mut selected_bytes = 0u64;
    for b in selected.values() {
        work.check()?;
        selected_bytes = selected_bytes
            .checked_add(b.len() as u64)
            .ok_or(Error::Budget)?
    }
    // R1 re-verifies candidates and hashes them into its commitment.
    work.charge(
        selected.len() as u64,
        selected_bytes.checked_mul(2).ok_or(Error::Budget)?,
    )?;
    let mut r = RestorationFraming::new(
        selected.len() as u64,
        work.framing_limits(selected.len() as u64, selected_bytes)?,
    )
    .map_err(commitment_error)?;
    for (k, b) in selected {
        r.candidate(&keys[k].cid, b).map_err(commitment_error)?
    }
    let r1 = r.finish().map_err(commitment_error)?;
    let mut objects = Vec::with_capacity(keys.len());
    for (name, k) in keys {
        work.check()?;
        let data = selected
            .get(name)
            .copied()
            .or(k.original)
            .ok_or(Error::Invalid("publication-blocked-unavailable-object"))?;
        objects.push(Object {
            cid: &k.cid,
            bytes: data,
        });
    }
    let virtual_input = Input {
        objects: &objects,
        ..input
    };
    let output = audit(virtual_input, work).map_err(|error| match error {
        Error::Member(_) => Error::Invalid("output member validation"),
        error => error,
    })?;
    require(
        output.losses().is_empty(),
        "publication-blocked-unavailable-object",
    )?;
    require(
        output.recipe_metadata_complete()
            && output.frontier() == original.frontier()
            && output.verified_requests() == original.frontier().through,
        "incomplete output",
    )?;
    let (items, size) = input_cost(virtual_input, work)?;
    let mut o = MemberFraming::new(
        Header {
            profile: input.context.profile,
            archive: input.context.archive,
            scope: input.context.scope,
            issuer: &input.context.issuer,
            plan: input.plan,
        },
        Counts {
            membership: input.membership.len() as u64,
            records: input.records.len() as u64,
            objects: objects.len() as u64,
        },
        Domain::Output,
        work.framing_limits(items, size)?,
    )
    .map_err(commitment_error)?;
    for m in input.membership {
        o.membership(m.cid, m.length).map_err(commitment_error)?
    }
    o.begin_records().map_err(commitment_error)?;
    for r in input.records {
        o.record(r.sequence, r.manifest, r.receipt, r.proof)
            .map_err(commitment_error)?
    }
    o.begin_objects().map_err(commitment_error)?;
    for b in objects {
        o.original_object(b.cid, b.bytes)
            .map_err(commitment_error)?
    }
    let o1 = o.finish().map_err(commitment_error)?;
    work.check()?;
    Ok((r1, o1))
}

/// Verify all supplied history, not just through the owner's selected checkpoint.
/// bytes counts encoded-input scan passes as documented in the codec design.
pub fn verify<'a>(
    input: Input<'a>,
    candidates: &'a [Object<'a>],
    observations: &[&[u8]],
    external: Option<&Checkpoint>,
    limits: Limits,
) -> Result<Replay> {
    let mut work = Work::new(limits)?;
    require(!observations.is_empty(), "missing observation history")?;
    if let Some(p) = external {
        require(
            p.context == *input.context
                && p.sequence > 0
                && p.sequence <= evidence::MAX_SAFE_INTEGER as u64,
            "external checkpoint context",
        )?
    }
    let original = audit(input, &mut work)?;
    let expected_frontier = frontier(&original);
    let keys = keys(input, &work)?;
    work.charge(candidates.len() as u64, 0)?;
    let mut physical = BTreeMap::new();
    let mut last: Option<String> = None;
    for c in candidates {
        work.charge(0, c.bytes.len() as u64)?;
        require(
            !c.bytes.is_empty() && c.bytes.len() <= 4 * 1024 * 1024,
            "candidate bounds",
        )?;
        let raw = c.cid.to_bytes();
        require(
            raw.len() == 36 && raw[..4] == [1, 0x55, 0x12, 0x20],
            "candidate CID",
        )?;
        let name = c.cid.to_string();
        require(
            last.as_ref().is_none_or(|old| old < &name),
            "candidate order or duplicate",
        )?;
        last = Some(name.clone());
        let target = keys
            .get(&name)
            .ok_or(Error::Invalid("candidate outside member"))?;
        require(
            target.length.is_none_or(|n| n == c.bytes.len() as u64),
            "candidate expected length",
        )?;
        require(work.hash(c.bytes)? == raw[4..], "candidate hash")?;
        physical.insert(name, c.bytes);
    }
    let mut previous: Option<Authenticated> = None;
    let mut loss_offset = 0;
    let mut selected = BTreeMap::new();
    let mut attempts = BTreeMap::<[u8; 16], Attempt>::new();
    let mut cached: Option<([u8; 32], [u8; 32])> = None;
    let mut checkpoint_seen = external.is_none();
    for raw in observations {
        work.charge(1, raw.len() as u64)?;
        let auth = observation::authenticate(raw, input.context, previous.as_ref())
            .map_err(|_| Error::Invalid("observation authentication"))?;
        let st = fields(auth.statement())?;
        let b = fields(&st["body"])?;
        let Ipld::String(event) = &st["event"] else {
            unreachable!()
        };
        if let Some(value) = b.get("member") {
            require(
                bytes::<32>(value)? == *original.commitment(),
                "member commitment",
            )?
        }
        if let Some(value) = b.get("frontier") {
            require(value == &expected_frontier, "metadata frontier")?
        }
        if auth.sequence() == 1 {
            require(event == "created", "created position")?
        } else if loss_offset < original.losses().len() {
            require(event == "unavailable", "initial loss incomplete")?;
            let expected = expected_partition(&auth, &original.losses()[loss_offset..])?;
            require(
                b["entries"] == Ipld::List(expected.clone()),
                "initial loss partition",
            )?;
            loss_offset += expected.len();
        } else {
            match event.as_str() {
                "unavailable" => return Err(Error::Invalid("late unavailable")),
                "restored" => {
                    let name = link(&b["cid"])?.to_string();
                    let data = physical
                        .get(&name)
                        .ok_or(Error::Invalid("restoration without candidate"))?;
                    require(
                        integer(&b["length"])? == data.len() as u64,
                        "restoration length",
                    )?;
                    require(!selected.contains_key(&name), "duplicate restoration")?;
                    selected.insert(name, *data);
                    cached = None;
                }
                "publication-intent" => {
                    let id = bytes::<16>(&b["attempt"])?;
                    require(!attempts.contains_key(&id), "duplicate intent")?;
                    let (r1, o1) = match cached {
                        Some(c) => c,
                        None => {
                            let c =
                                output_commitments(input, &original, &keys, &selected, &mut work)?;
                            cached = Some(c);
                            c
                        }
                    };
                    require(
                        bytes::<32>(&b["restorations"])? == r1,
                        "historical restorations",
                    )?;
                    require(bytes::<32>(&b["output"])? == o1, "intent output")?;
                    attempts.insert(
                        id,
                        Attempt {
                            id,
                            intent: auth.statement_cid().clone(),
                            output: o1,
                            restorations: r1,
                            failure_count: 0,
                            observed_at_sequence: None,
                        },
                    );
                }
                "publication-observed" | "publication-failed" => {
                    let id = bytes::<16>(&b["attempt"])?;
                    let a = attempts
                        .get_mut(&id)
                        .ok_or(Error::Invalid("unknown attempt"))?;
                    require(link(&b["intent"])? == &a.intent, "intent citation")?;
                    require(a.observed_at_sequence.is_none(), "event after observed")?;
                    if event == "publication-observed" {
                        require(bytes::<32>(&b["output"])? == a.output, "observed output")?;
                        a.observed_at_sequence = Some(auth.sequence());
                    } else {
                        a.failure_count = a.failure_count.checked_add(1).ok_or(Error::Budget)?
                    }
                }
                _ => return Err(Error::Invalid("event position")),
            }
        }
        if let Some(pin) = external {
            if pin.sequence == auth.sequence() {
                require(
                    &pin.statement == auth.statement_cid(),
                    "external checkpoint statement",
                )?;
                checkpoint_seen = true
            }
        }
        previous = Some(auth);
        work.check()?;
    }
    require(
        loss_offset == original.losses().len(),
        "initial loss incomplete",
    )?;
    require(
        selected.len() == physical.len(),
        "candidate without restoration",
    )?;
    require(checkpoint_seen, "external checkpoint absent")?;
    let tip = previous.expect("nonempty verified history");
    work.check()?;
    Ok(Replay {
        member: original,
        checkpoint: Checkpoint {
            context: input.context.clone(),
            sequence: tip.sequence(),
            statement: tip.statement_cid().clone(),
        },
        external: external.cloned(),
        restored: selected.len() as u64,
        attempts: attempts.into_values().collect(),
    })
}
