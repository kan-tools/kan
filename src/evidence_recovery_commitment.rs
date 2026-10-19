//! Streaming recovery framing commitments. A digest is not a verified member.
//!
//! Inputs must already be acquired under caller authority and read budgets. This
//! layer bounds its own work, checks framing/order/local sizes and hashes bytes;
//! it does not check record signatures, copy-plan truth or publication readiness.
use atproto_dasl::Cid;
use sha2::{Digest, Sha256};
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

const SAFE: u64 = 9_007_199_254_740_991;
const MAX_OBJECT: usize = 4 * 1024 * 1024;
type Result<T> = std::result::Result<T, Error>;
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("invalid recovery commitment framing: {0}")]
    Shape(&'static str),
    #[error("recovery commitment work budget exhausted")]
    Budget,
    #[error("recovery commitment cancelled")]
    Cancelled,
    #[error("recovery commitment builder previously failed")]
    Poisoned,
}
fn shape(ok: bool, reason: &'static str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(Error::Shape(reason))
    }
}

/// Caller-selected work limits, not archive format size ceilings. Byte budget
/// counts framing and hashing work; candidate verification hashes bytes twice.
#[derive(Clone)]
pub struct Limits {
    pub items: u64,
    pub bytes: u64,
    pub duration: Duration,
    pub cancelled: Arc<AtomicBool>,
}
#[derive(Clone, Copy)]
pub struct Counts {
    pub membership: u64,
    pub records: u64,
    pub objects: u64,
}
#[derive(Clone, Copy)]
pub enum Domain {
    Member,
    Output,
}
pub struct Header<'a> {
    pub profile: u8,
    pub archive: [u8; 32],
    pub scope: [u8; 32],
    pub issuer: &'a str,
    pub plan: Option<&'a [u8]>,
}
struct Meter {
    limits: Limits,
    deadline: Instant,
    bytes: u64,
    items: u64,
}
impl Meter {
    fn new(limits: Limits, items: u64) -> Result<Self> {
        shape(
            !limits.duration.is_zero() && limits.duration <= Duration::from_secs(3600),
            "duration",
        )?;
        if items > limits.items {
            return Err(Error::Budget);
        }
        let deadline = Instant::now()
            .checked_add(limits.duration)
            .ok_or(Error::Budget)?;
        let out = Self {
            limits,
            deadline,
            bytes: 0,
            items: 0,
        };
        out.check()?;
        Ok(out)
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
    fn spend(&mut self, bytes: usize) -> Result<()> {
        self.check()?;
        self.bytes = self.bytes.checked_add(bytes as u64).ok_or(Error::Budget)?;
        if self.bytes > self.limits.bytes {
            return Err(Error::Budget);
        }
        Ok(())
    }
    fn item(&mut self) -> Result<()> {
        self.check()?;
        self.items = self.items.checked_add(1).ok_or(Error::Budget)?;
        if self.items > self.limits.items {
            return Err(Error::Budget);
        }
        Ok(())
    }
}
struct Core {
    hash: Sha256,
    meter: Meter,
    failed: bool,
}
impl Core {
    fn new(domain: &[u8], limits: Limits, items: u64) -> Result<Self> {
        let mut out = Self {
            hash: Sha256::new(),
            meter: Meter::new(limits, items)?,
            failed: false,
        };
        out.put(domain)?;
        Ok(out)
    }
    fn put(&mut self, bytes: &[u8]) -> Result<()> {
        self.meter.check()?;
        for part in bytes.chunks(64 * 1024) {
            self.meter.spend(part.len())?;
            self.hash.update(part)
        }
        Ok(())
    }
    fn n(&mut self, n: u64) -> Result<()> {
        self.put(&n.to_be_bytes())
    }
    fn frame(&mut self, b: &[u8]) -> Result<()> {
        self.n(b.len() as u64)?;
        self.put(b)
    }
    fn finish(self) -> Result<[u8; 32]> {
        if self.failed {
            return Err(Error::Poisoned);
        }
        self.meter.check()?;
        Ok(self.hash.finalize().into())
    }
}
fn raw_key(cid: &Cid) -> Result<(String, Vec<u8>)> {
    let raw = cid.to_bytes();
    shape(
        raw.len() == 36 && raw[..4] == [1, 0x55, 0x12, 0x20],
        "object CID",
    )?;
    Ok((cid.to_string(), raw))
}
fn ordered(last: &mut Option<String>, next: String) -> Result<()> {
    shape(
        last.as_ref().is_none_or(|old| old < &next),
        "duplicate or unordered CID",
    )?;
    *last = Some(next);
    Ok(())
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Membership,
    Records,
    Objects,
}
/// Strictly ordered streaming input. Any rejected operation poisons the builder,
/// so ignoring an error cannot produce a digest of a silently shortened member.
pub struct MemberFraming {
    core: Core,
    counts: Counts,
    phase: Phase,
    seen: u64,
    last: Option<String>,
}
impl MemberFraming {
    pub fn new(header: Header<'_>, counts: Counts, domain: Domain, limits: Limits) -> Result<Self> {
        shape(matches!(header.profile, 2 | 3), "profile")?;
        shape(
            !header.issuer.is_empty() && header.issuer.len() <= 80,
            "issuer length",
        )?;
        for count in [counts.membership, counts.records, counts.objects] {
            shape(count <= SAFE, "count")?
        }
        let total = counts
            .membership
            .checked_add(counts.records)
            .and_then(|n| n.checked_add(counts.objects))
            .ok_or(Error::Budget)?;
        if header.profile == 2 {
            shape(
                header.plan.is_none() && counts.membership == 0,
                "profile2 plan",
            )?
        } else {
            shape(
                header
                    .plan
                    .is_some_and(|p| !p.is_empty() && p.len() <= 4096),
                "profile3 plan",
            )?
        }
        let domain = match domain {
            Domain::Member => b"tools.kan.recovery.member.v1\0".as_slice(),
            Domain::Output => b"tools.kan.recovery.output.v1\0".as_slice(),
        };
        let mut core = Core::new(domain, limits, total)?;
        core.n(header.profile.into())?;
        core.frame(&header.archive)?;
        core.frame(&header.scope)?;
        core.frame(header.issuer.as_bytes())?;
        core.frame(b"plan")?;
        core.n(u64::from(header.plan.is_some()))?;
        if let Some(plan) = header.plan {
            core.frame(plan)?
        }
        core.frame(b"original-membership")?;
        core.n(counts.membership)?;
        Ok(Self {
            core,
            counts,
            phase: Phase::Membership,
            seen: 0,
            last: None,
        })
    }
    fn operation(&mut self, operation: impl FnOnce(&mut Self) -> Result<()>) -> Result<()> {
        if self.core.failed {
            return Err(Error::Poisoned);
        }
        self.core.failed = true;
        let result = operation(self);
        if result.is_ok() {
            self.core.failed = false
        }
        result
    }
    pub fn membership(&mut self, cid: &Cid, length: u64) -> Result<()> {
        self.operation(|s| {
            shape(
                s.phase == Phase::Membership && s.seen < s.counts.membership,
                "membership position",
            )?;
            shape(
                (1..=MAX_OBJECT as u64).contains(&length),
                "membership length",
            )?;
            let (name, key) = raw_key(cid)?;
            ordered(&mut s.last, name)?;
            s.core.meter.item()?;
            s.core.frame(&key)?;
            s.core.n(length)?;
            s.seen += 1;
            Ok(())
        })
    }
    pub fn begin_records(&mut self) -> Result<()> {
        self.operation(|s| {
            shape(
                s.phase == Phase::Membership && s.seen == s.counts.membership,
                "incomplete membership",
            )?;
            s.core.frame(b"records")?;
            s.core.n(s.counts.records)?;
            s.phase = Phase::Records;
            s.seen = 0;
            s.last = None;
            Ok(())
        })
    }
    pub fn record(
        &mut self,
        sequence: u64,
        manifest: &[u8],
        receipt: &[u8],
        proof: &[u8],
    ) -> Result<()> {
        self.operation(|s| {
            shape(
                s.phase == Phase::Records && s.seen < s.counts.records && sequence == s.seen + 1,
                "record position",
            )?;
            for (bytes, max) in [(manifest, 65536), (receipt, 65536), (proof, 16384)] {
                shape(!bytes.is_empty() && bytes.len() <= max, "record bytes")?
            }
            s.core.meter.item()?;
            s.core.n(sequence)?;
            s.core.frame(manifest)?;
            s.core.frame(receipt)?;
            s.core.frame(proof)?;
            s.seen += 1;
            Ok(())
        })
    }
    pub fn begin_objects(&mut self) -> Result<()> {
        self.operation(|s| {
            shape(
                s.phase == Phase::Records && s.seen == s.counts.records,
                "incomplete records",
            )?;
            s.core.frame(b"original-objects")?;
            s.core.n(s.counts.objects)?;
            s.phase = Phase::Objects;
            s.seen = 0;
            s.last = None;
            Ok(())
        })
    }
    pub fn original_object(&mut self, cid: &Cid, bytes: &[u8]) -> Result<()> {
        self.operation(|s| {
            shape(
                s.phase == Phase::Objects && s.seen < s.counts.objects,
                "object position",
            )?;
            shape(bytes.len() <= MAX_OBJECT, "object bytes")?;
            let (name, key) = raw_key(cid)?;
            ordered(&mut s.last, name)?;
            s.core.meter.item()?;
            s.core.frame(&key)?;
            s.core.n(bytes.len() as u64)?;
            s.core.frame(bytes)?;
            s.seen += 1;
            Ok(())
        })
    }
    pub fn finish(self) -> Result<[u8; 32]> {
        if self.core.failed {
            return Err(Error::Poisoned);
        }
        shape(
            self.phase == Phase::Objects && self.seen == self.counts.objects,
            "incomplete objects",
        )?;
        self.core.finish()
    }
}
/// R1 framing also verifies candidate content addresses. It still does not prove
/// candidate membership, historical selection or a restoration observation.
pub struct RestorationFraming {
    core: Core,
    count: u64,
    seen: u64,
    last: Option<String>,
}
impl RestorationFraming {
    pub fn new(count: u64, limits: Limits) -> Result<Self> {
        shape(count <= SAFE, "count")?;
        let mut core = Core::new(b"tools.kan.recovery.restorations.v1\0", limits, count)?;
        core.n(count)?;
        Ok(Self {
            core,
            count,
            seen: 0,
            last: None,
        })
    }
    pub fn candidate(&mut self, cid: &Cid, bytes: &[u8]) -> Result<()> {
        if self.core.failed {
            return Err(Error::Poisoned);
        }
        self.core.failed = true;
        shape(self.seen < self.count, "candidate position")?;
        shape(
            !bytes.is_empty() && bytes.len() <= MAX_OBJECT,
            "candidate bytes",
        )?;
        let (name, key) = raw_key(cid)?;
        ordered(&mut self.last, name)?;
        self.core.meter.item()?;
        let mut hash = Sha256::new();
        for part in bytes.chunks(64 * 1024) {
            self.core.meter.spend(part.len())?;
            hash.update(part)
        }
        let actual: [u8; 32] = hash.finalize().into();
        shape(actual == key[4..], "candidate hash")?;
        self.core.frame(&key)?;
        self.core.n(bytes.len() as u64)?;
        self.core.frame(bytes)?;
        self.seen += 1;
        self.core.failed = false;
        Ok(())
    }
    pub fn finish(self) -> Result<[u8; 32]> {
        if self.core.failed {
            return Err(Error::Poisoned);
        }
        shape(self.seen == self.count, "incomplete candidates")?;
        self.core.finish()
    }
}
