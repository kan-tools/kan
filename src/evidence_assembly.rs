//! Disposable assembly over an explicit, authorized occurrence selection.
//! Source indices retain caller-owned occurrence/proof/snapshot lineage. This
//! module neither checks grants nor discovers records, and claims no completeness.
use crate::{
    evidence_capture::{Event, Observer, Outcome},
    evidence_reconstruction::{self as decode, Decoded, Frame},
};
use std::{
    collections::BTreeMap,
    ops::Range,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

pub const VERSION: &str = "kan-capture-assembly/1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unavailable {
    Erased,
    Missing,
    Corrupt,
    Withheld,
    KeyUnavailable,
}
#[derive(Clone, Copy)]
pub enum Payload<'a> {
    Available(&'a [u8]),
    Unavailable(Unavailable),
}
/// Identity comes from verified reader selection, never from captured JSON.
pub struct Input<'a> {
    pub scope: [u8; 32],
    pub writer: &'a str,
    pub payload: Payload<'a>,
}
#[derive(Debug)]
pub enum Observation<'a> {
    Capture(Frame<'a>),
    Opaque,
    Unsupported(decode::Unsupported),
    Malformed(decode::Error),
    Unavailable(Unavailable),
}
#[derive(Clone)]
pub struct Limits {
    pub occurrences: usize,
    /// Raw frame bytes plus caller-supplied writer bytes, counted per occurrence.
    pub input_bytes: u64,
    /// Decode, duplicate comparison and assembled copying work; not CPU time.
    pub scan_bytes: u64,
    pub assembled_bytes: u64,
    pub duration: Duration,
    pub cancelled: Arc<AtomicBool>,
}
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("assembly budget exhausted: {0}")]
    Limit(&'static str),
    #[error("assembly cancelled")]
    Cancelled,
}
type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceSpan {
    pub input: usize,
    /// Exact exclusive byte range within that input's decrypted frame.
    pub bytes: Range<usize>,
}
#[derive(Debug)]
pub struct Segment {
    pub offset: u64,
    pub length: usize,
    /// Exact duplicate frames share a segment, retaining every occurrence.
    pub sources: Vec<SourceSpan>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamIssue {
    OffsetOverflow { input: usize },
    Gap(Range<u64>),
    Overlap { input: usize },
    ConflictingExtents,
    BeyondExtent { input: usize },
    ChunkAfterEnd { input: usize },
    OrdinalConflict,
}
#[derive(Debug)]
pub struct Stream {
    pub segments: Vec<Segment>,
    /// Every request-end claim with its source. Responses have no extent claim.
    pub extents: Vec<(usize, u64)>,
    pub expected_bytes: Option<u64>,
    pub issues: Vec<StreamIssue>,
    /// A contiguous observed prefix only. Even Some(empty) is not a coverage
    /// certificate. None means absent data or contradictory/gapped segments.
    pub contiguous: Option<Vec<u8>>,
}
#[derive(Debug)]
pub struct Ordinal {
    pub value: u64,
    pub inputs: Vec<usize>,
    pub conflict: bool,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Terminal {
    Unknown,
    Claimed(Outcome),
    Conflicting,
}
#[derive(Debug)]
pub struct Group {
    pub scope: [u8; 32],
    pub writer: String,
    pub observer: Observer,
    pub attempt: String,
    pub ordinals: Vec<Ordinal>,
    /// No recognized capture at these ordinals; not proof of missing inputs.
    /// Unplaced unsupported/malformed/unavailable observations stay in Assembly.
    /// No invented trailing extent.
    pub ordinal_gaps: Vec<Range<u64>>,
    pub missing_start: bool,
    pub unexpected_starts: Vec<usize>,
    pub terminal: Terminal,
    pub events_after_terminal: bool,
    /// Observer claim only; not an exact count of lost remote records.
    pub unconfirmed_claim: bool,
    pub request: Stream,
    pub response: Stream,
}
#[derive(Debug)]
pub struct Assembly<'a> {
    /// Exactly one entry per input, in the same order. Keep caller lineage with it.
    pub observations: Vec<Observation<'a>>,
    pub groups: Vec<Group>,
    pub scanned_bytes: u64,
    pub assembled_bytes: u64,
}
struct Work {
    limits: Limits,
    deadline: Instant,
    scanned: u64,
    assembled: u64,
}
impl Work {
    fn check(&self) -> Result<()> {
        if self.limits.cancelled.load(Ordering::Relaxed) {
            return Err(Error::Cancelled);
        }
        if Instant::now() >= self.deadline {
            return Err(Error::Limit("duration"));
        }
        Ok(())
    }
    fn scan(&mut self, n: usize) -> Result<()> {
        self.check()?;
        self.scanned = self
            .scanned
            .checked_add(n as u64)
            .ok_or(Error::Limit("scan bytes"))?;
        if self.scanned > self.limits.scan_bytes {
            return Err(Error::Limit("scan bytes"));
        }
        Ok(())
    }
    fn copy(&mut self, n: usize) -> Result<()> {
        self.scan(n)?;
        self.assembled = self
            .assembled
            .checked_add(n as u64)
            .ok_or(Error::Limit("assembled bytes"))?;
        if self.assembled > self.limits.assembled_bytes {
            return Err(Error::Limit("assembled bytes"));
        }
        Ok(())
    }
}
fn frame<'s, 'a>(observations: &'s [Observation<'a>], i: usize) -> &'s Frame<'a> {
    match &observations[i] {
        Observation::Capture(f) => f,
        _ => unreachable!(),
    }
}
fn raw<'a>(input: &Input<'a>) -> &'a [u8] {
    match input.payload {
        Payload::Available(b) => b,
        _ => unreachable!(),
    }
}
fn identical(a: &[u8], b: &[u8], work: &mut Work) -> Result<bool> {
    if a.len() != b.len() {
        work.check()?;
        return Ok(false);
    }
    for (a, b) in a.chunks(65536).zip(b.chunks(65536)) {
        work.scan(a.len())?;
        if a != b {
            return Ok(false);
        }
    }
    Ok(true)
}
fn stream(
    ordinals: &[Ordinal],
    observations: &[Observation<'_>],
    request: bool,
    work: &mut Work,
) -> Result<Stream> {
    let mut out = Stream {
        segments: vec![],
        extents: vec![],
        expected_bytes: None,
        issues: vec![],
        contiguous: None,
    };
    for ordinal in ordinals {
        work.check()?;
        if ordinal.conflict {
            out.issues.push(StreamIssue::OrdinalConflict);
        }
        // Conflicting variants remain separate. Identical duplicates share only
        // their interpretation, never their occurrence identity.
        let variants = if ordinal.conflict {
            ordinal.inputs.as_slice()
        } else {
            &ordinal.inputs[..1]
        };
        for &i in variants {
            let f = frame(observations, i);
            if request {
                if let Event::RequestEnd { bytes } = f.header.event {
                    for &index in if ordinal.conflict {
                        std::slice::from_ref(&i)
                    } else {
                        &ordinal.inputs
                    } {
                        out.extents.push((index, bytes));
                    }
                }
            }
            let offset = match (&f.header.event, request) {
                (Event::RequestChunk { offset }, true)
                | (Event::ResponseChunk { offset }, false) => *offset,
                _ => continue,
            };
            let sources = if ordinal.conflict {
                std::slice::from_ref(&i)
            } else {
                &ordinal.inputs
            };
            out.segments.push(Segment {
                offset,
                length: f.body.len(),
                sources: sources
                    .iter()
                    .map(|&input| SourceSpan {
                        input,
                        bytes: frame(observations, input).body_span.clone(),
                    })
                    .collect(),
            });
        }
    }
    if let Some(&(_, n)) = out.extents.first() {
        if out.extents.iter().all(|&(_, x)| x == n) {
            out.expected_bytes = Some(n);
        } else {
            out.issues.push(StreamIssue::ConflictingExtents);
        }
    }
    out.segments.sort_by_key(|s| (s.offset, s.sources[0].input));
    work.check()?;
    let mut end = 0;
    let mut total = 0usize;
    let first_end = out
        .extents
        .iter()
        .map(|&(i, _)| frame(observations, i).header.ordinal)
        .min();
    for s in &out.segments {
        work.check()?;
        let input = s.sources[0].input;
        if first_end.is_some_and(|n| n < frame(observations, input).header.ordinal) {
            out.issues.push(StreamIssue::ChunkAfterEnd { input });
        }
        let Some(next) = s.offset.checked_add(s.length as u64) else {
            out.issues.push(StreamIssue::OffsetOverflow { input });
            continue;
        };
        if s.offset > end {
            out.issues.push(StreamIssue::Gap(end..s.offset));
        }
        // Empty frames at a covered offset contain no overlapping byte evidence.
        if s.length > 0 && s.offset < end {
            out.issues.push(StreamIssue::Overlap { input });
        }
        if out.expected_bytes.is_some_and(|extent| next > extent) {
            out.issues.push(StreamIssue::BeyondExtent { input });
        }
        end = end.max(next);
        total = total
            .checked_add(s.length)
            .ok_or(Error::Limit("assembled bytes"))?;
    }
    if let Some(n) = out.expected_bytes {
        if end < n {
            out.issues.push(StreamIssue::Gap(end..n));
        }
    }
    if out.issues.is_empty() && (!out.segments.is_empty() || out.expected_bytes == Some(0)) {
        work.copy(total)?;
        let mut bytes = Vec::with_capacity(total);
        for s in &out.segments {
            work.check()?;
            bytes.extend_from_slice(frame(observations, s.sources[0].input).body);
        }
        out.contiguous = Some(bytes);
    }
    Ok(out)
}

/// Assemble the explicit selection or refuse the whole operation on a budget.
/// No serializer is provided: API consumers must preserve u64 coordinates.
pub fn assemble<'a>(inputs: &[Input<'a>], limits: Limits) -> Result<Assembly<'a>> {
    assemble_observed(inputs, limits, || {})
}
fn assemble_observed<'a>(
    inputs: &[Input<'a>],
    limits: Limits,
    mut after_decode: impl FnMut(),
) -> Result<Assembly<'a>> {
    if limits.duration.is_zero() || limits.duration > Duration::from_secs(3600) {
        return Err(Error::Limit("duration"));
    }
    let deadline = Instant::now()
        .checked_add(limits.duration)
        .ok_or(Error::Limit("duration"))?;
    let mut work = Work {
        limits,
        deadline,
        scanned: 0,
        assembled: 0,
    };
    work.check()?;
    if inputs.len() > work.limits.occurrences {
        return Err(Error::Limit("occurrences"));
    }
    let mut input_bytes = 0u64;
    // Preflight every encoded input before decoding/allocating derived state.
    for input in inputs {
        work.check()?;
        let bytes = match input.payload {
            Payload::Available(b) => b.len(),
            _ => 0,
        };
        input_bytes = input_bytes
            .checked_add(bytes as u64)
            .and_then(|n| n.checked_add(input.writer.len() as u64))
            .ok_or(Error::Limit("input bytes"))?;
        if input_bytes > work.limits.input_bytes {
            return Err(Error::Limit("input bytes"));
        }
    }
    let mut observations = Vec::with_capacity(inputs.len());
    for input in inputs {
        work.check()?;
        observations.push(match input.payload {
            Payload::Unavailable(reason) => Observation::Unavailable(reason),
            Payload::Available(bytes) => {
                work.scan(bytes.len())?;
                match decode::decode(bytes) {
                    Ok(Decoded::Capture(f)) => Observation::Capture(f),
                    Ok(Decoded::Opaque) => Observation::Opaque,
                    Ok(Decoded::Unsupported(r)) => Observation::Unsupported(r),
                    Err(e) => Observation::Malformed(e),
                }
            }
        });
        after_decode();
    }
    type Key<'a> = ([u8; 32], &'a str, u8, &'a str);
    let mut grouped: BTreeMap<Key<'_>, BTreeMap<u64, Vec<usize>>> = BTreeMap::new();
    for (i, observation) in observations.iter().enumerate() {
        work.check()?;
        if let Observation::Capture(f) = observation {
            let observer = match f.header.observer {
                Observer::Collector => 0,
                Observer::Gateway => 1,
            };
            grouped
                .entry((
                    inputs[i].scope,
                    inputs[i].writer,
                    observer,
                    &f.header.attempt,
                ))
                .or_default()
                .entry(f.header.ordinal)
                .or_default()
                .push(i);
        }
    }
    let mut groups = Vec::with_capacity(grouped.len());
    for ((scope, writer, observer, attempt), ordered) in grouped {
        let mut ordinals = Vec::with_capacity(ordered.len());
        let mut gaps = vec![];
        let mut next = Some(0);
        let mut starts = vec![];
        let mut terminals = vec![];
        let mut unconfirmed = false;
        for (value, indices) in ordered {
            work.check()?;
            if let Some(n) = next {
                if value > n {
                    gaps.push(n..value);
                }
            }
            next = value.checked_add(1);
            let mut conflict = false;
            for &i in &indices[1..] {
                if !identical(raw(&inputs[indices[0]]), raw(&inputs[i]), &mut work)? {
                    conflict = true;
                }
            }
            for &i in &indices {
                let f = frame(&observations, i);
                unconfirmed |= f.header.unconfirmed_before > 0;
            }
            let variants = if conflict {
                indices.as_slice()
            } else {
                &indices[..1]
            };
            for &i in variants {
                match frame(&observations, i).header.event {
                    Event::Started { .. } => starts.push(i),
                    Event::Terminal { outcome } => terminals.push((value, outcome)),
                    _ => {}
                }
            }
            ordinals.push(Ordinal {
                value,
                inputs: indices,
                conflict,
            });
        }
        let missing_start = !starts
            .iter()
            .any(|&i| frame(&observations, i).header.ordinal == 0);
        let unexpected_starts = starts
            .into_iter()
            .filter(|&i| frame(&observations, i).header.ordinal != 0)
            .collect();
        let terminal = match terminals.as_slice() {
            [] => Terminal::Unknown,
            [(n, outcome)] if !ordinals.iter().any(|o| o.value == *n && o.conflict) => {
                Terminal::Claimed(*outcome)
            }
            _ => Terminal::Conflicting,
        };
        let events_after_terminal = terminals
            .first()
            .is_some_and(|(n, _)| ordinals.last().is_some_and(|o| o.value > *n));
        let request = stream(&ordinals, &observations, true, &mut work)?;
        let response = stream(&ordinals, &observations, false, &mut work)?;
        groups.push(Group {
            scope,
            writer: writer.into(),
            observer: if observer == 0 {
                Observer::Collector
            } else {
                Observer::Gateway
            },
            attempt: attempt.into(),
            ordinals,
            ordinal_gaps: gaps,
            missing_start,
            unexpected_starts,
            terminal,
            events_after_terminal,
            unconfirmed_claim: unconfirmed,
            request,
            response,
        });
    }
    work.check()?;
    Ok(Assembly {
        observations,
        groups,
        scanned_bytes: work.scanned,
        assembled_bytes: work.assembled,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cancellation_after_decode_stops_before_the_next_input() {
        let cancelled = Arc::new(AtomicBool::new(false));
        let limits = Limits {
            occurrences: 10,
            input_bytes: 100,
            scan_bytes: 100,
            assembled_bytes: 100,
            duration: Duration::from_secs(10),
            cancelled: cancelled.clone(),
        };
        let inputs = [
            Input {
                scope: [0; 32],
                writer: "w",
                payload: Payload::Available(b"opaque"),
            },
            Input {
                scope: [0; 32],
                writer: "w",
                payload: Payload::Available(b"second"),
            },
        ];
        let mut decoded = 0;
        let result = assemble_observed(&inputs, limits, || {
            decoded += 1;
            cancelled.store(true, Ordering::Relaxed);
        });
        assert_eq!(result.unwrap_err(), Error::Cancelled);
        assert_eq!(decoded, 1);
    }
}
