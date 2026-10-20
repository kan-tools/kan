//! Explicit observer-recorded relationships, never inferred conversation identity.
use crate::{evidence_capture::Event, evidence_service::unhex};
use serde_json::{json, Value};

pub(crate) fn link(event: &Event) -> Option<Value> {
    let Event::HttpMetadata {
        direction,
        headers,
        omitted,
    } = event
    else {
        return None;
    };
    if direction != "request" {
        return None;
    }
    const FIELDS: [&str; 4] = [
        "x-kan-session",
        "x-kan-parent-attempt",
        "x-kan-transition",
        "x-claude-code-session-id",
    ];
    if !headers
        .iter()
        .any(|(name, _)| FIELDS.iter().any(|f| name.eq_ignore_ascii_case(f)))
    {
        return None;
    }
    let invalid = || {
        Some(
            json!({"state":"invalid","reason":"Ambiguous or malformed explicit session headers; inspect the retained source."}),
        )
    };
    let mut values = Vec::new();
    for name in FIELDS {
        let found: Vec<_> = headers
            .iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case(name))
            .collect();
        if found.len() > 1 || omitted.iter().any(|n| n.eq_ignore_ascii_case(name)) {
            return invalid();
        }
        let value = match found.first() {
            None => None,
            Some((_, encoded)) => match unhex(encoded, 128)
                .ok()
                .and_then(|b| String::from_utf8(b).ok())
            {
                Some(s) => Some(s),
                None => return invalid(),
            },
        };
        values.push(value);
    }
    if let Some(session) = &values[3] {
        if values[..3].iter().any(Option::is_some)
            || session.is_empty()
            || session.len() > 128
            || !session.bytes().all(|c| c.is_ascii_graphic())
        {
            return invalid();
        }
        return Some(
            json!({"state":"claimed","scheme":"claude-code-header","session":session,"parent_attempt":null,"transition":"membership"}),
        );
    }
    let identifier = |s: &str| {
        s.len() == 64
            && s.bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    };
    let Some(session) = &values[0] else {
        return invalid();
    };
    if !identifier(session) || values[1].as_deref().is_some_and(|s| !identifier(s)) {
        return invalid();
    }
    let transition = values[2].as_deref().unwrap_or(if values[1].is_some() {
        "continue"
    } else {
        "start"
    });
    if (values[1].is_none() && transition != "start")
        || (values[1].is_some() && !matches!(transition, "continue" | "branch" | "compaction"))
    {
        return invalid();
    }
    Some(
        json!({"state":"claimed","scheme":"kan-header","session":session,"parent_attempt":values[1],"transition":transition}),
    )
}

// Reconstruction consumes the assembly's verified-identity grouping. The caller
// retains authorization/proof lineage for each input and applies its work budget.
pub(crate) fn metadata(
    group: &crate::evidence_assembly::Group,
    observations: &[crate::evidence_assembly::Observation<'_>],
    mut charge: impl FnMut(usize) -> Result<(), crate::evidence_service::Failure>,
) -> Result<Vec<Value>, crate::evidence_service::Failure> {
    use crate::evidence_assembly::Observation;
    const MAX_METADATA: usize = 2 * 1024 * 1024;
    struct Pending {
        total: u64,
        end: u64,
        observed: u64,
        ordinal: u64,
        bytes: Vec<u8>,
        sources: Vec<Value>,
        issue: Option<&'static str>,
    }
    impl Pending {
        fn mark(&mut self, issue: &'static str) {
            let rank = |value| match value {
                Some("invalid") => 3,
                Some("limited") => 2,
                Some("incomplete") => 1,
                _ => 0,
            };
            if rank(Some(issue)) > rank(self.issue) {
                self.issue = Some(issue);
            }
        }
    }
    fn finish(p: Pending) -> Value {
        let mut state = p.issue.unwrap_or(if p.end == p.total {
            "complete"
        } else {
            "incomplete"
        });
        let mut session = None;
        if state == "complete" {
            match serde_json::from_slice::<Event>(&p.bytes) {
                Ok(event) if matches!(&event, Event::HttpMetadata { direction, .. } if direction == "request") =>
                {
                    session = link(&event);
                }
                _ => state = "invalid",
            }
        }
        json!({"state":state,"fragmented":true,"session_link":session,"sources":p.sources,
            "expected_bytes":p.total.to_string(),"observed_bytes":p.observed.to_string(),"covered_through":p.end.to_string()})
    }
    let mut result = Vec::new();
    let mut pending: Option<Pending> = None;
    for ordinal in &group.ordinals {
        charge(0)?;
        let frames: Vec<_> = ordinal
            .inputs
            .iter()
            .filter_map(|i| match &observations[*i] {
                Observation::Capture(f) => Some((*i, f)),
                _ => None,
            })
            .collect();
        let metadata = frames.iter().find(|(_, f)| matches!(&f.header.event,
            Event::HttpMetadata { direction, .. } | Event::HttpMetadataChunk { direction, .. } if direction == "request"));
        let Some((_, frame)) = metadata else {
            if let Some(p) = pending.take() {
                result.push(finish(p));
            }
            continue;
        };
        let sources: Vec<_> = frames
            .iter()
            .map(|(i, f)| {
                let span = if matches!(f.header.event, Event::HttpMetadataChunk { .. }) {
                    &f.body_span
                } else {
                    &f.header_span
                };
                json!({"input":i.to_string(),"bytes":[span.start.to_string(),span.end.to_string()]})
            })
            .collect();
        match &frame.header.event {
            Event::HttpMetadata { .. } => {
                if let Some(p) = pending.take() {
                    result.push(finish(p));
                }
                charge(frame.header_span.len())?;
                result.push(json!({"state":if ordinal.conflict {"invalid"} else {"complete"},"fragmented":false,
                    "session_link":if ordinal.conflict {None} else {link(&frame.header.event)},"sources":sources}));
            }
            Event::HttpMetadataChunk { offset, total, .. } => {
                if *offset == 0 {
                    if let Some(p) = pending.take() {
                        result.push(finish(p));
                    }
                }
                let p = pending.get_or_insert_with(|| Pending {
                    total: *total,
                    end: 0,
                    observed: 0,
                    ordinal: ordinal.value,
                    bytes: Vec::new(),
                    sources: Vec::new(),
                    issue: if *offset != 0 {
                        Some("incomplete")
                    } else if *total == 0 {
                        Some("invalid")
                    } else if *total > MAX_METADATA as u64 {
                        Some("limited")
                    } else {
                        None
                    },
                });
                if p.total != *total || ordinal.conflict || frame.body.is_empty() {
                    p.mark("invalid");
                }
                if !p.sources.is_empty() && p.ordinal.checked_add(1) != Some(ordinal.value) {
                    p.mark("incomplete");
                }
                if *offset != p.end {
                    p.mark(if *offset < p.end {
                        "invalid"
                    } else {
                        "incomplete"
                    });
                }
                let end = offset.checked_add(frame.body.len() as u64);
                if end.is_none_or(|end| end > p.total) {
                    p.mark("invalid");
                }
                charge(frame.body.len())?;
                if p.issue.is_none() {
                    p.bytes.extend_from_slice(frame.body);
                }
                p.observed += frame.body.len() as u64;
                p.end = end.unwrap_or(u64::MAX);
                p.ordinal = ordinal.value;
                p.sources.extend(sources);
                if p.end == p.total {
                    result.push(finish(pending.take().unwrap()));
                }
            }
            _ => unreachable!(),
        }
    }
    if let Some(p) = pending {
        result.push(finish(p));
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence_service::hex;
    fn event(headers: Vec<(&str, String)>) -> Event {
        Event::HttpMetadata {
            direction: "request".into(),
            headers: headers
                .into_iter()
                .map(|(k, v)| (k.into(), hex(v.as_bytes())))
                .collect(),
            omitted: vec![],
        }
    }
    #[test]
    fn explicit_relationships_preserve_branches_and_refuse_ambiguous_headers() {
        for relation in ["continue", "branch", "compaction"] {
            let e = event(vec![
                ("x-kan-session", "a".repeat(64)),
                ("x-kan-parent-attempt", "b".repeat(64)),
                ("x-kan-transition", relation.into()),
            ]);
            let value = link(&e).unwrap();
            assert_eq!(value["state"], "claimed");
            assert_eq!(value["transition"], relation);
        }
        for headers in [
            vec![
                ("x-kan-session", "a".repeat(64)),
                ("X-Kan-Session", "b".repeat(64)),
            ],
            vec![("x-kan-session", "arbitrary label".into())],
            vec![("x-kan-parent-attempt", "b".repeat(64))],
            vec![
                ("x-kan-session", "a".repeat(64)),
                ("x-kan-transition", "branch".into()),
            ],
        ] {
            assert_eq!(link(&event(headers)).unwrap()["state"], "invalid");
        }
        assert!(link(&event(vec![("user-agent", "test".into())])).is_none());
        let v = link(&event(vec![(
            "x-claude-code-session-id",
            "fixture-session".into(),
        )]))
        .unwrap();
        assert_eq!(v["transition"], "membership");
        assert_eq!(v["scheme"], "claude-code-header");
    }
    fn frame(ordinal: u64, event: Event, body: &[u8]) -> Vec<u8> {
        let header = crate::evidence_capture::Header {
            version: 2,
            attempt: "a".repeat(64),
            observer: crate::evidence_capture::Observer::Collector,
            ordinal,
            observed_at_unix_micros: None,
            elapsed_micros: 0,
            unconfirmed_before: 0,
            event,
        };
        let h = serde_json::to_vec(&header).unwrap();
        let mut b = b"KANC2".to_vec();
        b.extend_from_slice(&(h.len() as u32).to_be_bytes());
        b.extend(h);
        b.extend(body);
        b
    }
    fn resolve(frames: &[Vec<u8>]) -> Vec<Value> {
        use crate::evidence_assembly as a;
        let inputs: Vec<_> = frames
            .iter()
            .map(|f| a::Input {
                scope: [1; 32],
                writer: "verified",
                payload: a::Payload::Available(f),
            })
            .collect();
        let assembled = a::assemble(
            &inputs,
            a::Limits {
                occurrences: 100,
                input_bytes: 4 * 1024 * 1024,
                scan_bytes: 16 * 1024 * 1024,
                assembled_bytes: 4 * 1024 * 1024,
                duration: std::time::Duration::from_secs(5),
                cancelled: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            },
        )
        .unwrap();
        metadata(&assembled.groups[0], &assembled.observations, |_| Ok(())).unwrap()
    }
    #[test]
    fn metadata_fragments_preserve_all_duplicate_citations_and_fail_incomplete_or_conflicting() {
        let event = event(vec![
            ("x-kan-session", "a".repeat(64)),
            ("x-kan-parent-attempt", "b".repeat(64)),
            ("x-kan-transition", "branch".into()),
        ]);
        let bytes = serde_json::to_vec(&event).unwrap();
        let middle = bytes.len() / 2;
        let first = frame(
            1,
            Event::HttpMetadataChunk {
                direction: "request".into(),
                offset: 0,
                total: bytes.len() as u64,
            },
            &bytes[..middle],
        );
        let last = frame(
            2,
            Event::HttpMetadataChunk {
                direction: "request".into(),
                offset: middle as u64,
                total: bytes.len() as u64,
            },
            &bytes[middle..],
        );
        let orphan = resolve(std::slice::from_ref(&last));
        assert_eq!(
            orphan[0]["observed_bytes"],
            (bytes.len() - middle).to_string()
        );
        let values = resolve(&[last.clone(), first.clone(), first.clone()]);
        assert_eq!(values.len(), 1);
        assert_eq!(values[0]["state"], "complete");
        assert_eq!(values[0]["session_link"]["transition"], "branch");
        assert_eq!(values[0]["sources"].as_array().unwrap().len(), 3);
        for frames in [
            vec![first.clone()],
            vec![last.clone()],
            vec![
                first.clone(),
                frame(
                    3,
                    Event::HttpMetadataChunk {
                        direction: "request".into(),
                        offset: middle as u64,
                        total: bytes.len() as u64,
                    },
                    &bytes[middle..],
                ),
            ],
            vec![
                first.clone(),
                last.clone(),
                frame(2, Event::ForwardingIntent, &[]),
            ],
            vec![
                first,
                frame(
                    2,
                    Event::HttpMetadataChunk {
                        direction: "response".into(),
                        offset: middle as u64,
                        total: bytes.len() as u64,
                    },
                    &bytes[middle..],
                ),
            ],
        ] {
            let values = resolve(&frames);
            assert!(values.iter().all(|v| v["session_link"].is_null()));
            assert!(values.iter().all(|v| v["state"] != "complete"));
        }
    }
    #[test]
    fn metadata_refuses_wrong_direction_malformed_documents_and_oversized_extents() {
        for bytes in [b"{}".as_slice(),br#"{"type":"http-metadata","direction":"response","headers":[],"omitted":[]}"#,br#"{"type":"http-metadata","direction":"request","direction":"request","headers":[],"omitted":[]}"#] {
            let values=resolve(&[frame(1,Event::HttpMetadataChunk{direction:"request".into(),offset:0,total:bytes.len() as u64},bytes)]);assert_eq!(values[0]["state"],"invalid");assert!(values[0]["session_link"].is_null());
        }
        let values = resolve(&[frame(
            1,
            Event::HttpMetadataChunk {
                direction: "request".into(),
                offset: 0,
                total: 3 * 1024 * 1024,
            },
            b"tiny",
        )]);
        assert_eq!(values[0]["state"], "limited");
    }
}
