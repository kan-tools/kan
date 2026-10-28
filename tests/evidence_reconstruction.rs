#![cfg(feature = "v2-crypto")]
use kan::{
    evidence_capture::{Event, Observer, Outcome, Recorder, Sink, Unconfirmed, CHUNK},
    evidence_reconstruction::{decode, Decoded, Error, Unsupported, MAX_FRAME, MAX_HEADER},
};

const HEADER: &str = r#"{"version":2,"attempt":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","observer":"collector","ordinal":9007199254740993,"observed_at_unix_micros":null,"elapsed_micros":18446744073709551615,"unconfirmed_before":0,"event":{"type":"request-chunk","offset":9007199254740995}}"#;
fn wire(header: &str, body: &[u8]) -> Vec<u8> {
    let mut bytes = b"KANC2".to_vec();
    bytes.extend_from_slice(&(header.len() as u32).to_be_bytes());
    bytes.extend_from_slice(header.as_bytes());
    bytes.extend_from_slice(body);
    bytes
}
fn rejected(bytes: &[u8], expected: Error) {
    assert_eq!(decode(bytes).unwrap_err(), expected);
}
fn unsupported(bytes: &[u8], expected: Unsupported) {
    assert!(matches!(decode(bytes).unwrap(), Decoded::Unsupported(reason) if reason==expected));
}

#[test]
fn exact_spans_binary_body_and_u64_coordinates_are_not_rounded() {
    let bytes = wire(HEADER, b"\0\xff\xc3\xa9");
    let Decoded::Capture(frame) = decode(&bytes).unwrap() else {
        panic!()
    };
    assert_eq!(&bytes[frame.header_span], HEADER.as_bytes());
    assert_eq!(&bytes[frame.body_span], b"\0\xff\xc3\xa9");
    assert_eq!(frame.body, b"\0\xff\xc3\xa9");
    assert_eq!(frame.header.ordinal, 9_007_199_254_740_993);
    assert_eq!(frame.header.elapsed_micros, u64::MAX);
    assert!(matches!(
        frame.header.event,
        Event::RequestChunk {
            offset: 9_007_199_254_740_995
        }
    ));
}

#[test]
fn opaque_and_unsupported_are_distinct_from_malformed_capture() {
    assert!(matches!(
        decode(b"ordinary imported text").unwrap(),
        Decoded::Opaque
    ));
    assert!(matches!(decode(b"").unwrap(), Decoded::Opaque));
    rejected(b"KANC", Error::Envelope);
    rejected(b"KANC2", Error::Envelope);
    unsupported(b"KANC3", Unsupported::Envelope);
    for (from, to, reason) in [
        ("\"version\":2", "\"version\":3", Unsupported::Version),
        (
            "\"collector\"",
            "\"future-observer\"",
            Unsupported::Observer,
        ),
        ("\"request-chunk\"", "\"future-event\"", Unsupported::Event),
    ] {
        unsupported(&wire(&HEADER.replace(from, to), b"raw"), reason);
    }
    let terminal = HEADER.replace(
        "\"request-chunk\",\"offset\":9007199254740995",
        "\"terminal\",\"outcome\":\"future-outcome\"",
    );
    unsupported(&wire(&terminal, b""), Unsupported::Outcome);
}

#[test]
fn duplicate_and_escaped_alias_keys_never_choose_a_winner() {
    for header in [
        HEADER.replace("\"version\":2", "\"version\":2,\"version\":3"),
        HEADER.replace("\"version\":2", r#""version":2,"ver\u0073ion":2"#),
        HEADER.replace(
            "\"type\":\"request-chunk\"",
            "\"type\":\"request-chunk\",\"type\":\"request-chunk\"",
        ),
        HEADER.replace(
            "\"request-chunk\",\"offset\":9007199254740995",
            "\"future\",\"nested\":{\"x\":1,\"x\":2}",
        ),
        HEADER.replace(
            "\"version\":2",
            "\"version\":3,\"extra\":[{\"x\":1,\"x\":2}]",
        ),
    ] {
        rejected(&wire(&header, b""), Error::Header);
    }
}

#[test]
fn recognized_shapes_reject_missing_extra_wrong_type_and_bad_integer_fields() {
    for header in [
        HEADER.replace("\"version\":2,", ""),
        HEADER.replace("\"version\":2", "\"version\":2.0"),
        HEADER.replace("\"version\":2", "\"version\":2,\"extra\":true"),
        HEADER.replace("\"offset\":9007199254740995", "\"offset\":-1"),
        HEADER.replace(
            "\"offset\":9007199254740995",
            "\"offset\":18446744073709551616",
        ),
        HEADER.replace("\"offset\":9007199254740995", "\"offset\":1.5"),
        HEADER.replace("\"offset\":9007199254740995", "\"offset\":\"1\""),
        HEADER.replace(
            "\"offset\":9007199254740995",
            "\"offset\":0,\"unexpected\":null",
        ),
        HEADER.replace("\"observer\":\"collector\"", "\"observer\":null"),
    ] {
        rejected(&wire(&header, b""), Error::Header);
    }
}

#[test]
fn bounded_header_body_and_total_before_materialization() {
    let mut declared = b"KANC2".to_vec();
    declared.extend_from_slice(&u32::MAX.to_be_bytes());
    rejected(&declared, Error::Limit);
    rejected(&wire(HEADER, &vec![0; CHUNK + 1]), Error::Limit);
    let header = format!("{}{}", HEADER, " ".repeat(MAX_HEADER - HEADER.len()));
    let max = wire(&header, &vec![0; CHUNK]);
    assert_eq!(max.len(), MAX_FRAME);
    assert!(matches!(decode(&max).unwrap(), Decoded::Capture(_)));
    let mut too_big = max;
    too_big.push(0);
    rejected(&too_big, Error::Limit);
    rejected(&wire(&(header + " "), b""), Error::Limit);
}

#[test]
fn malformed_json_encoding_trailing_data_and_nested_input_refuse() {
    for header in [
        "{}".to_owned(),
        "[]".to_owned(),
        format!("{HEADER}{{}}"),
        HEADER.replace("\"version\":2", "\"version\":NaN"),
        HEADER.replace(
            "\"version\":2",
            &format!(
                "\"version\":3,\"nest\":{}0{}",
                "[".repeat(130),
                "]".repeat(130)
            ),
        ),
        HEADER.replace("\"collector\"", r#""\ud800""#),
    ] {
        rejected(&wire(&header, b""), Error::Header);
    }
    let mut bad = wire(HEADER, b"");
    bad[9] = 255;
    rejected(&bad, Error::Header);
}

#[test]
fn non_chunk_events_cannot_smuggle_body_bytes() {
    for event in [
        r#"{"type":"request-end","bytes":0}"#,
        r#"{"type":"forwarding-intent"}"#,
        r#"{"type":"response-head","status":200}"#,
        r#"{"type":"terminal","outcome":"completed"}"#,
    ] {
        let header = HEADER.replace(
            r#"{"type":"request-chunk","offset":9007199254740995}"#,
            event,
        );
        rejected(&wire(&header, b"hidden"), Error::Body);
        assert!(matches!(
            decode(&wire(&header, b"")).unwrap(),
            Decoded::Capture(_)
        ));
    }
}

#[test]
fn identifiers_and_started_string_bounds_match_recorder() {
    for attempt in [
        "x".repeat(64),
        "A".repeat(64),
        "a".repeat(62),
        "a".repeat(66),
    ] {
        rejected(
            &wire(
                &HEADER.replace(
                    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                    &attempt,
                ),
                b"",
            ),
            Error::Header,
        );
    }
    for event in [
        format!(
            r#"{{"type":"started","method":"{}","route":"/"}}"#,
            "M".repeat(33)
        ),
        format!(
            r#"{{"type":"started","method":"POST","route":"{}"}}"#,
            "é".repeat(1025)
        ),
        r#"{"type":"transport-link","exchange":"abcd"}"#.into(),
    ] {
        rejected(
            &wire(
                &HEADER.replace(
                    r#"{"type":"request-chunk","offset":9007199254740995}"#,
                    &event,
                ),
                b"",
            ),
            Error::Header,
        );
    }
}

#[test]
fn all_truncated_header_prefixes_fail_without_panicking() {
    let bytes = wire(HEADER, b"");
    for n in 4..bytes.len() {
        rejected(&bytes[..n], Error::Envelope);
    }
}

#[test]
fn mutated_bounded_inputs_never_panic_or_claim_spans_outside_input() {
    let bytes = wire(HEADER, b"payload");
    for position in 0..bytes.len() {
        for replacement in [0, 0xff, b'"', b'{', b'9'] {
            let mut changed = bytes.clone();
            changed[position] = replacement;
            if let Ok(Decoded::Capture(frame)) = decode(&changed) {
                assert_eq!(frame.body, &changed[frame.body_span]);
                assert_eq!(frame.header_span.start, 9);
                assert!(frame.header_span.end <= changed.len());
            }
        }
    }
}

#[derive(Default)]
struct Memory(Vec<Vec<u8>>);
impl Sink for Memory {
    fn admit(&mut self, _: &[u8; 16], frame: &[u8]) -> Result<(), Unconfirmed> {
        self.0.push(frame.to_vec());
        Ok(())
    }
}
#[test]
fn current_production_recorder_event_forms_roundtrip_with_exact_bodies() {
    let mut memory = Memory::default();
    let mut notify = |_: &kan::evidence_capture::Health| {};
    {
        let mut recorder = Recorder::new(Observer::Gateway, &mut memory, &mut notify).unwrap();
        for event in [
            Event::Started {
                method: "POST".into(),
                route: "/messages".into(),
            },
            Event::RequestChunk { offset: 0 },
            Event::RequestEnd { bytes: 3 },
            Event::ForwardingIntent,
            Event::TransportLink {
                exchange: "01".repeat(32),
            },
            Event::HttpMetadataChunk {
                direction: "request".into(),
                offset: 0,
                total: 3,
            },
            Event::HttpMetadata {
                direction: "response".into(),
                headers: vec![("x".into(), "é".into())],
                omitted: vec!["authorization".into()],
            },
            Event::ResponseHead { status: 200 },
            Event::ResponseChunk { offset: 0 },
            Event::Terminal {
                outcome: Outcome::Completed,
            },
        ] {
            let body = if matches!(
                event,
                Event::RequestChunk { .. }
                    | Event::HttpMetadataChunk { .. }
                    | Event::ResponseChunk { .. }
            ) {
                b"raw".as_slice()
            } else {
                b""
            };
            recorder.record(event, body).unwrap();
        }
    }
    assert_eq!(memory.0.len(), 10);
    for (index, bytes) in memory.0.iter().enumerate() {
        let Decoded::Capture(frame) = decode(bytes).unwrap() else {
            panic!()
        };
        assert_eq!(frame.header.ordinal, index as u64);
        assert_eq!(frame.header.observer, Observer::Gateway);
        assert_eq!(frame.body, &bytes[frame.body_span]);
    }
}

#[test]
fn multibyte_and_escaped_header_text_preserves_original_byte_spans() {
    let header = HEADER.replace(
        r#"{"type":"request-chunk","offset":9007199254740995}"#,
        r#"{"type":"started","method":"POST","route":"/café/\u00e9"}"#,
    );
    assert_ne!(header.len(), header.chars().count());
    let bytes = wire(&header, b"");
    let Decoded::Capture(frame) = decode(&bytes).unwrap() else {
        panic!()
    };
    assert_eq!(frame.header_span, 9..9 + header.len());
    assert_eq!(&bytes[frame.header_span], header.as_bytes());
    assert_eq!(frame.body_span, bytes.len()..bytes.len());
    assert!(matches!(frame.header.event,Event::Started{route,..} if route=="/café/é"));
}

#[test]
fn every_recognized_event_rejects_extra_fields_including_unit_variants() {
    for event in [
        serde_json::json!({"type":"started","method":"POST","route":"/"}),
        serde_json::json!({"type":"request-chunk","offset":0}),
        serde_json::json!({"type":"request-end","bytes":0}),
        serde_json::json!({"type":"forwarding-intent"}),
        serde_json::json!({"type":"transport-link","exchange":"01".repeat(32)}),
        serde_json::json!({"type":"http-metadata-chunk","direction":"request","offset":0,"total":0}),
        serde_json::json!({"type":"http-metadata","direction":"response","headers":[],"omitted":[]}),
        serde_json::json!({"type":"response-head","status":200}),
        serde_json::json!({"type":"response-chunk","offset":0}),
        serde_json::json!({"type":"terminal","outcome":"completed"}),
    ] {
        let mut header: serde_json::Value = serde_json::from_str(HEADER).unwrap();
        header["event"] = event;
        assert!(matches!(
            decode(&wire(&header.to_string(), b"")).unwrap(),
            Decoded::Capture(_)
        ));
        for extra in [
            serde_json::json!(1),
            serde_json::json!({"nested":[1,2,3]}),
            serde_json::Value::Null,
        ] {
            let mut changed = header.clone();
            changed["event"]["unrecognized"] = extra;
            rejected(&wire(&changed.to_string(), b""), Error::Header);
        }
    }
}

#[test]
fn recognized_header_requires_explicit_timestamp_even_when_unknown() {
    let mut header: serde_json::Value = serde_json::from_str(HEADER).unwrap();
    header["observed_at_unix_micros"] = serde_json::Value::Null;
    assert!(matches!(
        decode(&wire(&header.to_string(), b"")),
        Ok(Decoded::Capture(_))
    ));
    header
        .as_object_mut()
        .unwrap()
        .remove("observed_at_unix_micros");
    rejected(&wire(&header.to_string(), b""), Error::Header);
}

#[test]
fn capture_family_size_limit_precedes_unknown_envelope_classification() {
    for version in [b'1', b'3', 0xff] {
        let mut bytes = vec![0; MAX_FRAME];
        bytes[..4].copy_from_slice(b"KANC");
        bytes[4] = version;
        assert!(matches!(
            decode(&bytes),
            Ok(Decoded::Unsupported(Unsupported::Envelope))
        ));
        bytes.push(0);
        rejected(&bytes, Error::Limit);
    }
    // Opaque non-capture inputs are not parsed or copied by this decoder.
    assert!(matches!(
        decode(&vec![0; MAX_FRAME + 1]),
        Ok(Decoded::Opaque)
    ));
}
