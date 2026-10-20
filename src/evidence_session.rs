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
}
