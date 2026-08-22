//! Production-parser conformance for RFC 2's implementation-independent
//! checked URI-v1 manifest.

use kan::uri::{AtAuthority, KanAuthority, ResolutionRequest, Route, ScopeSelector};
use serde_json::Value;

#[test]
fn every_parse_vector_matches_the_production_parser() {
    let manifest: Value = serde_json::from_str(include_str!("fixtures/uri-v1/manifest.json"))
        .expect("URI-v1 manifest must be JSON");
    let vectors = manifest["vectors"]
        .as_array()
        .expect("URI-v1 vectors must be an array");
    let mut checked = 0;
    for vector in vectors {
        if vector["phase"] != "parse" {
            continue;
        }
        checked += 1;
        let id = vector["id"].as_str().unwrap();
        let input = vector["input"].as_str().unwrap();
        let expected = &vector["expect"];
        match (ResolutionRequest::parse(input), expected["outcome"].as_str()) {
            (Err(error), Some("failure")) => assert_eq!(
                error.code(),
                expected["failure"].as_str().unwrap(),
                "vector {id}"
            ),
            (Ok(request), Some("success")) => assert_success(id, &request, expected),
            (result, outcome) => panic!(
                "vector {id}: production result {result:?} disagrees with expected outcome {outcome:?}"
            ),
        }
    }
    assert_eq!(checked, 46, "new parse vectors require explicit review");
}

#[test]
fn semantic_constraints_outside_the_finite_manifest_fail_closed() {
    let cases = [
        (
            "kan://did/plc/alice/example:scope/subject/x",
            "invalid-path-segment",
        ),
        (
            "kan+at://alice.example/example:scope/subject/x?source=unknown",
            "inapplicable-parameter",
        ),
        (
            "kan+at://alice.example/example:scope/subject/x?commit=not-a-cid",
            "non-canonical-identifier",
        ),
        (
            "kan+at://alice.example/example:scope/subject/x?source=appview&service=did:web:example.com",
            "non-canonical-identifier",
        ),
        (
            "kan://did/plc/alice/identity?trust=roles",
            "inapplicable-parameter",
        ),
        (
            "kan://local/example.com/subject/x",
            "non-canonical-identifier",
        ),
        (
            "kan+at://localhost/example:scope/subject/x",
            "malformed-uri",
        ),
        (
            "kan+git://one@two@example.com/example:scope/subject/x",
            "malformed-uri",
        ),
        (
            "kan://local/example:scope/subject/%40future:value",
            "unsupported-selector",
        ),
    ];
    for (input, expected) in cases {
        assert_eq!(
            ResolutionRequest::parse(input).unwrap_err().code(),
            expected,
            "{input}"
        );
    }
}

#[test]
fn structural_at_signs_canonicalize_without_becoming_regular_data() {
    let direct = ResolutionRequest::parse(
        "kan://local/%40id:bciqlonzrmcwluircewwu7evclx6tdwnc7aupnf6kb5no6nzlegmsiei/subject/x",
    )
    .unwrap();
    assert_eq!(
        direct.canonical_uri(),
        "kan://local/@id:bciqlonzrmcwluircewwu7evclx6tdwnc7aupnf6kb5no6nzlegmsiei/subject/x"
    );

    let git =
        ResolutionRequest::parse("kan+git://git%40automation@example.com/example:scope/subject/x")
            .unwrap();
    assert_eq!(
        git.canonical_uri(),
        "kan+git://git%40automation@example.com/example:scope/subject/x"
    );
}

fn assert_success(id: &str, request: &ResolutionRequest, expected: &Value) {
    assert_eq!(
        request.canonical_uri(),
        expected["canonical"].as_str().unwrap(),
        "vector {id}: canonical request"
    );
    assert_eq!(
        request.route().scheme().to_string(),
        expected["scheme"].as_str().unwrap(),
        "vector {id}: scheme"
    );
    assert_eq!(
        request.route().authority_name(),
        expected["authority"].as_str().unwrap(),
        "vector {id}: authority"
    );
    assert_eq!(
        request.resource().kind_name(),
        expected["resource"].as_str().unwrap(),
        "vector {id}: resource"
    );
    assert_eq!(
        request.resource().key().as_deref(),
        expected.get("resourceKey").and_then(Value::as_str),
        "vector {id}: resource key"
    );
    assert_eq!(
        request.scope_locator().map(ToString::to_string).as_deref(),
        expected.get("scopeLocator").and_then(Value::as_str),
        "vector {id}: scope locator"
    );
    assert_eq!(
        request
            .requested_scope()
            .map(|scope| scope.to_string())
            .as_deref(),
        expected.get("requestedScope").and_then(Value::as_str),
        "vector {id}: requested scope"
    );
    assert_eq!(
        request.evidence().sources,
        expected["evidence"]
            .get("sources")
            .and_then(Value::as_array)
            .map(|values| values
                .iter()
                .map(|value| value.as_str().unwrap().to_string())
                .collect::<Vec<_>>())
            .unwrap_or_default(),
        "vector {id}: sources"
    );
    for (name, actual) in [
        ("service", request.evidence().service.as_deref()),
        ("commit", request.evidence().commit.as_deref()),
        ("ref", request.evidence().git_ref.as_deref()),
        ("snapshot", request.evidence().snapshot.as_deref()),
    ] {
        assert_eq!(
            actual,
            expected["evidence"].get(name).and_then(Value::as_str),
            "vector {id}: {name}"
        );
    }
    assert_eq!(
        request
            .evaluation()
            .trust
            .as_ref()
            .map(|trust| trust.canonical_text())
            .as_deref(),
        expected["evaluation"].get("trust").and_then(Value::as_str),
        "vector {id}: trust"
    );
    assert_eq!(
        request.evaluation().at,
        expected["evaluation"].get("at").and_then(Value::as_u64),
        "vector {id}: at"
    );
    if let Some(version) = expected["evidence"].get("version").and_then(Value::as_str) {
        assert!(
            request
                .canonical_uri()
                .contains(&format!("version={version}")),
            "vector {id}: version"
        );
    }
    if let Some(transport) = expected.get("transport").and_then(Value::as_str) {
        let Route::Git(authority) = request.route() else {
            panic!("vector {id}: expected Git route");
        };
        assert_eq!(authority.transport.to_string(), transport, "vector {id}");
        assert_eq!(
            authority.transport_user.as_deref(),
            expected.get("transportUser").and_then(Value::as_str),
            "vector {id}: transport user"
        );
        assert_eq!(
            request.git_repository_path().as_deref(),
            expected.get("repositoryPath").and_then(Value::as_str),
            "vector {id}: repository path"
        );
    }
    match (request.route(), expected["authority"].as_str()) {
        (Route::Kan(KanAuthority::Did(_)), Some(authority))
        | (Route::At(AtAuthority::Did(_)), Some(authority)) => {
            assert!(authority.starts_with("did:"), "vector {id}");
        }
        _ => {}
    }
    if expected.get("requestedScope").is_some() {
        assert!(matches!(request.scope(), Some(ScopeSelector::Direct(_))));
    }
}

#[test]
fn composite_trust_is_typed_ordered_and_duplicate_free() {
    let specs = vec![
        "roles".to_string(),
        "did:key:zExample=0.50".to_string(),
        "did:key:zExample=0.25".to_string(),
    ];
    let trust = kan::uri::TrustSelection::from_specs(&specs)
        .unwrap()
        .unwrap();
    let request = ResolutionRequest::local_subject(
        "bciqlonzrmcwluircewwu7evclx6tdwnc7aupnf6kb5no6nzlegmsiei"
            .parse()
            .unwrap(),
        "x",
        Some(&trust),
    )
    .unwrap();
    assert_eq!(
        request.evaluation().trust.as_ref().unwrap().specs(),
        ["roles", "did:key:zExample=0.5", "did:key:zExample=0.25"]
    );
    assert_eq!(
        request.canonical_uri(),
        "kan://local/@id:bciqlonzrmcwluircewwu7evclx6tdwnc7aupnf6kb5no6nzlegmsiei/subject/x?trust=@set:%5B%22roles%22,%22did:key:zExample=0.5%22,%22did:key:zExample=0.25%22%5D"
    );

    for invalid in [
        "kan://local/kan-tools:day/subject/x?trust=@set:%5B%22roles%22%5D",
        "kan://local/kan-tools:day/subject/x?trust=@set:%5B%22roles%22,%22roles%22%5D",
        "kan://local/kan-tools:day/subject/x?trust=@future:value",
    ] {
        assert!(ResolutionRequest::parse(invalid).is_err(), "{invalid}");
    }
}
