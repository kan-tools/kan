// Unit fixtures stay outside production persistence modules.
use super::*;
#[test]
fn worker_disclosure_allowlist_applies_to_retained_ancestor_sources() {
    let mut directory = tempfile::Builder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        directory.permissions(std::fs::Permissions::from_mode(0o700));
    }
    let directory = directory.tempdir().unwrap();
    let workspace = Workspace::open(
        &directory.path().join("dependencies.sqlite"),
        crate::sign::Identity::generate(),
        [83; 32],
    )
    .unwrap();
    let parent = "a".repeat(64);
    let child = "b".repeat(64);
    for (id, source, parents) in [
        (&parent, "proof:other", vec![]),
        (&child, "proof:selected", vec![parent.clone()]),
    ] {
        workspace.put("analysis-job",id,json!({"draft":{"recipe":"session-brief","cites":[],"decode":true,"project":{"source":source,"subjects":["p"]},"derived_from":parents}})).unwrap();
        workspace
            .put("analysis-input", id, json!({"project":{"claims":[]}}))
            .unwrap();
    }
    assert!(matches!(
        worker_dependency_sources(&workspace, &child, &["proof:selected".into()]),
        Err(Failure::AccessLimited)
    ));
    assert!(worker_dependency_sources(
        &workspace,
        &child,
        &["proof:selected".into(), "proof:other".into()]
    )
    .is_ok());
}
#[test]
fn decoded_recipe_preserves_tool_arguments_and_partial_source_states_without_duplicate_events() {
    let input = json!({"pin":{"secret":"not prompt input"},"coverage":"partial","occurrences":[{"record":{"sequence":"4"}}],"groups":[{
        "request":{"state":"partial","parsed_json":{"duplicate":"huge"},"citation_sets":[[{"input":"0","bytes":["0","9000"]}]],"items":[{"kind":"context","text":null,"event_json":"whole envelope"},{"kind":"tool-use","text":"Write","event_json":"duplicate event","tool":{"json":"{\"content\":\"decide é🙂\"}","citation_set":"0"}}]},
        "response":{"state":"unavailable","parsed_json":null,"items":[],"citation_sets":[]}}]});
    let result = decoded_bundle(input).unwrap();
    assert_eq!(result["coverage"], "partial");
    assert!(result.get("pin").is_none());
    let stream = &result["groups"][0]["request"];
    assert_eq!(stream["items"].as_array().unwrap().len(), 1);
    assert!(stream.get("parsed_json").is_none());
    assert!(stream["items"][0].get("event_json").is_none());
    assert_eq!(
        stream["items"][0]["tool"]["json"],
        "{\"content\":\"decide é🙂\"}"
    );
    assert_eq!(stream["citation_sets"][0][0]["input"], "0");
    assert_eq!(result["groups"][0]["response"]["state"], "unavailable");
    let old: Draft =
        serde_json::from_value(json!({"recipe":"old","cites":[],"retry_of":null})).unwrap();
    assert!(!old.decode);
    assert!(serde_json::to_value(old).unwrap().get("decode").is_none());
    assert_eq!(bundled_recipes()[0].id, "documentation-summary");
    assert_eq!(bundled_recipes()[0].revision, "1");
}
