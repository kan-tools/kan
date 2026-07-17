//! AC-9 (`.design/agent-ax-and-tool-boundary.md`): the repo's Claude Code
//! plugin manifest and bundled MCP server declaration are present and
//! well-formed — the second of `kan mcp install`'s two registration paths.

use std::path::Path;

#[test]
fn plugin_manifest_has_required_fields() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(".claude-plugin/plugin.json");
    let contents = std::fs::read_to_string(&path).expect("plugin.json should exist");
    let json: serde_json::Value =
        serde_json::from_str(&contents).expect("plugin.json should be valid JSON");

    assert!(
        json["name"].as_str().is_some_and(|s| !s.is_empty()),
        "plugin.json needs a non-empty name"
    );
    assert!(
        json["description"].as_str().is_some_and(|s| !s.is_empty()),
        "plugin.json needs a non-empty description"
    );
}

#[test]
fn mcp_json_declares_the_kan_server() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(".mcp.json");
    let contents = std::fs::read_to_string(&path).expect(".mcp.json should exist");
    let json: serde_json::Value =
        serde_json::from_str(&contents).expect(".mcp.json should be valid JSON");

    let kan = &json["mcpServers"]["kan"];
    assert_eq!(kan["command"].as_str(), Some("kan"));
    assert_eq!(kan["args"], serde_json::json!(["mcp"]));
}
