//! `kan mcp`: one `rmcp` tool per CLI verb (ADR-10, closing Open Question
//! Q3), mirroring `docs/HANDOFF.md`'s CLI vocabulary 1:1. Every tool call
//! dispatches to the exact same `crate::actions` functions the CLI calls —
//! this module is presentation (typed params in, text out) only.

use std::path::PathBuf;

use rmcp::{
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{
        ListResourceTemplatesResult, ReadResourceRequestParams, ReadResourceResult,
        ResourceContents, ResourceTemplate, ServerCapabilities, ServerInfo,
    },
    service::RequestContext,
    tool, tool_handler, tool_router, ErrorData, RoleServer, ServerHandler, ServiceExt,
};
use schemars::JsonSchema;
use serde::Deserialize;

use crate::{actions, context::DEFAULT_BUDGET, workspace::Workspace};

/// The one MCP resource kan exposes (REQ-17, issue #28, minimal scope): a
/// subject's live claims, addressable as `kan://claims/<subject>` — the
/// same data `show` returns, via URI instead of a tool call. No resource
/// enumeration (`resources/list` stays empty/default) and no prompts —
/// deliberately the smallest real slice, per issue #28's own framing.
const CLAIMS_URI_PREFIX: &str = "kan://claims/";

fn claims_uri(subject: &str) -> String {
    format!("{CLAIMS_URI_PREFIX}{subject}")
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    // Boxed: `ServerInitializeError` is far larger than `Join`'s payload,
    // and clippy flags the resulting enum-size skew otherwise.
    #[error("mcp server failed to initialize: {0}")]
    Initialize(#[from] Box<rmcp::service::ServerInitializeError>),
    #[error("mcp server task panicked: {0}")]
    Join(#[from] tokio::task::JoinError),
}

pub async fn serve(cwd: PathBuf) -> Result<(), Error> {
    let server = KanServer::new(cwd)
        .serve(rmcp::transport::stdio())
        .await
        .map_err(Box::new)?;
    server.waiting().await?;
    Ok(())
}

/// `kan mcp install` — prints, never mutates, both current/documented
/// Claude Code registration mechanisms (confirmed via research, not
/// guessed): a bare `claude mcp add` command, and (once this repo's
/// `.claude-plugin/plugin.json` + `.mcp.json` exist) the plugin path.
pub fn install_instructions() -> String {
    let exe = std::env::current_exe()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "kan".to_string());

    let mut out = String::new();
    out.push_str("Register kan as an MCP server -- either path works:\n\n");
    out.push_str("1. Directly:\n");
    out.push_str(&format!("     claude mcp add kan -- {exe} mcp\n\n"));
    out.push_str("2. As a Claude Code plugin (this repo ships .claude-plugin/plugin.json\n");
    out.push_str("   and .mcp.json declaring the same server):\n");
    out.push_str("     /plugin install <path to this repo, or its marketplace entry>\n");
    out
}

fn to_error(e: actions::Error) -> ErrorData {
    ErrorData::internal_error(e.to_string(), None)
}

fn open_error(e: crate::workspace::Error) -> ErrorData {
    ErrorData::internal_error(e.to_string(), None)
}

#[derive(Debug, Deserialize, JsonSchema)]
struct NarrativeParams {
    /// The text of the claim.
    text: String,
    /// Subject rkey this claim is about (default: "general").
    #[serde(default)]
    subject: Option<String>,
    /// CIDs of prior claims this one cites.
    #[serde(default)]
    cites: Vec<String>,
    #[serde(default)]
    #[schemars(
        description = "A more specific artifact than the automatic HEAD-commit anchor: \"path\" or \"path:start-end\"."
    )]
    file: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct SameParams {
    /// The subject asserted to be the same as `b`.
    a: String,
    /// The subject `a` is asserted to be the same as.
    b: String,
    /// CIDs of prior claims this one cites.
    #[serde(default)]
    cites: Vec<String>,
    #[serde(default)]
    #[schemars(
        description = "A more specific artifact than the automatic HEAD-commit anchor: \"path\" or \"path:start-end\"."
    )]
    file: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct ResolveParams {
    /// The subject being resolved.
    subject: String,
    /// How it was resolved.
    text: String,
    /// CIDs of prior claims the `Resolution` claim cites.
    #[serde(default)]
    cites: Vec<String>,
    #[serde(default)]
    #[schemars(
        description = "A more specific artifact than the automatic HEAD-commit anchor: \"path\" or \"path:start-end\"."
    )]
    file: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct BlockParams {
    /// The subject that is blocked.
    subject: String,
    /// What it's blocked on.
    text: String,
    #[serde(default)]
    #[schemars(
        description = "A more specific artifact than the automatic HEAD-commit anchor: \"path\" or \"path:start-end\"."
    )]
    file: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct RetractParams {
    /// The CID of the claim to retract (must be your own).
    cid: String,
    #[serde(default)]
    #[schemars(
        description = "A more specific artifact than the automatic HEAD-commit anchor: \"path\" or \"path:start-end\"."
    )]
    file: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct MarkParams {
    /// The subject to mark.
    subject: String,
    /// The status value to write.
    value: crate::claim::StatusValue,
    #[serde(default)]
    #[schemars(
        description = "A more specific artifact than the automatic HEAD-commit anchor: \"path\" or \"path:start-end\"."
    )]
    file: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct SubjectParams {
    /// The subject rkey to show.
    subject: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct StatusParams {
    /// The subject rkey to check, or omit for every subject.
    #[serde(default)]
    subject: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct ContextParams {
    /// Token budget (default: 4096).
    #[serde(default)]
    budget: Option<usize>,
}

#[derive(Clone)]
pub struct KanServer {
    cwd: PathBuf,
    tool_router: ToolRouter<Self>,
}

impl KanServer {
    pub fn new(cwd: PathBuf) -> Self {
        Self {
            cwd,
            tool_router: Self::tool_router(),
        }
    }

    async fn workspace(&self) -> Result<Workspace, ErrorData> {
        Workspace::open(&self.cwd).await.map_err(open_error)
    }
}

#[tool_router]
impl KanServer {
    #[tool(description = "Record a finding (ClaimBody::Observation).")]
    async fn observe(&self, params: Parameters<NarrativeParams>) -> Result<String, ErrorData> {
        let mut ws = self.workspace().await?;
        let p = params.0;
        actions::observe(
            &mut ws, p.text, p.subject, p.cites, p.file, None, None, None,
        )
        .await
        .map(|r| r.confirmation())
        .map_err(to_error)
    }

    #[tool(description = "Record an intended approach (ClaimBody::Plan).")]
    async fn plan(&self, params: Parameters<NarrativeParams>) -> Result<String, ErrorData> {
        let mut ws = self.workspace().await?;
        let p = params.0;
        actions::plan(
            &mut ws, p.text, p.subject, p.cites, p.file, None, None, None,
        )
        .await
        .map(|r| r.confirmation())
        .map_err(to_error)
    }

    #[tool(description = "Record a choice made (ClaimBody::Decision).")]
    async fn decide(&self, params: Parameters<NarrativeParams>) -> Result<String, ErrorData> {
        let mut ws = self.workspace().await?;
        let p = params.0;
        actions::decide(
            &mut ws, p.text, p.subject, p.cites, p.file, None, None, None,
        )
        .await
        .map(|r| r.confirmation())
        .map_err(to_error)
    }

    #[tool(description = "Assert that two subjects are the same (Relation::SameAs).")]
    async fn same(&self, params: Parameters<SameParams>) -> Result<String, ErrorData> {
        let mut ws = self.workspace().await?;
        let p = params.0;
        actions::same(&mut ws, &p.a, &p.b, p.cites, p.file)
            .await
            .map(|r| r.confirmation())
            .map_err(to_error)
    }

    #[tool(
        description = "Record that a subject has been resolved: pairs a Resolution claim with a Status{Resolved} claim citing it."
    )]
    async fn resolve(&self, params: Parameters<ResolveParams>) -> Result<String, ErrorData> {
        let mut ws = self.workspace().await?;
        let p = params.0;
        actions::resolve(&mut ws, &p.subject, &p.text, p.cites, p.file, None, None)
            .await
            .map(|r| r.confirmation())
            .map_err(to_error)
    }

    #[tool(
        description = "Record that a subject is blocked: pairs a Blocker claim with a Status{Blocked} claim citing it."
    )]
    async fn block(&self, params: Parameters<BlockParams>) -> Result<String, ErrorData> {
        let mut ws = self.workspace().await?;
        let p = params.0;
        actions::block(&mut ws, &p.subject, &p.text, p.file, None, None)
            .await
            .map(|r| r.confirmation())
            .map_err(to_error)
    }

    #[tool(
        description = "Retract a prior claim of your own (ClaimBody::Retraction). Also works on a Retraction itself, as the undo mechanism."
    )]
    async fn retract(&self, params: Parameters<RetractParams>) -> Result<String, ErrorData> {
        let mut ws = self.workspace().await?;
        let p = params.0;
        actions::retract(&mut ws, &p.cid, p.file)
            .await
            .map(|r| r.confirmation())
            .map_err(to_error)
    }

    #[tool(description = "Write a bare Status claim with no paired narrative.")]
    async fn mark(&self, params: Parameters<MarkParams>) -> Result<String, ErrorData> {
        let mut ws = self.workspace().await?;
        let p = params.0;
        actions::mark(&mut ws, &p.subject, p.value, p.file)
            .await
            .map(|r| r.confirmation())
            .map_err(to_error)
    }

    #[tool(description = "Show a subject's live claims.")]
    async fn show(&self, params: Parameters<SubjectParams>) -> Result<String, ErrorData> {
        let ws = self.workspace().await?;
        actions::show(&ws, &params.0.subject).map_err(to_error)
    }

    #[tool(description = "Show status classification: one subject, or every subject if omitted.")]
    async fn status(&self, params: Parameters<StatusParams>) -> Result<String, ErrorData> {
        let ws = self.workspace().await?;
        actions::status(&ws, params.0.subject.as_deref()).map_err(to_error)
    }

    #[tool(description = "List open (not-yet-resolved) subjects.")]
    async fn issues(&self) -> Result<String, ErrorData> {
        let ws = self.workspace().await?;
        actions::issues(&ws).map_err(to_error)
    }

    #[tool(description = "Assemble the maximal-value claim set that fits under a token budget.")]
    async fn context(&self, params: Parameters<ContextParams>) -> Result<String, ErrorData> {
        let ws = self.workspace().await?;
        actions::context(&ws, params.0.budget.unwrap_or(DEFAULT_BUDGET)).map_err(to_error)
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for KanServer {
    /// Factual, not prescriptive: describes what a subject is and what
    /// each tool does, deliberately without recommending an order of
    /// operations or a workflow — that's process, and kan's scope is the
    /// durable claim log and reads over it, not opinions about when an
    /// agent should call which tool (`docs/DECISIONS.md`'s
    /// kan/companion-tool boundary rule).
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(
            ServerCapabilities::builder()
                .enable_tools()
                .enable_resources()
                .build(),
        )
        .with_instructions(
            "kan is an append-only, signed, content-addressed claim log for this repo. \
             A \"subject\" is a freely-chosen name (e.g. \"bug-42\") that claims are \
             about; the same subject name always refers to the same thing within one \
             log. observe/plan/decide/resolve/same each append one claim of a \
             different kind (finding, intended approach, choice made, resolution, or \
             an identity assertion that two subjects are the same). show returns one \
             subject's full live claim history; status returns Settled/Confirmed/ \
             Contested classification for one subject, or a one-line summary for \
             every subject if none is given. issues lists subjects that aren't \
             resolved yet. context returns the highest-value claims that fit under a \
             token budget. A subject's live claims are also readable as a resource \
             at kan://claims/<subject>, the same data the show tool returns.",
        )
    }

    /// Advertises `kan://claims/{subject}` (REQ-17) — no fixed enumeration
    /// of every subject as a `resources/list` entry, since subjects are
    /// open-ended; a client constructs a URI from a subject name it already
    /// knows (e.g. from `show`/`issues`/`status`).
    async fn list_resource_templates(
        &self,
        _request: Option<rmcp::model::PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListResourceTemplatesResult, ErrorData> {
        Ok(ListResourceTemplatesResult::with_all_items(vec![
            ResourceTemplate::new("kan://claims/{subject}", "subject-claims")
                .with_description("A subject's live claims — the same data the show tool returns.")
                .with_mime_type("text/plain"),
        ]))
    }

    async fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResult, ErrorData> {
        let Some(subject) = request.uri.strip_prefix(CLAIMS_URI_PREFIX) else {
            return Err(ErrorData::resource_not_found(
                format!("no such resource: {}", request.uri),
                None,
            ));
        };
        let ws = self.workspace().await?;
        let text = actions::show(&ws, subject).map_err(to_error)?;
        Ok(ReadResourceResult::new(vec![ResourceContents::text(
            text,
            claims_uri(subject),
        )]))
    }
}
