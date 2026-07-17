//! `kan mcp`: one `rmcp` tool per CLI verb (ADR-10, closing Open Question
//! Q3), mirroring `docs/HANDOFF.md`'s CLI vocabulary 1:1. Every tool call
//! dispatches to the exact same `crate::actions` functions the CLI calls —
//! this module is presentation (typed params in, text out) only.

use std::path::PathBuf;

use rmcp::{
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{ServerCapabilities, ServerInfo},
    tool, tool_handler, tool_router, ErrorData, ServerHandler, ServiceExt,
};
use schemars::JsonSchema;
use serde::Deserialize;

use crate::{actions, context::DEFAULT_BUDGET, workspace::Workspace};

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
}

#[derive(Debug, Deserialize, JsonSchema)]
struct SameParams {
    /// The subject asserted to be the same as `b`.
    a: String,
    /// The subject `a` is asserted to be the same as.
    b: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct ResolveParams {
    /// The subject being resolved.
    subject: String,
    /// How it was resolved.
    text: String,
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
struct SessionEndParams {
    /// Optional closing notes.
    #[serde(default)]
    notes: Option<String>,
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
        actions::observe(&mut ws, p.text, p.subject, p.cites)
            .await
            .map(|cid| cid.to_string())
            .map_err(to_error)
    }

    #[tool(description = "Record an intended approach (ClaimBody::Plan).")]
    async fn plan(&self, params: Parameters<NarrativeParams>) -> Result<String, ErrorData> {
        let mut ws = self.workspace().await?;
        let p = params.0;
        actions::plan(&mut ws, p.text, p.subject, p.cites)
            .await
            .map(|cid| cid.to_string())
            .map_err(to_error)
    }

    #[tool(description = "Record a choice made (ClaimBody::Decision).")]
    async fn decide(&self, params: Parameters<NarrativeParams>) -> Result<String, ErrorData> {
        let mut ws = self.workspace().await?;
        let p = params.0;
        actions::decide(&mut ws, p.text, p.subject, p.cites)
            .await
            .map(|cid| cid.to_string())
            .map_err(to_error)
    }

    #[tool(description = "Assert that two subjects are the same (Relation::SameAs).")]
    async fn same(&self, params: Parameters<SameParams>) -> Result<String, ErrorData> {
        let mut ws = self.workspace().await?;
        actions::same(&mut ws, &params.0.a, &params.0.b)
            .await
            .map(|cid| cid.to_string())
            .map_err(to_error)
    }

    #[tool(description = "Record that a subject has been resolved (ClaimBody::Resolution).")]
    async fn resolve(&self, params: Parameters<ResolveParams>) -> Result<String, ErrorData> {
        let mut ws = self.workspace().await?;
        actions::resolve(&mut ws, &params.0.subject, &params.0.text)
            .await
            .map(|cid| cid.to_string())
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

    #[tool(description = "Start a session.")]
    async fn session_start(&self) -> Result<String, ErrorData> {
        let mut ws = self.workspace().await?;
        actions::session_start(&mut ws)
            .await
            .map(|cid| cid.to_string())
            .map_err(to_error)
    }

    #[tool(description = "End a session, optionally with closing notes.")]
    async fn session_end(&self, params: Parameters<SessionEndParams>) -> Result<String, ErrorData> {
        let mut ws = self.workspace().await?;
        actions::session_end(&mut ws, params.0.notes)
            .await
            .map(|cid| cid.to_string())
            .map_err(to_error)
    }

    #[tool(description = "Assemble the maximal-value claim set that fits under a token budget.")]
    async fn context(&self, params: Parameters<ContextParams>) -> Result<String, ErrorData> {
        let ws = self.workspace().await?;
        actions::context(&ws, params.0.budget.unwrap_or(DEFAULT_BUDGET)).map_err(to_error)
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for KanServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build()).with_instructions(
            "kan: an append-only, provenance-preserving claim log for this repo. \
                 Use observe/plan/decide/resolve/same to record; show/status/issues/context \
                 to read.",
        )
    }
}
