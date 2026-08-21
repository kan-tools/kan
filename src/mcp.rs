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

/// Map an action error to the right MCP category. A caller-shaped mistake —
/// a bad CID, rejecting your own claim, `--title` without `--kind` — is
/// `invalid_params`, the same reasoning `trust_error` already uses: an agent
/// reads `internal_error` as a server fault it cannot fix and gives up,
/// rather than as its own fixable input (review/full-pass-v0.12 F5). Only
/// genuine substrate failures (store, index, git, publish, workspace) stay
/// `internal_error`.
fn to_error(e: actions::Error) -> ErrorData {
    match e {
        actions::Error::Usage(_)
        | actions::Error::InvalidCid(_, _)
        | actions::Error::UnknownClaim(_)
        | actions::Error::UnsupportedCorrectionTarget(_, _)
        | actions::Error::NotYourClaim(_)
        | actions::Error::CantRejectOwnClaim(_)
        | actions::Error::TitleKindRequireEachOther => {
            ErrorData::invalid_params(e.to_string(), None)
        }
        actions::Error::Publish(_)
        | actions::Error::Workspace(_)
        | actions::Error::Log(_)
        | actions::Error::Index(_)
        | actions::Error::Git(_) => ErrorData::internal_error(e.to_string(), None),
    }
}

fn open_error(e: crate::workspace::Error) -> ErrorData {
    ErrorData::internal_error(e.to_string(), None)
}

/// A malformed `trust` argument is the caller's mistake, not kan's, so it
/// surfaces as `invalid_params`. The important half is that it *fails*: a
/// tolerated-and-ignored trust selector would hand back a `Solo` view in
/// reply to a request for a wider one, with a success code attached
/// (`.design/kan-read-contract.md` REQ-4).
fn trust_error(e: crate::workspace::Error) -> ErrorData {
    ErrorData::invalid_params(e.to_string(), None)
}

/// `actions::warn_similar_subjects` for a single candidate (issue #47,
/// REQ-6/7) — `None` skips the check entirely, the same reasoning
/// `cli::subject_warnings` uses.
fn subject_warnings(ws: &Workspace, candidate: Option<&str>) -> Result<Vec<String>, ErrorData> {
    match candidate {
        Some(c) => actions::warn_similar_subjects(ws, &[c]).map_err(to_error),
        None => Ok(Vec::new()),
    }
}

/// REQ-8: appended as extra lines to the confirmation text MCP write tools
/// already return — unlike the CLI's stderr channel, MCP has no side
/// channel separate from the tool's own response, so the warning has to
/// ride in the same string.
fn append_warnings(mut confirmation: String, warnings: Vec<String>) -> String {
    for warning in warnings {
        confirmation.push('\n');
        confirmation.push_str("warning: ");
        confirmation.push_str(&warning);
    }
    confirmation
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
    /// Pairs a Status claim citing this one — the same pairing `resolve`/
    /// `block` hardcode, generalized to any status value.
    #[serde(default)]
    status: Option<StatusParam>,
    /// Declares the subject (ClaimBody::Subject) alongside this claim —
    /// requires `kind` too.
    #[serde(default)]
    title: Option<String>,
    /// Declares the subject's kind alongside this claim — requires `title`
    /// too.
    #[serde(default)]
    kind: Option<SubjectKindParam>,
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

/// The kind of domain edge to assert. Use `same` for identity, not this.
//
// Mirrors `claim::RelationKind` minus `SameAs` — the MCP counterpart to
// `cli::RelationKindArg`, enforced at the deserialization boundary rather
// than by a runtime check in `actions::relate`. A `//` comment on purpose:
// `schemars` would publish a doc comment here into every agent's context.
// kebab-case on the wire, because that is what every tool description and
// the CLI teach; the PascalCase forms this schema used to publish are kept
// as aliases so an agent (or a saved call) written against the old schema
// still deserializes (review/full-pass-v0.12 F5). The signed-content enums
// in `claim.rs` are deliberately NOT touched — their PascalCase is baked
// into CIDs — so the rename lives here, in the MCP mirror, exactly as the
// `SameAs`-minus pattern already did for the variant set.
#[derive(Debug, Clone, Copy, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
enum RelateKindParam {
    #[serde(alias = "Blocks")]
    Blocks,
    #[serde(alias = "About")]
    About,
    #[serde(alias = "ManifestsAt")]
    ManifestsAt,
    #[serde(alias = "DependsOn")]
    DependsOn,
    #[serde(alias = "Accepts")]
    Accepts,
    #[serde(alias = "InTensionWith")]
    InTensionWith,
    #[serde(alias = "Supersedes")]
    Supersedes,
    #[serde(alias = "Refutes")]
    Refutes,
}

/// MCP mirror of [`crate::claim::v1::StatusValue`], kebab-case with PascalCase
/// aliases. The claim type keeps its own serde untouched (signed content);
/// this exists only so the wire vocabulary matches the descriptions.
#[derive(Debug, Clone, Copy, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
enum StatusParam {
    #[serde(alias = "Open")]
    Open,
    #[serde(alias = "InProgress")]
    InProgress,
    #[serde(alias = "Blocked")]
    Blocked,
    #[serde(alias = "Resolved")]
    Resolved,
    #[serde(alias = "Closed")]
    Closed,
}

impl From<StatusParam> for crate::claim::v1::StatusValue {
    fn from(value: StatusParam) -> Self {
        match value {
            StatusParam::Open => Self::Open,
            StatusParam::InProgress => Self::InProgress,
            StatusParam::Blocked => Self::Blocked,
            StatusParam::Resolved => Self::Resolved,
            StatusParam::Closed => Self::Closed,
        }
    }
}

/// MCP mirror of [`crate::claim::v1::SubjectKind`], kebab-case with PascalCase
/// aliases. (Every variant here is a single word, so kebab-case and the
/// lowercased original coincide; the aliases keep the capitalized forms the
/// old schema advertised.)
#[derive(Debug, Clone, Copy, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
enum SubjectKindParam {
    #[serde(alias = "Issue")]
    Issue,
    #[serde(alias = "Idea")]
    Idea,
    #[serde(alias = "Question")]
    Question,
}

impl From<SubjectKindParam> for crate::claim::v1::SubjectKind {
    fn from(value: SubjectKindParam) -> Self {
        match value {
            SubjectKindParam::Issue => Self::Issue,
            SubjectKindParam::Idea => Self::Idea,
            SubjectKindParam::Question => Self::Question,
        }
    }
}

impl From<RelateKindParam> for crate::claim::v1::RelationKind {
    fn from(value: RelateKindParam) -> Self {
        match value {
            RelateKindParam::Blocks => Self::Blocks,
            RelateKindParam::About => Self::About,
            RelateKindParam::ManifestsAt => Self::ManifestsAt,
            RelateKindParam::DependsOn => Self::DependsOn,
            RelateKindParam::Accepts => Self::Accepts,
            RelateKindParam::InTensionWith => Self::InTensionWith,
            RelateKindParam::Supersedes => Self::Supersedes,
            RelateKindParam::Refutes => Self::Refutes,
        }
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
struct RelateParams {
    /// The subject the edge is asserted from.
    a: String,
    /// The kind of domain-semantic edge asserted.
    kind: RelateKindParam,
    /// The subject the edge is asserted to.
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
    /// Declares the subject (ClaimBody::Subject) alongside this claim —
    /// requires `kind` too.
    #[serde(default)]
    title: Option<String>,
    /// Declares the subject's kind alongside this claim — requires `title`
    /// too.
    #[serde(default)]
    kind: Option<SubjectKindParam>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct ResultParams {
    /// The subject the action's outcome is about.
    subject: String,
    /// What happened.
    text: String,
    /// CIDs of prior claims this one cites.
    #[serde(default)]
    cites: Vec<String>,
    #[serde(default)]
    #[schemars(
        description = "A more specific artifact than the automatic HEAD-commit anchor: \"path\" or \"path:start-end\"."
    )]
    file: Option<String>,
    /// Pairs a Status claim citing this one — the same pairing resolve/
    /// block hardcode, generalized.
    #[serde(default)]
    status: Option<StatusParam>,
    /// Declares the subject (ClaimBody::Subject) alongside this claim —
    /// requires `kind` too.
    #[serde(default)]
    title: Option<String>,
    /// Declares the subject's kind alongside this claim — requires `title`
    /// too.
    #[serde(default)]
    kind: Option<SubjectKindParam>,
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
    /// Declares the subject (ClaimBody::Subject) alongside this claim —
    /// requires `kind` too.
    #[serde(default)]
    title: Option<String>,
    /// Declares the subject's kind alongside this claim — requires `title`
    /// too.
    #[serde(default)]
    kind: Option<SubjectKindParam>,
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
struct RejectParams {
    /// The CID of the claim to reject (must be another author's).
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
    value: StatusParam,
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
    /// Whose claims to fold in, beyond your own. Each entry is a
    /// "did:key:...", "me" (this workspace's identity), "local" (every
    /// author already in this log), "roles" (every declared role), or
    /// "role:<name>". Omit to see only your own claims. An author you do
    /// not name is invisible, not down-weighted. A "did:key:...=<weight>"
    /// form is accepted but the weight is not yet folded -- only presence
    /// or absence changes the view (issue on weighted trust; see kan show
    /// --help).
    #[serde(default)]
    trust: Vec<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct StatusParams {
    /// The subject rkey to check, or omit for every subject.
    #[serde(default)]
    subject: Option<String>,
    /// See the `show` tool's `trust`.
    #[serde(default)]
    trust: Vec<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct TrustParams {
    /// See the `show` tool's `trust`.
    #[serde(default)]
    trust: Vec<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct ContextParams {
    /// Token budget (default: 4096).
    #[serde(default)]
    budget: Option<usize>,
    /// See the `show` tool's `trust`.
    #[serde(default)]
    trust: Vec<String>,
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

    /// Open for writing, **refusing an unusable subject name first**.
    ///
    /// An **early** refusal: a bad subject name is reported before a
    /// workspace is opened, so the error arrives before any store I/O.
    ///
    /// It is not what delivers REQ-3's "a refused write mints nothing" —
    /// that comes from `commit_identity` running inside `append` after
    /// validation, which holds for every failure cause rather than for the
    /// ones anybody hoisted. This was written when it *was* the mechanism.
    /// Kept because the CLI does the same and one surface should not refuse
    /// later than the other (CLAUDE.md's "one surface: CLI + MCP").
    async fn writing_workspace(&self, subjects: &[Option<&str>]) -> Result<Workspace, ErrorData> {
        for subject in subjects.iter().flatten() {
            actions::validate_subject_name(subject).map_err(to_error)?;
        }
        Workspace::open(&self.cwd).await.map_err(open_error)
    }

    /// The read tools' workspace: no identity resolved, no anchor computed,
    /// nothing created (`.design/identity-surface.md` REQ-2).
    ///
    /// This matters more here than on the CLI. An MCP server is a long-lived
    /// process with no terminal, so a keychain prompt raised by a read is one
    /// nobody can answer (#96) -- `kan status` over MCP failed exactly that
    /// way while this milestone was being built. A read that needs no
    /// identity cannot raise it.
    async fn reader(&self) -> Result<Workspace, ErrorData> {
        Workspace::open_read_only(&self.cwd)
            .await
            .map_err(open_error)
    }
}

#[tool_router]
impl KanServer {
    #[tool(
        description = "Record something you noticed -- a fact about the current state, not something you did (ClaimBody::Observation). Use result instead for the outcome of an action you took."
    )]
    async fn observe(&self, params: Parameters<NarrativeParams>) -> Result<String, ErrorData> {
        let p = params.0;
        let mut ws = self.writing_workspace(&[p.subject.as_deref()]).await?;
        let warnings = subject_warnings(&ws, p.subject.as_deref())?;
        actions::observe(
            &mut ws,
            p.text,
            p.subject,
            p.cites,
            p.file,
            p.status.map(Into::into),
            p.title,
            p.kind.map(Into::into),
        )
        .await
        .map(|r| append_warnings(r.confirmation(), warnings))
        .map_err(to_error)
    }

    #[tool(description = "Record an intended approach (ClaimBody::Plan).")]
    async fn plan(&self, params: Parameters<NarrativeParams>) -> Result<String, ErrorData> {
        let p = params.0;
        let mut ws = self.writing_workspace(&[p.subject.as_deref()]).await?;
        let warnings = subject_warnings(&ws, p.subject.as_deref())?;
        actions::plan(
            &mut ws,
            p.text,
            p.subject,
            p.cites,
            p.file,
            p.status.map(Into::into),
            p.title,
            p.kind.map(Into::into),
        )
        .await
        .map(|r| append_warnings(r.confirmation(), warnings))
        .map_err(to_error)
    }

    #[tool(description = "Record a choice made (ClaimBody::Decision).")]
    async fn decide(&self, params: Parameters<NarrativeParams>) -> Result<String, ErrorData> {
        let p = params.0;
        let mut ws = self.writing_workspace(&[p.subject.as_deref()]).await?;
        let warnings = subject_warnings(&ws, p.subject.as_deref())?;
        actions::decide(
            &mut ws,
            p.text,
            p.subject,
            p.cites,
            p.file,
            p.status.map(Into::into),
            p.title,
            p.kind.map(Into::into),
        )
        .await
        .map(|r| append_warnings(r.confirmation(), warnings))
        .map_err(to_error)
    }

    #[tool(
        description = "Record that a subject is blocked: pairs a Blocker claim with a Status{Blocked} claim citing it."
    )]
    async fn block(&self, params: Parameters<BlockParams>) -> Result<String, ErrorData> {
        let p = params.0;
        let mut ws = self.writing_workspace(&[Some(p.subject.as_str())]).await?;
        let warnings = subject_warnings(&ws, Some(&p.subject))?;
        actions::block(
            &mut ws,
            &p.subject,
            &p.text,
            p.file,
            p.title,
            p.kind.map(Into::into),
        )
        .await
        .map(|r| append_warnings(r.confirmation(), warnings))
        .map_err(to_error)
    }

    #[tool(
        description = "Record that a subject is now resolved -- an outcome that also closes the subject out; use result instead when it doesn't. Pairs a Resolution claim with a Status{Resolved} claim citing it."
    )]
    async fn resolve(&self, params: Parameters<ResolveParams>) -> Result<String, ErrorData> {
        let p = params.0;
        let mut ws = self.writing_workspace(&[Some(p.subject.as_str())]).await?;
        let warnings = subject_warnings(&ws, Some(&p.subject))?;
        actions::resolve(
            &mut ws,
            &p.subject,
            &p.text,
            p.cites,
            p.file,
            p.title,
            p.kind.map(Into::into),
        )
        .await
        .map(|r| append_warnings(r.confirmation(), warnings))
        .map_err(to_error)
    }

    #[tool(
        description = "Record the outcome of an action you just took -- what happened after you ran something, changed something, or executed a step (ClaimBody::Result). Use resolve instead when the outcome also means this subject's work is done."
    )]
    async fn result(&self, params: Parameters<ResultParams>) -> Result<String, ErrorData> {
        let p = params.0;
        let mut ws = self.writing_workspace(&[Some(p.subject.as_str())]).await?;
        let warnings = subject_warnings(&ws, Some(&p.subject))?;
        actions::result(
            &mut ws,
            &p.subject,
            &p.text,
            p.cites,
            p.file,
            p.status.map(Into::into),
            p.title,
            p.kind.map(Into::into),
        )
        .await
        .map(|r| append_warnings(r.confirmation(), warnings))
        .map_err(to_error)
    }

    #[tool(description = "Assert that two subjects are the same (Relation::SameAs).")]
    async fn same(&self, params: Parameters<SameParams>) -> Result<String, ErrorData> {
        let p = params.0;
        let mut ws = self
            .writing_workspace(&[Some(p.a.as_str()), Some(p.b.as_str())])
            .await?;
        let warnings = actions::warn_similar_subjects(&ws, &[&p.a, &p.b]).map_err(to_error)?;
        actions::same(&mut ws, &p.a, &p.b, p.cites, p.file)
            .await
            .map(|r| append_warnings(r.confirmation(), warnings))
            .map_err(to_error)
    }

    #[tool(
        description = "Assert a domain edge between two subjects: blocks, about, \
                       manifests-at, depends-on, accepts, in-tension-with, supersedes, or \
                       refutes. Not for \
                       identity -- use `same` for that."
    )]
    async fn relate(&self, params: Parameters<RelateParams>) -> Result<String, ErrorData> {
        let p = params.0;
        let mut ws = self
            .writing_workspace(&[Some(p.a.as_str()), Some(p.b.as_str())])
            .await?;
        let warnings = actions::warn_similar_subjects(&ws, &[&p.a, &p.b]).map_err(to_error)?;
        actions::relate(&mut ws, &p.a, p.kind.into(), &p.b, p.cites, p.file)
            .await
            .map(|r| append_warnings(r.confirmation(), warnings))
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

    #[tool(
        description = "Reject another author's claim (ClaimBody::Rejects) -- a local suppression honored only by folds that trust you. Errors, pointing to retract, if the target is your own claim."
    )]
    async fn reject(&self, params: Parameters<RejectParams>) -> Result<String, ErrorData> {
        let mut ws = self.workspace().await?;
        let p = params.0;
        actions::reject(&mut ws, &p.cid, p.file)
            .await
            .map(|r| r.confirmation())
            .map_err(to_error)
    }

    #[tool(description = "Write a bare Status claim with no paired narrative.")]
    async fn mark(&self, params: Parameters<MarkParams>) -> Result<String, ErrorData> {
        let p = params.0;
        let mut ws = self.writing_workspace(&[Some(p.subject.as_str())]).await?;
        let warnings = subject_warnings(&ws, Some(&p.subject))?;
        actions::mark(&mut ws, &p.subject, p.value.into(), p.file)
            .await
            .map(|r| append_warnings(r.confirmation(), warnings))
            .map_err(to_error)
    }

    #[tool(description = "Show a subject's live claims.")]
    async fn show(&self, params: Parameters<SubjectParams>) -> Result<String, ErrorData> {
        let ws = self.reader().await?;
        let (trust, empty_reason) = ws
            .trust_from_detailed(&params.0.trust)
            .map_err(trust_error)?;
        actions::show(&ws, &params.0.subject, &trust, empty_reason.as_deref()).map_err(to_error)
    }

    #[tool(
        description = "Show a subject's settled status, or a one-line summary of every \
                       subject if omitted."
    )]
    async fn status(&self, params: Parameters<StatusParams>) -> Result<String, ErrorData> {
        let ws = self.reader().await?;
        let (trust, empty_reason) = ws
            .trust_from_detailed(&params.0.trust)
            .map_err(trust_error)?;
        actions::status(
            &ws,
            params.0.subject.as_deref(),
            &trust,
            empty_reason.as_deref(),
        )
        .map_err(to_error)
    }

    #[tool(description = "List open (not-yet-resolved) subjects.")]
    async fn issues(&self, params: Parameters<TrustParams>) -> Result<String, ErrorData> {
        let ws = self.reader().await?;
        let (trust, empty_reason) = ws
            .trust_from_detailed(&params.0.trust)
            .map_err(trust_error)?;
        actions::issues(&ws, &trust, empty_reason.as_deref()).map_err(to_error)
    }

    #[tool(description = "Assemble the maximal-value claim set that fits under a token budget.")]
    async fn context(&self, params: Parameters<ContextParams>) -> Result<String, ErrorData> {
        let ws = self.reader().await?;
        let (trust, empty_reason) = ws
            .trust_from_detailed(&params.0.trust)
            .map_err(trust_error)?;
        actions::context(
            &ws,
            params.0.budget.unwrap_or(DEFAULT_BUDGET),
            &trust,
            empty_reason.as_deref(),
        )
        .map_err(to_error)
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for KanServer {
    /// Factual, not prescriptive: describes what a subject is and what
    /// each tool does, deliberately without recommending an order of
    /// operations or a workflow — that's process, and kan's scope is the
    /// durable claim log and reads over it, not opinions about when an
    /// agent should call which tool (`docs/DECISIONS.md`'s
    /// kan/companion-tool boundary rule). REQ-11: organized around the same
    /// four AX phases `cli::Command`'s declaration order groups by
    /// (Recording, Structuring, Correcting, Recalling), still guarded by
    /// `tests/mcp_server.rs`'s sequencing-language check.
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
             log. The tool surface groups into four phases. Recording (observe/plan/ \
             decide/block/resolve/result) each append a narrative claim (finding, \
             intended approach, choice made, blocker, resolution, or the outcome of \
             an action taken); block/resolve also pair a Status claim, observe/plan/ \
             decide/result can optionally pair one too via a status param, and every \
             Recording tool can optionally declare the subject's title/kind. observe \
             records something noticed; result records the outcome of an action \
             without necessarily closing anything out; resolve records an outcome \
             that also closes the subject (pairs Status{Resolved}). Structuring \
             (same/relate/mark) asserts \
             relationships and status independent of any narrative: same asserts two \
             subjects are the same, relate asserts a domain edge (blocks/about/ \
             manifests-at/depends-on/accepts/in-tension-with/supersedes/refutes), mark writes a \
             bare status value. \
             Correcting (retract/reject) supersedes a claim: retract for your own, \
             reject (a local suppression honored only by trusting folds) for another \
             author's. Recalling (show/status/issues/context) reads the claim graph: \
             show returns one subject's full live claim history; status returns \
             settled status for one subject, or a \
             one-line summary for every subject if none is given; issues lists \
             subjects that aren't resolved yet; context returns the highest-value \
             claims that fit under a token budget. A subject's live claims are also \
             readable as a resource at kan://claims/<subject>, the same data the show \
             tool returns.",
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
        let ws = self.reader().await?;
        // The resource URI carries a subject and nothing else, so this is
        // the default view — the same thing `show` with no `trust` returns,
        // which is what the resource template advertises. A trust-selected
        // read is a tool call, where the selection has somewhere to live.
        let trust = ws.local_trust().map_err(open_error)?;
        // `local` needs no explanation: it is every author in this log, so an
        // empty one means an empty log rather than a frame that excluded
        // something.
        let text = actions::show(&ws, subject, &trust, None).map_err(to_error)?;
        Ok(ReadResourceResult::new(vec![ResourceContents::text(
            text,
            claims_uri(subject),
        )]))
    }
}
