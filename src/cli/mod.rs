//! The CLI (`docs/HANDOFF.md`'s vocabulary table). M3 wired up `observe`,
//! `plan`, `decide`, `show`, `status`, `session`. M4a added `same` (the
//! identity fold). M4b adds `resolve`, git-genesis anchors
//! (`context::Workspace::open`), and `RelationProvider`s feeding
//! `status`'s state-fold classification. `issues`/`context` need budgeted
//! context assembly (M5); `kan mcp` is M5.

mod context;
mod session;
mod show;
mod status;

use atproto_dasl::Cid;
use clap::{Parser, Subcommand};

use crate::claim::{ClaimBody, ClaimContent, RelationKind, Rkey, SubjectRef};
pub use context::Workspace;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Context(#[from] context::Error),
    #[error(transparent)]
    Log(#[from] crate::store::log::Error),
    #[error(transparent)]
    Index(#[from] crate::store::index::Error),
    #[error("invalid --cites value {0:?}: {1}")]
    InvalidCites(String, atproto_dasl::DecodeError),
}

#[derive(Debug, Parser)]
#[command(name = "kan", about = "Local reasoning, global coherence.")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Record a finding.
    Observe(NarrativeArgs),
    /// Record an intended approach.
    Plan(NarrativeArgs),
    /// Record a choice made.
    Decide(NarrativeArgs),
    /// Show a subject's live claims.
    Show { subject: String },
    /// Show status: one subject, or every subject if omitted.
    Status { subject: Option<String> },
    /// Assert that `a` and `b` are the same subject (Relation::SameAs).
    Same { a: String, b: String },
    /// Record that a subject has been resolved.
    Resolve { subject: String, text: String },
    /// Session lifecycle.
    Session {
        #[command(subcommand)]
        action: SessionAction,
    },
}

#[derive(Debug, clap::Args)]
pub struct NarrativeArgs {
    pub text: String,
    /// Subject rkey this claim is about (default: "general").
    #[arg(long)]
    pub subject: Option<String>,
    /// CIDs of prior claims this one cites.
    #[arg(long = "cites")]
    pub cites: Vec<String>,
}

#[derive(Debug, Subcommand)]
pub enum SessionAction {
    Start,
    End {
        #[arg(long)]
        notes: Option<String>,
    },
}

const GENERAL_SUBJECT: &str = "general";

pub async fn run(cli: Cli) -> Result<(), Error> {
    let cwd = context::cwd()?;
    let mut ws = Workspace::open(&cwd).await?;

    match cli.command {
        Command::Observe(args) => {
            append_narrative(&mut ws, args, |text| ClaimBody::Observation { text }).await
        }
        Command::Plan(args) => {
            append_narrative(&mut ws, args, |text| ClaimBody::Plan { text }).await
        }
        Command::Decide(args) => {
            append_narrative(&mut ws, args, |text| ClaimBody::Decision { text }).await
        }
        Command::Show { subject } => show::show(&mut ws, &subject).await,
        Command::Status { subject } => status::status(&mut ws, subject.as_deref()).await,
        Command::Same { a, b } => same(&mut ws, &a, &b).await,
        Command::Resolve { subject, text } => resolve(&mut ws, &subject, &text).await,
        Command::Session { action } => match action {
            SessionAction::Start => session::start(&mut ws).await,
            SessionAction::End { notes } => session::end(&mut ws, notes).await,
        },
    }
}

async fn append_narrative(
    ws: &mut Workspace,
    args: NarrativeArgs,
    make_body: impl FnOnce(String) -> ClaimBody,
) -> Result<(), Error> {
    let subject = SubjectRef::Local(Rkey::from(
        args.subject.unwrap_or_else(|| GENERAL_SUBJECT.to_string()),
    ));
    let mut cites = Vec::with_capacity(args.cites.len());
    for raw in args.cites {
        let cid: Cid = raw
            .parse()
            .map_err(|e| Error::InvalidCites(raw.clone(), e))?;
        cites.push(cid);
    }

    append(ws, subject, make_body(args.text), cites).await
}

/// `kan same <a> <b>` — a directed, situated identity claim (`docs/SPEC.md`
/// §4.2): asserts `a` and `b` are the same subject from this author's
/// perspective. A single `SameAs` is one witness in the identity fold's
/// merge-class computation, not an immediate, unconditional merge — whether
/// it's honored depends on the viewer's `TrustBase`.
async fn same(ws: &mut Workspace, a: &str, b: &str) -> Result<(), Error> {
    let body = ClaimBody::Relation {
        kind: RelationKind::SameAs,
        target: SubjectRef::Local(Rkey::from(b)),
    };
    append(ws, SubjectRef::Local(Rkey::from(a)), body, vec![]).await
}

/// `kan resolve <subject> "<text>"` — asserts a subject is resolved
/// (`ClaimBody::Resolution`). Distinct from `ClaimBody::Status { value:
/// Resolved }`: this is a narrative claim (the fold never needs to reduce
/// or contest it), while `Status` is the structural, poset-classified kind
/// `fold::state` reduces (`docs/SPEC.md` §7).
async fn resolve(ws: &mut Workspace, subject: &str, text: &str) -> Result<(), Error> {
    let body = ClaimBody::Resolution {
        text: text.to_string(),
    };
    append(ws, SubjectRef::Local(Rkey::from(subject)), body, vec![]).await
}

async fn append(
    ws: &mut Workspace,
    subject: SubjectRef,
    body: ClaimBody,
    cites: Vec<Cid>,
) -> Result<(), Error> {
    let content = ClaimContent {
        author: ws.my_author(),
        workspace: ws.anchor.clone(),
        subject,
        body,
        cites,
        artifacts: vec![],
    };

    let claim_cid = ws.log.append(content, &ws.identity).await?;
    let claims = ws.log.iter_all().await?;
    ws.index.rebuild(&claims)?;

    println!("{claim_cid}");
    Ok(())
}
