//! The CLI (`docs/HANDOFF.md`'s vocabulary table). M3 wires up the subset
//! needed to dogfood kan on its own further development: `observe`, `plan`,
//! `decide`, `show`, `status`, `session`. `same`/`resolve`/`issues`/`context`
//! need the real identity/contest fold (M4) or budgeted context assembly
//! (M5) and land there; `kan mcp` is M5.

mod context;
mod session;
mod show;
mod status;

use clap::{Parser, Subcommand};
use ipld_core::cid::Cid;

use crate::claim::{AuthorId, ClaimBody, ClaimContent, Rkey, SubjectRef};
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
    InvalidCites(String, ipld_core::cid::Error),
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

    let content = ClaimContent {
        author: AuthorId {
            did: ws.identity.did(),
            agent: None,
        },
        workspace: ws.anchor.clone(),
        subject,
        body: make_body(args.text),
        cites,
        artifacts: vec![],
    };

    let claim_cid = ws.log.append(content, &ws.identity).await?;
    let claims = ws.log.iter_all().await?;
    ws.index.rebuild(&claims)?;

    println!("{claim_cid}");
    Ok(())
}
