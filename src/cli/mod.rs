//! The CLI (`docs/HANDOFF.md`'s vocabulary table): argument parsing and
//! printing only — every command dispatches straight to `crate::actions`,
//! the one action layer this surface shares with `kan mcp`
//! (`CLAUDE.md`'s "one surface: CLI + MCP").

use clap::{Parser, Subcommand};

use crate::{actions, context::DEFAULT_BUDGET, workspace::Workspace};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Workspace(#[from] crate::workspace::Error),
    #[error(transparent)]
    Actions(#[from] actions::Error),
    // Boxed to match `mcp::Error::Initialize`'s own boxing — see that
    // variant's comment.
    #[error(transparent)]
    Mcp(#[from] Box<crate::mcp::Error>),
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
    /// List open (not-yet-resolved) subjects.
    Issues,
    /// Session lifecycle.
    Session {
        #[command(subcommand)]
        action: SessionAction,
    },
    /// Assemble the maximal-value claim set that fits under a token budget.
    Context {
        #[arg(long)]
        budget: Option<usize>,
    },
    /// Start the MCP server over stdio.
    Mcp,
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

pub async fn run(cli: Cli) -> Result<(), Error> {
    let cwd = crate::workspace::cwd()?;

    // `kan mcp` doesn't open a single `Workspace` up front — it's a
    // long-lived process serving many tool calls, each of which opens its
    // own (`crate::workspace::Workspace::open`'s doc comment).
    if let Command::Mcp = cli.command {
        crate::mcp::serve(cwd).await.map_err(Box::new)?;
        return Ok(());
    }

    let mut ws = Workspace::open(&cwd).await?;
    match cli.command {
        Command::Observe(args) => {
            let cid = actions::observe(&mut ws, args.text, args.subject, args.cites).await?;
            println!("{cid}");
        }
        Command::Plan(args) => {
            let cid = actions::plan(&mut ws, args.text, args.subject, args.cites).await?;
            println!("{cid}");
        }
        Command::Decide(args) => {
            let cid = actions::decide(&mut ws, args.text, args.subject, args.cites).await?;
            println!("{cid}");
        }
        Command::Show { subject } => print!("{}", actions::show(&ws, &subject)?),
        Command::Status { subject } => print!("{}", actions::status(&ws, subject.as_deref())?),
        Command::Same { a, b } => {
            let cid = actions::same(&mut ws, &a, &b).await?;
            println!("{cid}");
        }
        Command::Resolve { subject, text } => {
            let cid = actions::resolve(&mut ws, &subject, &text).await?;
            println!("{cid}");
        }
        Command::Issues => print!("{}", actions::issues(&ws)?),
        Command::Session { action } => {
            let cid = match action {
                SessionAction::Start => actions::session_start(&mut ws).await?,
                SessionAction::End { notes } => actions::session_end(&mut ws, notes).await?,
            };
            println!("{cid}");
        }
        Command::Context { budget } => {
            print!(
                "{}",
                actions::context(&ws, budget.unwrap_or(DEFAULT_BUDGET))?
            );
        }
        Command::Mcp => unreachable!("handled above"),
    }
    Ok(())
}
