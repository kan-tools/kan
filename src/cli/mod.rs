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
    Same {
        a: String,
        b: String,
        /// Print a human-readable confirmation instead of the bare CID.
        #[arg(long, short)]
        verbose: bool,
    },
    /// Record that a subject has been resolved.
    Resolve {
        subject: String,
        text: String,
        /// Print a human-readable confirmation instead of the bare CID.
        #[arg(long, short)]
        verbose: bool,
    },
    /// List open (not-yet-resolved) subjects.
    Issues,
    /// Assemble the maximal-value claim set that fits under a token budget.
    Context {
        #[arg(long)]
        budget: Option<usize>,
    },
    /// MCP server over stdio, and related setup.
    Mcp {
        #[command(subcommand)]
        action: Option<McpAction>,
    },
}

#[derive(Debug, Subcommand)]
pub enum McpAction {
    /// Print registration instructions for this binary — no config-file
    /// mutation, just the commands to run.
    Install,
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
    /// Print a human-readable confirmation instead of the bare CID.
    #[arg(long, short)]
    pub verbose: bool,
}

pub async fn run(cli: Cli) -> Result<(), Error> {
    let cwd = crate::workspace::cwd()?;

    // `kan mcp` doesn't open a single `Workspace` up front — it's a
    // long-lived process serving many tool calls, each of which opens its
    // own (`crate::workspace::Workspace::open`'s doc comment).
    if let Command::Mcp { action } = &cli.command {
        match action {
            None => {
                crate::mcp::serve(cwd).await.map_err(Box::new)?;
            }
            Some(McpAction::Install) => print!("{}", crate::mcp::install_instructions()),
        }
        return Ok(());
    }

    let mut ws = Workspace::open(&cwd).await?;
    match cli.command {
        Command::Observe(args) => {
            let verbose = args.verbose;
            let result = actions::observe(&mut ws, args.text, args.subject, args.cites).await?;
            print_result(&result, verbose);
        }
        Command::Plan(args) => {
            let verbose = args.verbose;
            let result = actions::plan(&mut ws, args.text, args.subject, args.cites).await?;
            print_result(&result, verbose);
        }
        Command::Decide(args) => {
            let verbose = args.verbose;
            let result = actions::decide(&mut ws, args.text, args.subject, args.cites).await?;
            print_result(&result, verbose);
        }
        Command::Show { subject } => print!("{}", actions::show(&ws, &subject)?),
        Command::Status { subject } => print!("{}", actions::status(&ws, subject.as_deref())?),
        Command::Same { a, b, verbose } => {
            let result = actions::same(&mut ws, &a, &b).await?;
            print_result(&result, verbose);
        }
        Command::Resolve {
            subject,
            text,
            verbose,
        } => {
            let result = actions::resolve(&mut ws, &subject, &text).await?;
            print_result(&result, verbose);
        }
        Command::Issues => print!("{}", actions::issues(&ws)?),
        Command::Context { budget } => {
            print!(
                "{}",
                actions::context(&ws, budget.unwrap_or(DEFAULT_BUDGET))?
            );
        }
        Command::Mcp { .. } => unreachable!("handled above"),
    }
    Ok(())
}

fn print_result(result: &actions::AppendResult, verbose: bool) {
    if verbose {
        println!("{}", result.confirmation());
    } else {
        println!("{}", result.cid);
    }
}
