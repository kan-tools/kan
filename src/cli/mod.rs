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
        /// CIDs of prior claims this one cites.
        #[arg(long = "cites")]
        cites: Vec<String>,
        /// A more specific artifact than the automatic HEAD-commit anchor:
        /// `path` or `path:start-end`.
        #[arg(long)]
        file: Option<String>,
        /// Print a human-readable confirmation instead of the bare CID.
        #[arg(long, short)]
        verbose: bool,
    },
    /// Assert a domain-semantic edge between `a` and `b` (Relation::{Blocks,
    /// About, ManifestsAt, DependsOn, Accepts}). Not for identity — use
    /// `kan same` for `SameAs`.
    Relate {
        a: String,
        kind: RelationKindArg,
        b: String,
        /// CIDs of prior claims this one cites.
        #[arg(long = "cites")]
        cites: Vec<String>,
        /// A more specific artifact than the automatic HEAD-commit anchor:
        /// `path` or `path:start-end`.
        #[arg(long)]
        file: Option<String>,
        /// Print a human-readable confirmation instead of the bare CID.
        #[arg(long, short)]
        verbose: bool,
    },
    /// Record that a subject has been resolved. Pairs a `Resolution` claim
    /// with a `Status { value: Resolved }` claim citing it.
    Resolve {
        subject: String,
        text: String,
        /// CIDs of prior claims the `Resolution` claim cites.
        #[arg(long = "cites")]
        cites: Vec<String>,
        /// A more specific artifact than the automatic HEAD-commit anchor:
        /// `path` or `path:start-end`.
        #[arg(long)]
        file: Option<String>,
        /// Print a human-readable confirmation instead of the bare CID.
        #[arg(long, short)]
        verbose: bool,
    },
    /// Record that a subject is blocked. Pairs a `Blocker` claim with a
    /// `Status { value: Blocked }` claim citing it.
    Block {
        subject: String,
        text: String,
        /// A more specific artifact than the automatic HEAD-commit anchor:
        /// `path` or `path:start-end`.
        #[arg(long)]
        file: Option<String>,
        /// Print a human-readable confirmation instead of the bare CID.
        #[arg(long, short)]
        verbose: bool,
    },
    /// Retract a prior claim of your own (`ClaimBody::Retraction`). Also
    /// works on a `Retraction` itself — the undo mechanism.
    Retract {
        cid: String,
        /// A more specific artifact than the automatic HEAD-commit anchor:
        /// `path` or `path:start-end`.
        #[arg(long)]
        file: Option<String>,
        /// Print a human-readable confirmation instead of the bare CID.
        #[arg(long, short)]
        verbose: bool,
    },
    /// Reject another author's claim (ClaimBody::Rejects) — a local
    /// suppression honored only by folds that trust you. Errors, pointing to
    /// `kan retract`, if the target is your own claim.
    Reject {
        cid: String,
        /// A more specific artifact than the automatic HEAD-commit anchor:
        /// `path` or `path:start-end`.
        #[arg(long)]
        file: Option<String>,
        /// Print a human-readable confirmation instead of the bare CID.
        #[arg(long, short)]
        verbose: bool,
    },
    /// Write a bare status claim with no paired narrative.
    Mark {
        subject: String,
        value: StatusValueArg,
        /// A more specific artifact than the automatic HEAD-commit anchor:
        /// `path` or `path:start-end`.
        #[arg(long)]
        file: Option<String>,
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

/// Mirrors `claim::StatusValue` — kept as a separate CLI-layer type so
/// `claim.rs` stays free of a `clap` dependency (this file maps between the
/// two enums at the CLI/actions call boundary, in `run` below).
#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum StatusValueArg {
    Open,
    InProgress,
    Blocked,
    Resolved,
    Closed,
}

impl From<StatusValueArg> for crate::claim::StatusValue {
    fn from(value: StatusValueArg) -> Self {
        match value {
            StatusValueArg::Open => Self::Open,
            StatusValueArg::InProgress => Self::InProgress,
            StatusValueArg::Blocked => Self::Blocked,
            StatusValueArg::Resolved => Self::Resolved,
            StatusValueArg::Closed => Self::Closed,
        }
    }
}

/// Mirrors `claim::RelationKind`, minus `SameAs` (REQ-2 — `kan same` is the
/// only way to write a `SameAs` edge, so `same-as` is deliberately not a
/// valid value here; rejected at argument parsing, not a runtime check).
/// Kept as a separate CLI-layer type for the same reason `StatusValueArg` is.
#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum RelationKindArg {
    Blocks,
    About,
    ManifestsAt,
    DependsOn,
    Accepts,
}

impl From<RelationKindArg> for crate::claim::RelationKind {
    fn from(value: RelationKindArg) -> Self {
        match value {
            RelationKindArg::Blocks => Self::Blocks,
            RelationKindArg::About => Self::About,
            RelationKindArg::ManifestsAt => Self::ManifestsAt,
            RelationKindArg::DependsOn => Self::DependsOn,
            RelationKindArg::Accepts => Self::Accepts,
        }
    }
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
    /// A more specific artifact than the automatic HEAD-commit anchor:
    /// `path` or `path:start-end`.
    #[arg(long)]
    pub file: Option<String>,
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
            let result =
                actions::observe(&mut ws, args.text, args.subject, args.cites, args.file).await?;
            print_result(&result, verbose);
        }
        Command::Plan(args) => {
            let verbose = args.verbose;
            let result =
                actions::plan(&mut ws, args.text, args.subject, args.cites, args.file).await?;
            print_result(&result, verbose);
        }
        Command::Decide(args) => {
            let verbose = args.verbose;
            let result =
                actions::decide(&mut ws, args.text, args.subject, args.cites, args.file).await?;
            print_result(&result, verbose);
        }
        Command::Show { subject } => print!("{}", actions::show(&ws, &subject)?),
        Command::Status { subject } => print!("{}", actions::status(&ws, subject.as_deref())?),
        Command::Same {
            a,
            b,
            cites,
            file,
            verbose,
        } => {
            let result = actions::same(&mut ws, &a, &b, cites, file).await?;
            print_result(&result, verbose);
        }
        Command::Relate {
            a,
            kind,
            b,
            cites,
            file,
            verbose,
        } => {
            let result = actions::relate(&mut ws, &a, kind.into(), &b, cites, file).await?;
            print_result(&result, verbose);
        }
        Command::Resolve {
            subject,
            text,
            cites,
            file,
            verbose,
        } => {
            let result = actions::resolve(&mut ws, &subject, &text, cites, file).await?;
            print_paired_result(&result, verbose);
        }
        Command::Block {
            subject,
            text,
            file,
            verbose,
        } => {
            let result = actions::block(&mut ws, &subject, &text, file).await?;
            print_paired_result(&result, verbose);
        }
        Command::Retract { cid, file, verbose } => {
            let result = actions::retract(&mut ws, &cid, file).await?;
            print_result(&result, verbose);
        }
        Command::Reject { cid, file, verbose } => {
            let result = actions::reject(&mut ws, &cid, file).await?;
            print_result(&result, verbose);
        }
        Command::Mark {
            subject,
            value,
            file,
            verbose,
        } => {
            let result = actions::mark(&mut ws, &subject, value.into(), file).await?;
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

/// Bare-CID default is the narrative claim's CID only — the citable handle
/// an agent would chain a follow-up `--cites` off of, matching the existing
/// bare-CID-by-default contract (`--cites` piping, AC-6 of the AX pass).
fn print_paired_result(result: &actions::PairedAppendResult, verbose: bool) {
    if verbose {
        println!("{}", result.confirmation());
    } else {
        println!("{}", result.narrative.cid);
    }
}
