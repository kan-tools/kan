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
    #[error(transparent)]
    Sign(#[from] crate::sign::Error),
}

#[derive(Debug, Parser)]
#[command(name = "kan", about = "Local reasoning, global coherence.")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

/// REQ-10: declared in four AX-driven phases — Recording, Structuring,
/// Correcting, Recalling — so `kan --help`'s output (clap prints
/// subcommands in declaration order) teaches the phase structure with no
/// runtime cost, purely from ordering. `Mcp` sits outside the four phases
/// (setup/tooling, not a claim-graph verb) and stays last.
#[derive(Debug, Subcommand)]
pub enum Command {
    // --- Recording: append a claim ---
    /// Record something you noticed — a fact about the current state, not
    /// something you did. Use `result` instead for the outcome of an
    /// action you took.
    Observe(NarrativeArgs),
    /// Record an intended approach.
    Plan(NarrativeArgs),
    /// Record a choice made.
    Decide(NarrativeArgs),
    /// Record that a subject is blocked. Pairs a `Blocker` claim with a
    /// `Status { value: Blocked }` claim citing it.
    Block {
        subject: String,
        text: String,
        /// A more specific artifact than the automatic HEAD-commit anchor:
        /// `path` or `path:start-end`.
        #[arg(long)]
        file: Option<String>,
        /// Declares the subject (ClaimBody::Subject) alongside this claim —
        /// requires `--kind` too.
        #[arg(long)]
        title: Option<String>,
        /// Declares the subject's kind alongside this claim — requires
        /// `--title` too.
        #[arg(long)]
        kind: Option<SubjectKindArg>,
        /// Print a human-readable confirmation instead of the bare CID.
        #[arg(long, short)]
        verbose: bool,
    },
    /// Record that a subject is now resolved — an outcome that also closes
    /// the subject out; use `result` instead when it doesn't. Pairs a
    /// `Resolution` claim with a `Status { value: Resolved }` claim citing
    /// it.
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
        /// Declares the subject (ClaimBody::Subject) alongside this claim —
        /// requires `--kind` too.
        #[arg(long)]
        title: Option<String>,
        /// Declares the subject's kind alongside this claim — requires
        /// `--title` too.
        #[arg(long)]
        kind: Option<SubjectKindArg>,
        /// Print a human-readable confirmation instead of the bare CID.
        #[arg(long, short)]
        verbose: bool,
    },
    /// Record the outcome of an action you just took — what happened after
    /// you ran something, changed something, or executed a step. Use
    /// `resolve` instead when the outcome also means this subject's work
    /// is done.
    Result {
        subject: String,
        text: String,
        /// CIDs of prior claims this one cites.
        #[arg(long = "cites")]
        cites: Vec<String>,
        /// A more specific artifact than the automatic HEAD-commit anchor:
        /// `path` or `path:start-end`.
        #[arg(long)]
        file: Option<String>,
        /// Pairs a `Status { value }` claim citing this one — the same
        /// pairing `kan resolve`/`kan block` hardcode, generalized.
        #[arg(long)]
        status: Option<StatusValueArg>,
        /// Declares the subject (ClaimBody::Subject) alongside this claim —
        /// requires `--kind` too.
        #[arg(long)]
        title: Option<String>,
        /// Declares the subject's kind alongside this claim — requires
        /// `--title` too.
        #[arg(long)]
        kind: Option<SubjectKindArg>,
        /// Print a human-readable confirmation instead of the bare CID.
        #[arg(long, short)]
        verbose: bool,
    },

    // --- Structuring: relate subjects to each other ---
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

    // --- Correcting: undo or suppress a prior claim ---
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

    // --- Recalling: read the claim graph ---
    /// Show a subject's live claims.
    Show {
        subject: String,
        /// Structured output for programs. The rendered form is for people
        /// and is free to change; this shape is versioned and additive-only.
        #[arg(long)]
        json: bool,
    },
    /// Show status: one subject, or every subject if omitted.
    Status {
        subject: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// List open (not-yet-resolved) subjects.
    Issues {
        #[arg(long)]
        json: bool,
    },
    /// Assemble the maximal-value claim set that fits under a token budget.
    Context {
        #[arg(long)]
        budget: Option<usize>,
        #[arg(long)]
        json: bool,
    },

    /// Publish a subject's claims into the committed git tree (`.claims/`),
    /// sharing them with anyone who clones the repo. Writes files; never
    /// runs git.
    Publish {
        /// The subject to publish. Omit with `--all`.
        subject: Option<String>,
        /// Bring every already-published subject's file up to date, rather
        /// than publishing one subject.
        #[arg(long, conflicts_with = "subject")]
        all: bool,
    },

    /// Identity: recovery phrase export and restore.
    Identity {
        #[command(subcommand)]
        action: IdentityAction,
    },

    /// MCP server over stdio, and related setup.
    Mcp {
        #[command(subcommand)]
        action: Option<McpAction>,
    },
}

#[derive(Debug, Subcommand)]
pub enum IdentityAction {
    /// Print this repo's `did:key` identifier. Public, safe to share.
    Did,
    /// Print the 24-word recovery phrase for this repo's signing key.
    ///
    /// Gated twice: `--yes`, and an interactive terminal. The phrase *is*
    /// the private key, and this is the only command that will ever emit it.
    Phrase {
        /// Confirm you are somewhere the output will not be recorded.
        #[arg(long)]
        yes: bool,
    },
    /// Check a recovery phrase: prints the identity it belongs to.
    Restore {
        /// The 24 words, space-separated.
        #[arg(required = true, num_args = 1..)]
        phrase: Vec<String>,
    },
}

#[derive(Subcommand, Debug)]
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
    InTensionWith,
}

impl From<RelationKindArg> for crate::claim::RelationKind {
    fn from(value: RelationKindArg) -> Self {
        match value {
            RelationKindArg::Blocks => Self::Blocks,
            RelationKindArg::About => Self::About,
            RelationKindArg::ManifestsAt => Self::ManifestsAt,
            RelationKindArg::DependsOn => Self::DependsOn,
            RelationKindArg::Accepts => Self::Accepts,
            RelationKindArg::InTensionWith => Self::InTensionWith,
        }
    }
}

/// Mirrors `claim::SubjectKind`. Kept as a separate CLI-layer type for the
/// same reason `StatusValueArg`/`RelationKindArg` are.
#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum SubjectKindArg {
    Issue,
    Idea,
    Question,
}

impl From<SubjectKindArg> for crate::claim::SubjectKind {
    fn from(value: SubjectKindArg) -> Self {
        match value {
            SubjectKindArg::Issue => Self::Issue,
            SubjectKindArg::Idea => Self::Idea,
            SubjectKindArg::Question => Self::Question,
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
    /// Pairs a `Status { value }` claim citing this one — the same pairing
    /// `kan resolve`/`kan block` hardcode, generalized to any status value.
    #[arg(long)]
    pub status: Option<StatusValueArg>,
    /// Declares the subject (ClaimBody::Subject) alongside this claim —
    /// requires `--kind` too.
    #[arg(long)]
    pub title: Option<String>,
    /// Declares the subject's kind alongside this claim — requires
    /// `--title` too.
    #[arg(long)]
    pub kind: Option<SubjectKindArg>,
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
            print_naming_warnings(subject_warnings(&ws, args.subject.as_deref())?);
            let result = actions::observe(
                &mut ws,
                args.text,
                args.subject,
                args.cites,
                args.file,
                args.status.map(Into::into),
                args.title,
                args.kind.map(Into::into),
            )
            .await?;
            print_narrative_result(&result, verbose);
        }
        Command::Plan(args) => {
            let verbose = args.verbose;
            print_naming_warnings(subject_warnings(&ws, args.subject.as_deref())?);
            let result = actions::plan(
                &mut ws,
                args.text,
                args.subject,
                args.cites,
                args.file,
                args.status.map(Into::into),
                args.title,
                args.kind.map(Into::into),
            )
            .await?;
            print_narrative_result(&result, verbose);
        }
        Command::Decide(args) => {
            let verbose = args.verbose;
            print_naming_warnings(subject_warnings(&ws, args.subject.as_deref())?);
            let result = actions::decide(
                &mut ws,
                args.text,
                args.subject,
                args.cites,
                args.file,
                args.status.map(Into::into),
                args.title,
                args.kind.map(Into::into),
            )
            .await?;
            print_narrative_result(&result, verbose);
        }
        Command::Show { subject, json } => print!(
            "{}",
            if json {
                actions::show_json(&ws, &subject)?
            } else {
                actions::show(&ws, &subject)?
            }
        ),
        Command::Status { subject, json } => print!(
            "{}",
            if json {
                actions::status_json(&ws, subject.as_deref())?
            } else {
                actions::status(&ws, subject.as_deref())?
            }
        ),
        Command::Same {
            a,
            b,
            cites,
            file,
            verbose,
        } => {
            print_naming_warnings(actions::warn_similar_subjects(&ws, &[&a, &b])?);
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
            print_naming_warnings(actions::warn_similar_subjects(&ws, &[&a, &b])?);
            let result = actions::relate(&mut ws, &a, kind.into(), &b, cites, file).await?;
            print_result(&result, verbose);
        }
        Command::Resolve {
            subject,
            text,
            cites,
            file,
            title,
            kind,
            verbose,
        } => {
            print_naming_warnings(subject_warnings(&ws, Some(&subject))?);
            let result = actions::resolve(
                &mut ws,
                &subject,
                &text,
                cites,
                file,
                title,
                kind.map(Into::into),
            )
            .await?;
            print_paired_result(&result, verbose);
        }
        Command::Result {
            subject,
            text,
            cites,
            file,
            status,
            title,
            kind,
            verbose,
        } => {
            print_naming_warnings(subject_warnings(&ws, Some(&subject))?);
            let result = actions::result(
                &mut ws,
                &subject,
                &text,
                cites,
                file,
                status.map(Into::into),
                title,
                kind.map(Into::into),
            )
            .await?;
            print_narrative_result(&result, verbose);
        }
        Command::Block {
            subject,
            text,
            file,
            title,
            kind,
            verbose,
        } => {
            print_naming_warnings(subject_warnings(&ws, Some(&subject))?);
            let result =
                actions::block(&mut ws, &subject, &text, file, title, kind.map(Into::into)).await?;
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
        Command::Publish { subject, all } => match (subject, all) {
            (Some(subject), _) => {
                print_naming_warnings(subject_warnings(&ws, Some(&subject))?);
                println!("{}", actions::publish(&mut ws, &subject).await?);
            }
            (None, true) => println!("{}", actions::publish_all(&mut ws).await?),
            (None, false) => {
                return Err(actions::Error::Usage(
                    "give a subject to publish (`kan publish <subject>`), or `--all` to \
                     refresh every already-published subject"
                        .to_string(),
                )
                .into())
            }
        },
        Command::Mark {
            subject,
            value,
            file,
            verbose,
        } => {
            print_naming_warnings(subject_warnings(&ws, Some(&subject))?);
            let result = actions::mark(&mut ws, &subject, value.into(), file).await?;
            print_result(&result, verbose);
        }
        Command::Issues { json } => print!(
            "{}",
            if json {
                actions::issues_json(&ws)?
            } else {
                actions::issues(&ws)?
            }
        ),
        Command::Context { budget, json } => {
            let budget = budget.unwrap_or(DEFAULT_BUDGET);
            print!(
                "{}",
                if json {
                    actions::context_json(&ws, budget)?
                } else {
                    actions::context(&ws, budget)?
                }
            );
        }
        Command::Identity { action } => match action {
            IdentityAction::Did => println!("{}", ws.identity.did()),
            IdentityAction::Phrase { yes } => {
                // Terminal-sensing gate. An MCP server, a CI job, and an AI
                // agent's shell all have their output captured rather than
                // attached to a terminal, so this refuses in exactly the
                // places where the phrase would end up written down
                // permanently by accident. `--yes` alone is a speed bump;
                // this is the part that actually holds.
                use std::io::IsTerminal;
                if !std::io::stdout().is_terminal() || !std::io::stdin().is_terminal() {
                    eprintln!(
                        "refusing: `kan identity phrase` only runs in an interactive \
                         terminal.\n\nstdout or stdin is not a TTY here, which means this \
                         output is being captured -- a pipe, a CI job, an MCP server, or an \
                         AI agent's shell. The phrase is your private signing key; kan will \
                         not emit it somewhere it is likely to be recorded.\n\nRun it \
                         directly in a terminal you trust."
                    );
                    return Ok(());
                }
                if !yes {
                    eprintln!(
                        "This prints your signing key as 24 words. Anyone who reads them \
                         can sign claims as you.\n\nWrite them on paper and store them the \
                         way you would a seed phrase. Re-run with --yes to print."
                    );
                    return Ok(());
                }
                println!("{}", crate::sign::recovery_phrase(&ws.identity)?);
            }
            IdentityAction::Restore { phrase } => {
                let restored = crate::sign::from_recovery_phrase(&phrase.join(" "))?;
                if restored.did() == ws.identity.did() {
                    println!(
                        "that phrase belongs to {} -- it matches this repo's identity.",
                        restored.did()
                    );
                } else {
                    println!(
                        "that phrase belongs to {}\nthis repo's identity is {}\n\nThey do \
                         not match. kan does not overwrite an existing identity \
                         automatically: move `.kan/` aside, or point KAN_IDENTITY_FILE at a \
                         file holding this key, so nothing is replaced by accident.",
                        restored.did(),
                        ws.identity.did()
                    );
                }
            }
        },
        Command::Mcp { .. } => unreachable!("handled above"),
    }
    Ok(())
}

/// `actions::warn_similar_subjects` for a single candidate — `None` skips
/// the check entirely (REQ-6/7): a caller who didn't explicitly type a
/// subject (`observe`/`plan`/`decide`'s default-to-`"general"` case) never
/// typed anything that could be a naming-variant typo in the first place.
fn subject_warnings(ws: &Workspace, candidate: Option<&str>) -> Result<Vec<String>, Error> {
    match candidate {
        Some(c) => Ok(actions::warn_similar_subjects(ws, &[c])?),
        None => Ok(Vec::new()),
    }
}

/// REQ-8: printed to stderr, never blocking — the write proceeds
/// regardless, and stdout's bare-CID default is unaffected.
fn print_naming_warnings(warnings: Vec<String>) {
    for warning in warnings {
        eprintln!("warning: {warning}");
    }
}

fn print_result(result: &actions::AppendResult, verbose: bool) {
    if verbose {
        println!("{}", result.confirmation());
    } else {
        println!("{}", result.cid);
    }
}

/// Bare-CID default is the narrative claim's CID only, matching
/// `print_paired_result`'s convention — REQ-7's optional `Subject` claim
/// only shows up under `--verbose`.
fn print_narrative_result(result: &actions::NarrativeResult, verbose: bool) {
    if verbose {
        println!("{}", result.confirmation());
    } else {
        println!("{}", result.narrative.cid);
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
