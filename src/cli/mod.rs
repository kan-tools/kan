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
// `--version` from Cargo.toml. Absent until now (#100), which quietly left
// ADR-50's contract half-built: the `--json` payload carries a schema
// version, and the binary producing it carried none, so a consumer could
// check the shape and not the tool. `day` shells out to this binary and had
// no way to say "I need kan >= x".
#[command(version)]
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
        /// Either the subject (when a second positional follows) or the
        /// text. Both `<subject> <text>` and `<text> --subject <s>` work.
        first: String,
        second: Option<String>,
        /// Subject rkey, as an alternative to giving it positionally.
        #[arg(long)]
        subject: Option<String>,
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
        /// Either the subject (when a second positional follows) or the
        /// text. Both `<subject> <text>` and `<text> --subject <s>` work.
        first: String,
        second: Option<String>,
        /// Subject rkey, as an alternative to giving it positionally.
        #[arg(long)]
        subject: Option<String>,
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
        /// Either the subject (when a second positional follows) or the
        /// text. Both `<subject> <text>` and `<text> --subject <s>` work.
        first: String,
        second: Option<String>,
        /// Subject rkey, as an alternative to giving it positionally.
        #[arg(long)]
        subject: Option<String>,
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
        /// Fold under `PeerContested` over these authors instead of the
        /// `Solo` default: `did:key:...`, `did:key:...=<weight>`, or `me`
        /// for this workspace's own identity. Repeat for several authors.
        /// Weight defaults to 1.0 and must be in [0,1]; an author you do
        /// not name is invisible, not merely down-weighted.
        #[arg(long = "trust", value_name = "AUTHOR[=WEIGHT]")]
        trust: Vec<String>,
    },
    /// Show status: one subject, or every subject if omitted.
    Status {
        subject: Option<String>,
        #[arg(long)]
        json: bool,
        /// See `kan show --help`.
        #[arg(long = "trust", value_name = "AUTHOR[=WEIGHT]")]
        trust: Vec<String>,
    },
    /// List open (not-yet-resolved) subjects.
    Issues {
        #[arg(long)]
        json: bool,
        /// See `kan show --help`.
        #[arg(long = "trust", value_name = "AUTHOR[=WEIGHT]")]
        trust: Vec<String>,
    },
    /// Assemble the maximal-value claim set that fits under a token budget.
    Context {
        #[arg(long)]
        budget: Option<usize>,
        #[arg(long)]
        json: bool,
        /// See `kan show --help`.
        #[arg(long = "trust", value_name = "AUTHOR[=WEIGHT]")]
        trust: Vec<String>,
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

    /// Rebuild this repo's log from the published `.claims/` tree.
    ///
    /// The inverse of `publish`, for the case where `.kan/` is gone: every
    /// claim you published is a complete signed record, so the log can be
    /// rebuilt from the tracked tree without trusting it.
    ///
    /// Restores only claims signed by *this* identity — another actor's are
    /// read from the overlay and never enter your log. If nothing in the
    /// tree is yours, this refuses and writes nothing, because that is what
    /// a lost signing key looks like from the inside: run `kan identity
    /// restore` first.
    Restore,

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

/// Read one line of secret input without it reaching argv.
///
/// On a terminal, `rpassword` reads with echo disabled so the phrase never
/// appears on screen or in scrollback. Off a terminal it is read as a plain
/// line from stdin — the automation path.
///
/// The branch is explicit because `rpassword` does **not** fall back: spiked
/// before use per `CLAUDE.md`'s crate rule, it fails with "Device not
/// configured" when stdin is not a TTY.
fn read_secret_line(prompt: &str) -> Result<String, Error> {
    use std::io::IsTerminal;
    if std::io::stdin().is_terminal() {
        Ok(rpassword::prompt_password(prompt)
            .map_err(|e| actions::Error::Usage(format!("could not read the phrase: {e}")))?)
    } else {
        let mut line = String::new();
        std::io::stdin()
            .read_line(&mut line)
            .map_err(|e| actions::Error::Usage(format!("could not read the phrase: {e}")))?;
        Ok(line.trim_end_matches(['\n', '\r']).to_string())
    }
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
    ///
    /// The phrase is read from stdin, never from the command line. On a
    /// terminal you are prompted and the words are not echoed; otherwise it
    /// is read from a pipe, which is the automation path.
    Restore {
        /// Rejected. The phrase is your private key and must not appear in
        /// argv — see the error text.
        #[arg(hide = true, num_args = 0..)]
        phrase: Vec<String>,
    },
    /// Declare additional signing identities ("roles") for this workspace —
    /// a director and a prover signing separately, say.
    Role {
        #[command(subcommand)]
        action: RoleAction,
    },
}

#[derive(Subcommand, Debug)]
pub enum RoleAction {
    /// Mint a role key deliberately and register it.
    ///
    /// This is the explicit opt-in the `WouldMintSecondIdentity` guard is
    /// waiting for. Without it, pointing `KAN_IDENTITY_FILE` at a new key
    /// file against a non-empty log is refused — the guard cannot tell a
    /// deliberate role from the accidental identity-mint that silently hid
    /// a whole log. Declaring the role is how you say which one this is.
    ///
    /// Afterwards, run kan with `KAN_IDENTITY_FILE` set to the role's key
    /// to write as that role, and read with `--trust roles` to see every
    /// role's claims rather than only the active one's.
    Add {
        /// A short name for the role, e.g. `director`.
        name: String,
        /// Where to keep the role's key file. Defaults to
        /// `.kan/roles.d/<name>`.
        #[arg(long)]
        key: Option<String>,
    },
    /// List this workspace's declared roles, with their DIDs.
    List {
        #[arg(long)]
        json: bool,
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

/// Resolve a verb's subject and text from whichever form the caller used.
///
/// Every claim-writing verb now accepts **both**:
///
/// ```text
/// kan observe <SUBJECT> <TEXT>
/// kan observe <TEXT> --subject <SUBJECT>
/// kan result  <SUBJECT> <TEXT>
/// kan result  <TEXT> --subject <SUBJECT>
/// ```
///
/// Before this, `observe`/`plan`/`decide` took `--subject` and
/// `result`/`resolve`/`block` took it positionally, with nothing to infer
/// which was which. Two independent sessions got it wrong in opposite
/// directions, and issue #101 records that it cost **lost writes** — a long
/// claim retyped after `error: unexpected argument '--subject'`.
///
/// Accepting both was chosen over unifying on one form (the earlier
/// decision, recorded on `v0.6.1-cleanup`) because the evidence changed what
/// the problem was. Unifying is a breaking change that removes the stress
/// only after a deprecation window and forces `day` to migrate; accepting
/// both removes it now and breaks nothing. The consistency argument was
/// aesthetic. The lost-write argument is not.
///
/// `default_subject` is `Some("general")` for the narrative verbs, which have
/// always had that fallback, and `None` for the verbs that require a subject
/// — those error rather than guess.
fn subject_and_text(
    first: String,
    second: Option<String>,
    flag: Option<String>,
    default_subject: Option<&str>,
) -> Result<(String, String), Error> {
    match (second, flag) {
        // Both forms at once: refuse rather than silently pick one.
        (Some(_), Some(_)) => Err(actions::Error::Usage(
            "give the subject once -- either positionally (`kan <verb> <subject> <text>`) \
             or with --subject, not both"
                .to_string(),
        )
        .into()),
        (Some(text), None) => Ok((first, text)),
        (None, Some(subject)) => Ok((subject, first)),
        (None, None) => match default_subject {
            Some(default) => Ok((default.to_string(), first)),
            None => Err(actions::Error::Usage(format!(
                "this verb needs a subject: `kan <verb> <subject> \"{}\"`, or \
                 `kan <verb> \"{}\" --subject <subject>`",
                elide(&first),
                elide(&first)
            ))
            .into()),
        },
    }
}

/// First few words of a claim, for an error message that has to quote it back
/// without dumping a paragraph into the terminal.
fn elide(text: &str) -> String {
    let head: String = text.chars().take(40).collect();
    if text.chars().count() > 40 {
        format!("{head}...")
    } else {
        head
    }
}

#[derive(Debug, clap::Args)]
pub struct NarrativeArgs {
    /// Either the subject (when a second positional follows) or the claim
    /// text. See `subject_and_text`.
    pub first: String,
    /// The claim text, when the subject was given positionally.
    pub second: Option<String>,
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
            let (subject, text) =
                subject_and_text(args.first, args.second, args.subject, Some("general"))?;
            print_naming_warnings(subject_warnings(&ws, Some(&subject))?);
            let result = actions::observe(
                &mut ws,
                text,
                Some(subject),
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
            let (subject, text) =
                subject_and_text(args.first, args.second, args.subject, Some("general"))?;
            print_naming_warnings(subject_warnings(&ws, Some(&subject))?);
            let result = actions::plan(
                &mut ws,
                text,
                Some(subject),
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
            let (subject, text) =
                subject_and_text(args.first, args.second, args.subject, Some("general"))?;
            print_naming_warnings(subject_warnings(&ws, Some(&subject))?);
            let result = actions::decide(
                &mut ws,
                text,
                Some(subject),
                args.cites,
                args.file,
                args.status.map(Into::into),
                args.title,
                args.kind.map(Into::into),
            )
            .await?;
            print_narrative_result(&result, verbose);
        }
        Command::Show {
            subject,
            json,
            trust,
        } => {
            let trust = ws.trust_from(&trust)?;
            print!(
                "{}",
                if json {
                    actions::show_json(&ws, &subject, &trust)?
                } else {
                    actions::show(&ws, &subject, &trust)?
                }
            )
        }
        Command::Status {
            subject,
            json,
            trust,
        } => {
            let trust = ws.trust_from(&trust)?;
            print!(
                "{}",
                if json {
                    actions::status_json(&ws, subject.as_deref(), &trust)?
                } else {
                    actions::status(&ws, subject.as_deref(), &trust)?
                }
            )
        }
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
            first,
            second,
            subject,
            cites,
            file,
            title,
            kind,
            verbose,
        } => {
            let (subject, text) = subject_and_text(first, second, subject, None)?;
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
            first,
            second,
            subject,
            cites,
            file,
            status,
            title,
            kind,
            verbose,
        } => {
            let (subject, text) = subject_and_text(first, second, subject, None)?;
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
            first,
            second,
            subject,
            file,
            title,
            kind,
            verbose,
        } => {
            let (subject, text) = subject_and_text(first, second, subject, None)?;
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
        Command::Restore => print!("{}", actions::restore(&mut ws).await?),
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
        Command::Issues { json, trust } => {
            let trust = ws.trust_from(&trust)?;
            print!(
                "{}",
                if json {
                    actions::issues_json(&ws, &trust)?
                } else {
                    actions::issues(&ws, &trust)?
                }
            )
        }
        Command::Context {
            budget,
            json,
            trust,
        } => {
            let budget = budget.unwrap_or(DEFAULT_BUDGET);
            let trust = ws.trust_from(&trust)?;
            print!(
                "{}",
                if json {
                    actions::context_json(&ws, budget, &trust)?
                } else {
                    actions::context(&ws, budget, &trust)?
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
                // argv is not a place a private key may go.
                //
                // Shell history keeps it indefinitely, `ps` exposes it to
                // every other process for the life of the command, and it
                // lands in terminal scrollback and any agent transcript.
                // `kan identity phrase` is gated twice so the phrase never
                // reaches somewhere permanent; accepting it here on the
                // command line undid that entirely. Rejected rather than
                // deprecated: using it once is already a leak, so accepting
                // it "for compatibility" would preserve the defect.
                if !phrase.is_empty() {
                    return Err(actions::Error::Usage(
                        "the recovery phrase must not be passed on the command line -- it \
                         is your private signing key, and argv is visible in shell history, \
                         in `ps` output to other processes, and in terminal scrollback.\n\n\
                         Run `kan identity restore` with no arguments and enter it at the \
                         prompt, or pipe it in:\n    \
                         cat phrase.txt | kan identity restore\n\n\
                         If you already ran it with the words as arguments, clear them from \
                         your shell history."
                            .to_string(),
                    )
                    .into());
                }
                let phrase = read_secret_line("Recovery phrase (input hidden): ")?;
                let restored = crate::sign::from_recovery_phrase(&phrase)?;
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
            IdentityAction::Role { action } => match action {
                RoleAction::Add { name, key } => {
                    let kan_dir = ws.root.join(".kan");
                    let key_path = match key {
                        Some(k) => std::path::PathBuf::from(k),
                        None => kan_dir.join("roles.d").join(&name),
                    };
                    // Record the identity that was already signing here
                    // before this role existed, while it is loaded and its
                    // DID is in hand. Once KAN_IDENTITY_FILE points at a
                    // role, kan never consults the keychain, so this is the
                    // only cheap moment to learn it — and without it,
                    // `--trust roles` omits everything written before the
                    // first role was declared.
                    crate::sign::register_active(
                        &kan_dir,
                        &ws.identity.did(),
                        &kan_dir.join("identity"),
                    )?;
                    let role = crate::sign::add_role(&kan_dir, &name, &key_path)?;
                    println!("declared role `{}`: {}", role.name, role.did);
                    println!("key: {}", role.key_path.display());
                    println!(
                        "\nWrite as this role:\n    KAN_IDENTITY_FILE={} kan observe <subject> \
                         <text>\n\nRead every role's claims (the default Solo view shows only \
                         the active identity's):\n    kan show <subject> --trust roles",
                        role.key_path.display()
                    );
                }
                RoleAction::List { json } => {
                    let roles = crate::sign::list_roles(&ws.root.join(".kan"))?;
                    if json {
                        print!("{}", actions::roles_json(&ws, &roles)?);
                    } else if roles.is_empty() {
                        println!(
                            "no declared roles. This workspace signs as one identity: {}",
                            ws.identity.did()
                        );
                    } else {
                        println!("active: {}", ws.identity.did());
                        for role in roles {
                            println!("{}\t{}\t{}", role.name, role.did, role.key_path.display());
                        }
                    }
                }
            },
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
