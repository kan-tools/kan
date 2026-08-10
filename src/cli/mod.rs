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
    /// Show a subject's live claims, or every subject's with `--all`.
    Show {
        /// Omit when using `--all`.
        subject: Option<String>,
        /// Every subject's live claims, from one invocation.
        ///
        /// A program reading the whole claim graph otherwise pays one process
        /// startup per subject, and that startup -- not the fold, and not the
        /// log size -- is where the time goes (#123). Requires `--json`:
        /// the rendered form is for people, and nobody reads forty subjects'
        /// full claim histories at a terminal.
        #[arg(long, conflicts_with = "subject")]
        all: bool,
        /// Structured output for programs. The rendered form is for people
        /// and is free to change; this shape is versioned and additive-only.
        #[arg(long)]
        json: bool,
        /// Narrow or widen the trust base. The default is `local` — every
        /// author with a claim in this workspace's log. Also accepts `me`
        /// (the active identity alone), `roles` (only the identities this
        /// workspace has declared), `role:<name>` (one declared role), a
        /// bare `did:key:...`, or `did:key:...=<weight>`. Repeat for several
        /// authors. Weight defaults to 1.0 and must be in [0,1]; an author
        /// you do not name is invisible, not merely down-weighted.
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

/// A yes/no confirmation, for an act that destroys something.
///
/// Sibling of [`read_secret_line`], and gated the same way: this repository
/// already treats an interactive terminal as the signal that a human is
/// present to answer for a sensitive irreversible act (`kan identity phrase`).
/// Anything other than an explicit yes is a no -- a bare Enter must not delete
/// a secret.
pub fn confirm(question: &str) -> Result<bool, actions::Error> {
    use std::io::Write;
    eprint!("{question} [y/N] ");
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .map_err(|e| actions::Error::Usage(format!("could not read the answer: {e}")))?;
    Ok(matches!(
        line.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
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
    /// Print this repo's X25519 encryption public key.
    ///
    /// Public and safe to share, like the DID. It is what a future encrypted
    /// backup or a peer wraps a content key to, and it is derived from the
    /// same secret the recovery phrase already reproduces -- so there is no
    /// second thing to write down.
    EncryptionKey,
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
    /// Point this workspace at a signing key it already has claims from.
    ///
    /// The supported way back from a lost or unreachable identity (#90):
    /// a moved checkout, a rebuilt binary, an upgrade that could no longer
    /// read the keychain. Verifies the key authored claims in this log
    /// before switching, and refuses -- naming the DIDs the log does
    /// contain -- if it did not.
    Adopt {
        /// A file holding the signing key to adopt. Must already exist.
        #[arg(long)]
        key: String,
    },
    /// Declare additional signing identities ("roles") for this workspace —
    /// a director and a prover signing separately, say.
    Role {
        #[command(subcommand)]
        action: RoleAction,
    },
    /// List every author with a claim in this log, marking which ones were
    /// declared as roles.
    ///
    /// The undeclared ones are the signal that an unexpected identity has
    /// written here — an upgrade that re-minted (#90), or an old `KAN_AGENT`
    /// value (#136). Both otherwise present as "some claims seem to be
    /// missing", which is the hardest shape to act on; this is the same fact
    /// stated positively.
    Authors {
        #[arg(long)]
        json: bool,
    },
    /// Move this repo's secret into the OS keychain.
    ///
    /// The opt-in. Since v0.12 a fresh workspace roots in a `0600` file, and
    /// this is how you choose the keychain instead. It never changes the DID.
    Protect {
        /// Delete the plaintext copy without asking once the keychain holds it.
        #[arg(long)]
        yes: bool,
    },
    /// Move this repo's secret out of the OS keychain into a `0600` file.
    ///
    /// The exit for a workspace created before v0.12. On macOS a keychain
    /// entry is authorised to the binary that created it, so an upgraded kan
    /// blocks on a prompt that never arrives in CI, a container, an MCP server
    /// or a `day` subprocess (#96) -- this is the way out of that.
    Unprotect {
        /// Suppress the warning printed when `.kan/` already holds a secret
        /// at the destination. It does NOT skip a confirmation: unprotect has
        /// none, because it never deletes a SECRET -- a differing one at the
        /// destination is refused outright rather than confirmed past. (It does
        /// remove the pointer file, once the secret is safely on disk.)
        #[arg(long)]
        yes: bool,
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
    /// Bring a pre-v0.12 `.kan/roles` file across into the log, once.
    ///
    /// Roles are claims since v0.12, so the file is no longer read. This
    /// declares each of its rows properly. It is idempotent, and it never
    /// rewrites or deletes the file — whether to keep it is your call, and
    /// the reason to is that a kan older than v0.12 can still read it.
    Import,
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
    Supersedes,
    Refutes,
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
            RelationKindArg::Supersedes => Self::Supersedes,
            RelationKindArg::Refutes => Self::Refutes,
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

    // An EARLY refusal, so a bad subject name is reported before a workspace
    // is opened at all. Cheaper, and the error arrives before any store I/O.
    //
    // It is no longer what delivers REQ-3's "a refused write mints nothing":
    // that comes from `commit_identity` running inside `append` AFTER
    // validation, so the property holds for every failure cause rather than
    // for the ones anybody hoisted. This check was written when it WAS the
    // mechanism, and a cold review showed the suite stays green with both
    // hoists deleted -- so treat the tests beside it as pinning where the
    // error surfaces, not whether an identity is minted.
    //
    // Kept rather than removed, and kept in addition to `append`'s own check
    // rather than replacing it: `append` is the single choke point every
    // write verb reaches, and a check on some of them is a check on none
    // (#144).
    for subject in declared_subjects(&cli.command) {
        actions::validate_subject_name(&subject)?;
    }

    // Read verbs open READ-ONLY, which is the milestone in one branch
    // (`.design/identity-surface.md` REQ-2): no identity is resolved,
    // derived or persisted, and no anchor is computed. Routing it here
    // rather than inside each verb means a read cannot acquire a write's
    // prerequisites by being called from the wrong place.
    if is_read_only(&cli.command) {
        let ws = Workspace::open_read_only(&cwd).await?;
        // `adopt` is the one command routed here that WRITES afterwards
        // (REQ-9): switching the workspace's identity orphans every role
        // declaration authored by the old one, so the set is carried across.
        // It is still opened read-only, because adopt must run on a workspace
        // whose identity cannot be resolved -- that is the state it exists to
        // repair -- and appending needs a second, writable open once the new
        // key is in place.
        if let Command::Identity {
            action: IdentityAction::Adopt { key },
        } = &cli.command
        {
            print!(
                "{}",
                actions::adopt_identity_carrying_roles(&ws, &std::path::PathBuf::from(key)).await?
            );
            return Ok(());
        }
        return run_read(cli.command, &ws);
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
        // Routed to `run_read` above, before this workspace was opened.
        Command::Show { .. }
        | Command::Status { .. }
        | Command::Issues { .. }
        | Command::Context { .. } => {
            unreachable!("read verbs are dispatched by `is_read_only`")
        }
        Command::Identity { action } => {
            // `kan identity ...` is a command ABOUT the identity, so asking
            // for it is the point rather than a side effect of asking for
            // something else. The read-only actions are routed away above.
            ws.commit_identity().await?;
            match action {
                IdentityAction::Did => println!("{}", ws.identity()?.did()),
                IdentityAction::EncryptionKey => {
                    println!("{}", ws.identity()?.encryption_key().public_hex())
                }
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
                    let (phrase, root) =
                        crate::sign::workspace_phrase(&ws.root.join(".kan"), ws.identity()?)?;
                    println!("{phrase}");
                    eprintln!("\nThese words are {}.", root.describe());
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
                    // A phrase is 32 bytes of BIP-39 entropy under both schemes,
                    // so it always has two readings and nothing in the words says
                    // which. Rather than guess, report both and say which one --
                    // if either -- is this repo's.
                    let candidates = crate::sign::candidate_identities(&phrase)?;
                    let active_did = ws.identity()?.did();
                    let matched = candidates
                        .iter()
                        .find(|(_, identity)| identity.did() == active_did);
                    match matched {
                        Some((root, identity)) => println!(
                        "that phrase belongs to {} -- it matches this repo's identity.\n\nRead \
                         as {}.",
                        identity.did(),
                        root.describe()
                    ),
                        None => {
                            println!("this repo's identity is {}", ws.identity()?.did());
                            println!(
                                "\nThat phrase does not match it. It could be read two ways, \
                                  and neither is this repo:"
                            );
                            for (root, identity) in &candidates {
                                println!("  as {:?}: {}", root, identity.did());
                            }
                            println!(
                            "\nkan does not overwrite an existing identity automatically: move \
                             `.kan/` aside, or point KAN_IDENTITY_FILE at a file holding the \
                             right key, so nothing is replaced by accident."
                        );
                        }
                    }
                }
                IdentityAction::Adopt { .. }
                | IdentityAction::Authors { .. }
                | IdentityAction::Protect { .. }
                | IdentityAction::Unprotect { .. } => {
                    unreachable!("dispatched without an identity by `is_read_only`")
                }
                IdentityAction::Role { action } => match action {
                    RoleAction::Add { name, key } => {
                        let kan_dir = ws.root.join(".kan");
                        let key_path = match key {
                            Some(k) => std::path::PathBuf::from(k),
                            None => kan_dir.join("roles.d").join(&name),
                        };
                        // Minting the key, refusing a non-workspace signer,
                        // auto-declaring the primary and appending the
                        // declaration all live in one action now, because
                        // they are one atomic intent and splitting them across
                        // the CLI is how the file version came to check a
                        // clash in a different place from where it wrote.
                        let role = actions::declare_role(&mut ws, &name, &key_path).await?;
                        println!("declared role `{}`: {}", role.name, role.did);
                        println!("key: {}", role.key_path.display());
                        println!(
                        "\nWrite as this role:\n    KAN_IDENTITY_FILE={} kan observe <subject> \
                         <text>\n\nEvery role's claims are in the default view already -- it \
                         trusts every author in this log. `--trust roles` NARROWS to just the \
                         declared ones:\n    kan show <subject> --trust roles",
                        role.key_path.display()
                    );
                    }
                    RoleAction::Import => {
                        let roles_file = ws.root.join(".kan").join(crate::sign::ROLES_FILE);
                        if !roles_file.exists() {
                            println!(
                                "nothing to import: this workspace has no `.kan/{}` file. \
                                 Roles are declared with `kan identity role add <name>`.",
                                crate::sign::ROLES_FILE
                            );
                            return Ok(());
                        }
                        let summary = actions::import_roles(&mut ws).await?;

                        for (name, did) in &summary.imported {
                            println!("declared role `{name}`: {did}");
                        }
                        for name in &summary.already_declared {
                            println!("already declared, skipped: `{name}`");
                        }
                        for (name, file_did, live_did) in &summary.conflicts {
                            // Reported rather than resolved: rebinding a live
                            // name during a migration is precisely the silent
                            // change nobody would go looking for.
                            eprintln!(
                                "NOT imported: `{name}` names {file_did} in the file, but \
                                 this workspace already declares that name for {live_did}. \
                                 Retract the live declaration first if the file is right."
                            );
                        }
                        if summary.imported.is_empty() && summary.conflicts.is_empty() {
                            println!("nothing new to import.");
                        }

                        // The one thing kan will not decide, stated with the
                        // one fact needed to decide it.
                        println!(
                            "\n`.kan/{}` is no longer read by this kan, and is safe to \
                             remove. Keep it only if you may run a kan older than v0.12: \
                             that version reads the file and cannot interpret a role \
                             declaration. kan has not modified it.",
                            crate::sign::ROLES_FILE
                        );
                    }
                    RoleAction::List { .. } => {
                        unreachable!("`role list` is a read, dispatched by `is_read_only`")
                    }
                },
            }
        }
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

/// `kan identity role list`, on the **read** path.
///
/// Reads the declared set out of the log and resolves the active identity
/// without creating one: `active_did` answers question 2 ("who would sign
/// here") via the selection, where `identity()` needs a workspace opened for
/// writing. A workspace whose own identity is gone still lists what it
/// declared, which is the state an operator is most likely to be inspecting.
fn print_role_list(ws: &Workspace, json: bool) -> Result<(), Error> {
    let declared = ws.declared_roles()?;
    let roles = declared.roles().to_vec();
    if json {
        print!("{}", actions::roles_json(ws, &roles)?);
    } else if roles.is_empty() {
        // REQ-8's three states. Matched here rather than
        // rendered through `roles::empty_reason`, which is
        // a short clause for `--trust role:<name>`'s error
        // and drops what this surface should keep: the
        // common case names the identity this workspace
        // signs as, which is the next thing an operator
        // asks.
        match &declared {
            crate::roles::Declared::NoWorkspaceIdentity => println!(
                "no role can be honoured here: this workspace's own \
                                     identity is unreachable, and only the identity a \
                                     workspace resolves to may declare roles."
            ),
            crate::roles::Declared::OnlyForeign { count } => println!(
                "no declared roles. {count} declaration(s) in this log \
                                     were authored by other identities, which grants them \
                                     nothing."
            ),
            _ => match ws.active_did() {
                Ok(did) => println!(
                    "no declared roles. This workspace signs as one \
                                         identity: {did}"
                ),
                Err(_) => println!("no declared roles."),
            },
        }
        print!(
            "{}",
            crate::roles::legacy_file_notice(&ws.root.join(".kan"), &declared)
        );
    } else {
        match ws.active_did() {
            Ok(did) => println!("active: {did}"),
            // Same reason as `roles_json`: this is a read,
            // and the lost-key workspace is exactly where
            // it needs to work.
            Err(_) => println!("active: (none -- this workspace resolves no identity)"),
        }
        for role in roles {
            // Two columns, not three: REQ-4 drops the key
            // path, which was machine-specific, unchecked,
            // and for a keychain-rooted primary named a
            // file that never existed.
            println!("{}\t{}", role.name, role.did);
        }
    }

    Ok(())
}

/// The verbs that only ever read. Kept as one list rather than spread across
/// the dispatch, so "is this a read" has a single answer.
fn is_read_only(command: &Command) -> bool {
    matches!(
        command,
        Command::Show { .. }
            | Command::Status { .. }
            | Command::Issues { .. }
            | Command::Context { .. }
            // Neither of these resolves an identity, and both are commands
            // you reach for precisely when the identity IS the problem.
            //
            // `adopt` is #153: it repoints the workspace at a key it already
            // has claims from, and taking a writable `&Workspace` meant
            // `Workspace::open` — and with it identity resolution — had to
            // succeed first. In the state adopt exists to repair, that trips
            // the very guard adopt is the remedy for. It needs the index and
            // the root, and nothing else.
            //
            // `identity authors` is the same shape: it reports which log
            // authors were never declared, which is the #90/#136 diagnostic.
            // Requiring a resolvable identity to run it would make it refuse
            // in exactly the workspace it exists to explain.
            // `identity role list` joins them for the same reason, and
            // REQ-9's lost-key test is what found it: since v0.12 the declared
            // set comes from the LOG, so listing it needs no signing identity
            // -- and the workspace where you most want to run it is the one
            // whose identity is gone. Dispatched as a write, it tripped
            // `WouldMintSecondIdentity` and refused to show the very registry
            // the operator was trying to recover.
            | Command::Identity {
                action: IdentityAction::Role { action: RoleAction::List { .. } }
                    | IdentityAction::Adopt { .. }
                    | IdentityAction::Authors { .. }
                    // `protect`/`unprotect` MOVE a secret; they never create
                    // one. Routing them through `commit_identity` would mean
                    // minting an identity in order to protect it -- a creation
                    // as a side effect of a command that is not about creating
                    // one, which is AC-8's class. They resolve via `at_rest`
                    // and refuse when there is nothing to move.
                    | IdentityAction::Protect { .. }
                    | IdentityAction::Unprotect { .. }
            }
    )
}

/// The read verbs, against a workspace opened without an identity.
fn run_read(command: Command, ws: &Workspace) -> Result<(), Error> {
    match command {
        Command::Identity { action } => match action {
            IdentityAction::Adopt { key } => print!(
                "{}",
                actions::adopt_identity(ws, &std::path::PathBuf::from(key))?
            ),
            IdentityAction::Role {
                action: RoleAction::List { json },
            } => print_role_list(ws, json)?,
            IdentityAction::Authors { json } => print!("{}", actions::authors(ws, json)?),
            IdentityAction::Protect { yes } => {
                print!("{}", actions::protect_identity(ws, yes)?)
            }
            IdentityAction::Unprotect { yes } => {
                print!("{}", actions::unprotect_identity(ws, yes)?)
            }
            other => unreachable!("{other:?} is not a read-only identity action"),
        },
        Command::Show {
            subject,
            all,
            json,
            trust,
        } => {
            let (trust, empty_reason) = ws.trust_from_detailed(&trust)?;
            let empty_reason = empty_reason.as_deref();
            match (all, subject) {
                (true, _) if !json => {
                    return Err(actions::Error::Usage(
                        "`kan show --all` needs `--json`. It exists for programs reading the \
                         whole claim graph in one invocation; the rendered form is for \
                         people, and forty subjects' full claim histories is not something \
                         anyone reads at a terminal."
                            .to_string(),
                    )
                    .into())
                }
                (true, _) => print!("{}", actions::show_all_json(ws, &trust, empty_reason)?),
                (false, None) => {
                    return Err(actions::Error::Usage(
                        "give a subject to show (`kan show <subject>`), or `--all --json` for \
                         every subject at once"
                            .to_string(),
                    )
                    .into())
                }
                (false, Some(subject)) => print!(
                    "{}",
                    if json {
                        actions::show_json(ws, &subject, &trust, empty_reason)?
                    } else {
                        actions::show(ws, &subject, &trust, empty_reason)?
                    }
                ),
            }
        }
        Command::Status {
            subject,
            json,
            trust,
        } => {
            let (trust, empty_reason) = ws.trust_from_detailed(&trust)?;
            print!(
                "{}",
                if json {
                    actions::status_json(ws, subject.as_deref(), &trust, empty_reason.as_deref())?
                } else {
                    actions::status(ws, subject.as_deref(), &trust, empty_reason.as_deref())?
                }
            )
        }
        Command::Issues { json, trust } => {
            let (trust, empty_reason) = ws.trust_from_detailed(&trust)?;
            print!(
                "{}",
                if json {
                    actions::issues_json(ws, &trust, empty_reason.as_deref())?
                } else {
                    actions::issues(ws, &trust, empty_reason.as_deref())?
                }
            )
        }
        Command::Context {
            budget,
            json,
            trust,
        } => {
            let budget = budget.unwrap_or(DEFAULT_BUDGET);
            let (trust, empty_reason) = ws.trust_from_detailed(&trust)?;
            print!(
                "{}",
                if json {
                    actions::context_json(ws, budget, &trust, empty_reason.as_deref())?
                } else {
                    actions::context(ws, budget, &trust, empty_reason.as_deref())?
                }
            );
        }
        // `is_read_only` is the gate, and it names exactly these four.
        other => unreachable!("{other:?} is not a read verb"),
    }
    Ok(())
}

/// The subject a write command names, if it names one — for validating it
/// before anything is opened or minted.
///
/// Mirrors `subject_and_text`'s positional-or-flag rule rather than
/// reimplementing it: when a second positional is present the first is the
/// subject, otherwise `--subject` is. A command whose subject cannot be
/// determined here returns `None` and is checked by `append` as before —
/// this is an early refusal, never the only one.
fn declared_subjects(command: &Command) -> Vec<String> {
    // `same` and `relate` name TWO subjects, and `append` only ever validates
    // the one the claim is about -- so the second went unchecked, and #144's
    // reported symptom came back verbatim on the CLI:
    //
    //     $ kan same good $'bad\nname'      # accepted
    //     $ kan status --json | jq '[.subjects[].subject]'
    //     ["bad\nname"]
    //
    // Worse than the original: the merge class then DISPLAYS under the bad
    // name, so the good subject disappears from `status` entirely. MCP
    // validated both all along, so this was a property of one surface out of
    // two -- the shape "one surface: CLI + MCP" exists to prevent, inverted
    // rather than closed.
    if let Command::Same { a, b, .. } = command {
        return vec![a.clone(), b.clone()];
    }
    if let Command::Relate { a, b, .. } = command {
        return vec![a.clone(), b.clone()];
    }
    declared_subject(command).into_iter().collect()
}

fn declared_subject(command: &Command) -> Option<String> {
    let (first, second, flag) = match command {
        Command::Observe(a) | Command::Plan(a) | Command::Decide(a) => {
            (Some(&a.first), a.second.as_ref(), a.subject.as_ref())
        }
        Command::Block {
            first,
            second,
            subject,
            ..
        }
        | Command::Resolve {
            first,
            second,
            subject,
            ..
        }
        | Command::Result {
            first,
            second,
            subject,
            ..
        } => (Some(first), second.as_ref(), subject.as_ref()),
        Command::Mark { subject, .. }
        | Command::Publish {
            subject: Some(subject),
            ..
        } => return Some(subject.clone()),
        _ => return None,
    };
    match (second, flag) {
        (Some(_), None) => first.cloned(),
        (None, Some(flag)) => Some(flag.clone()),
        // Both or neither: `subject_and_text` has its own answer for these,
        // and duplicating it here would be a second place to get it wrong.
        _ => None,
    }
}
