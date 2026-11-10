//! Human record/recall facade over the shared v2 Library actions. No v1 process,
//! repository discovery, key creation or implicit migration is involved.
use crate::evidence_library::{self as library, Query, Readers, RecordDraft, SourceConfig};
use crate::{evidence_gateway::secret_file, evidence_service::Failure, sign::Identity};
use clap::{Args, Subcommand};
use serde::Deserialize;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub version: u8,
    pub allowed_worktrees: Vec<PathBuf>,
    pub source: String,
    pub reader_config: PathBuf,
    pub signing_key: PathBuf,
    pub workspace: PathBuf,
    pub workspace_key: PathBuf,
    pub git_root: Option<PathBuf>,
    pub annotation_outbox: Option<PathBuf>,
    pub analysis_config: Option<PathBuf>,
    #[serde(default)]
    pub workspace_erasure_history: Vec<crate::evidence_erasure_history::Access>,
}
fn key(path: &Path) -> Result<[u8; 32]> {
    if !path.is_absolute() {
        return Err("profile paths must be absolute".into());
    }
    Ok(crate::evidence_crypto::read_private_key(path)?)
}
impl Profile {
    pub fn load(path: &Path) -> Result<Self> {
        if !path.is_absolute() {
            return Err("profile must be an absolute private file".into());
        }
        let value: Self = serde_json::from_slice(&secret_file(path)?)?;
        let cwd = std::env::current_dir()?.canonicalize()?;
        if value.allowed_worktrees.is_empty() || value.allowed_worktrees.len() > 16 {
            return Err("profile requires 1..16 explicitly allowed worktrees".into());
        }
        let mut allowed = false;
        for root in &value.allowed_worktrees {
            if !root.is_absolute() || root.parent().is_none() {
                return Err("invalid allowed worktree".into());
            }
            let canonical = root.canonicalize()?;
            if &canonical != root {
                return Err("allowed worktrees must be canonical paths".into());
            }
            allowed |= cwd.starts_with(canonical);
        }
        if !allowed {
            return Err("current directory is outside this profile's explicit worktrees".into());
        }
        if value.git_root.as_ref().is_some_and(|p| !p.is_absolute())
            || value.version != 1
            || [
                &value.reader_config,
                &value.signing_key,
                &value.workspace,
                &value.workspace_key,
            ]
            .iter()
            .any(|p| !p.is_absolute())
            || value
                .annotation_outbox
                .as_ref()
                .is_some_and(|p| !p.is_absolute())
            || value
                .analysis_config
                .as_ref()
                .is_some_and(|p| !p.is_absolute())
        {
            return Err("invalid record profile".into());
        }
        Ok(value)
    }
    fn artifacts(&self, file: Option<&str>) -> Result<Vec<crate::claim::v1::ArtifactRef>> {
        let Some(root) = &self.git_root else {
            if file.is_some() {
                return Err("--file requires an explicitly configured git_root".into());
            }
            return Ok(Vec::new());
        };
        let git = crate::git::GitSubstrate::open(root)?;
        let head = git.head_commit()?;
        let mut artifacts = vec![crate::claim::v1::ArtifactRef::Commit(head.clone())];
        if let Some(file) = file {
            artifacts.push(crate::actions::parse_file_artifact(file, &head));
        }
        Ok(artifacts)
    }
    pub fn open(&self, analysis: bool) -> Result<Readers> {
        let scopes: Vec<SourceConfig> = serde_json::from_slice(&secret_file(&self.reader_config)?)?;
        if scopes.is_empty() || scopes.len() > 16 {
            return Err("profile requires 1..16 proof sources".into());
        }
        let mut proofs = Vec::new();
        for scope in scopes {
            if scope.protocol.as_deref() != Some(crate::evidence_proof_service::PROTOCOL)
                || scope.historical_key_files.len() > 64
            {
                return Err("record profile requires explicit proof sources".into());
            }
            let mut reader = crate::evidence_reader::proof::Reader::new(
                Identity::load_existing(&self.signing_key)?,
                crate::evidence_reader::proof::Access {
                    binding: crate::evidence_proof_service::Binding {
                        profile: scope.profile.ok_or("missing proof profile")?,
                        archive: scope.archive.ok_or("missing archive")?,
                        scope: scope.scope,
                        issuer: scope.issuer,
                    },
                    endpoint: scope.endpoint,
                    private_key: key(&scope.private_key_file)?,
                },
            )?
            .with_historical_keys(
                scope
                    .historical_key_files
                    .iter()
                    .map(|p| key(p))
                    .collect::<Result<Vec<_>>>()?,
            )?;
            if let Some(epochs) = scope.epoch_keys {
                reader = reader.with_epochs(epochs)?;
            }
            proofs.push(reader);
        }
        let mut reader = Readers::new(None, proofs)?.with_workspace(
            crate::evidence_workspace::Workspace::open(
                &self.workspace,
                Identity::load_existing(&self.signing_key)?,
                key(&self.workspace_key)?,
            )?
            .with_erasure_histories(self.workspace_erasure_history.clone())?,
        );
        if let Some(path) = &self.annotation_outbox {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Outbox {
                spool: PathBuf,
                endpoint: String,
                recipient: String,
                #[serde(default)]
                erasure_history: Option<crate::evidence_erasure_history::Access>,
            }
            let o: Outbox = serde_json::from_slice(&secret_file(path)?)?;
            if !o.spool.is_absolute() {
                return Err("outbox spool must be absolute".into());
            }
            let mut outbox = library::AnnotationOutbox::new(
                o.spool,
                o.endpoint,
                crate::evidence_service::unhex(&o.recipient, 32)?
                    .try_into()
                    .map_err(|_| Failure::Invalid)?,
            )?;
            if let Some(history) = o.erasure_history {
                outbox = outbox.with_erasure_history(history)?;
            }
            reader = reader.with_annotation_outbox(outbox)?;
        }
        if analysis {
            let path = self
                .analysis_config
                .as_ref()
                .ok_or("profile has no analysis configuration")?;
            reader = reader.with_analysis(serde_json::from_slice(&secret_file(path)?)?)?;
        }
        Ok(reader)
    }
}
#[derive(Args)]
pub struct Base {
    /// Explicit private v2 project profile; no repository discovery.
    #[arg(long)]
    pub profile: PathBuf,
    #[arg(long)]
    pub json: bool,
    /// Retry an exact authored operation using its returned nonce/time object.
    #[arg(long)]
    pub operation: Option<String>,
}
#[derive(Args)]
pub struct Narrative {
    #[command(flatten)]
    pub base: Base,
    pub text: String,
    #[arg(long, default_value = "general")]
    pub subject: String,
    #[arg(long = "cites", visible_alias = "cite")]
    pub cites: Vec<String>,
    #[arg(long)]
    pub status: Option<String>,
    #[arg(long)]
    pub title: Option<String>,
    #[arg(long)]
    pub kind: Option<String>,
    #[arg(long)]
    pub file: Option<String>,
}
#[derive(Args)]
pub struct Outcome {
    #[command(flatten)]
    pub base: Base,
    pub first: String,
    pub second: Option<String>,
    #[arg(long)]
    pub subject: Option<String>,
    #[arg(long = "cites", visible_alias = "cite")]
    pub cites: Vec<String>,
    #[arg(long)]
    pub file: Option<String>,
    #[arg(long)]
    pub status: Option<String>,
    #[arg(long)]
    pub title: Option<String>,
    #[arg(long)]
    pub kind: Option<String>,
}
#[derive(Args)]
pub struct Relation {
    #[command(flatten)]
    pub base: Base,
    pub subject: String,
    pub target: String,
    #[arg(long = "cites", visible_alias = "cite")]
    pub cites: Vec<String>,
    #[arg(long)]
    pub file: Option<String>,
}
#[derive(Args)]
pub struct Relate {
    #[command(flatten)]
    pub base: Base,
    pub subject: String,
    pub kind: String,
    pub target: String,
    #[arg(long = "cites", visible_alias = "cite")]
    pub cites: Vec<String>,
    #[arg(long)]
    pub file: Option<String>,
}
#[derive(Args)]
pub struct Mark {
    #[command(flatten)]
    pub base: Base,
    pub subject: String,
    pub value: String,
    #[arg(long)]
    pub file: Option<String>,
}
#[derive(Args)]
pub struct Correction {
    #[command(flatten)]
    pub base: Base,
    pub cid: String,
    #[arg(long)]
    pub file: Option<String>,
}
#[derive(Args)]
pub struct Recall {
    #[command(flatten)]
    pub base: Base,
    pub subject: Option<String>,
    #[arg(long = "trust")]
    pub trust: Vec<String>,
    #[arg(long, default_value_t = 1024)]
    pub budget: usize,
    #[arg(long = "derived-report")]
    pub derived: Vec<String>,
    #[arg(long, default_value_t = 256)]
    pub derived_budget: usize,
    #[arg(long)]
    pub cursor: Option<String>,
    #[arg(long, conflicts_with = "subject")]
    pub all: bool,
}
#[derive(Args)]
pub struct Extraction {
    #[command(flatten)]
    pub base: Base,
    #[arg(long, required_unless_present_any = ["plan","project_file"])]
    pub from: Option<u64>,
    #[arg(long, required_unless_present_any = ["plan","project_file"])]
    pub through: Option<u64>,
    /// Exact signed discovery pin in a private file; freezes the selected frontier.
    #[arg(long, conflicts_with = "plan")]
    pub pin_file: Option<PathBuf>,
    /// Previously frozen private extraction plan. Submission checks it again.
    #[arg(long,conflicts_with_all=["from","through"])]
    pub plan: Option<PathBuf>,
    #[arg(long, default_value = "session-brief")]
    pub recipe: String,
    /// Prior validated consolidations over inputs also included in this interval.
    #[arg(long = "derived-report")]
    pub derived_from: Vec<String>,
    /// Explicit finalized boundary; requires an opted-in analysis configuration.
    #[arg(long, requires = "finalized_attempt")]
    pub finalized_session: Option<String>,
    #[arg(long, requires = "finalized_session")]
    pub finalized_attempt: Option<String>,
    /// Exact statement target/reason unit ids and UTF-8 spans, in a private JSON file.
    #[arg(long, conflicts_with = "plan")]
    pub assessment_file: Option<PathBuf>,
    /// Bounded authored subject/prefix/relations/trust selector in private JSON.
    #[arg(long, conflicts_with_all = ["plan","assessment_file"])]
    pub project_file: Option<PathBuf>,
    /// Explicit paid submission. Without this flag only a plan is produced.
    #[arg(long)]
    pub run: bool,
}
#[derive(Subcommand)]
pub enum Command {
    /// List versioned built-in recipes without opening a workspace or worker.
    Recipes {
        #[arg(long)]
        decision: bool,
    },
    /// Record an observation through the v2 knowledge interface.
    Observe(Narrative),
    Plan(Narrative),
    Decide(Narrative),
    Result(Outcome),
    Block(Outcome),
    Resolve(Outcome),
    Same(Relation),
    Relate(Relate),
    Mark(Mark),
    Retract(Correction),
    Reject(Correction),
    Show(Recall),
    Status(Recall),
    Issues(Recall),
    Context(Recall),
    /// Preview a bundled post-session derived report; --run invokes the configured provider.
    Summarize(Extraction),
    Extract(Extraction),
    /// Read a derived report without calling the provider or promoting notes.
    Report {
        #[command(flatten)]
        base: Base,
        id: String,
        #[arg(long)]
        cursor: Option<String>,
    },
    /// Explicitly author an edited statement derived from a reviewed report.
    Promote {
        #[command(flatten)]
        base: Base,
        id: String,
        #[arg(long)]
        subject: String,
        #[arg(long)]
        text: String,
        #[arg(long, default_value = "observe")]
        as_verb: String,
        #[arg(long)]
        save: bool,
    },
    /// Project-scoped typed MCP; read-only unless --writes is explicit.
    Mcp {
        #[command(flatten)]
        base: Base,
        #[arg(long)]
        writes: bool,
        #[arg(long)]
        analysis: bool,
    },
}
fn relation_kind(value: &str) -> Result<&'static str> {
    Ok(
        match value.to_ascii_lowercase().replace(['-', '_'], "").as_str() {
            "blocks" => "Blocks",
            "about" => "About",
            "manifestsat" => "ManifestsAt",
            "dependson" => "DependsOn",
            "accepts" => "Accepts",
            "intensionwith" => "InTensionWith",
            "supersedes" => "Supersedes",
            "refutes" => "Refutes",
            _ => return Err("unknown relation kind; use same for SameAs".into()),
        },
    )
}
fn status(value: &str) -> Result<Value> {
    Ok(json!(match value.to_ascii_lowercase().as_str() {
        "open" => "Open",
        "inprogress" | "in-progress" => "InProgress",
        "blocked" => "Blocked",
        "resolved" => "Resolved",
        "closed" => "Closed",
        _ => return Err("unknown status".into()),
    }))
}
fn write_draft(
    profile: &Profile,
    verb: &str,
    subject: String,
    text: Option<String>,
    target: Option<String>,
    cites: Vec<String>,
) -> Value {
    json!({"source":profile.source,"verb":verb,"subject":subject,"text":text,"target":target,"relation":null,"status":null,"title":null,"subject_kind":null,"cites":cites,"evidence":[],"artifacts":[],"operation":null})
}
fn execute(profile: &Profile, mut query: Query) -> Result<Value> {
    let writing = matches!(&query, Query::Record { .. });
    if let Query::Record { draft } | Query::RecordPreview { draft } = &mut query {
        if writing && draft.operation.is_none() {
            draft.operation = Some(library::RecordOperation::fresh()?);
        }
        if writing {
            eprintln!(
                "Authored operation (retain for an exact retry): {}",
                serde_json::to_string(&draft.operation)?
            );
        }
        for artifact in profile.artifacts(None)? {
            if !draft.artifacts.contains(&artifact) {
                draft.artifacts.push(artifact);
            }
        }
    }
    let reader = profile.open(false)?;
    let raw = tokio::runtime::Runtime::new()?.block_on(reader.execute(query))?;
    Ok(serde_json::from_slice(&raw)?)
}
fn print(mut value: Value, json_output: bool, writing: bool) -> Result<()> {
    if writing {
        value
            .as_object_mut()
            .ok_or("invalid receipt")?
            .remove("record");
    }
    if serde_json::to_vec(&value)?.len() > 12 * 1024 {
        return Err("normal output exceeds 12 KiB; narrow the view".into());
    }
    if json_output {
        println!("{}", serde_json::to_string(&value)?);
        return Ok(());
    }
    if writing {
        for cid in value["claims"].as_array().ok_or("missing record receipt")? {
            println!("{}", cid.as_str().ok_or("invalid record reference")?);
        }
        eprintln!(
            "Saved in encrypted workspace; ledger publication: {}",
            value["publication"]
        );
    } else {
        if let Some(claims) = value["view"]["claims"].as_array() {
            for c in claims {
                println!(
                    "{} {}: {}",
                    c["cid"].as_str().unwrap_or(""),
                    c["kind"].as_str().unwrap_or(""),
                    c["text"].as_str().unwrap_or("")
                );
            }
        }
        if let Some(subjects) = value["view"]["subjects"].as_array() {
            for s in subjects {
                println!("{} {}", s["subjects"], s["state"]);
                if let Some(cs) = s["claims"].as_array() {
                    for c in cs {
                        println!(
                            "  {} {}: {}",
                            c["cid"].as_str().unwrap_or(""),
                            c["kind"].as_str().unwrap_or(""),
                            c["text"].as_str().unwrap_or("")
                        );
                    }
                }
                if let Some(c) = s.get("record") {
                    println!("{}", c);
                }
            }
        }
        if let Some(entries) = value["entries"].as_array() {
            for entry in entries {
                match entry["type"].as_str() {
                    Some("claim") => println!("{}", serde_json::to_string_pretty(&entry["claim"])?),
                    Some("subject-state") => println!("{}", entry["subject"]),
                    _ => println!("{}", entry),
                }
            }
        }
        if !value["next"].is_null() {
            eprintln!(
                "Continue with the same arguments and --cursor '{}'",
                value["next"]
            );
        }
        eprintln!("{}", value["coverage"].as_str().unwrap_or(""));
    }
    Ok(())
}
pub fn run(command: Command) -> Result<()> {
    let (base, verb, mut draft) = match command {
        Command::Recipes { decision } => {
            let recipes = if decision {
                library::bundled_decision_recipes()
            } else {
                library::bundled_recipes()
            };
            println!("{}", serde_json::to_string_pretty(&recipes)?);
            return Ok(());
        }
        Command::Observe(a) => return narrative(a, "observe"),
        Command::Plan(a) => return narrative(a, "plan"),
        Command::Decide(a) => return narrative(a, "decide"),
        Command::Result(a) => outcome(a, "result")?,
        Command::Block(a) => outcome(a, "block")?,
        Command::Resolve(a) => outcome(a, "resolve")?,
        Command::Same(a) => relation(a, "same")?,
        Command::Relate(a) => {
            let p = Profile::load(&a.base.profile)?;
            let mut d = write_draft(&p, "relate", a.subject, None, Some(a.target), a.cites);
            d["relation"] = json!(relation_kind(&a.kind)?);
            d["artifacts"] = json!(p.artifacts(a.file.as_deref())?);
            (a.base, "relate", d)
        }
        Command::Mark(a) => {
            let p = Profile::load(&a.base.profile)?;
            let mut v = write_draft(&p, "mark", a.subject, None, None, vec![]);
            v["status"] = status(&a.value)?;
            v["artifacts"] = json!(p.artifacts(a.file.as_deref())?);
            (a.base, "mark", v)
        }
        Command::Retract(a) => correction(a, "retract")?,
        Command::Reject(a) => correction(a, "reject")?,
        Command::Show(a) => return read(a, "show"),
        Command::Status(a) => return read(a, "status"),
        Command::Issues(a) => return read(a, "issues"),
        Command::Context(a) => return read(a, "context"),
        Command::Summarize(a) | Command::Extract(a) => return extract(a),
        Command::Report { base, id, cursor } => {
            let p = Profile::load(&base.profile)?;
            let value = execute(
                &p,
                Query::Report {
                    id,
                    cursor: cursor.map(|v| serde_json::from_str(&v)).transpose()?,
                },
            )?;
            return print_report(value, base.json);
        }
        Command::Promote {
            base,
            id,
            subject,
            text,
            as_verb,
            save,
        } => {
            let p = Profile::load(&base.profile)?;
            let mut d = write_draft(&p, &as_verb, subject, Some(text), None, vec![]);
            d["derived_from"] = json!([id]);
            d["operation"] = base
                .operation
                .as_ref()
                .map(|v| serde_json::from_str(v))
                .transpose()?
                .unwrap_or(Value::Null);
            let draft = serde_json::from_value(d)?;
            if !save {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&execute(&p, Query::RecordPreview { draft })?)?
                );
                return Ok(());
            }
            return print(execute(&p, Query::Record { draft })?, base.json, true);
        }

        Command::Mcp {
            base,
            writes,
            analysis,
        } => {
            let p = Profile::load(&base.profile)?;
            return tokio::runtime::Runtime::new()?.block_on(library::serve_mcp(
                p.open(analysis)?,
                writes,
                false,
            ));
        }
    };
    let profile = Profile::load(&base.profile)?;
    draft["verb"] = json!(verb);
    draft["operation"] = base
        .operation
        .as_ref()
        .map(|v| serde_json::from_str(v))
        .transpose()?
        .unwrap_or(Value::Null);
    let args: RecordDraft = serde_json::from_value(draft)?;
    print(
        execute(&profile, Query::Record { draft: args })?,
        base.json,
        true,
    )
}
pub fn narrative(a: Narrative, verb: &str) -> Result<()> {
    let p = Profile::load(&a.base.profile)?;
    let mut d = write_draft(&p, verb, a.subject, Some(a.text), None, a.cites);
    d["artifacts"] = json!(p.artifacts(a.file.as_deref())?);
    d["operation"] = a
        .base
        .operation
        .as_ref()
        .map(|v| serde_json::from_str(v))
        .transpose()?
        .unwrap_or(Value::Null);
    if let Some(v) = a.status {
        d["status"] = status(&v)?;
    }
    d["title"] = json!(a.title);
    d["subject_kind"] = json!(a.kind.map(|v| match v.to_ascii_lowercase().as_str() {
        "issue" => "Issue".to_owned(),
        "idea" => "Idea".to_owned(),
        "question" => "Question".to_owned(),
        _ => v,
    }));
    print(
        execute(
            &p,
            Query::Record {
                draft: serde_json::from_value(d)?,
            },
        )?,
        a.base.json,
        true,
    )
}
fn outcome(a: Outcome, verb: &'static str) -> Result<(Base, &'static str, Value)> {
    let p = Profile::load(&a.base.profile)?;
    let (subject, text) = match (a.second, a.subject) {
        (Some(text), None) => (a.first, text),
        (None, Some(subject)) => (subject, a.first),
        _ => return Err("use SUBJECT TEXT or TEXT --subject SUBJECT, not both".into()),
    };
    let mut d = write_draft(&p, verb, subject, Some(text), None, a.cites);
    d["artifacts"] = json!(p.artifacts(a.file.as_deref())?);
    if let Some(value) = a.status {
        d["status"] = status(&value)?;
    }
    d["title"] = json!(a.title);
    d["subject_kind"] = json!(a.kind.map(|v| match v.to_ascii_lowercase().as_str() {
        "issue" => "Issue".into(),
        "idea" => "Idea".into(),
        "question" => "Question".into(),
        _ => v,
    }));
    Ok((a.base, verb, d))
}
fn relation(a: Relation, verb: &'static str) -> Result<(Base, &'static str, Value)> {
    let p = Profile::load(&a.base.profile)?;
    let mut d = write_draft(&p, verb, a.subject, None, Some(a.target), a.cites);
    d["artifacts"] = json!(p.artifacts(a.file.as_deref())?);
    Ok((a.base, verb, d))
}
fn correction(a: Correction, verb: &'static str) -> Result<(Base, &'static str, Value)> {
    let p = Profile::load(&a.base.profile)?;
    let mut d = write_draft(&p, verb, "general".into(), None, Some(a.cid), vec![]);
    d["artifacts"] = json!(p.artifacts(a.file.as_deref())?);
    Ok((a.base, verb, d))
}
fn read(a: Recall, verb: &str) -> Result<()> {
    if a.base.operation.is_some() {
        return Err("--operation is an authored-write retry, not a read option".into());
    }
    let p = Profile::load(&a.base.profile)?;
    let source = p.source.clone();
    print(
        execute(
            &p,
            Query::Recall {
                source,
                verb: verb.into(),
                subject: a.subject,
                trust: a.trust,
                budget: a.budget,
                derived: a.derived,
                derived_budget: a.derived_budget,
                cursor: a.cursor.map(|v| serde_json::from_str(&v)).transpose()?,
            },
        )?,
        a.base.json,
        false,
    )
}

fn print_report(value: Value, json_output: bool) -> Result<()> {
    if json_output {
        println!("{}", serde_json::to_string(&value)?);
    } else {
        println!("Report {} — {}", value["id"], value["state"]);
        for input in value["inputs"].as_array().ok_or("invalid report inputs")? {
            println!(
                "Input {} — {}: {}",
                input["input"],
                input["availability"],
                input["uri"].as_str().unwrap_or("unavailable")
            );
        }
        for block in value["blocks"].as_array().ok_or("invalid report")? {
            if let Some(text) = block["text"].as_str() {
                if block["fragment"] == 0 && block["kind"] == "decision-assessment" {
                    println!("\nModel assessment — {}", block["question_id"]);
                } else if block["fragment"] == 0 && block["kind"].is_string() {
                    println!(
                        "\n{} / {} / {}",
                        block["kind"], block["basis"], block["stance"]
                    );
                }
                print!("{text}");
                if let Some(uncertainty) = block["uncertainty"].as_str() {
                    println!("\nUncertainty: {uncertainty}");
                }
                if let Some(witnesses) = block["witnesses"].as_array() {
                    for witness in witnesses {
                        println!("\nSource: {}", witness["reference_request"]);
                    }
                }
            }
        }
        println!();
        eprintln!("{}", value["coverage"].as_str().unwrap_or(""));
        if !value["next"].is_null() {
            eprintln!(
                "More report pages; copy next as --cursor: {}",
                value["next"]
            );
        }
    }
    Ok(())
}
fn extract(a: Extraction) -> Result<()> {
    if a.base.operation.is_some() {
        return Err(
            "use --plan for an exact extraction job; --operation only retries authored writes"
                .into(),
        );
    }
    let p = Profile::load(&a.base.profile)?;
    let reader = p.open(true)?;
    let runtime = tokio::runtime::Runtime::new()?;
    let plan: Value = if let Some(path) = &a.plan {
        if !path.is_absolute() {
            return Err("plan must be an absolute private file".into());
        }
        serde_json::from_slice(&secret_file(path)?)?
    } else {
        let selection = library::ExtractionSelection {
            source: p.source.clone(),
            from: a.from.unwrap_or(0),
            through: a.through.unwrap_or(0),
            recipe: a.recipe,
            pin: a
                .pin_file
                .as_ref()
                .map(|path| -> Result<crate::evidence_reader::proof::Pin> {
                    if !path.is_absolute() {
                        return Err("pin file must be absolute".into());
                    }
                    Ok(serde_json::from_slice(&secret_file(path)?)?)
                })
                .transpose()?,
            project: a
                .project_file
                .as_ref()
                .map(|path| -> Result<_> {
                    if !path.is_absolute() {
                        return Err("project selector file must be absolute and private".into());
                    }
                    Ok(serde_json::from_slice(&secret_file(path)?)?)
                })
                .transpose()?,
            assessment: a
                .assessment_file
                .as_ref()
                .map(|path| -> Result<_> {
                    if !path.is_absolute() {
                        return Err("assessment file must be absolute and private".into());
                    }
                    Ok(serde_json::from_slice(&secret_file(path)?)?)
                })
                .transpose()?,
            derived_from: a.derived_from,
            finalized: a.finalized_session.map(|session| {
                crate::evidence_library::proof::analysis::Finalized {
                    session,
                    attempt: a.finalized_attempt.expect("clap requires attempt"),
                }
            }),
        };
        serde_json::from_slice(
            &runtime.block_on(reader.execute(Query::ExtractPlan { selection }))?,
        )?
    };
    if plan["selection"]["source"] != p.source {
        return Err("frozen plan belongs to another profile collection".into());
    }
    if !a.run {
        println!("{}", serde_json::to_string_pretty(&plan)?);
        return Ok(());
    }
    let selection = serde_json::from_value(plan["selection"].clone())?;
    let result: Value =
        serde_json::from_slice(&runtime.block_on(reader.execute(Query::ExtractRun {
            selection,
            preview: plan["digest"].as_str().ok_or("missing plan digest")?.into(),
            nonce: plan["nonce"].as_str().ok_or("missing plan nonce")?.into(),
            wait: true,
        }))?)?;
    println!("{}", serde_json::to_string(&result)?);
    Ok(())
}
