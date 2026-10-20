//! Experimental archive, durable delivery and raw snapshot tools; no live cutover.
use clap::{Parser, Subcommand};
#[cfg(feature = "v2-crypto")]
#[path = "kan-v2/managed.rs"]
mod managed;
use kan::{
    evidence_store::{Ledger, RecoveryReader},
    migration_preflight,
};
use std::path::PathBuf;

#[derive(Parser)]
#[command(about = "Experimental kan v2 archive and durable delivery tools")]
struct Cli {
    /// Independent host-local inventory; enroll registered services, senders and Library workspaces.
    #[cfg(feature = "v2-crypto")]
    #[arg(long, global = true)]
    deployment: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}
#[cfg(feature = "v2-crypto")]
#[derive(clap::Args)]
struct ProxyCapture {
    /// Existing private operations journal; replaces blocking stderr health output.
    #[arg(long)]
    health_journal: Option<PathBuf>,
    #[arg(long, value_enum, default_value = "opaque")]
    profile: kan::evidence_gateway::Profile,
    #[arg(long)]
    spool: PathBuf,
    #[arg(long)]
    key: PathBuf,
    #[arg(long)]
    recipient: String,
    /// Signed epoch history; overrides the fixed recipient for each new attempt.
    #[arg(long)]
    key_history: Option<PathBuf>,
    /// Cumulative awaited I/O budget, excluding synchronous capture work.
    #[arg(long, default_value_t=300, value_parser=clap::value_parser!(u32).range(1..=86400))]
    deadline_seconds: u32,
}
/// Optional explicit proof profile. All three owner pins are required together.
#[derive(clap::Args)]
struct ProofOptions {
    /// Explicit recipe-bound profile 3; never inferred from database contents.
    #[arg(long, requires_all = ["proof_archive", "proof_scope", "proof_issuer"])]
    copy_profile: bool,
    #[arg(long, requires_all = ["proof_scope", "proof_issuer"])]
    proof_archive: Option<String>,
    #[arg(long, requires_all = ["proof_archive", "proof_issuer"])]
    proof_scope: Option<String>,
    #[arg(long, requires_all = ["proof_archive", "proof_scope"])]
    proof_issuer: Option<String>,
}
impl ProofOptions {
    fn binding(
        self,
    ) -> Result<Option<kan::evidence_store::attested::Binding>, Box<dyn std::error::Error>> {
        match (self.proof_archive, self.proof_scope, self.proof_issuer) {
            (None, None, None) => Ok(None),
            (Some(archive), Some(scope), Some(issuer)) => {
                Ok(Some(kan::evidence_store::attested::Binding {
                    archive: kan::evidence_service::unhex(&archive, 32)?
                        .try_into()
                        .map_err(|_| "proof archive must be 32 bytes")?,
                    scope: kan::evidence_service::unhex(&scope, 32)?
                        .try_into()
                        .map_err(|_| "proof scope must be 32 bytes")?,
                    issuer,
                }))
            }
            _ => Err("all proof owner pins are required together".into()),
        }
    }
}
#[derive(Subcommand)]
enum Command {
    /// Pin a fully verified legacy source in a NEW private recipe artifact.
    CopyPlan {
        database: PathBuf,
        plan: PathBuf,
        #[arg(long)]
        scope: String,
        #[arg(long)]
        issuer: String,
        #[arg(long)]
        historical_issuer: String,
        /// Fresh owner-generated 32-byte nonce for this destination.
        #[arg(long)]
        nonce: String,
    },
    /// Copy one bounded batch of an exact pinned recipe; never activates a service.
    CopyBatch {
        database: PathBuf,
        archive: PathBuf,
        #[arg(long)]
        plan: PathBuf,
        #[arg(long)]
        key: PathBuf,
        /// Required for existing output, including interrupted initialization.
        #[arg(long)]
        resume: bool,
        #[command(flatten)]
        proof: ProofOptions,
        #[arg(long, default_value_t = 128)]
        objects: usize,
        #[arg(long, default_value_t = 128)]
        records: usize,
        #[arg(long, default_value_t = 16777216)]
        bytes: usize,
    },
    /// Initialize a separate private operations journal bound to an existing spool.
    #[cfg(feature = "v2-crypto")]
    OpsInit {
        journal: PathBuf,
        #[arg(long)]
        spool: PathBuf,
    },
    /// Read the same operations snapshot used by the dashboard.
    #[cfg(feature = "v2-crypto")]
    OpsStatus { journal: PathBuf },
    /// Build bounded deduplicated totals of retained collection observations.
    #[cfg(feature = "v2-crypto")]
    OpsOverview { collection: PathBuf },
    /// Copy a stopped standalone journal into a new collection, preserving the source.
    #[cfg(feature = "v2-crypto")]
    OpsAdopt {
        source: PathBuf,
        collection: PathBuf,
    },
    /// Select a fresh health generation, retaining sealed history; stop writers first.
    #[cfg(feature = "v2-crypto")]
    OpsRotate { collection: PathBuf },
    /// List retained generations in bounded pages; counts are not additive.
    #[cfg(feature = "v2-crypto")]
    OpsGenerations {
        collection: PathBuf,
        #[arg(long, default_value_t = 0)]
        after: usize,
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
    /// Read one hash-verified sealed generation, without modifying it.
    #[cfg(feature = "v2-crypto")]
    OpsHistory {
        collection: PathBuf,
        #[arg(long)]
        generation: String,
    },
    /// Continuously deliver retained signed requests, with bounded retry backoff.
    #[cfg(feature = "v2-crypto")]
    SpoolWatch {
        spool: PathBuf,
        /// Independently current owner erasure custody for this sender.
        #[arg(long)]
        erasure_history: Option<PathBuf>,
        /// Independent encrypted annotation workspace and source-custody config.
        #[arg(long)]
        publication_guard: Option<PathBuf>,
        #[arg(long)]
        journal: PathBuf,
        #[arg(long)]
        endpoint: String,
    },
    /// Read-only operator dashboard; access remotely through an authenticated tunnel.
    #[cfg(feature = "v2-crypto")]
    Dashboard {
        journal: PathBuf,
        #[arg(long, default_value = "127.0.0.1:7283")]
        listen: std::net::SocketAddr,
        #[arg(long)]
        token_file: PathBuf,
    },

    /// Human evidence Library; separate reader identity and explicitly configured scopes.
    #[cfg(feature = "v2-crypto")]
    Library {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        signing_key: PathBuf,
        #[arg(long)]
        #[arg(required_unless_present_any = ["request", "mcp"])]
        token_file: Option<PathBuf>,
        /// Encrypted persistent search index and saved view declarations.
        #[arg(long, requires = "workspace_key")]
        workspace: Option<PathBuf>,
        #[arg(long, requires = "workspace")]
        workspace_key: Option<PathBuf>,
        /// Independent current owner erasure custody; repeat for each managed source.
        #[arg(long, requires = "workspace")]
        workspace_erasure_history: Vec<PathBuf>,
        /// Mount existing operations with a separate read credential.
        #[arg(long, requires = "operations_token_file")]
        operations_journal: Option<PathBuf>,
        #[arg(long, requires = "operations_journal")]
        operations_token_file: Option<PathBuf>,
        /// Fixed annotation publication destination: spool, endpoint, recipient.
        #[arg(long, requires = "workspace")]
        annotation_outbox: Option<PathBuf>,
        /// Private fixed recipes, inference gateway, input grants and quotas.
        #[arg(long, requires = "workspace")]
        analysis_config: Option<PathBuf>,
        /// Mount separately authorized owner maintenance with its own journal/keys.
        #[arg(long)]
        owner_config: Option<PathBuf>,
        /// Serve the shared v2 API as a bounded stdio MCP server; read-only by default.
        #[arg(long, conflicts_with = "request")]
        mcp: bool,
        /// Explicitly expose Library write tools (annotations, indexing, views, analysis).
        #[arg(long, requires = "mcp")]
        mcp_writes: bool,
        /// Independently expose owner tools from the supplied owner configuration.
        #[arg(long, requires_all = ["mcp", "owner_config"])]
        mcp_owner: bool,
        /// Execute one shared Library API request from a JSON file and exit.
        #[arg(long)]
        request: Option<PathBuf>,
        #[arg(long, default_value = "127.0.0.1:7284")]
        listen: std::net::SocketAddr,
    },

    /// Recover a stopped encrypted reader/owner workspace to a new file; retain originals.
    #[cfg(feature = "v2-crypto")]
    RecoverWorkspace {
        database: PathBuf,
        destination: PathBuf,
        #[arg(long)]
        signing_key: PathBuf,
        #[arg(long)]
        recipient_key: PathBuf,
    },

    /// Execute a separately authorized owner-maintenance API request.
    #[cfg(feature = "v2-crypto")]
    Owner {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        request: PathBuf,
    },
    /// TLS 1.3 gateway; explicit client CA authorizes this single-tenant instance.
    #[cfg(feature = "v2-crypto")]
    Gateway {
        #[arg(long)]
        listen: std::net::SocketAddr,
        #[arg(long)]
        certificate: PathBuf,
        #[arg(long)]
        tls_key: PathBuf,
        #[arg(long)]
        client_ca: PathBuf,
        #[arg(long)]
        provider: String,
        #[arg(long)]
        provider_key_file: Option<PathBuf>,
        #[command(flatten)]
        capture: ProxyCapture,
    },
    /// Loopback collector authenticated by a local bearer token; mutual TLS upstream.
    #[cfg(feature = "v2-crypto")]
    Collector {
        #[arg(long)]
        listen: std::net::SocketAddr,
        #[arg(long)]
        gateway: String,
        #[arg(long)]
        server_ca: PathBuf,
        /// PEM containing client certificate chain and private key.
        #[arg(long)]
        identity: PathBuf,
        #[arg(long)]
        token_file: PathBuf,
        #[command(flatten)]
        capture: ProxyCapture,
    },
    /// Experimental single POST: raw stdin/body stdout, capture health on stderr.
    #[cfg(feature = "v2-crypto")]
    CapturePost {
        #[arg(long)]
        endpoint: String,
        #[arg(long)]
        spool: PathBuf,
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        recipient: String,
        #[arg(long, default_value_t = 300, value_parser = clap::value_parser!(u32).range(1..=86400))]
        /// Cumulative awaited network/output I/O budget; excludes capture work.
        deadline_seconds: u32,
    },
    /// Recover an explicitly pinned import into a NEW private plaintext directory.
    #[cfg(feature = "v2-crypto")]
    RestoreImport {
        #[command(flatten)]
        proof: ProofOptions,
        database: PathBuf,
        destination: PathBuf,
        #[arg(long)]
        expected_plan: String,
        #[arg(long)]
        scope: String,
        #[arg(long)]
        writer: String,
        #[arg(long)]
        recipient_key: PathBuf,
        #[arg(long, default_value_t = 1_000_000)]
        max_records: u64,
    },
    /// Verify a recovered copy against the current selected v1 source, without cutover.
    #[cfg(feature = "v2-crypto")]
    ReconcileImport {
        #[command(flatten)]
        options: ImportOptions,
        #[arg(long)]
        recovered: PathBuf,
    },
    /// Pin a source inventory and destination without importing.
    #[cfg(feature = "v2-crypto")]
    ImportPlan {
        #[command(flatten)]
        options: ImportOptions,
    },
    /// Queue a bounded batch of a pinned raw snapshot; never sends or cuts over.
    #[cfg(feature = "v2-crypto")]
    ImportV1 {
        #[command(flatten)]
        options: ImportOptions,
        #[arg(long)]
        expected_plan: String,
        #[arg(long)]
        key: PathBuf,
        #[arg(long, default_value_t = 128, value_parser = clap::value_parser!(u16).range(1..=1024))]
        limit: u16,
    },
    /// Create a new queue for one explicit scope, writer and destination.
    SpoolInit {
        spool: PathBuf,
        #[arg(long)]
        scope: String,
        #[arg(long)]
        writer: String,
        #[arg(long)]
        audience: String,
        #[arg(long)]
        budget: u64,
    },
    /// Audit and inspect a queue; lookup an operation after uncertain admission.
    SpoolStatus {
        spool: PathBuf,
        /// Independently current owner erasure custody for this sender.
        #[arg(long)]
        erasure_history: Option<PathBuf>,
        #[arg(long)]
        operation: Option<String>,
    },
    /// Emit the exact oldest signed request to stdout; does not dequeue it.
    SpoolHead {
        spool: PathBuf,
        #[arg(long)]
        erasure_history: Option<PathBuf>,
        /// Independent encrypted annotation workspace and source-custody config.
        #[arg(long)]
        publication_guard: Option<PathBuf>,
    },
    /// Encrypt bounded raw stdin and durably queue it; performs no network request.
    #[cfg(feature = "v2-crypto")]
    QueueInput {
        spool: PathBuf,
        /// Independently current owner erasure custody for this sender.
        #[arg(long)]
        erasure_history: Option<PathBuf>,
        #[arg(long)]
        key: PathBuf,
        /// Canonical hex X25519 public recipient (32 bytes).
        #[arg(long)]
        recipient: String,
        /// Stable caller-selected 16-byte hex ID; reuse is refused, never resealed.
        #[arg(long)]
        operation: String,
    },
    /// Deliver retained bytes; stop on any failure without skipping the head.
    #[cfg(feature = "v2-crypto")]
    SpoolDrain {
        spool: PathBuf,
        /// Independently current owner erasure custody for this sender.
        #[arg(long)]
        erasure_history: Option<PathBuf>,
        /// Independent encrypted annotation workspace and source-custody config.
        #[arg(long)]
        publication_guard: Option<PathBuf>,
        #[arg(long)]
        endpoint: String,
        #[arg(long, default_value_t = 128, value_parser = clap::value_parser!(u16).range(1..=1024))]
        limit: u16,
    },
    /// Authenticate a signed encrypted request and emit raw plaintext to stdout.
    #[cfg(feature = "v2-crypto")]
    DecryptRequest {
        request: PathBuf,
        /// Explicit owner-only file containing exactly 32 raw private-key bytes.
        #[arg(long)]
        recipient_key: PathBuf,
        #[arg(long)]
        scope: String,
        #[arg(long)]
        writer: String,
    },
    /// Initialize the lease in a pre-provisioned private access-policy directory.
    #[cfg(feature = "v2-service")]
    InitAccessPolicy { config: PathBuf },
    /// Establish independently retained owner-signed erasure genesis. Outputs the
    /// pinned configuration to use with --erasure-history on BOTH services.
    #[cfg(feature = "v2-service")]
    InitErasureHistory {
        config: PathBuf,
        #[arg(long)]
        signing_key: PathBuf,
    },
    /// Apply independently current erasure custody to an inactive restored archive.
    /// Does not activate services or purge derivatives, spools or backups.
    #[cfg(feature = "v2-service")]
    ReconcileErasure {
        archive: PathBuf,
        #[arg(long)]
        erasure_history: PathBuf,
    },
    /// Reconcile admitted erased operations in a retained sender spool.
    #[cfg(feature = "v2-service")]
    ReconcileSpoolErasure {
        spool: PathBuf,
        #[arg(long)]
        erasure_history: PathBuf,
    },
    /// Initialize an empty independently recoverable archive key history.
    #[cfg(feature = "v2-crypto")]
    InitKeyHistory { config: PathBuf },
    /// Serve an existing opaque partition on loopback; payload encryption is external.
    #[cfg(feature = "v2-service")]
    Serve {
        archive: PathBuf,
        #[arg(long)]
        scope: String,
        #[arg(long)]
        signing_key: PathBuf,
        #[arg(long)]
        grants: PathBuf,
        #[arg(long, default_value = "127.0.0.1:7282")]
        listen: std::net::SocketAddr,
    },
    /// Append encrypted queued requests to an explicitly selected proof archive.
    #[cfg(feature = "v2-service")]
    ServeAdmitted {
        archive: PathBuf,
        #[arg(long)]
        binding: PathBuf,
        #[arg(long)]
        signing_key: PathBuf,
        #[arg(
            long,
            required_unless_present = "access_policy",
            conflicts_with = "access_policy"
        )]
        grants: Option<PathBuf>,
        /// Owner-pinned live policy config, replacing a static grants file.
        #[arg(long)]
        access_policy: Option<PathBuf>,
        /// Independently retained owner history; missing or stale custody blocks
        /// service requests, including when an older archive is restored.
        #[arg(long)]
        erasure_history: Option<PathBuf>,
        #[arg(long, default_value = "127.0.0.1:7282")]
        listen: std::net::SocketAddr,
    },
    /// Serve proof metadata read-only, including archives with unavailable payloads.
    #[cfg(feature = "v2-service")]
    ServeProof {
        archive: PathBuf,
        /// Owner-selected JSON binding: profile, archive, scope and issuer.
        #[arg(long)]
        binding: PathBuf,
        #[arg(long)]
        signing_key: PathBuf,
        #[arg(
            long,
            required_unless_present = "access_policy",
            conflicts_with = "access_policy"
        )]
        grants: Option<PathBuf>,
        #[arg(long)]
        access_policy: Option<PathBuf>,
        /// Independently retained owner history; missing or stale custody blocks
        /// service requests, including when an older archive is restored.
        #[arg(long)]
        erasure_history: Option<PathBuf>,
        #[arg(long, default_value = "127.0.0.1:7283")]
        listen: std::net::SocketAddr,
        #[arg(long, default_value_t = 100000)]
        items: u64,
        #[arg(long, default_value_t = 67108864)]
        metadata_bytes: u64,
    },
    /// Sign a bounded unsigned request from stdin using an explicit existing key.
    #[cfg(feature = "v2-service")]
    SignRequest {
        #[arg(long)]
        key: PathBuf,
    },
    /// Send an exact signed request file; verify the pinned issuer and reply binding.
    #[cfg(feature = "v2-service")]
    Rpc {
        request: PathBuf,
        #[arg(long)]
        endpoint: String,
        #[arg(long)]
        issuer: String,
    },
    /// Locate existing v1 workspaces; source files are not changed.
    Discover {
        #[arg(required = true)]
        roots: Vec<PathBuf>,
    },
    /// Hash raw evidence and inspect CAR framing; does not import or verify claims.
    Preview {
        root: PathBuf,
        /// Treat root as an explicitly selected raw log directory.
        #[arg(long)]
        store: bool,
    },
    /// Inventory public identity events beneath an explicitly selected config root.
    PreviewIdentity { config_root: PathBuf },
    /// Create a new opaque ledger. Its parent directory must already exist.
    Init {
        archive: PathBuf,
        /// Explicitly resume an interrupted initialization or reopen a valid archive.
        #[arg(long)]
        resume: bool,
        #[command(flatten)]
        proof: ProofOptions,
    },
    /// Verify structural evidence in a quiescent file; does not check writable admission.
    Verify {
        database: PathBuf,
        #[command(flatten)]
        proof: ProofOptions,
    },
    /// Make and verify a consistent local backup into a new file.
    Backup {
        archive: PathBuf,
        destination: PathBuf,
        #[command(flatten)]
        proof: ProofOptions,
    },
    /// Read exact canonical record bytes despite damaged derived lookups.
    ReadRecord { database: PathBuf, sequence: u64 },
    /// Read and hash-check one opaque object using an offline key scan.
    ReadObject { database: PathBuf, cid: String },
    /// Rebuild derived data into a NEW file; retain the source and any failed output.
    Recover {
        database: PathBuf,
        destination: PathBuf,
        #[command(flatten)]
        proof: ProofOptions,
    },
}

#[cfg(feature = "v2-crypto")]
#[derive(clap::Args)]
struct ImportOptions {
    source: PathBuf,
    #[arg(long)]
    erasure_history: Option<PathBuf>,
    #[arg(long)]
    spool: PathBuf,
    /// Explicit lineage token, 32 bytes of lowercase hex; never inferred from names.
    #[arg(long)]
    source_id: String,
    #[arg(long)]
    recipient: String,
    #[arg(long, value_enum, default_value = "workspace")]
    selection: ImportSelection,
}
#[cfg(feature = "v2-crypto")]
#[derive(Clone, Copy, clap::ValueEnum)]
enum ImportSelection {
    Workspace,
    Store,
    Identity,
}
#[cfg(feature = "v2-crypto")]
fn import_plan(
    options: ImportOptions,
) -> Result<(kan::evidence_import::Plan, kan::evidence_spool::Spool), Box<dyn std::error::Error>> {
    let mut spool = open_spool(&options.spool, options.erasure_history)?;
    let selection = match options.selection {
        ImportSelection::Workspace => kan::evidence_import::Selection::Workspace,
        ImportSelection::Store => kan::evidence_import::Selection::Store,
        ImportSelection::Identity => kan::evidence_import::Selection::Identity,
    };
    let plan = kan::evidence_import::Plan::build(
        &options.source,
        selection,
        fixed_hex::<32>(&options.source_id)?,
        fixed_hex::<32>(&options.recipient)?,
        &mut spool,
    )?;
    Ok((plan, spool))
}

fn read_erasure_history(
    path: Option<PathBuf>,
) -> Result<Option<kan::evidence_erasure_history::Access>, Box<dyn std::error::Error>> {
    path.map(|path| {
        Ok(serde_json::from_slice(&bounded_read(
            std::fs::File::open(path)?,
            65536,
        )?)?)
    })
    .transpose()
}
#[cfg(feature = "v2-crypto")]
fn read_publication_guard(
    path: Option<PathBuf>,
) -> Result<Option<std::sync::Arc<kan::evidence_workspace::Workspace>>, Box<dyn std::error::Error>>
{
    path.map(|path| {
        let config: kan::evidence_workspace::publication::Config =
            serde_json::from_slice(&bounded_read(std::fs::File::open(path)?, 65536)?)?;
        Ok(config.open()?)
    })
    .transpose()
}
fn open_spool(
    path: &std::path::Path,
    history: Option<PathBuf>,
) -> Result<kan::evidence_spool::Spool, Box<dyn std::error::Error>> {
    let mut spool = kan::evidence_spool::Spool::open(path)?;
    if let Some(history) = read_erasure_history(history)? {
        spool = spool.with_erasure_history(history)?;
    }
    Ok(spool)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn run() -> Result<(), Box<dyn std::error::Error>> {
    #[allow(unused_mut)]
    let mut cli = Cli::parse();
    #[cfg(feature = "v2-crypto")]
    let deployment = cli
        .deployment
        .as_deref()
        .map(managed::Deployment::load)
        .transpose()?;
    #[cfg(feature = "v2-crypto")]
    let managed_workspace = deployment
        .as_ref()
        .map(|d| d.enroll(&mut cli.command))
        .transpose()?
        .flatten();
    match cli.command {
        #[cfg(feature = "v2-crypto")]
        Command::OpsInit { journal, spool } => {
            kan::evidence_operations::Journal::create(&journal, &spool)
                .map_err(|_| "operations initialization failed; preserve partial output")?;
            print_json(&serde_json::json!({"initialized":true}))?;
        }
        #[cfg(feature = "v2-crypto")]
        Command::OpsStatus { journal } => {
            let snapshot = kan::evidence_operations::Journal::open(&journal)
                .and_then(|mut j| j.snapshot())
                .map_err(|_| "operations status unavailable")?;
            print_json(&serde_json::to_value(&snapshot)?)?;
        }
        #[cfg(feature = "v2-crypto")]
        Command::OpsOverview { collection } => {
            use kan::evidence_operations_collection::overview::{build, Limits};
            let result = build(
                &collection,
                &std::sync::atomic::AtomicBool::new(false),
                Limits::default(),
            )
            .map_err(|e| format!("operations overview failed: {e}"))?;
            print_json(&serde_json::to_value(result)?)?;
        }
        #[cfg(feature = "v2-crypto")]
        Command::OpsAdopt { source, collection } => {
            kan::evidence_operations_collection::adopt(&source, &collection).map_err(|_| {
                "operations adoption failed; preserve partial output and inspect source/collection"
            })?;
            print_json(&serde_json::json!({"adopted":true,"source_preserved":true}))?;
        }
        #[cfg(feature = "v2-crypto")]
        Command::OpsRotate { collection } => {
            kan::evidence_operations_collection::rotate(&collection).map_err(|_| {
                "operations rotation failed or commit uncertain; inspect collection before retrying"
            })?;
            print_json(&serde_json::json!({"rotated":true,"history_preserved":true}))?;
        }
        #[cfg(feature = "v2-crypto")]
        Command::OpsGenerations {
            collection,
            after,
            limit,
        } => {
            let page = kan::evidence_operations_collection::generations(&collection, after, limit)
                .map_err(|_| "operations collection unavailable")?;
            print_json(&serde_json::to_value(page)?)?;
        }
        #[cfg(feature = "v2-crypto")]
        Command::OpsHistory {
            collection,
            generation,
        } => {
            let history = kan::evidence_operations_collection::history(&collection, &generation)
                .map_err(|_| "operations generation unavailable or not verified")?;
            print_json(&serde_json::to_value(history)?)?;
        }
        #[cfg(feature = "v2-crypto")]
        Command::SpoolWatch {
            spool,
            erasure_history,
            publication_guard,
            journal,
            endpoint,
        } => {
            let history = read_erasure_history(erasure_history)?;
            let publication = read_publication_guard(publication_guard)?;
            tokio::runtime::Runtime::new()?.block_on(async {
                tokio::select! {
                    result=kan::evidence_operations::drain_with_publication(&spool,&journal,&endpoint,history,publication)=>result.map_err(|_|"archive worker failed; inspect queue and journal"),
                    _=shutdown()=>Ok(())
                }
            })?;
        }
        #[cfg(feature = "v2-crypto")]
        Command::Dashboard {
            journal,
            listen,
            token_file,
        } => {
            if !listen.ip().is_loopback() {
                return Err("dashboard requires literal loopback".into());
            }
            let token = kan::evidence_gateway::secret_file(&token_file)?;
            let token = String::from_utf8(token)?.trim_end_matches('\n').to_string();
            tokio::runtime::Runtime::new()?.block_on(async {
                let listener = tokio::net::TcpListener::bind(listen).await?;
                eprintln!("dashboard http://{}", listener.local_addr()?);
                tokio::select! {
                    result=kan::evidence_dashboard::serve(listener,token,journal)=>result,
                    _=shutdown()=>Ok(())
                }
            })?;
        }
        #[cfg(feature = "v2-crypto")]
        Command::RecoverWorkspace {
            database,
            destination,
            signing_key,
            recipient_key,
        } => {
            print_json(&kan::evidence_workspace::Workspace::recover(
                &database,
                &destination,
                service_identity(&signing_key)?,
                recipient_private(&recipient_key)?,
            )?)?;
        }
        #[cfg(feature = "v2-crypto")]
        Command::Owner { config, request } => {
            let owner = load_owner(&config, deployment.as_ref())?;
            let request = serde_json::from_slice(&kan::evidence_gateway::secret_file(&request)?)?;
            let value = tokio::runtime::Runtime::new()?.block_on(owner.execute(request))?;
            println!("{}", serde_json::to_string(&value)?);
        }
        #[cfg(feature = "v2-crypto")]
        Command::Library {
            config,
            signing_key,
            token_file,
            listen,
            workspace,
            workspace_key,
            workspace_erasure_history,
            annotation_outbox,
            analysis_config,
            owner_config,
            operations_journal,
            operations_token_file,
            request,
            mcp,
            mcp_writes,
            mcp_owner,
        } => {
            #[derive(serde::Deserialize)]
            #[serde(deny_unknown_fields)]
            struct SelectedScope {
                scope: String,
                endpoint: String,
                issuer: String,
                private_key_file: PathBuf,
                #[serde(default)]
                historical_key_files: Vec<PathBuf>,
                #[serde(default)]
                epoch_keys: Option<kan::evidence_keys::ReaderAccess>,
                #[serde(default)]
                protocol: Option<String>,
                #[serde(default)]
                profile: Option<kan::evidence_proof_service::Profile>,
                #[serde(default)]
                archive: Option<String>,
            }
            if !listen.ip().is_loopback() {
                return Err("reader requires literal loopback".into());
            }
            let bytes = kan::evidence_gateway::secret_file(&config)?;
            let configured: Vec<SelectedScope> = serde_json::from_slice(&bytes)?;
            if configured.is_empty() || configured.len() > 16 {
                return Err("reader requires 1..16 configured scopes".into());
            }
            let mut scopes = Vec::new();
            let mut proofs = Vec::new();
            for entry in configured {
                if !entry.private_key_file.is_absolute() {
                    return Err("reader key paths must be absolute".into());
                }
                match entry.protocol.as_deref().unwrap_or("legacy") {
                    "legacy"
                        if entry.profile.is_none()
                            && entry.archive.is_none()
                            && entry.historical_key_files.is_empty()
                            && entry.epoch_keys.is_none() => {}
                    kan::evidence_proof_service::PROTOCOL => {
                        if entry.historical_key_files.len() > 64
                            || entry.historical_key_files.iter().any(|p| !p.is_absolute())
                        {
                            return Err("invalid historical key selection".into());
                        }
                        let keys = entry
                            .historical_key_files
                            .iter()
                            .map(|p| recipient_private(p))
                            .collect::<Result<Vec<_>, _>>()?;
                        let mut reader = kan::evidence_reader::proof::Reader::new(
                            service_identity(&signing_key)?,
                            kan::evidence_reader::proof::Access {
                                binding: kan::evidence_proof_service::Binding {
                                    profile: entry
                                        .profile
                                        .ok_or("proof source requires profile")?,
                                    archive: entry
                                        .archive
                                        .ok_or("proof source requires archive")?,
                                    scope: entry.scope,
                                    issuer: entry.issuer,
                                },
                                endpoint: entry.endpoint,
                                private_key: recipient_private(&entry.private_key_file)?,
                            },
                        )?
                        .with_historical_keys(keys)?;
                        if let Some(managed) = &managed_workspace {
                            let binding = reader.binding();
                            if !managed.sources.iter().any(|h| &h.binding == binding) {
                                return Err("Library source is absent from managed custody".into());
                            }
                        }
                        if let Some(epochs) = entry.epoch_keys {
                            reader = reader.with_epochs(epochs)?;
                        }
                        proofs.push(reader);
                        continue;
                    }
                    _ => return Err("unsupported or inconsistent reader protocol".into()),
                }
                if managed_workspace.is_some() {
                    return Err("managed Library requires proof sources".into());
                }
                scopes.push(kan::evidence_reader::ScopeAccess {
                    scope: fixed_hex(&entry.scope)?,
                    endpoint: entry.endpoint,
                    issuer: entry.issuer,
                    private_key: recipient_private(&entry.private_key_file)?,
                });
            }
            let legacy = if scopes.is_empty() {
                None
            } else {
                Some(kan::evidence_reader::Reader::new(
                    service_identity(&signing_key)?,
                    scopes,
                )?)
            };
            let mut reader = kan::evidence_library::Readers::new(legacy, proofs)?;
            if let (Some(path), Some(key)) = (workspace, workspace_key) {
                let histories = if let Some(managed) = &managed_workspace {
                    managed.sources.clone()
                } else {
                    workspace_erasure_history
                        .iter()
                        .map(
                            |path| -> Result<
                                kan::evidence_erasure_history::Access,
                                Box<dyn std::error::Error>,
                            > {
                                Ok(serde_json::from_slice(&bounded_read(
                                    std::fs::File::open(path)?,
                                    65536,
                                )?)?)
                            },
                        )
                        .collect::<Result<Vec<_>, _>>()?
                };
                reader = reader.with_workspace(
                    kan::evidence_workspace::Workspace::open(
                        &path,
                        service_identity(&signing_key)?,
                        recipient_private(&key)?,
                    )?
                    .with_erasure_histories(histories)?,
                );
            }
            if let Some(path) = owner_config {
                reader = reader.with_owner(load_owner(&path, deployment.as_ref())?);
            }
            if let Some(path) = analysis_config {
                reader = reader.with_analysis(serde_json::from_slice(
                    &kan::evidence_gateway::secret_file(&path)?,
                )?)?;
            }
            if let Some(path) = annotation_outbox {
                #[derive(serde::Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Outbox {
                    spool: PathBuf,
                    endpoint: String,
                    recipient: String,
                    #[serde(default)]
                    erasure_history: Option<kan::evidence_erasure_history::Access>,
                }
                let mut config: Outbox =
                    serde_json::from_slice(&kan::evidence_gateway::secret_file(&path)?)?;
                if !config.spool.is_absolute() {
                    return Err("annotation spool must be absolute".into());
                }
                if let (Some(deployment), Some(workspace)) = (&deployment, &managed_workspace) {
                    config.erasure_history = Some(deployment.outbox(
                        &config.spool,
                        workspace,
                        config.erasure_history,
                    )?);
                }
                let mut outbox = kan::evidence_library::AnnotationOutbox::new(
                    config.spool,
                    config.endpoint,
                    fixed_hex(&config.recipient)?,
                )?;
                if let Some(history) = config.erasure_history {
                    outbox = outbox.with_erasure_history(history)?;
                }
                reader = reader.with_annotation_outbox(outbox)?;
            }
            if let (Some(journal), Some(token_path)) = (operations_journal, operations_token_file) {
                let token = String::from_utf8(kan::evidence_gateway::secret_file(&token_path)?)?
                    .trim_end_matches('\n')
                    .to_string();
                reader =
                    reader.with_operations(kan::evidence_dashboard::Embedded::new(journal, token)?);
            }
            if mcp {
                tokio::runtime::Runtime::new()?.block_on(kan::evidence_library::serve_mcp(
                    reader, mcp_writes, mcp_owner,
                ))?;
                return Ok(());
            }
            if let Some(path) = request {
                let bytes = kan::evidence_gateway::secret_file(&path)?;
                let request: kan::evidence_library::Query = serde_json::from_slice(&bytes)?;
                let result = tokio::runtime::Runtime::new()?.block_on(reader.execute(request))?;
                println!("{}", String::from_utf8(result)?);
                return Ok(());
            }
            let token_file = token_file.ok_or("library server requires a token file")?;
            let token = String::from_utf8(kan::evidence_gateway::secret_file(&token_file)?)?
                .trim_end_matches('\n')
                .to_string();
            tokio::runtime::Runtime::new()?.block_on(async {
                let listener = tokio::net::TcpListener::bind(listen).await?;
                eprintln!("library http://{}", listener.local_addr()?);
                tokio::select! { result=kan::evidence_library::serve_readers(listener,token,reader)=>result, _=shutdown()=>Ok(()) }
            })?;
        }
        #[cfg(feature = "v2-crypto")]
        Command::Gateway {
            listen,
            certificate,
            tls_key,
            client_ca,
            provider,
            provider_key_file,
            capture,
        } => {
            use kan::{evidence_capture::Route, evidence_gateway as gateway};
            let tls = gateway::server_tls(
                &gateway::secret_file(&certificate)?,
                &gateway::secret_file(&tls_key)?,
                &gateway::secret_file(&client_ca)?,
            )?;
            let provider_key = provider_key_file
                .map(|p| gateway::secret_file(&p))
                .transpose()?;
            run_proxy(
                listen,
                gateway::ListenerAuth::MutualTls(tls),
                Route::new(&provider)?,
                kan::evidence_capture::Observer::Gateway,
                capture,
                provider_key,
            )?;
        }
        #[cfg(feature = "v2-crypto")]
        Command::Collector {
            listen,
            gateway: endpoint,
            server_ca,
            identity,
            token_file,
            capture,
        } => {
            use kan::{evidence_capture::Route, evidence_gateway as gateway};
            if !listen.ip().is_loopback() {
                return Err("collector requires literal loopback".into());
            }
            let route = Route::mutual_tls(
                &endpoint,
                &gateway::secret_file(&server_ca)?,
                &gateway::secret_file(&identity)?,
            )?;
            let token = String::from_utf8(gateway::secret_file(&token_file)?)?;
            run_proxy(
                listen,
                gateway::ListenerAuth::LoopbackToken(token.trim_end_matches('\n').into()),
                route,
                kan::evidence_capture::Observer::Collector,
                capture,
                None,
            )?;
        }
        #[cfg(feature = "v2-crypto")]
        Command::CapturePost {
            endpoint,
            spool,
            key,
            recipient,
            deadline_seconds,
        } => {
            use kan::evidence_capture::{self as capture, EncryptedSpool};
            let route = capture::Route::new(&endpoint)?;
            let signer = service_identity(&key)?;
            let recipient = fixed_hex::<32>(&recipient)?;
            let request = bounded_read(std::io::stdin().lock(), capture::MAX_REQUEST)?;
            // Open failure is degraded capture, not permission to drop inference.
            let mut spool = kan::evidence_spool::Spool::open_for_capture(&spool).ok();
            // A readable, mismatched writer is a configuration error. Storage
            // that cannot be inspected still follows the visible-gap policy.
            if let Some(queue) = spool.as_mut() {
                if let Ok(status) = queue.status() {
                    if status.writer != signer.did().as_str() {
                        return Err("capture signing key does not match spool writer".into());
                    }
                }
            }
            let mut sink = EncryptedSpool {
                spool: spool.as_mut(),
                signer: &signer,
                recipient,
            };
            let mut notify = |health: &capture::Health| {
                use std::io::Write;
                let stderr = std::io::stderr();
                let mut stderr = stderr.lock();
                let _ = serde_json::to_writer(&mut stderr, health);
                let _ = writeln!(stderr);
            };
            let runtime = tokio::runtime::Runtime::new()?;
            let result = runtime.block_on(capture::forward(
                &route,
                request,
                &mut sink,
                &mut notify,
                &mut tokio::io::stdout(),
                std::time::Duration::from_secs(u64::from(deadline_seconds)),
            ));
            // Tokio stdout uses a blocking worker. A full downstream pipe must
            // not make runtime destruction wait forever after the I/O deadline.
            runtime.shutdown_timeout(std::time::Duration::from_millis(100));
            result?;
        }
        #[cfg(feature = "v2-crypto")]
        Command::RestoreImport {
            proof,
            database,
            destination,
            expected_plan,
            scope,
            writer,
            recipient_key,
            max_records,
        } => {
            let pins = kan::evidence_restore::Pins {
                expected_plan: &expected_plan,
                scope: fixed_hex::<32>(&scope)?,
                writer: &writer,
                recipient_private: recipient_private(&recipient_key)?,
                max_records,
            };
            let copied = proof.copy_profile;
            let report = match proof.binding()? {
                None => kan::evidence_restore::restore(&database, &destination, &pins)?,
                Some(b) => kan::evidence_restore::restore_proof(
                    &database,
                    &destination,
                    &pins,
                    &kan::evidence_proof_service::Binding {
                        profile: if copied {
                            kan::evidence_proof_service::Profile::Copied
                        } else {
                            kan::evidence_proof_service::Profile::Admitted
                        },
                        archive: kan::evidence_service::hex(&b.archive),
                        scope: kan::evidence_service::hex(&b.scope),
                        issuer: b.issuer,
                    },
                )?,
            };
            print_json(&report)?;
        }
        #[cfg(feature = "v2-crypto")]
        Command::ReconcileImport { options, recovered } => {
            let (plan, mut spool) = import_plan(options)?;
            print_json(&plan.reconcile(&recovered, &mut spool)?)?;
        }
        #[cfg(feature = "v2-crypto")]
        Command::ImportPlan { options } => {
            let (plan, mut spool) = import_plan(options)?;
            print_json(
                &serde_json::json!({"plan": plan.summary(), "progress": plan.progress(&mut spool)?}),
            )?;
        }
        #[cfg(feature = "v2-crypto")]
        Command::ImportV1 {
            options,
            expected_plan,
            key,
            limit,
        } => {
            let signer = service_identity(&key)?;
            let (plan, mut spool) = import_plan(options)?;
            let progress = plan.enqueue(&expected_plan, &mut spool, &signer, usize::from(limit))?;
            print_json(&serde_json::to_value(progress)?)?;
        }
        Command::SpoolInit {
            spool,
            scope,
            writer,
            audience,
            budget,
        } => {
            let mut queue =
                kan::evidence_spool::Spool::create(&spool, &scope, &writer, &audience, budget)?;
            print_json(&serde_json::json!({"status": queue.status()?, "experimental": true}))?;
        }
        Command::SpoolStatus {
            spool,
            operation,
            erasure_history,
        } => {
            let mut queue = open_spool(&spool, erasure_history)?;
            let found = operation
                .as_deref()
                .map(|id| queue.operation(id))
                .transpose()?;
            print_json(
                &serde_json::json!({"status": queue.status()?, "operation_id": operation,
                "operation": found, "experimental": true, "durability": "local-spool"}),
            )?;
        }
        Command::SpoolHead {
            spool,
            erasure_history,
            publication_guard,
        } => {
            let queue = open_spool(&spool, erasure_history)?;
            let bytes = queue.head()?.ok_or("queue is empty")?;
            #[cfg(feature = "v2-crypto")]
            let publication = read_publication_guard(publication_guard)?;
            #[cfg(feature = "v2-crypto")]
            let _custody = publication
                .as_ref()
                .map(|w| w.authorize_publication(&bytes))
                .transpose()?;
            #[cfg(not(feature = "v2-crypto"))]
            if publication_guard.is_some() {
                return Err("publication guard requires v2-crypto".into());
            }
            use std::io::Write;
            std::io::stdout().lock().write_all(&bytes)?;
        }
        #[cfg(feature = "v2-crypto")]
        Command::QueueInput {
            spool,
            erasure_history,
            key,
            recipient,
            operation,
        } => {
            let recipient = fixed_hex::<32>(&recipient)?;
            let operation = fixed_hex::<16>(&operation)?;
            let signer = service_identity(&key)?;
            let mut queue = open_spool(&spool, erasure_history)?;
            let plaintext =
                bounded_read(std::io::stdin().lock(), kan::evidence_crypto::MAX_PLAINTEXT)?;
            let queued = kan::evidence_delivery::queue(
                &mut queue, &signer, &recipient, &operation, &plaintext,
            )?;
            print_json(
                &serde_json::json!({"queued": queued, "durability": "local-spool", "remote_acknowledged": false}),
            )?;
        }
        #[cfg(feature = "v2-crypto")]
        Command::SpoolDrain {
            spool,
            erasure_history,
            publication_guard,
            endpoint,
            limit,
        } => {
            let mut queue = open_spool(&spool, erasure_history)?;
            let publication = read_publication_guard(publication_guard)?;
            tokio::runtime::Runtime::new()?.block_on(async {
                for _ in 0..limit {
                    let delivered = match publication.as_deref() {
                        Some(workspace) => {
                            kan::evidence_delivery::deliver_with_workspace(
                                &mut queue, &endpoint, workspace,
                            )
                            .await?
                        }
                        None => kan::evidence_delivery::deliver_one(&mut queue, &endpoint).await?,
                    };
                    let Some(delivered) = delivered else {
                        break;
                    };
                    print_json(&serde_json::json!({"acknowledged": delivered}))?;
                }
                print_json(&serde_json::json!({"status": queue.status()?, "experimental": true}))?;
                Ok::<_, Box<dyn std::error::Error>>(())
            })?;
        }
        #[cfg(feature = "v2-crypto")]
        Command::DecryptRequest {
            request,
            recipient_key,
            scope,
            writer,
        } => {
            let scope = fixed_hex::<32>(&scope)?;
            let private: [u8; 32] = recipient_private(&recipient_key)?;
            let request = bounded_read(
                std::fs::File::open(request)?,
                kan::evidence_service::MAX_REQUEST,
            )?;
            let plaintext =
                kan::evidence_delivery::decrypt_request(&request, &private, &scope, &writer)?;
            use std::io::Write;
            std::io::stdout().lock().write_all(&plaintext)?;
        }
        #[cfg(feature = "v2-crypto")]
        Command::InitKeyHistory { config } => {
            let history: kan::evidence_keys::Access =
                serde_json::from_slice(&bounded_read(std::fs::File::open(config)?, 65536)?)?;
            history.initialize()?;
            print_json(&serde_json::json!({"initialized":true,"epochs":0}))?;
        }
        #[cfg(feature = "v2-service")]
        Command::InitAccessPolicy { config } => {
            let policy: kan::evidence_policy::Access =
                serde_json::from_slice(&bounded_read(std::fs::File::open(config)?, 65536)?)?;
            policy.initialize()?;
            print_json(
                &serde_json::json!({"initialized":true,"grants":"none; preview and apply an owner policy before starting services"}),
            )?;
        }
        #[cfg(feature = "v2-service")]
        Command::InitErasureHistory {
            config,
            signing_key,
        } => {
            let mut history: kan::evidence_erasure_history::Access =
                serde_json::from_slice(&bounded_read(std::fs::File::open(config)?, 65536)?)?;
            let signer = service_identity(&signing_key)?;
            if history.owner != signer.did().as_str() || history.minimum.is_some() {
                return Err("initialization needs the configured owner and no existing pin".into());
            }
            match history.initialize() {
                Ok(()) | Err(kan::evidence_service::Failure::Conflict) => {}
                Err(error) => return Err(error.into()),
            }
            // Validate any interrupted/existing history against this exact owner
            // and binding. Never replace a record to finish initialization.
            let existing_tip = history.read()?.tip;
            history.minimum = Some(if let Some(id) = existing_tip {
                id
            } else {
                let change = history.preview(
                    None,
                    kan::evidence_service::hex(&rand::random::<[u8; 32]>()),
                )?;
                let record = kan::evidence_erasure_history::Record::sign(change, &signer)?;
                let id = record.id()?;
                history.append(record)?;
                id
            });
            print_json(
                &serde_json::json!({"initialized":true,"config":history,"backups":"Keep this history independently of archive backups; a retained pin is a rollback floor, not a remote freshness oracle.","erasure_workflow":"Coordinated payload, spool, derivative and backup cleanup remains separate."}),
            )?;
        }
        #[cfg(feature = "v2-service")]
        Command::ReconcileErasure {
            archive,
            erasure_history,
        } => {
            let history: kan::evidence_erasure_history::Access = serde_json::from_slice(
                &bounded_read(std::fs::File::open(erasure_history)?, 65536)?,
            )?;
            print_json(&history.reconcile_archive(&archive)?)?;
        }
        #[cfg(feature = "v2-service")]
        Command::ReconcileSpoolErasure {
            spool,
            erasure_history,
        } => {
            let history: kan::evidence_erasure_history::Access = serde_json::from_slice(
                &bounded_read(std::fs::File::open(erasure_history)?, 65536)?,
            )?;
            let mut spool = kan::evidence_spool::Spool::open(&spool)?;
            let mut report = spool.reconcile_erasure(&history)?;
            report["page_reclamation"] = serde_json::json!(if spool.reclaim_erased_pages()? {
                "completed"
            } else {
                "pending"
            });
            print_json(&report)?;
        }
        #[cfg(feature = "v2-service")]
        Command::Serve {
            archive,
            scope,
            signing_key,
            grants,
            listen,
        } => {
            let scope: [u8; 32] = kan::evidence_service::unhex(&scope, 32)?
                .try_into()
                .map_err(|_| "scope must be 32 bytes")?;
            let signer = service_identity(&signing_key)?;
            let grants =
                serde_json::from_slice(&bounded_read(std::fs::File::open(grants)?, 65536)?)?;
            let service = kan::evidence_service::Service::new(
                Ledger::open(&archive)?,
                scope,
                signer,
                grants,
            )?;
            let runtime = tokio::runtime::Runtime::new()?;
            runtime.block_on(async {
                let listener=kan::evidence_http::bind(listen).await?;
                println!("{}",serde_json::json!({"listen":listener.local_addr()?.to_string(),"issuer":service.issuer(),"experimental":true,"payload_encryption":"caller-supplied","grant_history":"not-retained","startup":"full-audit"}));
                kan::evidence_http::serve(listener,service).await
            })?;
        }
        #[cfg(feature = "v2-service")]
        Command::ServeAdmitted {
            archive,
            binding,
            signing_key,
            grants,
            access_policy,
            erasure_history,
            listen,
        } => {
            let binding: kan::evidence_proof_service::Binding =
                serde_json::from_slice(&bounded_read(std::fs::File::open(binding)?, 4096)?)?;
            if binding.profile != kan::evidence_proof_service::Profile::Admitted {
                return Err("ingest requires an explicitly admitted profile".into());
            }
            let service = kan::evidence_service::AdmittingService::new(
                kan::evidence_store::attested::Archive::open(&archive, binding.owner_binding()?)?,
                service_identity(&signing_key)?,
                match grants {
                    Some(path) => {
                        serde_json::from_slice(&bounded_read(std::fs::File::open(path)?, 65536)?)?
                    }
                    None => Vec::new(),
                },
            )?;
            let service = match access_policy {
                Some(path) => service.with_policy(serde_json::from_slice(&bounded_read(
                    std::fs::File::open(path)?,
                    65536,
                )?)?)?,
                None => service,
            };
            let service = match erasure_history {
                Some(path) => service.with_erasure_history(serde_json::from_slice(
                    &bounded_read(std::fs::File::open(path)?, 65536)?,
                )?)?,
                None => service,
            };
            tokio::runtime::Runtime::new()?.block_on(async {
                let listener=kan::evidence_http::bind(listen).await?;
                eprintln!("proof ingest http://{}/v1/rpc",listener.local_addr()?);
                #[cfg(feature="v2-crypto")]
                {tokio::select!{result=kan::evidence_http::serve_admitted(listener,service)=>result,_=shutdown()=>Ok(())}}
                #[cfg(not(feature="v2-crypto"))]
                {kan::evidence_http::serve_admitted(listener,service).await}
            })?;
        }
        #[cfg(feature = "v2-service")]
        Command::ServeProof {
            archive,
            binding,
            signing_key,
            grants,
            access_policy,
            erasure_history,
            listen,
            items,
            metadata_bytes,
        } => {
            let binding =
                serde_json::from_slice(&bounded_read(std::fs::File::open(binding)?, 4096)?)?;
            let grants = match grants {
                Some(path) => {
                    serde_json::from_slice(&bounded_read(std::fs::File::open(path)?, 65536)?)?
                }
                None => Vec::new(),
            };
            if items == 0 || metadata_bytes == 0 {
                return Err("proof read budgets must be positive".into());
            }
            let service = kan::evidence_proof_service::Service::new(
                archive,
                binding,
                service_identity(&signing_key)?,
                grants,
                kan::evidence_store::inventory::Budget {
                    items,
                    metadata_bytes,
                    duration: std::time::Duration::from_secs(4),
                    cancelled: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
                },
            )?;
            let service = match access_policy {
                Some(path) => service.with_policy(serde_json::from_slice(&bounded_read(
                    std::fs::File::open(path)?,
                    65536,
                )?)?)?,
                None => service,
            };
            let service = match erasure_history {
                Some(path) => service.with_erasure_history(serde_json::from_slice(
                    &bounded_read(std::fs::File::open(path)?, 65536)?,
                )?)?,
                None => service,
            };
            tokio::runtime::Runtime::new()?.block_on(async {
                let listener = kan::evidence_http::bind(listen).await?;
                eprintln!("proof reader http://{}/v2/read", listener.local_addr()?);
                #[cfg(feature = "v2-crypto")]
                { tokio::select! { result=kan::evidence_http::serve_proof(listener,service)=>result, _=shutdown()=>Ok(()) } }
                #[cfg(not(feature = "v2-crypto"))]
                { kan::evidence_http::serve_proof(listener,service).await }
            })?;
        }
        #[cfg(feature = "v2-service")]
        Command::SignRequest { key } => {
            let request = serde_json::from_slice(&bounded_read(
                std::io::stdin().lock(),
                kan::evidence_service::MAX_REQUEST,
            )?)?;
            let signed =
                kan::evidence_service::SignedRequest::sign(request, &service_identity(&key)?)?;
            // Exact wire bytes: adding a newline would make the signed envelope noncanonical.
            use std::io::Write;
            std::io::stdout().lock().write_all(&signed.bytes()?)?;
        }
        #[cfg(feature = "v2-service")]
        Command::Rpc {
            request,
            endpoint,
            issuer,
        } => {
            let bytes = bounded_read(
                std::fs::File::open(request)?,
                kan::evidence_service::MAX_REQUEST,
            )?;
            kan::evidence_service::SignedRequest::decode(&bytes)?;
            let reply = tokio::runtime::Runtime::new()?
                .block_on(kan::evidence_http::send(&endpoint, &issuer, &bytes))?;
            println!("{}", serde_json::to_string(&reply)?);
            if reply.reply.result.is_err() {
                return Err("service returned the signed failure printed above".into());
            }
        }
        Command::Discover { roots } => println!(
            "{}",
            serde_json::to_string_pretty(&migration_preflight::discover(&roots))?
        ),
        Command::Preview { root, store } => println!(
            "{}",
            serde_json::to_string_pretty(&if store {
                migration_preflight::preview_store(&root)?
            } else {
                migration_preflight::preview(&root)?
            })?
        ),
        Command::PreviewIdentity { config_root } => println!(
            "{}",
            serde_json::to_string_pretty(&migration_preflight::preview_identity(&config_root)?)?
        ),
        Command::CopyPlan {
            database,
            plan,
            scope,
            issuer,
            historical_issuer,
            nonce,
        } => {
            kan::evidence_store::copy_upgrade::validate_plan_destination(&database, &plan)?;
            let source = kan::evidence_store::copy_upgrade::PlannedCopy::open(
                &database,
                kan::evidence_copy_plan::Target {
                    scope: fixed_hex(&scope)?,
                    issuer,
                },
                historical_issuer,
                fixed_hex(&nonce)?,
            )?;
            let path = plan.to_str().ok_or("plan JSON requires a UTF-8 path")?;
            kan::evidence_store::copy_upgrade::retain_plan(&plan, &source)?;
            print_json(
                &serde_json::json!({"plan":path,"archive":hex(&source.plan().archive_id()),"source_through":source.plan().source().through,"profile":3,"promoted":false}),
            )?;
        }
        Command::CopyBatch {
            database,
            archive,
            plan,
            key,
            resume,
            proof,
            objects,
            records,
            bytes,
        } => {
            if !proof.copy_profile {
                return Err("copy-batch requires --copy-profile and all owner pins".into());
            }
            let binding = proof.binding()?.ok_or("copy requires owner pins")?;
            let recipe = kan::evidence_store::copy_upgrade::read_plan_for_copy(
                &plan,
                &database,
                &archive,
                &binding.archive,
            )?;
            let source = kan::evidence_store::copy_upgrade::PlannedCopy::confirm(
                &database,
                &recipe,
                &binding.archive,
            )?;
            let signer = kan::sign::Identity::load_existing(&key)?;
            if signer.did().as_str() != binding.issuer {
                return Err("copy signer differs from owner issuer".into());
            }
            let budget = kan::evidence_store::copied::Budget {
                objects,
                records,
                bytes,
            };
            budget.validate()?;
            let mut destination = if resume {
                kan::evidence_store::copied::Archive::resume_initialization(
                    &archive, &source, binding,
                )?
            } else {
                kan::evidence_store::copied::Archive::create(&archive, &source, binding)?
            };
            let now = u64::try_from(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)?
                    .as_millis(),
            )?;
            let batch = destination.copy_batch(&source, &signer, now, budget)?;
            print_json(
                &serde_json::json!({"profile":3,"copy":batch.status,"objects_written":batch.objects_written,"records_written":batch.records_written,"bytes_written":batch.bytes_written,"promoted":false,"activated":false}),
            )?;
        }
        Command::Init {
            archive,
            resume,
            proof,
        } => {
            if proof.copy_profile {
                return Err(
                    "profile 3 initialization requires copy-batch with a pinned source and recipe"
                        .into(),
                );
            }
            let binding = proof.binding()?;
            let archive_text = archive
                .to_str()
                .ok_or("init JSON requires a UTF-8 archive path")?;
            let (commits, profile) = if let Some(binding) = binding {
                let store = if resume {
                    kan::evidence_store::attested::Archive::resume_initialization(&archive, binding)
                } else {
                    kan::evidence_store::attested::Archive::create(&archive, binding)
                }
                .map_err(|e| format!("cannot initialize {}: {e}", archive.display()))?;
                (store.verify()?.through, 2)
            } else {
                let store = if resume {
                    Ledger::resume_initialization(&archive)
                } else {
                    Ledger::create(&archive)
                }
                .map_err(|e| format!("cannot initialize {}: {e}", archive.display()))?;
                (store.verify()?.commits, 1)
            };
            println!(
                "{}",
                serde_json::json!({"archive":archive_text,"created":if resume {None} else {Some(archive_text)},"resume_requested":resume,"commits":commits,"profile":profile,"experimental":true})
            );
        }
        Command::Verify { database, proof } => {
            let copy_profile = proof.copy_profile;
            let binding = proof.binding()?;
            let attested = binding.is_some();
            let mut copy = None;
            let report = if let Some(binding) = binding {
                if copy_profile {
                    let report =
                        kan::evidence_store::copied::Archive::verify_file(&database, binding)?;
                    copy = Some(report.copy);
                    report.contents
                } else {
                    kan::evidence_store::attested::Archive::verify_file(&database, binding)?
                }
            } else {
                Ledger::verify_file(&database)?
            };
            println!(
                "{}",
                serde_json::json!({"copy":copy,"objects":report.objects,"erased_objects":report.erased_objects,"commits":report.commits,"bytes":report.bytes,"through":report.snapshot.through,"tip":report.snapshot.tip.map(|c|c.to_string()),"verification":if report.erased_objects>0 {"retained-payloads-issuer-proofs-and-erasure-authorizations"} else if attested {"payloads-writer-requests-and-issuer-proofs"} else {"structural-closure"},"writable_admission":"not-checked","cryptographic_admission":if attested {"proof-purpose-dependent"} else {"not-verified"},"historical_completeness":"not-verified"})
            );
        }
        Command::Backup {
            archive,
            destination,
            proof,
        } => {
            let copy_profile = proof.copy_profile;
            let binding = proof.binding()?;
            let attested = binding.is_some();
            let destination_text = destination
                .to_str()
                .ok_or("backup JSON requires a UTF-8 destination path")?;
            let mut copy = None;
            let result = if let Some(binding) = binding {
                if copy_profile {
                    kan::evidence_store::copied::Archive::open(&archive, binding)?
                        .backup(&destination)
                        .map(|report| {
                            copy = Some(report.copy);
                            report.contents
                        })
                } else {
                    kan::evidence_store::attested::Archive::open(&archive, binding)?
                        .backup(&destination)
                }
            } else {
                Ledger::open(&archive)?.backup(&destination)
            };
            let report = result.map_err(|e| {
                format!(
                    "backup into {} failed: {e}; any output is retained",
                    destination.display()
                )
            })?;
            println!(
                "{}",
                serde_json::json!({"copy":copy,"backup":destination_text,"objects":report.objects,"erased_objects":report.erased_objects,"commits":report.commits,"bytes":report.bytes,"independent_backup":false,"issuer_proofs":if attested {"verified-preserved"} else {"not-present"}})
            );
        }
        Command::ReadRecord { database, sequence } => {
            let record = RecoveryReader::open(&database)
                .and_then(|reader| reader.record(sequence))
                .map_err(|e| {
                    format!(
                        "cannot read sequence {sequence} from {}: {e}",
                        database.display()
                    )
                })?;
            println!(
                "{}",
                serde_json::json!({
                    "sequence":record.sequence, "encoding":"hex", "record_format":"dag-cbor",
                    "manifest_cid":record.manifest.cid().to_string(), "manifest":hex(record.manifest.bytes()),
                    "receipt_cid":record.receipt.cid().to_string(), "receipt":hex(record.receipt.bytes()),
                    "verification":"canonical-records-and-receipt-binding",
                    "cryptographic_admission":"not-verified", "historical_completeness":"not-verified"
                })
            );
        }
        Command::ReadObject { database, cid } => {
            let id = cid
                .parse()
                .map_err(|e| format!("invalid ciphertext CID: {e}"))?;
            let bytes = RecoveryReader::open(&database)
                .and_then(|reader| reader.read_object(&id))
                .map_err(|e| {
                    format!("cannot read object {cid} from {}: {e}", database.display())
                })?;
            println!(
                "{}",
                serde_json::json!({
                    "cid":id.to_string(), "encoding":"hex", "bytes":hex(&bytes), "length":bytes.len(),
                    "verification":"length-and-content-hash", "content":"opaque-ciphertext",
                    "cryptographic_admission":"not-verified", "historical_completeness":"not-verified"
                })
            );
        }
        Command::Recover {
            database,
            destination,
            proof,
        } => {
            let copy_profile = proof.copy_profile;
            let binding = proof.binding()?;
            let attested = binding.is_some();
            // JSON paths must be representable BEFORE creating any output file.
            let source_text = database
                .to_str()
                .ok_or("recovery JSON requires a UTF-8 source path")?;
            let destination_text = destination
                .to_str()
                .ok_or("recovery JSON requires a UTF-8 destination path")?;
            let mut copy = None;
            let result = if let Some(binding) = binding {
                if copy_profile {
                    kan::evidence_store::copied::Recovery::open(&database, binding)
                        .map_err(|e| {
                            format!("cannot read recovery source {}: {e}", database.display())
                        })?
                        .rebuild(&destination)
                        .map(|report| {
                            copy = Some(report.copy);
                            report.contents
                        })
                } else {
                    kan::evidence_store::attested::Recovery::open(&database, binding)
                        .map_err(|e| {
                            format!("cannot read recovery source {}: {e}", database.display())
                        })?
                        .rebuild(&destination)
                }
            } else {
                RecoveryReader::open(&database)
                    .map_err(|e| {
                        format!("cannot read recovery source {}: {e}", database.display())
                    })?
                    .rebuild(&destination)
            };
            let report = result.map_err(|e| format!(
                "recovery into {} failed: {e}; destination must be a new file; any output is retained",
                destination.display()))?;
            println!(
                "{}",
                serde_json::json!({"copy":copy,
                    "source":source_text, "recovered":destination_text, "objects":report.objects,"erased_objects":report.erased_objects,
                    "commits":report.commits, "bytes":report.bytes, "through":report.snapshot.through,
                    "tip":report.snapshot.tip.map(|c|c.to_string()), "verification":if report.erased_objects>0 {"retained-payloads-issuer-proofs-and-erasure-authorizations"} else if attested {"payloads-writer-requests-and-issuer-proofs"} else {"structural-closure"},
                    "cryptographic_admission":if attested {"proof-purpose-dependent"} else {"not-verified"}, "historical_completeness":"not-verified",
                    "independent_backup":false, "promoted":false
                })
            );
        }
    }
    Ok(())
}

fn print_json(value: &serde_json::Value) -> std::io::Result<()> {
    use std::io::Write;
    let mut out = std::io::stdout().lock();
    serde_json::to_writer(&mut out, value)?;
    out.write_all(b"\n")?;
    out.flush()
}

fn fixed_hex<const N: usize>(value: &str) -> Result<[u8; N], Box<dyn std::error::Error>> {
    kan::evidence_service::unhex(value, N)?
        .try_into()
        .map_err(|_| "incorrect hex length".into())
}

#[cfg(feature = "v2-crypto")]
fn recipient_private(path: &std::path::Path) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    Ok(kan::evidence_crypto::read_private_key(path)?)
}

#[cfg(feature = "v2-service")]
fn bounded_read(reader: impl std::io::Read, limit: usize) -> std::io::Result<Vec<u8>> {
    use std::io::Read;
    let mut bytes = Vec::new();
    reader.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(std::io::Error::other("input exceeds byte limit"));
    }
    Ok(bytes)
}

#[cfg(feature = "v2-service")]
fn service_identity(
    path: &std::path::Path,
) -> Result<kan::sign::Identity, Box<dyn std::error::Error>> {
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > 1024 {
        return Err("signing key must be a small regular owner-only file".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err("signing key must be owner-only".into());
        }
    }
    #[cfg(not(unix))]
    return Err("service key-file permission validation is currently Unix-only".into());
    #[cfg(unix)]
    Ok(kan::sign::Identity::load_existing(path)?)
}
#[cfg(feature = "v2-crypto")]
fn run_proxy(
    listen: std::net::SocketAddr,
    auth: kan::evidence_gateway::ListenerAuth,
    route: kan::evidence_capture::Route,
    observer: kan::evidence_capture::Observer,
    capture: ProxyCapture,
    provider_key: Option<Vec<u8>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let provider_key = provider_key
        .map(|bytes| {
            let bytes = bytes.strip_suffix(b"\n").unwrap_or(&bytes);
            let mut value = reqwest::header::HeaderValue::from_bytes(bytes)?;
            value.set_sensitive(true);
            Ok::<_, reqwest::header::InvalidHeaderValue>(value)
        })
        .transpose()?;
    let signer = service_identity(&capture.key)?;
    let (report, guard) = if let Some(path) = &capture.health_journal {
        match kan::evidence_operations::reporter_at(
            path.clone(),
            capture.spool.clone(),
            signer.did().to_string(),
        ) {
            Ok((report, guard)) => (report, Some(guard)),
            Err(_) => {
                eprintln!("health reporter could not start; recording coverage is unknown");
                let report: kan::evidence_gateway::HealthReporter = std::sync::Arc::new(|_| {});
                (report, None)
            }
        }
    } else {
        let report: kan::evidence_gateway::HealthReporter = std::sync::Arc::new(|h| {
            if let Ok(json) = serde_json::to_string(h) {
                eprintln!("{json}");
            }
        });
        (report, None)
    };
    let config = kan::evidence_gateway::Config {
        profile: capture.profile,
        provider_key,
        route,
        observer,
        spool: capture.spool,
        signer,
        recipient: fixed_hex::<32>(&capture.recipient)?,
        key_history: capture
            .key_history
            .map(
                |p| -> Result<kan::evidence_keys::Access, Box<dyn std::error::Error>> {
                    Ok(serde_json::from_slice(
                        &kan::evidence_gateway::secret_file(&p)?,
                    )?)
                },
            )
            .transpose()?,
        io_budget: std::time::Duration::from_secs(u64::from(capture.deadline_seconds)),
        report,
    };
    config.validate()?;
    auth.validate(listen)?;
    let runtime = tokio::runtime::Runtime::new()?;
    let result = runtime.block_on(async move {
        let listener = tokio::net::TcpListener::bind(listen).await?;
        eprintln!(
            "{}",
            serde_json::json!({"listening":listener.local_addr()?.to_string(),"observer":observer})
        );
        tokio::select! {
            result=kan::evidence_gateway::serve(listener,auth,config)=>result,
            _=shutdown()=>Ok(())
        }
    });
    if let Some(guard) = guard {
        guard.join();
    }
    result?;
    Ok(())
}
#[cfg(feature = "v2-crypto")]
async fn shutdown() {
    #[cfg(unix)]
    {
        if let Ok(mut term) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            tokio::select! { _=tokio::signal::ctrl_c()=>{}, _=term.recv()=>{} }
            return;
        }
    }
    let _ = tokio::signal::ctrl_c().await;
}
fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(feature = "v2-crypto")]
fn load_owner(
    path: &std::path::Path,
    deployment: Option<&managed::Deployment>,
) -> Result<std::sync::Arc<kan::evidence_library::Owner>, Box<dyn std::error::Error>> {
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct File {
        journal: PathBuf,
        signing_key: PathBuf,
        recipient_key: PathBuf,
        authority: kan::evidence_library::OwnerConfig,
    }
    let config: File = serde_json::from_slice(&kan::evidence_gateway::secret_file(path)?)?;
    if !config.journal.is_absolute()
        || !config.signing_key.is_absolute()
        || !config.recipient_key.is_absolute()
    {
        return Err("owner paths must be absolute".into());
    }
    if let Some(deployment) = deployment {
        deployment.validate_owner(&config.authority)?;
    }
    let workspace = kan::evidence_workspace::Workspace::open(
        &config.journal,
        service_identity(&config.signing_key)?,
        recipient_private(&config.recipient_key)?,
    )?;
    Ok(kan::evidence_library::Owner::new(
        config.authority,
        workspace,
    )?)
}
