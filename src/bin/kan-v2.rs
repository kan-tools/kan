//! Experimental archive maintenance and migration preflight; no live cutover.
use clap::{Parser, Subcommand};
use kan::{
    evidence_store::{Ledger, RecoveryReader},
    migration_preflight,
};
use std::path::PathBuf;

#[derive(Parser)]
#[command(about = "Experimental kan v2 archive maintenance and read-only migration preflight")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
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
    },
    /// Verify structural evidence in a quiescent file; does not check writable admission.
    Verify { database: PathBuf },
    /// Make and verify a consistent local backup into a new file.
    Backup {
        archive: PathBuf,
        destination: PathBuf,
    },
    /// Read exact canonical record bytes despite damaged derived lookups.
    ReadRecord { database: PathBuf, sequence: u64 },
    /// Read and hash-check one opaque object using an offline key scan.
    ReadObject { database: PathBuf, cid: String },
    /// Rebuild derived data into a NEW file; retain the source and any failed output.
    Recover {
        database: PathBuf,
        destination: PathBuf,
    },
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn run() -> Result<(), Box<dyn std::error::Error>> {
    match Cli::parse().command {
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
        Command::Init { archive, resume } => {
            let archive_text = archive
                .to_str()
                .ok_or("init JSON requires a UTF-8 archive path")?;
            let store = if resume {
                Ledger::resume_initialization(&archive)
            } else {
                Ledger::create(&archive)
            }
            .map_err(|e| format!("cannot initialize {}: {e}", archive.display()))?;
            println!(
                "{}",
                serde_json::json!({"archive":archive_text,"created":if resume { None } else { Some(archive_text) },"resume_requested":resume,"commits":store.verify()?.commits,"experimental":true})
            );
        }
        Command::Verify { database } => {
            let report = Ledger::verify_file(&database)?;
            println!(
                "{}",
                serde_json::json!({"objects":report.objects,"commits":report.commits,"bytes":report.bytes,"through":report.snapshot.through,"tip":report.snapshot.tip.map(|c|c.to_string()),"verification":"structural-closure","writable_admission":"not-checked","cryptographic_admission":"not-verified","historical_completeness":"not-verified"})
            );
        }
        Command::Backup {
            archive,
            destination,
        } => {
            let destination_text = destination
                .to_str()
                .ok_or("backup JSON requires a UTF-8 destination path")?;
            let report = Ledger::open(&archive)?.backup(&destination).map_err(|e| {
                format!(
                    "backup into {} failed: {e}; any output is retained",
                    destination.display()
                )
            })?;
            println!(
                "{}",
                serde_json::json!({"backup":destination_text,"objects":report.objects,"commits":report.commits,"bytes":report.bytes,"independent_backup":false})
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
        } => {
            // JSON paths must be representable BEFORE creating any output file.
            let source_text = database
                .to_str()
                .ok_or("recovery JSON requires a UTF-8 source path")?;
            let destination_text = destination
                .to_str()
                .ok_or("recovery JSON requires a UTF-8 destination path")?;
            let reader = RecoveryReader::open(&database)
                .map_err(|e| format!("cannot read recovery source {}: {e}", database.display()))?;
            let report = reader.rebuild(&destination).map_err(|e| format!(
                "recovery into {} failed: {e}; destination must be a new file; any output is retained",
                destination.display()))?;
            println!(
                "{}",
                serde_json::json!({
                    "source":source_text, "recovered":destination_text, "objects":report.objects,
                    "commits":report.commits, "bytes":report.bytes, "through":report.snapshot.through,
                    "tip":report.snapshot.tip.map(|c|c.to_string()), "verification":"structural-closure",
                    "cryptographic_admission":"not-verified", "historical_completeness":"not-verified",
                    "independent_backup":false, "promoted":false
                })
            );
        }
    }
    Ok(())
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
fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}
