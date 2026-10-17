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
    /// Locate existing v1 workspaces; source files are not changed.
    Discover {
        #[arg(required = true)]
        roots: Vec<PathBuf>,
    },
    /// Hash raw evidence and inspect CAR framing; does not import or verify claims.
    Preview { root: PathBuf },
    /// Create a new opaque ledger. Its parent directory must already exist.
    Init { archive: PathBuf },
    /// Verify a quiescent archive/backup file without writing to it.
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
        Command::Discover { roots } => println!(
            "{}",
            serde_json::to_string_pretty(&migration_preflight::discover(&roots))?
        ),
        Command::Preview { root } => println!(
            "{}",
            serde_json::to_string_pretty(&migration_preflight::preview(&root)?)?
        ),
        Command::Init { archive } => {
            let store = Ledger::create(&archive)?;
            println!(
                "{}",
                serde_json::json!({"created":archive,"commits":store.verify()?.commits,"experimental":true})
            );
        }
        Command::Verify { database } => {
            let report = Ledger::verify_file(&database)?;
            println!(
                "{}",
                serde_json::json!({"objects":report.objects,"commits":report.commits,"bytes":report.bytes,"through":report.snapshot.through,"tip":report.snapshot.tip.map(|c|c.to_string()),"cryptographic_admission":"not-verified"})
            );
        }
        Command::Backup {
            archive,
            destination,
        } => {
            let report = Ledger::open(&archive)?.backup(&destination)?;
            println!(
                "{}",
                serde_json::json!({"backup":destination,"objects":report.objects,"commits":report.commits,"bytes":report.bytes,"independent_backup":false})
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
fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}
