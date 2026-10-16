//! Experimental archive maintenance and migration preflight; no live cutover.
use clap::{Parser, Subcommand};
use kan::{evidence_store::Ledger, migration_preflight};
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
