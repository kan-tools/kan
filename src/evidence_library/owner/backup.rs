//! Owner-triggered destination verification and cold-restore coverage.
use super::*;
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub database: PathBuf,
    pub binding: Binding,
    pub destination: String,
    pub independent: bool,
    pub checkpoints: PathBuf,
    #[serde(default)]
    pub checkpoint: Option<PathBuf>,
    #[serde(default)]
    pub checkpoint_author: Option<String>,
    #[serde(default)]
    pub witnessed: Option<PathBuf>,
}
impl Config {
    pub(super) fn validate(&self) -> Result<(), Failure> {
        self.binding.owner_binding()?;
        private_directory(&self.checkpoints)?;
        if !self.database.is_absolute()
            || self.checkpoint.as_ref().is_some_and(|p| !p.is_absolute())
            || self.witnessed.as_ref().is_some_and(|p| !p.is_absolute())
            || self.checkpoint.is_some() != self.checkpoint_author.is_some()
            || self.destination.is_empty()
            || self.destination.len() > 128
        {
            return Err(Failure::Invalid);
        }
        Ok(())
    }
    pub(super) fn perform(
        &self,
        operation: Operation,
        output: Option<&Path>,
        workspace: &Workspace,
    ) -> Result<Value, Failure> {
        let observed = crate::evidence_backup::inspect(
            &self.database,
            &self.binding,
            &self.destination,
            self.independent,
        )?;
        let witness: Option<crate::evidence_reader::proof::Pin> =
            self.witnessed.as_ref().map(|p| read(p)).transpose()?;
        let checkpoint = if operation == Operation::VerifyBackup {
            workspace.backup_checkpoint(observed.clone())?
        } else if operation == Operation::VerifyRestore {
            read(self.checkpoint.as_deref().ok_or(Failure::Invalid)?)?
        } else {
            return Err(Failure::Invalid);
        };
        let author = if operation == Operation::VerifyBackup {
            workspace.author()
        } else {
            self.checkpoint_author.clone().ok_or(Failure::Invalid)?
        };
        let mut report =
            crate::evidence_backup::coverage(&checkpoint, &author, &observed, witness.as_ref())?;
        if operation == Operation::VerifyBackup {
            let output = output.ok_or(Failure::Invalid)?;
            // surface-write: evidence-backup-checkpoint:receipt
            crate::persistence::write_new_owner_only(
                crate::persistence::SurfaceWrite::EvidenceBackupCheckpoint,
                output,
                &serde_json::to_vec(&checkpoint).map_err(|_| Failure::Invalid)?,
            )
            .map_err(|_| Failure::Unavailable)?;
            std::fs::File::open(output.parent().ok_or(Failure::Invalid)?)
                .and_then(|f| f.sync_all())
                .map_err(|_| Failure::Unavailable)?;
            report["checkpoint_file"] = json!(output);
        }
        report["checkpoint"] = serde_json::to_value(checkpoint).map_err(|_| Failure::Invalid)?;
        Ok(report)
    }
}
fn read<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, Failure> {
    use std::io::Read;
    let metadata = std::fs::symlink_metadata(path).map_err(|_| Failure::Missing)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > 262144 {
        return Err(Failure::Invalid);
    }
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .map_err(|_| Failure::Missing)?
        .take(262145)
        .read_to_end(&mut bytes)
        .map_err(|_| Failure::Unavailable)?;
    if bytes.len() > 262144 {
        return Err(Failure::Invalid);
    }
    serde_json::from_slice(&bytes).map_err(|_| Failure::Corrupt)
}
