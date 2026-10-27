//! Advisory only: never open a log, load keys, create a marker or infer cutover.
use std::{fs, io::Write, path::Path};

fn directory(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|m| m.is_dir() && !m.file_type().is_symlink())
}

fn exists(path: &Path) -> bool {
    // Metadata only, including broken links; no target is opened.
    fs::symlink_metadata(path).is_ok()
}

fn workspace(path: &Path) -> bool {
    directory(&path.join(".claims"))
        || (directory(&path.join(".kan"))
            && (["log", "overlay", "scope"]
                .iter()
                .any(|name| directory(&path.join(".kan").join(name)))
                || ["seed", "identity"]
                    .iter()
                    .any(|name| exists(&path.join(".kan").join(name)))))
}

pub(super) fn emit() {
    let Ok(cwd) = std::env::current_dir() else {
        return;
    };
    // Look upward only, bounded even in an unusually deep tree. A nested Git
    // project must not inherit a reminder about an unrelated outer workspace.
    for root in cwd.ancestors().take(64) {
        if workspace(root) {
            let fenced = directory(&root.join(".kan")) && exists(&root.join(".kan/V2_FENCE"));
            // JSON escaping prevents project names from injecting terminal controls
            // or extra diagnostic lines. Never interpolate them into shell commands.
            let root = serde_json::to_string(&root.to_string_lossy()).unwrap_or_default();
            let state = if fenced {
                "A v1 writer-fence marker is present; it does not prove import, verification or activation completed. Do not remove it to bypass migration."
            } else {
                "Migration is not confirmed by this notice. Retained v1 files can also belong to an already migrated project."
            };
            let message = format!(
                "[kan:legacy-workspace] Legacy v1 workspace detected at {root}.\n\
                 `kan` now runs v2; repository claim commands belong to optional `kan-v1`.\n\
                 {state}\n\
                 If not migrated: (1) from that project root, run `kan preview .` to inspect source evidence read-only; preserve originals and backups.\n\
                 (2) Configure the destination, keys and owner migration target; stop old writers, then preview/apply fence-migration and finalize-migration and deliver the queue.\n\
                 (3) Independently back up and verify the final snapshot; preview/apply activate-migration and explicitly restart clients. Import alone is not cutover.\n\
                 Runbook: https://github.com/kan-tools/kan/blob/main/docs/V2-LIBRARY.md#fenced-migration-and-reversible-client-cutover (source inventory: docs/V2-IMPORT.md).\n\
                 Agents: report this notice to the owner; do not migrate, activate or delete data without authorization.\n\
                 For known migrated projects, `--no-migration-notice` suppresses this reminder for one invocation; it does not certify migration.\n"
            );
            // Stderr only: JSON, exact-byte downloads and MCP stdout are untouched.
            // A closed diagnostic pipe must not change the requested command.
            let _ = std::io::stderr().lock().write_all(message.as_bytes());
            return;
        }
        if exists(&root.join(".git")) {
            return;
        }
    }
}
