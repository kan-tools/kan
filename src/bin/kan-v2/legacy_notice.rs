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

fn display_path(path: &Path) -> String {
    // JSON handles C0 controls, quotes and backslashes. Escape the remaining
    // controls and Unicode bidi formatting characters before terminal output.
    let json = serde_json::to_string(&path.to_string_lossy()).unwrap_or_default();
    let mut safe = String::with_capacity(json.len());
    for ch in json.chars() {
        if ch.is_control()
            || matches!(ch, '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
        {
            use std::fmt::Write;
            let _ = write!(safe, "\\u{:04x}", ch as u32);
        } else {
            safe.push(ch);
        }
    }
    safe
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
            // Never interpolate project paths into shell commands.
            let root = display_path(root);
            let state = if fenced {
                "A v1 writer-fence marker is present; it does not prove import, verification or activation completed. Do not remove it to bypass migration."
            } else {
                "Migration is not confirmed by this notice. Retained v1 files can also belong to an already migrated project."
            };
            let message = format!(
                "Legacy v1 workspace detected at {root}.\n\
                 `kan` now runs v2; repository claim commands belong to optional `kan-v1`.\n\
                 {state}\n\
                 If not migrated: (1) from that project root, run `kan preview .` to inspect source evidence read-only; preserve originals and backups.\n\
                 (2) Configure the destination, keys and owner migration target; stop old writers, then preview/apply fence-migration and finalize-migration and deliver the queue.\n\
                 (3) Independently back up and verify the final snapshot; preview/apply activate-migration and explicitly restart clients. Import alone is not cutover.\n\
                 Runbook: https://github.com/kan-tools/kan/blob/main/docs/V2-LIBRARY.md#fenced-migration-and-reversible-client-cutover (source inventory: docs/V2-IMPORT.md).\n\
                 Agents: report this notice to the owner; do not migrate, activate or delete data without authorization.\n\
                 For known migrated projects, `--no-migration-notice` suppresses this reminder for one invocation; it does not certify migration.\n"
            );
            let message: String = message
                .lines()
                .map(|line| format!("[kan:legacy-workspace] {line}\n"))
                .collect();
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
