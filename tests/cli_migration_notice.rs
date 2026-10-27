#![cfg(feature = "v2-crypto")]

use std::{
    fs,
    path::Path,
    process::{Command, Output},
};

fn project() -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    fs::create_dir(root.path().join(".git")).unwrap();
    root
}

fn kan(root: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_kan"))
        .current_dir(root)
        .args(args)
        .output()
        .unwrap()
}

fn stderr(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).unwrap()
}

#[test]
fn help_version_and_errors_keep_their_contract_with_a_legacy_notice() {
    let root = project();
    fs::create_dir_all(root.path().join(".kan/log")).unwrap();
    let evidence = root.path().join(".kan/log/repo.car");
    fs::write(&evidence, b"retained damaged evidence").unwrap();
    for args in [&["--help"][..], &["--version"][..]] {
        let output = kan(root.path(), args);
        assert!(output.status.success());
        let notice = stderr(&output);
        assert_eq!(notice.matches("[kan:legacy-workspace]").count(), 1);
        for text in [
            "kan preview .",
            "fence-migration",
            "finalize-migration",
            "activate-migration",
            "not cutover",
            "do not migrate",
            "--no-migration-notice",
        ] {
            assert!(notice.contains(text), "{notice}");
        }
        assert!(!String::from_utf8_lossy(&output.stdout).contains("legacy-workspace"));
    }
    let output = kan(root.path(), &["observe"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(stderr(&output).contains("unrecognized subcommand"));
    assert!(stderr(&output).contains("optional `kan-v1`"));
    assert_eq!(fs::read(evidence).unwrap(), b"retained damaged evidence");
    assert!(!root.path().join(".kan/V2_FENCE").exists());
    assert_eq!(fs::read_dir(root.path().join(".kan")).unwrap().count(), 1);
}

#[test]
fn published_claims_notice_preserves_json_and_fence_is_not_completion() {
    let root = project();
    fs::create_dir(root.path().join(".claims")).unwrap();
    let output = kan(root.path(), &["preview", "."]);
    assert!(output.status.success(), "{}", stderr(&output));
    let _: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(stderr(&output).contains("already migrated project"));
    assert!(!root.path().join(".kan").exists());
    fs::create_dir(root.path().join(".kan")).unwrap();
    let fence = root.path().join(".kan/V2_FENCE");
    fs::write(&fence, b"partial fence bytes").unwrap();
    let output = kan(root.path(), &["--version"]);
    assert!(stderr(&output).contains("does not prove import, verification or activation"));
    assert_eq!(fs::read(fence).unwrap(), b"partial fence bytes");
}

#[test]
fn detection_walks_project_ancestors_but_stops_at_nested_repository() {
    let root = project();
    assert!(kan(root.path(), &["--version"]).stderr.is_empty());
    fs::create_dir_all(root.path().join(".kan/scope")).unwrap();
    let child = root.path().join("src/nested");
    fs::create_dir_all(&child).unwrap();
    assert!(stderr(&kan(&child, &["--version"])).contains("legacy-workspace"));
    fs::write(child.join(".git"), b"gitdir: unrelated-worktree").unwrap();
    assert!(kan(&child, &["--version"]).stderr.is_empty());
}

#[test]
fn explicit_suppression_is_per_invocation_and_not_a_positional() {
    let root = project();
    fs::create_dir(root.path().join(".claims")).unwrap();
    for args in [
        &["--no-migration-notice", "--help"][..],
        &["--version", "--no-migration-notice"][..],
        &["preview", ".", "--no-migration-notice"][..],
    ] {
        let output = kan(root.path(), args);
        assert!(output.status.success(), "{}", stderr(&output));
        assert!(output.stderr.is_empty());
    }
    assert!(stderr(&kan(root.path(), &["--version"])).contains("legacy-workspace"));
    assert!(
        stderr(&kan(root.path(), &["--", "--no-migration-notice"])).contains("legacy-workspace")
    );
    assert_eq!(fs::read_dir(root.path()).unwrap().count(), 2);
}

#[cfg(unix)]
#[test]
fn marker_symlinks_are_not_followed_and_project_names_are_escaped() {
    use std::os::unix::fs::symlink;
    let root = project();
    let target = tempfile::tempdir().unwrap();
    fs::create_dir(target.path().join("log")).unwrap();
    symlink(target.path(), root.path().join(".kan")).unwrap();
    symlink(target.path(), root.path().join(".claims")).unwrap();
    assert!(kan(root.path(), &["--version"]).stderr.is_empty());
    let odd = root.path().join("project\n\u{1b}[31m");
    fs::create_dir_all(odd.join(".claims")).unwrap();
    let output = kan(&odd, &["--version"]);
    let notice = stderr(&output);
    assert!(notice.contains("project\\n\\u001b[31m"), "{notice}");
    assert!(!notice.contains('\u{1b}'));
}
