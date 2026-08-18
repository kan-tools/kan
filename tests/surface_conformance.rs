//! `.design/read-write-surface-conformance.md`: the committed declaration is
//! checked against facts gathered independently from persistence owners and
//! SQLite itself. Neither side can silently add a stored value for the other.

use std::collections::{BTreeMap, BTreeSet};

use kan::surface::SurfaceValue;
use kan::{
    claim::{Anchor, AuthorId, ClaimBody, ClaimContent, Rkey, SubjectRef},
    sign::Identity,
    store::{index::Index, log::Log},
};
use sha2::{Digest, Sha256};

const CATALOG: &str = include_str!("fixtures/read-write-surface.tsv");
const RULE_EVIDENCE: &[(&str, &str)] = &[
    ("claim-log", "tests/claim_substrate.rs"),
    ("current-root", "tests/log_recovery.rs"),
    ("atomic-head-replacement", "tests/log_concurrency.rs"),
    ("write-coordination", "tests/log_concurrency.rs"),
    ("published-claim", "tests/git_tree_trust.rs"),
    ("auto-git-tree-connection", "tests/reader.rs"),
    ("overlay-from-git-tree", "tests/surface_conformance.rs"),
    ("overlay-root", "tests/surface_conformance.rs"),
    ("index-freshness", "tests/workspace_staleness.rs"),
    ("index-from-media", "tests/surface_conformance.rs"),
    ("car-repair-temp", "tests/log_recovery.rs"),
    ("identity-at-rest", "tests/at_rest_guards.rs"),
    ("control-event-ledger", "tests/identity_ledger.rs"),
    ("atomic-control-event-install", "tests/identity_ledger.rs"),
    ("identity-profile-config", "tests/system_identity.rs"),
    ("default-actor-profile", "tests/system_identity.rs"),
    ("atomic-profile-install", "tests/system_identity.rs"),
    ("profile-write-coordination", "tests/system_identity.rs"),
    ("profile-credential-key", "tests/system_identity.rs"),
    ("stable-enrollment-nonce", "tests/system_identity_cli.rs"),
    ("platform-config-root", "tests/system_identity_cli.rs"),
    (
        "repository-inception-store",
        "tests/repository_identity_store.rs",
    ),
    (
        "stable-repository-nonce",
        "tests/repository_identity_store.rs",
    ),
    (
        "repository-write-coordination",
        "tests/repository_identity_store.rs",
    ),
    (
        "atomic-repository-inception-install",
        "tests/repository_identity_store.rs",
    ),
    ("identity-precedence", "tests/identity_cells.rs"),
    ("role-key", "tests/role_registry_invariants.rs"),
    ("legacy-role-config", "tests/role_declarations.rs"),
    ("git-ancestry", "tests/git_ancestry_cache.rs"),
    ("git-anchor", "tests/git_substrate.rs"),
    ("connection-config", ".design/medium-architecture.md"),
];
const PERSISTENCE_PATH_EXPRESSIONS: &[(&str, &str, &str)] = &[
    ("src/actions.rs", "\".kan\"", "workspace persistence root"),
    ("src/actions.rs", "\"identity\"", "identity:identity"),
    (
        "src/actions.rs",
        "crate::sign::IDENTITY_ID_FILE",
        "identity:identity-id",
    ),
    ("src/actions.rs", "crate::sign::SEED_FILE", "identity:seed"),
    (
        "src/actions.rs",
        "crate::sign::SEED_ID_FILE",
        "identity:seed-id",
    ),
    (
        "src/actions.rs",
        "crate::transport::git_tree::CLAIMS_DIR",
        "git-tree:.claims",
    ),
    (
        "src/actions.rs",
        "format!(\"seed.replaced-{stamp}\")",
        "identity:seed.replaced-*",
    ),
    (
        "src/actions.rs",
        "format!(\"{}.protected-{stamp}\", from.file().unwrap())",
        "identity:*.protected-*",
    ),
    (
        "src/actions.rs",
        "from.file().unwrap()",
        "identity:selected-file",
    ),
    ("src/actions.rs", "\", \"", "not a path"),
    ("src/actions.rs", "\" = \"", "not a path"),
    ("src/actions.rs", "\"\\n\"", "not a path"),
    ("src/sign.rs", "", "thread join, not a path"),
    (
        "src/identity/ledger.rs",
        "\"events\"",
        "identity-ledger:events/*.cbor",
    ),
    (
        "src/identity/repository_store.rs",
        "\"inception.cbor\"",
        "repository-identity:inception.cbor",
    ),
    (
        "src/identity/repository_store.rs",
        "\"initialization-nonce\"",
        "repository-identity:initialization-nonce",
    ),
    (
        "src/identity/repository_store.rs",
        "\"LOCK\"",
        "repository-identity:LOCK",
    ),
    (
        "src/identity/repository_store.rs",
        "format!(\".tmp-{}-{sequence}\", std::process::id())",
        "repository-identity:.tmp-*",
    ),
    (
        "src/identity/system.rs",
        "\"identity\"",
        "identity profiles root",
    ),
    (
        "src/identity/system.rs",
        "\"profiles\"",
        "identity-profiles:profiles/*.json",
    ),
    (
        "src/identity/system.rs",
        "\"credentials\"",
        "credentials:owner-only-file",
    ),
    (
        "src/identity/system.rs",
        "\"enrollment-nonce\"",
        "identity-profiles:enrollment-nonce",
    ),
    (
        "src/identity/system.rs",
        "name",
        "credentials:owner-only-file",
    ),
    (
        "src/identity/system.rs",
        "\"Library\"",
        "platform configuration directory",
    ),
    (
        "src/identity/system.rs",
        "\"Application Support\"",
        "platform configuration directory",
    ),
    (
        "src/identity/system.rs",
        "\".config\"",
        "platform configuration directory",
    ),
    (
        "src/identity/system.rs",
        "\"kan\"",
        "platform configuration directory",
    ),
    (
        "src/identity/system.rs",
        "path",
        "credentials:selected-owner-only-file",
    ),
    (
        "src/identity/system.rs",
        "format!(\"{}.json\", profile.alias)",
        "identity-profiles:profiles/*.json",
    ),
    (
        "src/identity/system.rs",
        "format!(\"{alias}.json\")",
        "identity-profiles:profiles/*.json",
    ),
    (
        "src/identity/system.rs",
        "\"default\"",
        "identity-profiles:default",
    ),
    (
        "src/identity/system.rs",
        "\"LOCK\"",
        "identity-profiles:LOCK",
    ),
    (
        "src/identity/system.rs",
        "format!(\".tmp-{}-{sequence}\", std::process::id())",
        "identity-profiles:.tmp-*",
    ),
    (
        "src/identity/ledger.rs",
        "format!(\"{proved}.cbor\")",
        "identity-ledger:events/*.cbor",
    ),
    (
        "src/identity/ledger.rs",
        "format!(\".tmp-{}-{sequence}-{}\", std::process::id(), proved)",
        "identity-ledger:events/.tmp-*",
    ),
    ("src/sign.rs", "\"identity\"", "identity:identity"),
    ("src/sign.rs", "\"log\"", "local-log directory"),
    ("src/sign.rs", "\"repo.car\"", "local-log:repo.car"),
    ("src/sign.rs", "IDENTITY_ID_FILE", "identity:identity-id"),
    ("src/sign.rs", "ROLES_FILE", "repo-config:legacy-roles"),
    ("src/sign.rs", "SEED_FILE", "identity:seed"),
    ("src/sign.rs", "SEED_ID_FILE", "identity:seed-id"),
    ("src/sign.rs", "account_file", "identity:selected-pointer"),
    ("src/sign.rs", "dest_name", "identity:selected-destination"),
    ("src/sign.rs", "f", "identity:selected-file"),
    (
        "src/sign.rs",
        "from.file().expect(\"an unprotected state names a file\")",
        "identity:selected-file",
    ),
    ("src/sign.rs", "pointer", "identity:selected-pointer"),
    (
        "src/store/log.rs",
        "\"repo.car\"",
        "local-log:repo.car, overlay:repo.car",
    ),
    (
        "src/store/log.rs",
        "\"HEAD\"",
        "local-log:HEAD, overlay:HEAD",
    ),
    (
        "src/store/log.rs",
        "\"tmp\"",
        "local-log:HEAD.tmp, overlay:HEAD.tmp",
    ),
    (
        "src/store/log.rs",
        "\"repair\"",
        "local-log:repo.repair, overlay:repo.repair",
    ),
    (
        "src/store/log.rs",
        "\"LOCK\"",
        "local-log:LOCK, overlay:LOCK",
    ),
    (
        "src/store/log.rs",
        "name",
        "local-log:repo.car.damaged-*, overlay:repo.car.damaged-*",
    ),
    (
        "src/store/log.rs",
        "\"log\"",
        "test-only temporary log directory",
    ),
    (
        "src/store/log.rs",
        "\"unknown\"",
        "test-only unsupported-codec log directory",
    ),
    (
        "src/store/log.rs",
        "\"substitution\"",
        "test-only substituted-record log directory",
    ),
    (
        "src/transport/git_tree.rs",
        "CLAIMS_DIR",
        "git-tree:.claims",
    ),
    (
        "src/transport/git_tree.rs",
        "&rel",
        "git-tree:subject-directory",
    ),
    (
        "src/transport/git_tree.rs",
        "format!(\"{leaf}.md\")",
        "git-tree:claim-file",
    ),
    (
        "src/transport/git_tree.rs",
        "file_name(subject)",
        "git-tree:claim-file",
    ),
    (
        "src/transport/git_tree.rs",
        "legacy_file_name(subject)",
        "git-tree:legacy-claim-file",
    ),
    ("src/transport/git_tree.rs", "\",\"", "not a path"),
    ("src/transport/git_tree.rs", "\"/\"", "not a path"),
    ("src/workspace.rs", "\".git\"", "repo-config:auto-git-tree"),
    ("src/workspace.rs", "\".kan\"", "workspace persistence root"),
    ("src/workspace.rs", "\"index.sqlite\"", "sqlite:meta"),
    ("src/workspace.rs", "\"log\"", "local-log:repo.car"),
    ("src/workspace.rs", "\"overlay\"", "overlay:repo.car"),
    (
        "src/workspace.rs",
        "crate::transport::git_tree::CLAIMS_DIR",
        "git-tree:.claims",
    ),
    ("src/workspace.rs", "\", \"", "not a path"),
];
const PERSISTENCE_MODULES: &[&str] = &[
    "src/actions.rs",
    "src/identity/ledger.rs",
    "src/identity/repository_store.rs",
    "src/identity/system.rs",
    "src/sign.rs",
    "src/store/index.rs",
    "src/store/log.rs",
    "src/persistence.rs",
    "src/transport/git_tree.rs",
    "src/workspace.rs",
];
const PERSISTENCE_MUTATION_SITES: &[(&str, &str, &str, usize)] = &[
    ("src/actions.rs", "create_dir_all", "Container", 1),
    ("src/actions.rs", "remove_file", "IdentityKeyMaterial", 1),
    ("src/actions.rs", "remove_file", "IdentityPointer", 2),
    ("src/actions.rs", "rename", "IdentityBackup", 2),
    (
        "src/identity/ledger.rs",
        "create_dir_all",
        "IdentityLedger",
        1,
    ),
    (
        "src/identity/system.rs",
        "create_dir_all",
        "IdentityProfiles",
        2,
    ),
    (
        "src/identity/repository_store.rs",
        "create_dir_all",
        "RepositoryIdentity",
        2,
    ),
    (
        "src/identity/repository_store.rs",
        "open_lock_file",
        "RepositoryIdentity",
        1,
    ),
    (
        "src/identity/repository_store.rs",
        "remove_file",
        "RepositoryIdentity",
        1,
    ),
    (
        "src/identity/repository_store.rs",
        "rename",
        "RepositoryIdentity",
        1,
    ),
    (
        "src/identity/repository_store.rs",
        "write",
        "RepositoryIdentity",
        1,
    ),
    (
        "src/identity/repository_store.rs",
        "write_new_owner_only",
        "RepositoryIdentity",
        1,
    ),
    (
        "src/identity/system.rs",
        "create_dir_all",
        "SystemCredentials",
        1,
    ),
    (
        "src/identity/system.rs",
        "open_lock_file",
        "IdentityProfiles",
        1,
    ),
    (
        "src/identity/system.rs",
        "remove_file",
        "IdentityProfiles",
        1,
    ),
    ("src/identity/system.rs", "rename", "IdentityProfiles", 1),
    ("src/identity/system.rs", "write", "IdentityProfiles", 1),
    (
        "src/identity/system.rs",
        "write_new_owner_only",
        "IdentityProfiles",
        1,
    ),
    ("src/identity/ledger.rs", "remove_file", "IdentityLedger", 1),
    ("src/identity/ledger.rs", "rename", "IdentityLedger", 1),
    ("src/identity/ledger.rs", "write", "IdentityLedger", 1),
    ("src/sign.rs", "create_dir_all", "Container", 1),
    ("src/sign.rs", "create_dir_all", "IdentityKeyMaterial", 2),
    ("src/sign.rs", "create_dir_all", "IdentitySeed", 1),
    ("src/sign.rs", "remove_file", "IdentityPointer", 1),
    ("src/sign.rs", "set_permissions", "IdentityKeyMaterial", 1),
    ("src/sign.rs", "write", "IdentityKeyMaterial", 1),
    ("src/sign.rs", "write", "IdentityPointer", 1),
    ("src/sign.rs", "write", "IdentitySeed", 1),
    (
        "src/sign.rs",
        "write_new_owner_only",
        "SystemCredentials",
        1,
    ),
    ("src/store/index.rs", "create_dir_all", "Sqlite", 1),
    ("src/store/index.rs", "remove_file", "Sqlite", 2),
    ("src/store/log.rs", "copy_async", "LocalLogDamaged", 1),
    ("src/store/log.rs", "copy_async", "Overlay", 1),
    ("src/store/log.rs", "create_dir_all_async", "LocalLogCar", 1),
    ("src/store/log.rs", "create_dir_all_async", "Overlay", 1),
    (
        "src/store/log.rs",
        "create_file_async",
        "LocalLogHeadTemp",
        1,
    ),
    ("src/store/log.rs", "create_file_async", "LocalLogRepair", 1),
    ("src/store/log.rs", "create_file_async", "Overlay", 2),
    ("src/store/log.rs", "open_append_async", "LocalLogCar", 1),
    ("src/store/log.rs", "open_append_async", "Overlay", 1),
    ("src/store/log.rs", "open_lock_file", "LocalLogLock", 1),
    ("src/store/log.rs", "open_lock_file", "Overlay", 1),
    ("src/store/log.rs", "rename_async", "LocalLogCar", 1),
    ("src/store/log.rs", "rename_async", "LocalLogHead", 1),
    ("src/store/log.rs", "rename_async", "Overlay", 2),
    ("src/transport/git_tree.rs", "create_dir_all", "GitTree", 1),
    ("src/transport/git_tree.rs", "remove_file", "GitTree", 1),
    ("src/transport/git_tree.rs", "write", "GitTree", 1),
    ("src/workspace.rs", "remove_dir_all", "Overlay", 2),
];

#[derive(Debug)]
struct Row<'a> {
    status: &'a str,
    authority: &'a str,
    source: &'a str,
    scope: &'a str,
    artifact: &'a str,
    value: &'a str,
    writer: &'a str,
    reader: &'a str,
    rule: &'a str,
    lifecycle: &'a str,
    design: &'a str,
}

fn rows() -> Vec<Row<'static>> {
    CATALOG
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .enumerate()
        .map(|(index, line)| {
            let fields: Vec<_> = line.split('\t').collect();
            assert_eq!(
                fields.len(),
                11,
                "surface row {} has {} fields, expected 11: {line}",
                index + 1,
                fields.len()
            );
            Row {
                status: fields[0],
                authority: fields[1],
                source: fields[2],
                scope: fields[3],
                artifact: fields[4],
                value: fields[5],
                writer: fields[6],
                reader: fields[7],
                rule: fields[8],
                lifecycle: fields[9],
                design: fields[10],
            }
        })
        .collect()
}

fn sqlite_values() -> Vec<(String, String)> {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("index.sqlite");
    let mut index = kan::store::index::Index::open(&path).unwrap();
    index.rebuild(&[], &[], None).unwrap();
    drop(index);
    let connection = rusqlite::Connection::open(path).unwrap();
    let mut out = Vec::new();
    let mut table_statement = connection
        .prepare(
            "SELECT name FROM sqlite_master \
             WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
        )
        .unwrap();
    let tables: Vec<String> = table_statement
        .query_map([], |row| row.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    drop(table_statement);
    for table in tables {
        let mut statement = connection
            .prepare(&format!("PRAGMA table_info({table})"))
            .unwrap();
        let columns = statement
            .query_map([], |row| row.get::<_, String>(1))
            .unwrap();
        for column in columns {
            out.push((format!("sqlite:{table}"), column.unwrap()));
        }
    }
    let mut statement = connection
        .prepare("SELECT key FROM meta ORDER BY key")
        .unwrap();
    for key in statement
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
    {
        out.push(("sqlite:meta-key".into(), key.unwrap()));
    }
    out
}

fn implemented_values() -> BTreeSet<(String, String)> {
    let declared = kan::store::log::SURFACE_VALUES
        .iter()
        .chain(kan::transport::git_tree::SURFACE_VALUES)
        .chain(kan::sign::SURFACE_VALUES)
        .chain(kan::workspace::SURFACE_VALUES)
        .chain(kan::git::SURFACE_VALUES)
        .chain(kan::actions::SURFACE_VALUES)
        .chain(kan::identity::ledger::SURFACE_VALUES)
        .chain(kan::identity::repository_store::SURFACE_VALUES)
        .chain(kan::identity::system::SURFACE_VALUES)
        .map(|SurfaceValue { artifact, value }| ((*artifact).into(), (*value).into()));
    declared.chain(sqlite_values()).collect()
}

#[test]
fn catalog_is_well_formed_and_cites_real_designs() {
    fn heading_anchor(heading: &str) -> String {
        heading
            .to_ascii_lowercase()
            .chars()
            .filter_map(|c| {
                if c.is_ascii_alphanumeric() || c == '-' || c == ' ' {
                    Some(if c == ' ' { '-' } else { c })
                } else {
                    None
                }
            })
            .collect()
    }

    let rows = rows();
    assert!(
        !rows.is_empty(),
        "an empty catalog cannot establish coverage"
    );
    let mut keys = BTreeSet::new();
    let rules: BTreeMap<_, _> = RULE_EVIDENCE.iter().copied().collect();
    for row in rows {
        assert!(["implemented", "planned"].contains(&row.status), "{row:?}");
        assert!(
            ["authoritative-kan", "authoritative-other", "derived"].contains(&row.authority),
            "{row:?}"
        );
        assert!(
            [
                "local-log",
                "git-tree",
                "replica",
                "atproto",
                "repo-config",
                "system-config",
                "identity-store",
                "identity-ledger",
                "identity-profiles",
                "repository-identity",
                "external-git",
                "overlay",
                "sqlite-index"
            ]
            .contains(&row.source),
            "{row:?}"
        );
        assert!(["claim", "repository", "system", "invocation"].contains(&row.scope));
        for required in [
            row.artifact,
            row.value,
            row.writer,
            row.reader,
            row.rule,
            row.lifecycle,
            row.design,
        ] {
            assert!(!required.is_empty(), "empty required field: {row:?}");
        }
        assert!(
            row.rule.starts_with("derive:")
                || row.rule.starts_with("validate:")
                || row.rule.starts_with("select:"),
            "unknown rule form: {row:?}"
        );
        let rule_id = row.rule.split_once(':').unwrap().1;
        let evidence = rules
            .get(rule_id)
            .unwrap_or_else(|| panic!("unregistered conformance rule `{rule_id}`: {row:?}"));
        assert!(
            std::path::Path::new(evidence).exists(),
            "rule `{rule_id}` names missing evidence `{evidence}`"
        );
        assert!(
            keys.insert((row.artifact, row.value)),
            "duplicate catalog key ({}, {})",
            row.artifact,
            row.value
        );
        if row.status == "planned" {
            let (path, anchor) = row.design.split_once('#').unwrap_or((row.design, ""));
            assert!(
                std::path::Path::new(path).exists(),
                "missing design: {row:?}"
            );
            assert!(
                !anchor.is_empty(),
                "planned row has no design section: {row:?}"
            );
            let design = std::fs::read_to_string(path).unwrap();
            assert!(
                design
                    .lines()
                    .filter(|line| line.starts_with('#'))
                    .any(|heading| {
                        heading_anchor(heading.trim_start_matches('#').trim()) == anchor
                    }),
                "planned row cites missing section `{anchor}` in `{path}`: {row:?}"
            );
        }
    }
}

#[test]
fn every_implemented_value_has_exactly_one_catalog_row_and_no_row_is_fiction() {
    let actual = implemented_values();
    let catalog: BTreeSet<_> = rows()
        .into_iter()
        .filter(|row| row.status == "implemented")
        .map(|row| (row.artifact.to_string(), row.value.to_string()))
        .collect();
    let missing: Vec<_> = actual.difference(&catalog).collect();
    let fictional: Vec<_> = catalog.difference(&actual).collect();
    assert!(
        missing.is_empty() && fictional.is_empty(),
        "surface mismatch\nmissing catalog rows: {missing:#?}\nimplemented rows with no owner: {fictional:#?}"
    );
}

#[test]
fn persistence_modules_cannot_add_an_unreviewed_path_literal() {
    fn call_arguments(source: &str, constructor: &str) -> Vec<String> {
        let mut out = Vec::new();
        for suffix in source.split(constructor).skip(1) {
            let mut depth = 1usize;
            let mut quoted = false;
            let mut escaped = false;
            let mut end = None;
            for (index, ch) in suffix.char_indices() {
                if quoted {
                    if escaped {
                        escaped = false;
                    } else if ch == '\\' {
                        escaped = true;
                    } else if ch == '"' {
                        quoted = false;
                    }
                } else {
                    match ch {
                        '"' => quoted = true,
                        '(' | '[' | '{' => depth += 1,
                        ')' | ']' | '}' => {
                            depth -= 1;
                            if depth == 0 {
                                end = Some(index);
                                break;
                            }
                        }
                        _ => {}
                    }
                }
            }
            let argument = &suffix[..end.expect("unterminated persistence path constructor")];
            out.push(argument.split_whitespace().collect::<Vec<_>>().join(" "));
        }
        out
    }

    let expected: BTreeSet<_> = PERSISTENCE_PATH_EXPRESSIONS
        .iter()
        .map(|(module, literal, _)| (module.to_string(), literal.to_string()))
        .collect();
    let mut actual = BTreeSet::new();
    for module in PERSISTENCE_PATH_EXPRESSIONS
        .iter()
        .map(|(module, _, _)| *module)
        .collect::<BTreeSet<_>>()
    {
        let source = std::fs::read_to_string(module).unwrap();
        for constructor in [".join(", ".with_extension(", ".with_file_name("] {
            for argument in call_arguments(&source, constructor) {
                actual.insert((module.to_string(), argument));
            }
        }
    }
    let unreviewed: Vec<_> = actual.difference(&expected).collect();
    let stale: Vec<_> = expected.difference(&actual).collect();
    assert!(
        unreviewed.is_empty() && stale.is_empty(),
        "persistence path inventory mismatch\nunreviewed: {unreviewed:#?}\nstale: {stale:#?}"
    );
    for (module, literal, artifact) in PERSISTENCE_PATH_EXPRESSIONS {
        assert!(
            !artifact.is_empty(),
            "{module} path `{literal}` has no named storage artifact"
        );
    }
}

#[test]
fn every_module_that_mutates_the_filesystem_is_registered() {
    fn rust_files(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_dir() {
                rust_files(&entry.path(), out);
            } else if entry.path().extension().and_then(|e| e.to_str()) == Some("rs") {
                out.push(entry.path());
            }
        }
    }

    let registered: BTreeSet<_> = PERSISTENCE_MODULES.iter().copied().collect();
    let mut unregistered = Vec::new();
    let mut files = Vec::new();
    rust_files(std::path::Path::new("src"), &mut files);
    for file in files {
        let source = std::fs::read_to_string(&file).unwrap();
        let writes = [
            "std::fs::write",
            "std::fs::rename",
            "std::fs::copy",
            "std::fs::remove_file",
            "std::fs::remove_dir_all",
            "fs::write",
            "fs::rename",
            "fs::copy",
            "File::create",
            "OpenOptions",
        ]
        .iter()
        .any(|needle| source.contains(needle));
        let path = file.to_string_lossy();
        if writes && !registered.contains(path.as_ref()) {
            unregistered.push(path.into_owned());
        }
    }
    assert!(
        unregistered.is_empty(),
        "filesystem-mutating module(s) lack surface registration: {unregistered:#?}"
    );
}

#[test]
fn every_filesystem_mutation_names_its_catalog_surface_at_the_call_site() {
    let catalog_artifacts: BTreeSet<_> = rows()
        .into_iter()
        .filter(|row| row.status == "implemented")
        .map(|row| row.artifact)
        .collect();
    let mutation_apis = [
        "std::fs::create_dir_all",
        "std::fs::write",
        "std::fs::rename",
        "std::fs::copy",
        "std::fs::remove_file",
        "std::fs::remove_dir_all",
        "std::fs::remove_dir",
        "std::fs::hard_link",
        "std::fs::set_permissions",
        "std::os::unix::fs::symlink",
        "std::os::windows::fs::symlink_file",
        "std::os::windows::fs::symlink_dir",
        "std::fs::DirBuilder::create",
        "fs::create_dir_all",
        "fs::File::create",
        "fs::OpenOptions::new",
        "fs::write",
        "fs::rename",
        "fs::copy",
        "fs::remove_file",
        "fs::remove_dir_all",
        "fs::set_permissions",
        "File::create",
        "OpenOptions::new",
    ];

    for module in PERSISTENCE_MODULES {
        if *module == "src/persistence.rs" {
            continue;
        }
        let source = std::fs::read_to_string(module).unwrap();
        let lines: Vec<_> = source.lines().collect();
        for (index, line) in lines.iter().enumerate() {
            let code = line.trim_start();
            if code.starts_with("//")
                || !((code.contains("crate::persistence::")
                    && !code.contains("crate::persistence::SurfaceWrite::"))
                    || mutation_apis.iter().any(|api| code.contains(api)))
            {
                continue;
            }
            let annotation = index
                .checked_sub(1)
                .and_then(|previous| lines[previous].trim().strip_prefix("// surface-write: "))
                .unwrap_or_else(|| {
                    panic!(
                        "{module}:{} filesystem mutation lacks an immediately preceding `// surface-write: <catalog artifact>` annotation: {code}",
                        index + 1
                    )
                });
            for artifact in annotation.split(',') {
                assert!(
                    artifact == "container:workspace" || catalog_artifacts.contains(artifact),
                    "{module}:{} mutation cites unknown surface artifact `{artifact}`",
                    index + 1
                );
            }
        }
    }
}

#[test]
fn every_persistence_facade_call_is_independently_inventoried() {
    fn rust_sources(root: &std::path::Path, out: &mut Vec<String>) {
        for entry in std::fs::read_dir(root).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                rust_sources(&path, out);
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                out.push(path.to_string_lossy().replace('\\', "/"));
            }
        }
    }

    fn compact_code(source: &str) -> String {
        let bytes = source.as_bytes();
        let mut out = String::new();
        let mut index = 0usize;
        let mut block_depth = 0usize;
        let mut quoted = false;
        let mut escaped = false;
        while index < bytes.len() {
            if block_depth > 0 {
                if bytes[index..].starts_with(b"/*") {
                    block_depth += 1;
                    index += 2;
                } else if bytes[index..].starts_with(b"*/") {
                    block_depth -= 1;
                    index += 2;
                } else {
                    index += 1;
                }
                continue;
            }
            if quoted {
                if escaped {
                    escaped = false;
                } else if bytes[index] == b'\\' {
                    escaped = true;
                } else if bytes[index] == b'"' {
                    quoted = false;
                }
                index += 1;
                continue;
            }
            if bytes[index..].starts_with(b"//") {
                index += bytes[index..]
                    .iter()
                    .position(|byte| *byte == b'\n')
                    .unwrap_or(bytes.len() - index);
            } else if bytes[index..].starts_with(b"/*") {
                block_depth = 1;
                index += 2;
            } else if bytes[index] == b'"' {
                quoted = true;
                index += 1;
            } else {
                let ch = source[index..].chars().next().unwrap();
                if !ch.is_whitespace() {
                    out.push(ch);
                }
                index += ch.len_utf8();
            }
        }
        assert_eq!(
            block_depth, 0,
            "unterminated block comment in production source"
        );
        out
    }

    fn calls(source: &str) -> Vec<(String, String, String)> {
        // Match the module boundary, not one spelling of the route to it.
        // `crate::`, `super::`, and a crate alias such as `c::persistence::`
        // must all enter the same exact call inventory.
        let prefix = "persistence::";
        let mut out = Vec::new();
        let mut cursor = 0;
        while let Some(relative) = source[cursor..].find(prefix) {
            let start = cursor + relative;
            let suffix = &source[start + prefix.len()..];
            if suffix.starts_with("SurfaceWrite::") {
                cursor = start + prefix.len();
                continue;
            }
            let function: String = suffix
                .chars()
                .take_while(|ch| ch.is_ascii_alphanumeric() || *ch == '_')
                .collect();
            let rest = &suffix[function.len()..];
            assert!(
                !function.is_empty() && rest.starts_with('('),
                "persistence facade must be called directly, never imported, aliased, or stored: {}",
                &source[start..source.len().min(start + 120)]
            );

            let mut depth = 0usize;
            let mut quoted = false;
            let mut escaped = false;
            let mut end = None;
            for (index, ch) in rest.char_indices() {
                if quoted {
                    if escaped {
                        escaped = false;
                    } else if ch == '\\' {
                        escaped = true;
                    } else if ch == '"' {
                        quoted = false;
                    }
                    continue;
                }
                match ch {
                    '"' => quoted = true,
                    '(' => depth += 1,
                    ')' => {
                        depth -= 1;
                        if depth == 0 {
                            end = Some(index);
                            break;
                        }
                    }
                    _ => {}
                }
            }
            let end = end.expect("unterminated persistence facade call");
            let arguments = &rest[..=end];
            let marker = "SurfaceWrite::";
            let capability_start = arguments.find(marker).unwrap_or_else(|| {
                panic!("{function} call has no literal SurfaceWrite capability")
            }) + marker.len();
            let capability: String = arguments[capability_start..]
                .chars()
                .take_while(|ch| ch.is_ascii_alphanumeric() || *ch == '_')
                .collect();
            assert!(!capability.is_empty(), "{function} has an empty capability");
            let line_start = source[..start].rfind('\n').map_or(0, |newline| newline + 1);
            let preceding = source[..line_start]
                .lines()
                .rev()
                .find(|line| !line.trim().is_empty())
                .unwrap_or("");
            let annotation = preceding
                .trim()
                .strip_prefix("// surface-write: ")
                .unwrap_or_else(|| {
                    panic!("{function} call has no preceding surface-write annotation")
                })
                .to_string();
            let function_len = function.len();
            out.push((function, capability, annotation));
            cursor = start + prefix.len() + function_len + end + 1;
        }
        out
    }

    let expected: BTreeMap<_, _> = PERSISTENCE_MUTATION_SITES
        .iter()
        .map(|(module, function, capability, count)| {
            (
                (
                    module.to_string(),
                    function.to_string(),
                    capability.to_string(),
                ),
                *count,
            )
        })
        .collect();
    let mut actual = BTreeMap::new();
    let mut modules = Vec::new();
    rust_sources(std::path::Path::new("src"), &mut modules);
    modules.sort();
    for module in modules {
        let source = std::fs::read_to_string(&module).unwrap();
        let compact = compact_code(&source);
        if module == "src/persistence.rs" {
            assert_eq!(
                format!("{:x}", Sha256::digest(source.as_bytes())),
                "c13e0b2f25c19f26b9294375f22d182230b97bffd62318ab6dfb09f264a6a793",
                "the raw-mutation facade changed; review and update its committed implementation digest together with facade-call negative controls"
            );
            assert!(
                !compact.contains("macro_rules!"),
                "the raw-mutation facade may not export or hide calls in a macro; every expanded call site must remain independently inventoried"
            );
            assert_eq!(
                compact.matches("implSurfaceWrite{").count(),
                1,
                "SurfaceWrite may have only its catalog-artifact implementation; mutation methods would bypass call-site inventory"
            );
            assert!(
                !compact.contains("forSurfaceWrite{") && !compact.contains("trait"),
                "the persistence facade may not add extension or trait methods to SurfaceWrite"
            );
            let marker = "implSurfaceWrite{";
            let body_start = compact.find(marker).unwrap() + marker.len();
            let mut depth = 1usize;
            let mut body_end = None;
            for (offset, ch) in compact[body_start..].char_indices() {
                match ch {
                    '{' => depth += 1,
                    '}' => {
                        depth -= 1;
                        if depth == 0 {
                            body_end = Some(body_start + offset);
                            break;
                        }
                    }
                    _ => {}
                }
            }
            let body = &compact[body_start..body_end.expect("unterminated SurfaceWrite impl")];
            assert_eq!(
                body.matches("fn").count(),
                1,
                "SurfaceWrite may expose only artifacts(); facade mutations must remain free functions with inventoried call sites"
            );
            assert!(body.contains("pubconstfnartifacts(self)"));
            continue;
        }
        if let Some(line) = source.lines().find(|line| {
            let code = line.trim_start();
            code.contains("use ") && code.contains("persistence")
        }) {
            panic!(
                "{module} imports or re-exports the persistence facade; call it fully qualified so the mutation inventory remains complete: {line}"
            );
        }
        assert!(
            !compact.contains("$crate::persistence::"),
            "{module} reaches the persistence facade through a macro-only `$crate` route"
        );
        assert!(
            !compact.contains("macro_rules!") || !compact.contains("crate::persistence::"),
            "{module} hides a persistence mutation inside a macro; inventory each expanded call directly"
        );
        assert_eq!(
            source.matches("crate::persistence::").count(),
            compact.matches("crate::persistence::").count(),
            "{module} must spell every persistence route exactly as `crate::persistence::` so the call-site inventory sees it"
        );
        let module_declaration = usize::from(module == "src/lib.rs");
        assert_eq!(
            compact.matches("persistence").count(),
            compact.matches("crate::persistence::").count() + module_declaration,
            "{module} reaches the persistence facade through a non-canonical alias or token route"
        );
        for broad_suppression in [
            "allow(clippy::all",
            "expect(clippy::all",
            "allow(clippy::restriction",
            "expect(clippy::restriction",
            "allow(warnings",
            "expect(warnings",
        ] {
            assert!(
                !compact.contains(broad_suppression),
                "{module} broadly suppresses the compiler persistence policy via `{broad_suppression}`"
            );
        }
        match module.as_str() {
            "src/lib.rs" | "src/main.rs" => {
                assert_eq!(compact.matches("clippy::disallowed_methods").count(), 1);
                assert_eq!(compact.matches("clippy::disallowed_types").count(), 1);
                assert!(compact.contains("#![deny(clippy::disallowed_methods)]"));
                assert!(compact.contains("#![deny(clippy::disallowed_types)]"));
            }
            _ => {
                assert!(
                    !compact.contains("clippy::disallowed_methods")
                        && !compact.contains("clippy::disallowed_types"),
                    "{module} locally suppresses or redefines the compiler persistence policy; only src/persistence.rs may allow it"
                );
            }
        }
        for (function, capability, annotation) in calls(&source) {
            let typed = kan::persistence::SurfaceWrite::ALL
                .iter()
                .find(|candidate| format!("{candidate:?}") == capability)
                .unwrap_or_else(|| panic!("unknown SurfaceWrite capability `{capability}`"));
            for artifact in annotation.split(',') {
                assert!(
                    typed.artifacts().contains(&artifact),
                    "{module} {function} labels `{artifact}` with capability `{capability}`, whose allowed artifacts are {:?}",
                    typed.artifacts()
                );
            }
            *actual
                .entry((module.clone(), function, capability))
                .or_insert(0usize) += 1;
        }
    }
    assert_eq!(
        actual, expected,
        "persistence facade call inventory changed; classify every new or removed mutation site explicitly"
    );
}

#[test]
fn compiler_resolves_filesystem_aliases_to_the_single_mutation_facade() {
    let policy = std::fs::read_to_string("clippy.toml").unwrap();
    assert_eq!(
        format!("{:x}", Sha256::digest(policy.as_bytes())),
        "92a6e752525c4f798066c599cc7bc7c7e33bf6c0b90ea4b619b7ebc31064e790",
        "the compiler mutation policy changed; review and update its committed digest together with raw-API negative controls"
    );
    for method in [
        "std::fs::create_dir",
        "std::fs::create_dir_all",
        "std::fs::write",
        "std::fs::rename",
        "std::fs::copy",
        "std::fs::remove_file",
        "std::fs::remove_dir_all",
        "std::fs::set_permissions",
        "std::fs::File::create",
        "std::fs::File::create_new",
        "std::fs::File::options",
        "std::fs::File::set_len",
        "std::fs::File::set_permissions",
        "std::fs::File::set_modified",
        "std::fs::File::set_times",
        "std::fs::OpenOptions::open",
        "tokio::fs::create_dir_all",
        "tokio::fs::create_dir",
        "tokio::fs::write",
        "tokio::fs::rename",
        "tokio::fs::copy",
        "tokio::fs::remove_file",
        "tokio::fs::remove_dir_all",
        "tokio::fs::remove_dir",
        "tokio::fs::hard_link",
        "tokio::fs::set_permissions",
        "tokio::fs::symlink",
        "tokio::fs::DirBuilder::create",
        "tokio::fs::File::create",
        "tokio::fs::File::options",
        "tokio::fs::File::set_len",
        "tokio::fs::File::set_permissions",
        "tokio::fs::OpenOptions::open",
    ] {
        assert!(policy.contains(method), "compiler policy omits `{method}`");
    }
    let library = std::fs::read_to_string("src/lib.rs").unwrap();
    assert!(library.contains("#![deny(clippy::disallowed_methods)]"));
    assert!(library.contains("#![deny(clippy::disallowed_types)]"));
    let binary = std::fs::read_to_string("src/main.rs").unwrap();
    assert!(binary.contains("#![deny(clippy::disallowed_methods)]"));
    assert!(binary.contains("#![deny(clippy::disallowed_types)]"));
    let facade = std::fs::read_to_string("src/persistence.rs").unwrap();
    assert!(facade.contains("#![allow(clippy::disallowed_methods)]"));
    assert!(facade.contains("#![allow(clippy::disallowed_types)]"));

    let catalog_artifacts: BTreeSet<_> = rows()
        .into_iter()
        .filter(|row| row.status == "implemented")
        .map(|row| row.artifact)
        .collect();
    assert_eq!(
        kan::persistence::SurfaceWrite::ALL.len(),
        kan::persistence::SurfaceWrite::Count as usize,
        "SurfaceWrite variant omitted from the exhaustive capability inventory"
    );
    for capability in kan::persistence::SurfaceWrite::ALL {
        for artifact in capability.artifacts() {
            assert!(
                *artifact == "container:workspace" || catalog_artifacts.contains(artifact),
                "typed persistence capability cites uncataloged artifact `{artifact}`"
            );
        }
    }
}

#[test]
fn the_catalog_represents_authority_source_and_scope_as_independent_axes() {
    let rows = rows();
    let claims: BTreeMap<_, _> = rows
        .iter()
        .filter(|row| row.scope == "claim")
        .map(|row| (row.source, row.authority))
        .collect();
    for source in ["local-log", "git-tree", "replica", "atproto"] {
        assert_eq!(claims.get(source), Some(&"authoritative-kan"));
    }
    assert!(rows.iter().any(|row| row.source == "repo-config"));
    assert!(rows.iter().any(|row| row.source == "system-config"));
    assert!(rows
        .iter()
        .any(|row| { row.source == "external-git" && row.authority == "authoritative-other" }));
}

fn observation(did: &str, subject: &str, text: &str) -> ClaimContent {
    ClaimContent {
        author: AuthorId {
            did: did.to_string(),
            agent: None,
        },
        workspace: Anchor::Workspace("surface-conformance".into()),
        subject: SubjectRef::Local(Rkey::from(subject)),
        body: ClaimBody::Observation { text: text.into() },
        cites: vec![],
        artifacts: vec![],
        recorded_at: None,
    }
}

fn semantic_claims(
    claims: &[(atproto_dasl::Cid, kan::store::log::StoredClaim)],
) -> Vec<(String, ClaimContent, String)> {
    claims
        .iter()
        .map(|(cid, stored)| {
            (
                cid.to_string(),
                stored.claim.content.clone(),
                stored.rev.clone(),
            )
        })
        .collect()
}

#[tokio::test]
async fn sqlite_is_recomputed_from_authoritative_claims_not_from_itself() {
    let dir = tempfile::tempdir().unwrap();
    let identity = Identity::generate();
    let mut log = Log::open_or_create(&dir.path().join("log"), &identity)
        .await
        .unwrap();
    let cid = log
        .append(
            observation(&identity.did(), "surface", "authoritative"),
            &identity,
        )
        .await
        .unwrap();
    let claims = log.iter_all().await.unwrap();
    let index_path = dir.path().join("index.sqlite");
    let mut index = Index::open(&index_path).unwrap();
    index
        .rebuild(&claims, &[], log.current_root().as_ref())
        .unwrap();
    drop(index);

    let connection = rusqlite::Connection::open(&index_path).unwrap();
    connection
        .execute("UPDATE claims_v2 SET raw = X'00'", [])
        .unwrap();
    drop(connection);

    let mut index = Index::open(&index_path).unwrap();
    index
        .rebuild(&claims, &[], log.current_root().as_ref())
        .unwrap();
    let rebuilt = index.all_stored_claims().unwrap();
    assert_eq!(rebuilt.len(), 1);
    assert_eq!(rebuilt[0].0, cid);
    assert_eq!(
        rebuilt[0].1.claim.content.body,
        claims[0].1.claim.content.body
    );

    drop(index);
    std::fs::remove_file(&index_path).unwrap();
    let mut index = Index::open(&index_path).unwrap();
    index
        .rebuild(&claims, &[], log.current_root().as_ref())
        .unwrap();
    assert_eq!(
        semantic_claims(&index.all_stored_claims().unwrap()),
        semantic_claims(&rebuilt)
    );
}

fn init_repo(path: &std::path::Path) {
    let status = std::process::Command::new("git")
        .args(["init", "-q"])
        .current_dir(path)
        .status()
        .unwrap();
    assert!(status.success());
    let status = std::process::Command::new("git")
        .args([
            "-c",
            "user.email=kan-test@example.com",
            "-c",
            "user.name=kan-test",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-q",
            "--allow-empty",
            "-m",
            "init",
        ])
        .current_dir(path)
        .status()
        .unwrap();
    assert!(status.success());
}

fn run_kan(path: &std::path::Path, args: &[&str]) -> std::process::Output {
    std::process::Command::new(env!("CARGO_BIN_EXE_kan"))
        .args(args)
        .current_dir(path)
        .env("KAN_NO_KEYCHAIN", "1")
        .output()
        .unwrap()
}

#[test]
fn workspace_routes_overlay_io_through_overlay_capabilities() {
    let workspace = std::fs::read_to_string("src/workspace.rs").unwrap();
    assert_eq!(
        workspace.matches("Log::open_or_create_overlay").count(),
        3,
        "every writable overlay open must select the overlay capability route"
    );
    assert_eq!(
        workspace.matches("Log::open_overlay_read_only").count(),
        1,
        "the read-only overlay must retain its surface identity for any later write"
    );
    for forbidden in [
        "Log::open_or_create(&kan_dir.join(\"overlay\")",
        "Log::open_or_create(&overlay_dir",
        "Log::open_read_only(&kan_dir.join(\"overlay\")",
    ] {
        assert!(
            !workspace.contains(forbidden),
            "overlay path borrowed the authoritative local-log route: {forbidden}"
        );
    }

    let log = std::fs::read_to_string("src/store/log.rs").unwrap();
    assert!(log.contains("Self::open_or_create_on(dir, identity, LogSurface::Overlay)"));
    assert!(log.contains("Self::open_read_only_on(dir, LogSurface::Overlay)"));
}

#[test]
fn production_workspace_rejects_a_poisoned_fresh_index_and_recomputes_json() {
    let repo = tempfile::tempdir().unwrap();
    init_repo(repo.path());
    let write = run_kan(repo.path(), &["observe", "poison", "authoritative"]);
    assert!(
        write.status.success(),
        "{}",
        String::from_utf8_lossy(&write.stderr)
    );
    let write_other = run_kan(repo.path(), &["observe", "other", "also authoritative"]);
    assert!(
        write_other.status.success(),
        "{}",
        String::from_utf8_lossy(&write_other.stderr)
    );
    let before = run_kan(repo.path(), &["show", "poison", "--json"]);
    assert!(
        before.status.success(),
        "{}",
        String::from_utf8_lossy(&before.stderr)
    );

    let before_other = run_kan(repo.path(), &["show", "other", "--json"]);
    assert!(
        before_other.status.success(),
        "{}",
        String::from_utf8_lossy(&before_other.stderr)
    );

    let connection = rusqlite::Connection::open(repo.path().join(".kan/index.sqlite")).unwrap();
    let raws: Vec<Vec<u8>> = connection
        .prepare("SELECT raw FROM claims_v2 ORDER BY content_cid")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(raws.len(), 2);
    connection
        .execute(
            "UPDATE claims_v2 SET raw = ?1 WHERE raw = ?2",
            rusqlite::params![raws[1], raws[0]],
        )
        .unwrap();
    drop(connection);

    let after = run_kan(repo.path(), &["show", "poison", "--json"]);
    assert!(
        after.status.success(),
        "{}",
        String::from_utf8_lossy(&after.stderr)
    );
    assert_eq!(before.stdout, after.stdout, "recomputed JSON changed");
    let after_other = run_kan(repo.path(), &["show", "other", "--json"]);
    assert_eq!(
        before_other.stdout, after_other.stdout,
        "a valid-CBOR substitution changed the other subject's JSON"
    );
}

#[test]
fn production_workspace_recovers_when_a_projection_column_has_the_wrong_type() {
    let repo = tempfile::tempdir().unwrap();
    init_repo(repo.path());
    let write = run_kan(repo.path(), &["observe", "typed-poison", "authoritative"]);
    assert!(
        write.status.success(),
        "{}",
        String::from_utf8_lossy(&write.stderr)
    );
    let before = run_kan(repo.path(), &["show", "typed-poison", "--json"]);
    assert!(
        before.status.success(),
        "{}",
        String::from_utf8_lossy(&before.stderr)
    );

    let connection = rusqlite::Connection::open(repo.path().join(".kan/index.sqlite")).unwrap();
    connection
        .execute("UPDATE claims_v2 SET origin = X'00'", [])
        .unwrap();
    drop(connection);

    let after = run_kan(repo.path(), &["show", "typed-poison", "--json"]);
    assert!(
        after.status.success(),
        "{}",
        String::from_utf8_lossy(&after.stderr)
    );
    assert_eq!(before.stdout, after.stdout, "typed corruption changed JSON");
}

#[test]
fn production_workspace_recovers_when_projection_metadata_has_the_wrong_type() {
    let repo = tempfile::tempdir().unwrap();
    init_repo(repo.path());
    let write = run_kan(repo.path(), &["observe", "meta-poison", "authoritative"]);
    assert!(
        write.status.success(),
        "{}",
        String::from_utf8_lossy(&write.stderr)
    );
    let before = run_kan(repo.path(), &["show", "meta-poison", "--json"]);
    assert!(before.status.success());

    let connection = rusqlite::Connection::open(repo.path().join(".kan/index.sqlite")).unwrap();
    connection
        .execute(
            "UPDATE meta SET value = X'00' WHERE key = 'built_from_root_v2'",
            [],
        )
        .unwrap();
    drop(connection);

    let after = run_kan(repo.path(), &["show", "meta-poison", "--json"]);
    assert!(
        after.status.success(),
        "derived metadata corruption blocked an authoritative read: {}",
        String::from_utf8_lossy(&after.stderr)
    );
    assert_eq!(before.stdout, after.stdout);
}

#[test]
fn production_workspace_recreates_a_malformed_projection_schema() {
    let repo = tempfile::tempdir().unwrap();
    init_repo(repo.path());
    let write = run_kan(repo.path(), &["observe", "schema-poison", "authoritative"]);
    assert!(
        write.status.success(),
        "{}",
        String::from_utf8_lossy(&write.stderr)
    );
    let before = run_kan(repo.path(), &["show", "schema-poison", "--json"]);
    assert!(before.status.success());

    let connection = rusqlite::Connection::open(repo.path().join(".kan/index.sqlite")).unwrap();
    connection
        .execute_batch(
            "DROP TABLE claims_v2;
             CREATE TABLE claims_v2 (structurally_wrong TEXT);",
        )
        .unwrap();
    drop(connection);

    let after = run_kan(repo.path(), &["show", "schema-poison", "--json"]);
    assert!(
        after.status.success(),
        "{}",
        String::from_utf8_lossy(&after.stderr)
    );
    assert_eq!(before.stdout, after.stdout, "schema recovery changed JSON");

    std::fs::write(repo.path().join(".kan/index.sqlite"), b"not a database").unwrap();
    let after_bytes = run_kan(repo.path(), &["show", "schema-poison", "--json"]);
    assert!(
        after_bytes.status.success(),
        "{}",
        String::from_utf8_lossy(&after_bytes.stderr)
    );
    assert_eq!(before.stdout, after_bytes.stdout);

    let connection = rusqlite::Connection::open(repo.path().join(".kan/index.sqlite")).unwrap();
    connection
        .execute_batch(
            "DROP INDEX claims_v2_by_origin;
             CREATE TABLE claims_v2_by_origin (wrong TEXT);",
        )
        .unwrap();
    drop(connection);
    let after_conflict = run_kan(repo.path(), &["show", "schema-poison", "--json"]);
    assert!(
        after_conflict.status.success(),
        "{}",
        String::from_utf8_lossy(&after_conflict.stderr)
    );
    assert_eq!(before.stdout, after_conflict.stdout);

    let connection = rusqlite::Connection::open(repo.path().join(".kan/index.sqlite")).unwrap();
    connection
        .execute_batch(
            "CREATE TRIGGER hostile_projection_trigger
             BEFORE INSERT ON claims_v2
             BEGIN SELECT RAISE(FAIL, 'projection trigger fired'); END;",
        )
        .unwrap();
    drop(connection);
    let after_trigger = run_kan(repo.path(), &["show", "schema-poison", "--json"]);
    assert!(
        after_trigger.status.success(),
        "{}",
        String::from_utf8_lossy(&after_trigger.stderr)
    );
    assert_eq!(before.stdout, after_trigger.stdout);

    let connection = rusqlite::Connection::open(repo.path().join(".kan/index.sqlite")).unwrap();
    connection
        .execute_batch(
            "CREATE TRIGGER hostile_append_trigger
             BEFORE INSERT ON claims_v2
             BEGIN SELECT RAISE(FAIL, 'projection trigger fired after append'); END;",
        )
        .unwrap();
    drop(connection);
    let append = run_kan(
        repo.path(),
        &["observe", "after-trigger", "must report success"],
    );
    assert!(
        append.status.success(),
        "authoritative append was reported as failed: {}",
        String::from_utf8_lossy(&append.stderr)
    );
    let appended = run_kan(repo.path(), &["show", "after-trigger", "--json"]);
    assert!(appended.status.success());
    assert!(String::from_utf8_lossy(&appended.stdout).contains("must report success"));
}

#[test]
fn production_workspace_bypasses_an_unopenable_projection_path() {
    let repo = tempfile::tempdir().unwrap();
    init_repo(repo.path());
    let write = run_kan(
        repo.path(),
        &["observe", "unopenable-index", "authoritative"],
    );
    assert!(write.status.success());
    let before = run_kan(repo.path(), &["show", "unopenable-index", "--json"]);
    assert!(before.status.success());

    let index = repo.path().join(".kan/index.sqlite");
    std::fs::rename(&index, repo.path().join(".kan/index.sqlite.saved")).unwrap();
    std::fs::create_dir(&index).unwrap();

    let after = run_kan(repo.path(), &["show", "unopenable-index", "--json"]);
    assert!(
        after.status.success(),
        "disposable projection path blocked an authoritative read: {}",
        String::from_utf8_lossy(&after.stderr)
    );
    assert_eq!(before.stdout, after.stdout);

    let append = run_kan(
        repo.path(),
        &["observe", "after-unopenable-index", "still authoritative"],
    );
    assert!(
        append.status.success(),
        "disposable projection path made an authoritative append report failure: {}",
        String::from_utf8_lossy(&append.stderr)
    );
    let appended = run_kan(repo.path(), &["show", "after-unopenable-index", "--json"]);
    assert!(appended.status.success());
    assert!(String::from_utf8_lossy(&appended.stdout).contains("still authoritative"));
}

#[cfg(unix)]
#[test]
fn production_workspace_bypasses_an_unremovable_corrupt_projection() {
    use std::os::unix::fs::PermissionsExt;

    struct RestoreMode {
        path: std::path::PathBuf,
        mode: u32,
    }
    impl Drop for RestoreMode {
        fn drop(&mut self) {
            let _ =
                std::fs::set_permissions(&self.path, std::fs::Permissions::from_mode(self.mode));
        }
    }

    let repo = tempfile::tempdir().unwrap();
    init_repo(repo.path());
    let write = run_kan(repo.path(), &["observe", "locked-index", "authoritative"]);
    assert!(write.status.success());
    let before = run_kan(repo.path(), &["show", "locked-index", "--json"]);
    assert!(before.status.success());

    let kan_dir = repo.path().join(".kan");
    let index = kan_dir.join("index.sqlite");
    std::fs::remove_file(&index).unwrap();
    std::fs::write(&index, b"not a sqlite database").unwrap();
    let original_mode = std::fs::metadata(&kan_dir).unwrap().permissions().mode();
    std::fs::set_permissions(&kan_dir, std::fs::Permissions::from_mode(0o555)).unwrap();
    let restore = RestoreMode {
        path: kan_dir,
        mode: original_mode,
    };

    let after = run_kan(repo.path(), &["show", "locked-index", "--json"]);
    drop(restore);
    assert!(
        after.status.success(),
        "an unremovable disposable projection blocked an authoritative read: {}",
        String::from_utf8_lossy(&after.stderr)
    );
    assert_eq!(before.stdout, after.stdout);
}

#[cfg(unix)]
#[test]
fn production_workspace_bypasses_an_unremovable_semantically_poisoned_projection() {
    use std::os::unix::fs::PermissionsExt;

    struct RestoreMode {
        path: std::path::PathBuf,
        mode: u32,
    }
    impl Drop for RestoreMode {
        fn drop(&mut self) {
            let _ =
                std::fs::set_permissions(&self.path, std::fs::Permissions::from_mode(self.mode));
        }
    }

    let repo = tempfile::tempdir().unwrap();
    init_repo(repo.path());
    let write = run_kan(
        repo.path(),
        &["observe", "locked-valid-index", "authoritative"],
    );
    assert!(write.status.success());
    let before = run_kan(repo.path(), &["show", "locked-valid-index", "--json"]);
    assert!(before.status.success());

    let kan_dir = repo.path().join(".kan");
    let index = kan_dir.join("index.sqlite");
    let connection = rusqlite::Connection::open(&index).unwrap();
    connection
        .execute("UPDATE claims_v2 SET origin = 'semantically-poisoned'", [])
        .unwrap();
    drop(connection);

    let original_mode = std::fs::metadata(&kan_dir).unwrap().permissions().mode();
    std::fs::set_permissions(&kan_dir, std::fs::Permissions::from_mode(0o555)).unwrap();
    let restore = RestoreMode {
        path: kan_dir,
        mode: original_mode,
    };

    let after = run_kan(repo.path(), &["show", "locked-valid-index", "--json"]);
    drop(restore);
    assert!(
        after.status.success(),
        "an unremovable poisoned projection blocked an authoritative read: {}",
        String::from_utf8_lossy(&after.stderr)
    );
    assert_eq!(before.stdout, after.stdout);
}

#[test]
fn caller_selected_role_key_is_an_implemented_authoritative_surface() {
    let sign = std::fs::read_to_string("src/sign.rs").unwrap();
    assert!(
        sign.contains(
            "// surface-write: identity:seed,identity:identity,identity:roles.d,identity:role-key-path\n        crate::persistence::set_permissions"
        ),
        "private-key permission tightening must declare both default roles.d and caller-selected role-key artifacts"
    );
    let values = implemented_values();
    assert!(values.contains(&(
        "identity:role-key-path".to_string(),
        "caller-selected".to_string()
    )));
    let row = rows()
        .into_iter()
        .find(|row| row.artifact == "identity:role-key-path")
        .unwrap();
    assert_eq!(row.reader, "crate::sign");
    assert_eq!(row.rule, "validate:role-key");
    let default_row = rows()
        .into_iter()
        .find(|row| row.artifact == "identity:roles.d")
        .unwrap();
    assert_eq!(default_row.reader, "crate::sign");
    assert_eq!(default_row.rule, "validate:role-key");

    let repo = tempfile::tempdir().unwrap();
    init_repo(repo.path());
    let external_dir = tempfile::tempdir().unwrap();
    let external = external_dir.path().join("auditor.key");
    let output = run_kan(
        repo.path(),
        &[
            "identity",
            "role",
            "add",
            "auditor",
            "--key",
            external.to_str().unwrap(),
        ],
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        external.exists(),
        "caller-selected role key was not created"
    );

    let default = run_kan(repo.path(), &["identity", "role", "add", "reviewer"]);
    assert!(
        default.status.success(),
        "{}",
        String::from_utf8_lossy(&default.stderr)
    );
    let default_key = repo.path().join(".kan/roles.d/reviewer");
    assert!(default_key.exists(), "default role key was not created");
    let role = Identity::load_existing(&default_key).expect("default role key must be readable");
    let role_did = role.did();
    assert!(
        String::from_utf8_lossy(&default.stdout).contains(&role_did),
        "declared role DID did not come from the persisted default key"
    );
}

fn copy_tree(from: &std::path::Path, to: &std::path::Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), target).unwrap();
        }
    }
}

#[tokio::test]
async fn overlay_is_recomputed_from_authoritative_git_tree_claims() {
    use kan::transport::{git_tree::GitTree, Transport};

    let publisher = tempfile::tempdir().unwrap();
    init_repo(publisher.path());
    let peer = Identity::generate();
    let log = Log::open_or_create(&publisher.path().join(".kan/log"), &peer)
        .await
        .unwrap();
    let mut tree = GitTree::new(log, publisher.path());
    let cid = tree
        .publish(observation(&peer.did(), "foreign", "from peer"), &peer)
        .await
        .unwrap();

    let reader = tempfile::tempdir().unwrap();
    init_repo(reader.path());
    copy_tree(
        &publisher.path().join(".claims"),
        &reader.path().join(".claims"),
    );
    let own = Identity::generate();
    own.save(&reader.path().join(".kan/identity")).unwrap();
    let mut workspace = kan::workspace::Workspace::open(reader.path())
        .await
        .unwrap();
    let before = workspace.index.all_stored_claims().unwrap();
    assert!(before.iter().any(|(found, _)| found == &cid));
    let trust = kan::fold::TrustBase::peer_contested(std::collections::HashMap::from([(
        AuthorId {
            did: peer.did(),
            agent: None,
        },
        1.0,
    )]));
    let before_json = kan::actions::show_all_json(&workspace, &trust, None).unwrap();
    let origins = || {
        let connection =
            rusqlite::Connection::open(reader.path().join(".kan/index.sqlite")).unwrap();
        let mut statement = connection
            .prepare("SELECT content_cid, origin FROM claims_v2 ORDER BY content_cid")
            .unwrap();
        statement
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .unwrap()
            .map(Result::unwrap)
            .collect::<Vec<_>>()
    };
    let before_origins = origins();

    workspace.log_and_identity().await.unwrap();
    workspace.rebuild_overlay().await.unwrap();
    let after = workspace.index.all_stored_claims().unwrap();
    assert_eq!(semantic_claims(&before), semantic_claims(&after));
    assert_eq!(
        before_json,
        kan::actions::show_all_json(&workspace, &trust, None).unwrap()
    );
    assert_eq!(before_origins, origins(), "medium provenance changed");
}
