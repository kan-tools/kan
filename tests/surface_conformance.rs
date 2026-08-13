//! `.design/read-write-surface-conformance.md`: the committed declaration is
//! checked against facts gathered independently from persistence owners and
//! SQLite itself. Neither side can silently add a stored value for the other.

use std::collections::{BTreeMap, BTreeSet};

use kan::surface::StoredValue;
use kan::{
    claim::{Anchor, AuthorId, ClaimBody, ClaimContent, Rkey, SubjectRef},
    sign::Identity,
    store::{index::Index, log::Log},
};

const CATALOG: &str = include_str!("fixtures/read-write-surface.tsv");
const RULE_EVIDENCE: &[(&str, &str)] = &[
    ("claim-log", "tests/claim_substrate.rs"),
    ("current-root", "tests/log_recovery.rs"),
    ("write-coordination", "tests/log_concurrency.rs"),
    ("published-claim", "tests/git_tree_trust.rs"),
    ("auto-git-tree-connection", "tests/reader.rs"),
    ("overlay-from-git-tree", "tests/surface_conformance.rs"),
    ("overlay-root", "tests/surface_conformance.rs"),
    ("index-freshness", "tests/workspace_staleness.rs"),
    ("index-from-media", "tests/surface_conformance.rs"),
    ("identity-at-rest", "tests/at_rest_guards.rs"),
    ("identity-precedence", "tests/identity_cells.rs"),
    ("role-key", "tests/role_registry_invariants.rs"),
    ("legacy-role-config", "tests/role_declarations.rs"),
    ("git-ancestry", "tests/git_ancestry_cache.rs"),
    ("git-anchor", "tests/git_substrate.rs"),
    ("connection-config", ".design/medium-architecture.md"),
];
const PERSISTENCE_PATH_LITERALS: &[(&str, &str, &str)] = &[
    ("src/store/log.rs", "repo.car", "local-log:repo.car"),
    ("src/store/log.rs", "HEAD", "local-log:HEAD"),
    ("src/store/log.rs", "LOCK", "local-log:LOCK"),
    (
        "src/store/index.rs",
        "",
        "sqlite schema is runtime-introspected",
    ),
    ("src/sign.rs", "identity", "identity:identity"),
    ("src/sign.rs", "log", "local-log:repo.car"),
    ("src/sign.rs", "repo.car", "local-log:repo.car"),
    ("src/workspace.rs", ".git", "repo-config:auto-git-tree"),
    ("src/workspace.rs", ".kan", "workspace persistence root"),
    ("src/workspace.rs", "index.sqlite", "sqlite:meta"),
    ("src/workspace.rs", "log", "local-log:repo.car"),
    ("src/workspace.rs", "overlay", "overlay:repo.car"),
    // Formatting joins, not filesystem paths.
    ("src/workspace.rs", ", ", "not a path"),
    ("src/transport/git_tree.rs", ",", "not a path"),
    ("src/transport/git_tree.rs", "/", "not a path"),
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
    kan::store::index::Index::open(&path).unwrap();
    let connection = rusqlite::Connection::open(path).unwrap();
    let mut out = Vec::new();
    for table in ["meta", "claims_v2"] {
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
    out
}

fn implemented_values() -> BTreeSet<(String, String)> {
    let declared = kan::store::log::STORED_VALUES
        .iter()
        .chain(kan::transport::git_tree::STORED_VALUES)
        .chain(kan::sign::STORED_VALUES)
        .chain(kan::workspace::STORED_VALUES)
        .chain(kan::git::SURFACE_VALUES)
        .map(|StoredValue { artifact, value }| ((*artifact).into(), (*value).into()));
    declared.chain(sqlite_values()).collect()
}

#[test]
fn catalog_is_well_formed_and_cites_real_designs() {
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
            let path = row.design.split('#').next().unwrap();
            assert!(
                std::path::Path::new(path).exists(),
                "missing design: {row:?}"
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
    let expected: BTreeSet<_> = PERSISTENCE_PATH_LITERALS
        .iter()
        .map(|(module, literal, _)| (module.to_string(), literal.to_string()))
        .collect();
    let mut actual = BTreeSet::new();
    for module in PERSISTENCE_PATH_LITERALS
        .iter()
        .map(|(module, _, _)| *module)
        .collect::<BTreeSet<_>>()
    {
        let source = std::fs::read_to_string(module).unwrap();
        for suffix in source.split(".join(\"").skip(1) {
            if let Some((literal, _)) = suffix.split_once("\")") {
                actual.insert((module.to_string(), literal.to_string()));
            }
        }
    }
    let unreviewed: Vec<_> = actual.difference(&expected).collect();
    assert!(
        unreviewed.is_empty(),
        "persistence path literal(s) lack a reviewed surface artifact: {unreviewed:#?}"
    );
    for (module, literal, artifact) in PERSISTENCE_PATH_LITERALS {
        assert!(
            !artifact.is_empty(),
            "{module} path `{literal}` has no named storage artifact"
        );
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

    workspace.log_and_identity().await.unwrap();
    workspace.rebuild_overlay().await.unwrap();
    let after = workspace.index.all_stored_claims().unwrap();
    assert_eq!(semantic_claims(&before), semantic_claims(&after));
}
