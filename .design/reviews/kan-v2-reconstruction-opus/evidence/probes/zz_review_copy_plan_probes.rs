// Reviewer-authored entry-point probes for copy-plan custody (temporary in tests/).
#![cfg(feature = "v2-storage")]
use kan::{
    evidence_service::{self as service, Command, Grant, Request, Service, SignedRequest},
    evidence_store::Ledger,
    sign::Identity,
};
use std::{
    io::Write,
    path::{Path, PathBuf},
};
fn identity(n: u8) -> Identity {
    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(&[n; 32]).unwrap();
    Identity::load_existing(file.path()).unwrap()
}
fn fixture(parent: &Path) -> PathBuf {
    let root = parent.join("source");
    let mut s = Service::new(
        Ledger::create(&root).unwrap(),
        [1; 32],
        identity(7),
        vec![Grant { principal: identity(6).did().to_string(), append: true, inventory: false }],
    )
    .unwrap();
    let mut previous = None;
    for n in 0..2u8 {
        let signer = identity(6);
        let bytes = SignedRequest::sign(
            Request {
                version: 1,
                scope: service::hex(&[1; 32]),
                principal: signer.did().to_string(),
                audience: identity(7).did().to_string(),
                expires: None,
                command: Command::Append {
                    id: service::hex(&[n + 1; 16]),
                    position: n as u64,
                    previous,
                    ciphertext: service::hex(b"synthetic opaque payload"),
                },
            },
            &signer,
        )
        .unwrap()
        .bytes()
        .unwrap();
        assert!(s.dispatch(&bytes, 100 + n as u64).unwrap().reply.result.is_ok());
        previous = Some(service::append_manifest(&bytes).unwrap().cid().to_string());
    }
    drop(s);
    root.join("archive.sqlite")
}
fn copy_plan(cwd: &Path, db: &str, plan: &str) -> std::process::Output {
    std::process::Command::new(env!("CARGO_BIN_EXE_kan-v2"))
        .current_dir(cwd)
        .args([
            "copy-plan", db, plan,
            "--scope", &service::hex(&[1; 32]),
            "--issuer", identity(8).did().as_str(),
            "--historical-issuer", identity(7).did().as_str(),
            "--nonce", &service::hex(&[9; 32]),
        ])
        .output()
        .unwrap()
}
fn report(label: &str, o: &std::process::Output, preserved: Option<bool>, db_same: bool) {
    println!(
        "PROBE {label}: exit={:?} stdout_empty={} stderr={:?} target_preserved={:?} db_unchanged={}",
        o.status.code(),
        o.stdout.is_empty(),
        String::from_utf8_lossy(&o.stderr).trim(),
        preserved,
        db_same
    );
}
fn sidecars(db: &Path) -> Vec<String> {
    let mut v: Vec<_> = std::fs::read_dir(db.parent().unwrap())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}

#[test]
fn review_copy_plan_entry_point_probes() {
    let content = b"owner-selected unrelated bytes that must survive".to_vec();
    // AP1: source named through a symlinked directory; Unicode alias written via real path.
    // AP2: relative source and relative case-alias plan from the source directory.
    // AP3: plan is a hard link to the main database.
    // AP4: non-existing case-alias sidecar name must be refused and not created.
    // AP5: controls: ordinary existing file preserved; ordinary new path succeeds.
    for case in ["AP1", "AP2", "AP3", "AP4", "AP5a", "AP5b", "AP6"] {
        let t = tempfile::tempdir().unwrap();
        let db = fixture(t.path());
        let before = std::fs::read(&db).unwrap();
        let dir = db.parent().unwrap().to_path_buf();
        let (cwd, src, plan_arg, target): (PathBuf, String, String, PathBuf) = match case {
            "AP1" => {
                let link = t.path().join("linked");
                std::os::unix::fs::symlink(&dir, &link).unwrap();
                let target = dir.join("archive.sqlite-ſhm");
                std::fs::write(&target, &content).unwrap();
                (t.path().into(), link.join("archive.sqlite").to_str().unwrap().into(), target.to_str().unwrap().into(), target)
            }
            "AP2" => {
                let target = dir.join("archive.sqlite-Shm");
                std::fs::write(&target, &content).unwrap();
                (dir.clone(), "archive.sqlite".into(), "archive.sqlite-Shm".into(), target)
            }
            "AP3" => {
                let target = t.path().join("hard.cbor");
                std::fs::hard_link(&db, &target).unwrap();
                (t.path().into(), db.to_str().unwrap().into(), target.to_str().unwrap().into(), target)
            }
            "AP4" => {
                let target = dir.join("archive.sqlite-Wal");
                (t.path().into(), db.to_str().unwrap().into(), target.to_str().unwrap().into(), target)
            }
            "AP5a" => {
                let target = t.path().join("existing.cbor");
                std::fs::write(&target, &content).unwrap();
                (t.path().into(), db.to_str().unwrap().into(), target.to_str().unwrap().into(), target)
            }
            "AP5b" => {
                let target = t.path().join("fresh.cbor");
                (t.path().into(), db.to_str().unwrap().into(), target.to_str().unwrap().into(), target)
            }
            // AP6: source path through `..`/`.` components; Unicode-uppercase alias via other spelling.
            _ => {
                let target = dir.join("archive.sqlite-JOURNAL");
                std::fs::write(&target, &content).unwrap();
                let odd = dir.join("..").join("source").join(".").join("archive.sqlite");
                (t.path().into(), odd.to_str().unwrap().into(), target.to_str().unwrap().into(), target)
            }
        };
        let existed = target.exists();
        let o = copy_plan(&cwd, &src, &plan_arg);
        let preserved = if case == "AP3" {
            Some(std::fs::read(&target).unwrap() == before)
        } else if existed {
            Some(std::fs::read(&target).map(|b| b == content).unwrap_or(false))
        } else {
            None
        };
        report(case, &o, preserved, std::fs::read(&db).unwrap() == before);
        println!("PROBE {case} dir listing after: {:?} target_exists={}", sidecars(&db), target.exists());
        match case {
            "AP5b" => assert!(o.status.success()),
            "AP5a" => assert!(!o.status.success() && preserved == Some(true)),
            "AP4" => assert!(!o.status.success() && !target.exists()),
            _ => {
                assert!(!o.status.success(), "{case}");
                assert_eq!(preserved, Some(true), "{case}");
            }
        }
        assert_eq!(std::fs::read(&db).unwrap(), before, "{case}");
    }
}
