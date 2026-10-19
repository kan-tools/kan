#!/usr/bin/env python3
"""Reviewer mutation runner (run with python3 -I; cwd = export root via argv).

Each mutant: exact single-occurrence textual replacement, run the named cargo
tests, record the log under review-evidence/raw/mutants/, restore, and verify
the restored file's sha256 equals the manifest hash. Never touches git.
Usage: mutate.py <export_root> <manifest.json> [name ...]
"""
import hashlib, json, subprocess, sys
from pathlib import Path

ROOT = Path(sys.argv[1]).resolve()
MANIFEST = json.load(open(sys.argv[2]))["files"]
ONLY = set(sys.argv[3:])
OUT = ROOT / "review-evidence/raw/mutants"
OUT.mkdir(parents=True, exist_ok=True)
DEST = "evidence_copy_destination"
ALL_DEST = [DEST, "evidence_attested_followups", "evidence_attested_store", "evidence_attested_lifecycle"]

# (name, file, old, new, [(suite, test-or-None)], expectation)
CASES = [
    # --- author controls, reproduced independently ---
    ("A-complete-without-source-digest", "src/evidence_store/copied.rs", "digest == plan.source().digest", "{ let _ = digest; true }", [(DEST, "empty_record_history_is_incomplete_until_all_staged_objects_are_copied")], "kill"),
    ("A-skip-preflight-completeness", "src/evidence_store/attested.rs", "if target.is_some() && !status.source_copy_complete {", "if false && target.is_some() && !status.source_copy_complete {", [(DEST, "bounded_copy_preserves_original_bytes_and_acknowledged_proofs_before_new_admission")], "kill"),
    ("A-skip-writer-membership-check", "src/evidence_store/attested.rs", "copied::admission_ready(tx, binding, plan, previous.through)?;", "copied::check_plan(tx, binding, plan)?;", [(DEST, "admission_rechecks_original_membership_after_staging_under_writer_transaction")], "kill"),
    ("A-ignore-external-archive", "src/evidence_store/copied.rs", "plan.check_archive(&binding.archive)?;", "", [(DEST, "owner_recipe_signer_and_profile_are_required_before_mutation")], "kill"),
    ("A-ignore-historical-issuer", "src/evidence_store/attested.rs", "if signed.request.audience != plan.source().historical_issuer {", "if false && signed.request.audience != plan.source().historical_issuer {", [(DEST, "profile3_rejects_mixed_historical_issuers_with_a_specific_reason")], "kill"),
    ("A-ignore-retained-position", "src/evidence_store/attested.rs", "if record.sequence > plan.source().through {", "if false && record.sequence > plan.source().through {", [(DEST, "profile3_rejects_retained_after_admission_and_admission_inside_original_prefix")], "kill"),
    ("A-oracle-omits-independent-sort", ".design/tools/copy_source_digest.py", "sorted(conn.execute('SELECT cid,bytes FROM objects ORDER BY length(bytes) DESC,cid DESC').fetchall(),key=lambda row:row[0])", "conn.execute('SELECT cid,bytes FROM objects ORDER BY length(bytes) DESC,cid DESC').fetchall()", [("evidence_copy_source", "source_fingerprint_matches_an_independent_python_byte_oracle")], "kill"),
    ("A-wrong-inventory-capability", "src/evidence_store/copied.rs", "crate::persistence::SurfaceWrite::EvidenceCopy,", "crate::persistence::SurfaceWrite::EvidenceAttestation,", [("surface_conformance", "every_persistence_facade_call_is_independently_inventoried")], "kill"),
    ("A-unregistered-plan-file-write", "src/evidence_store/copy_upgrade.rs", "crate::persistence::SurfaceWrite::EvidenceCopyPlan,", "crate::persistence::SurfaceWrite::EvidenceArchive,", [("surface_conformance", "every_persistence_facade_call_is_independently_inventoried")], "kill"),
    # --- reviewer mutants ---
    ("R1-allow-admission-inside-prefix", "src/evidence_store/attested.rs", "if copy.is_some_and(|p| record.sequence <= p.source().through) {", "if false && copy.is_some_and(|p| record.sequence <= p.source().through) {", [(s, None) for s in ALL_DEST], "kill"),
    ("R2-no-profile3-schema-check", "src/evidence_store/copied.rs", "    ledger.check_profile(3)?;\n    ledger.check_copy_schema()?;\n    let contents", "    ledger.check_profile(3)?;\n    let contents", [(s, None) for s in ALL_DEST], "probe"),
    ("R3-skip-inventory-prefix-compare", "src/evidence_store/copied.rs", "if id != expected.get::<_, String>(0)? || length != expected.get::<_, i64>(1)? {", "if false {", [(s, None) for s in ALL_DEST], "probe"),
    ("R4-skip-record-prefix-compare", "src/evidence_store/copied.rs", "if old.manifest.bytes() != expected.manifest.bytes()\n                || old.receipt.bytes() != expected.receipt.bytes()", "if false", [(s, None) for s in ALL_DEST], "probe"),
    ("R5-drop-incomplete-untracked-guard", "src/evidence_store/copied.rs", "if !complete && (through > plan.source().through || objects != original_objects) {", "if false {", [(s, None) for s in ALL_DEST], "probe"),
    ("R6-rebuild-skips-precommit-copy-audit", "src/evidence_store.rs", "                copied::full_audit(&target, binding, plan)?;\n", "                let _ = plan;\n", [(s, None) for s in ALL_DEST], "kill"),
    ("R7-object-byte-budget-ignored", "src/evidence_store/copied.rs", "if objects_written == budget.objects || length > budget.bytes - bytes_written {", "if objects_written == budget.objects {", [(s, None) for s in ALL_DEST], "kill"),
    ("R8-records-before-objects-guard-removed", "src/evidence_store/copied.rs", "            if before.contents.commits > 0 {\n                return Err(corrupt(\"records precede complete original inventory\"));\n            }\n", "", [(s, None) for s in ALL_DEST], "probe"),
    ("R9-cli-copy-batch-without-copy-profile-flag", "src/bin/kan-v2.rs", "            if !proof.copy_profile {\n                return Err(\"copy-batch requires --copy-profile and all owner pins\".into());\n            }\n", "", [(DEST, None), ("recovery_cli", None)], "probe"),
]

def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()

def run(name, rel, old, new, targets, expect):
    path = ROOT / rel
    before = path.read_text()
    assert sha(path) == MANIFEST[rel], f"{rel} not at manifest hash before {name}"
    n = before.count(old)
    # Author controls mirror scripts/copy_destination_negative_controls.py,
    # which replaces the FIRST occurrence; reviewer mutants must be unique.
    assert n == 1 or (name.startswith("A-") and n >= 1), f"{name}: pattern count {n}"
    path.write_text(before.replace(old, new, 1))
    log, verdicts = [], []
    try:
        for suite, test in targets:
            cmd = ["cargo", "test", "--features", "v2-crypto", "--test", suite]
            if test:
                cmd += [test, "--", "--exact"]
            r = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, timeout=1800)
            text = r.stdout + r.stderr
            log.append(f"$ {' '.join(cmd)}\nexit={r.returncode}\n{text}")
            if "could not compile" in text or "error[E" in text:
                verdicts.append(f"{suite}:COMPILE-ERROR")
            elif r.returncode != 0:
                failed = [l for l in text.splitlines() if l.startswith("test ") and l.endswith("FAILED")]
                verdicts.append(f"{suite}:KILLED by {failed}")
            else:
                verdicts.append(f"{suite}:passed")
    finally:
        path.write_text(before)
        assert sha(path) == MANIFEST[rel], f"{rel} restore mismatch"
    (OUT / f"{name}.txt").write_text("\n".join(log))
    killed = any("KILLED" in v for v in verdicts)
    compile_err = any("COMPILE" in v for v in verdicts)
    status = "COMPILE-ERROR" if compile_err else ("KILLED" if killed else "SURVIVED")
    line = f"{name} [{expect}] (occurrences={n}, first replaced) -> {status}: {'; '.join(verdicts)}"
    print(line, flush=True)
    return line

lines = []
for case in CASES:
    if ONLY and case[0] not in ONLY:
        continue
    lines.append(run(*case))
(OUT / "SUMMARY.txt").write_text("\n".join(lines) + "\n")
