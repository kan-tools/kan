"""Reviewer mutation runner for 423054a. Run with python3 -I from anywhere.

Each case replaces exactly one occurrence, runs cargo, restores the original
bytes and checks sha256 before the next case. A case is KILLED only when the
expected named test is reported FAILED without a compile error.
"""
import hashlib
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(sys.argv[1]).resolve()
OUT = pathlib.Path(sys.argv[2]).resolve()
OUT.mkdir(parents=True, exist_ok=True)
CU = "src/evidence_store/copy_upgrade.rs"
CP = "src/evidence_store/copied.rs"
BIN = "src/bin/kan-v2.rs"
SUITE = "evidence_copy_destination"

# (name, file, old, new, named test or None for "any test in suite")
CASES = [
    # Author's six controls (same patterns as scripts/copy_destination_followup_controls.py).
    ("A1-remove-plan-custody-guards", CU,
     "    if same_existing_file(database, plan) {",
     "    return Ok(());\n    #[allow(unreachable_code)]\n    if same_existing_file(database, plan) {",
     "plan_custody_refuses_sqlite_families_before_opening_or_writing"),
    ("A2-skip-cli-copy-path-checks", BIN,
     "kan::evidence_store::copy_upgrade::read_plan_for_copy(\n                &plan,\n                &database,\n                &archive,\n                &binding.archive,\n            )?",
     "kan::evidence_store::copy_upgrade::read_plan(&plan, &binding.archive)?",
     "owner_cli_plan_paths_cannot_be_sqlite_files_or_sidecars"),
    ("A3-omit-profile3-full-audit-schema", CP,
     "    ledger.check_profile(3)?;\n    ledger.check_copy_schema()?;", "    ledger.check_profile(3)?;",
     "profile3_schema_drift_refuses_open_verify_resume_and_stale_handle_backup"),
    ("A4-skip-object-prefix-comparison", CP,
     "if id != expected.get::<_, String>(0)? || length != expected.get::<_, i64>(1)? {",
     "if false && (id != expected.get::<_, String>(0)? || length != expected.get::<_, i64>(1)?) {",
     "resume_refuses_self_consistent_foreign_object_prefix_before_advancing"),
    ("A5-skip-record-prefix-comparison", CP,
     "if old.manifest.bytes() != expected.manifest.bytes()\n                || old.receipt.bytes() != expected.receipt.bytes()\n            {",
     "if false && (old.manifest.bytes() != expected.manifest.bytes()\n                || old.receipt.bytes() != expected.receipt.bytes())\n            {",
     "resume_refuses_valid_foreign_receipt_prefix_before_signing_more_proofs"),
    ("A6-omit-cli-explicit-profile", BIN,
     "if !proof.copy_profile {", "if false && !proof.copy_profile {",
     "owner_cli_copy_preconditions_refuse_without_creating_output"),
    # Reviewer mutants: whole destination suite.
    ("R1-drop-destination-family-check", CU,
     '    plan_outside_sqlite(&root.join("archive.sqlite"), path)?;\n', "", None),
    ("R2-drop-source-family-check-on-read", CU,
     "    let source = std::fs::canonicalize(source)?;\n    plan_outside_sqlite(&source, path)?;",
     "    let _ = source;", None),
    ("R3-drop-retain-plan-check", CU,
     "    plan_outside_sqlite(&source.reader.source, path)?;\n    let plan = source.plan();",
     "    let plan = source.plan();", None),
    ("R4-drop-inode-alias-check", CU,
     "    if same_existing_file(database, plan) {",
     "    if false && same_existing_file(database, plan) {", None),
    ("R5-no-source-canonicalize", CU,
     "    let source = std::fs::canonicalize(source)?;",
     "    let source = source.to_path_buf();", None),
    ("R6-no-destination-root-canonicalize", CU,
     "        std::fs::canonicalize(destination_root)?\n    } else {",
     "        destination_root.to_path_buf()\n    } else {", None),
    ("R7-revert-plan-privacy-wording", CU,
     'Error::Invalid("database must be owner-only") => Error::Invalid("plan must be owner-only"),',
     'Error::Invalid("database must be owner-only") => Error::Invalid("database must be owner-only"),',
     None),
    ("R8-record-prefix-ignores-receipt", CP,
     "if old.manifest.bytes() != expected.manifest.bytes()\n                || old.receipt.bytes() != expected.receipt.bytes()\n            {",
     "if old.manifest.bytes() != expected.manifest.bytes()\n            {", None),
    ("R9-object-prefix-ignores-length", CP,
     "if id != expected.get::<_, String>(0)? || length != expected.get::<_, i64>(1)? {",
     "if id != expected.get::<_, String>(0)? {\n                let _ = length;", None),
]


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


only = set(sys.argv[3:])
originals = {}
for _, f, *_ in CASES:
    p = ROOT / f
    originals.setdefault(p, (p.read_bytes(), sha(p)))
summary = []
try:
    for name, f, old, new, test in CASES:
        if only and name not in only:
            continue
        p = ROOT / f
        before, digest = originals[p]
        text = before.decode()
        n = text.count(old)
        if n != 1:
            summary.append(f"PATTERN-COUNT-{n}: {name}")
            print(summary[-1], flush=True)
            continue
        p.write_text(text.replace(old, new, 1))
        cmd = ["cargo", "test", "--features", "v2-crypto", "--test", SUITE]
        if test:
            cmd += [test, "--", "--exact"]
        run = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, timeout=600)
        p.write_bytes(before)
        assert sha(p) == digest, f"restore failed {p}"
        log = run.stdout + run.stderr
        (OUT / f"{name}.txt").write_text("+ " + " ".join(cmd) + "\n" + log + f"\nexit={run.returncode}\n")
        failed = sorted({l.split()[1] for l in log.splitlines()
                         if l.startswith("test ") and l.rstrip().endswith("FAILED")})
        if "could not compile" in log or "error[E" in log:
            verdict = "COMPILE-ERROR"
        elif run.returncode == 0:
            verdict = "SURVIVED"
        elif test and test not in failed:
            verdict = "FAILED-WITHOUT-NAMED-TEST"
        else:
            verdict = "KILLED"
        summary.append(f"{verdict}: {name} failed={failed}")
        print(summary[-1], flush=True)
finally:
    for p, (before, digest) in originals.items():
        p.write_bytes(before)
        assert sha(p) == digest
print("all mutated files restored and sha256-verified", flush=True)
(OUT / "SUMMARY.txt").write_text("\n".join(summary) + "\nall mutated files restored and sha256-verified\n")
