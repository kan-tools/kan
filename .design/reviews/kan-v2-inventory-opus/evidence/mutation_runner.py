#!/usr/bin/env python3
"""Independent reviewer's compiled mutation runner (not the author's script).

Run with -I from the export root. Writes logs only under review-evidence/mutations.
Every mutation is an exact single-occurrence replacement (or a reverse patch for
the complete f656994 production reversion). Tracked bytes are restored in a
finally block and checked against the frozen manifest SHA-256 after each case.
"""
import hashlib, json, os, subprocess, sys, time
from pathlib import Path

ROOT = Path.cwd()
OUT = ROOT / "review-evidence" / "mutations"
MANIFEST = json.load(open(ROOT.parent / "inventory-identity.json"))["files"]
INV = "src/evidence_store/inventory.rs"
ES = "src/evidence_store.rs"
FEATURES = ["--features", "v2-crypto"]
A_TESTS = [
    "unicode_sidecar_aliases_refuse_before_copy_resume_and_preserve_the_plan",
    "sidecar_hardlink_identity_is_rejected_even_with_an_unrelated_plan_name",
    "unicode_reserved_plan_suffix_is_refused_even_before_any_sidecar_exists",
    "unicode_source_sidecar_plan_is_refused_before_a_fresh_sqlite_reader_can_consume_it",
]


def sha(path):
    return hashlib.sha256((ROOT / path).read_bytes()).hexdigest()


def cargo(args, log, timeout=900):
    cmd = ["cargo", "test"] + FEATURES + args
    start = time.time()
    run = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, timeout=timeout)
    text = "$ " + " ".join(cmd) + "\n" + run.stdout + run.stderr + f"\nexit={run.returncode} elapsed={time.time()-start:.1f}s\n"
    (OUT / log).write_text(text)
    failed = sorted({l.split()[1] for l in text.splitlines() if l.startswith("test ") and l.endswith("FAILED")})
    passed = sum(1 for l in text.splitlines() if l.startswith("test ") and l.endswith(" ok"))
    return run.returncode, "could not compile" in text, failed, passed


def mutate(path, old, new):
    text = (ROOT / path).read_text()
    assert text.count(old) == 1, (path, old[:60], text.count(old))
    (ROOT / path).write_text(text.replace(old, new))


def restore(path, original):
    (ROOT / path).write_text(original)
    assert sha(path) == MANIFEST[path], "restore mismatch " + path


# (name, file, old, new, cargo args, expectation note)
A_ARGS = ["--test", "evidence_copy_destination", "--test", "zz_review_probe", "--no-fail-fast"]
INV_ARGS = ["--test", "evidence_inventory", "--no-fail-fast"]
CASES = [
    # ---- scope A partial mutants (reviewer's own) ----
    ("A-M1-drop-existing-identity", ES, "            sqlite_name_eq(target.as_os_str(), source.as_os_str())\n                || same_existing_file(target, source)",
     "            sqlite_name_eq(target.as_os_str(), source.as_os_str())", A_ARGS),
    ("A-M2-ascii-only-name-eq", ES, "    match (a.to_str(), b.to_str()) {\n        (Some(a), Some(b)) => a",
     "    match (None::<&str>, b.to_str()) {\n        (Some(a), Some(b)) => a", A_ARGS),
    ("A-M3-drop-basename-suffix-check", ES, "        }) && same_existing_file(&parent.join(base), source)",
     "        }) && false && same_existing_file(&parent.join(base), source)", A_ARGS),
    # ---- scope B: author's ten controls, rerun independently ----
    ("B-author-indexed-large-row-materialization", INV, "SELECT length(bytes) FROM objects NOT INDEXED WHERE +cid=?", "SELECT length(bytes) FROM objects WHERE cid=?", INV_ARGS),
    ("B-author-omit-sqlite-vm-callback", INV, "        1000,\n", "        0,\n", ["--lib", "evidence_store::inventory::tests"]),
    ("B-author-require-payloads-at-startup", INV, "        let plan = plan(&reader, profile, &binding)?;", "        reader.ledger.verify_contents()?;\n        let plan = plan(&reader, profile, &binding)?;", INV_ARGS),
    ("B-author-omit-payload-hash", INV, "bytes.len() != expected || ciphertext_cid(&bytes) != *id", "bytes.len() != expected", INV_ARGS),
    ("B-author-omit-retained-position", INV, "if record.sequence > p.source().through {", "if false && record.sequence > p.source().through {", INV_ARGS),
    ("B-author-omit-admitted-prefix-guard", INV, "if plan.is_some_and(|p| record.sequence <= p.source().through) {", "if false && plan.is_some_and(|p| record.sequence <= p.source().through) {", INV_ARGS),
    ("B-author-omit-historical-issuer", INV, 'if record.receipt.body()["issuer"] != historical {', 'if false && record.receipt.body()["issuer"] != historical {', INV_ARGS),
    ("B-author-omit-metadata-digest-refusal", INV, "            if !matches\n", "            if false && !matches\n", INV_ARGS),
    ("B-author-ignore-page-row-limit", INV, "records.len() < limit.rows", "records.len() < 40", INV_ARGS),
    ("B-author-omit-writer-verification", INV, '    let signed = service::verify_retained_request(&record, &bytes)\n        .map_err(|_| corrupt("selected writer request"))?;',
     '    let signed: service::SignedRequest = serde_json::from_slice(&bytes).map_err(|_| corrupt("selected writer request"))?;', INV_ARGS),
    # ---- scope B: reviewer's own mutants ----
    ("B-M1-omit-proof-cardinality", INV, "        if u64::try_from(proof_count).ok() != Some(frontier.through) {", "        if false && u64::try_from(proof_count).ok() != Some(frontier.through) {", INV_ARGS),
    ("B-M2-omit-schema-check", INV, "    schema(&reader.ledger.conn, profile)?;\n", "", INV_ARGS),
    ("B-M3-omit-cursor-context-check", INV, "            if cursor.profile != self.profile\n", "            if false && cursor.profile != self.profile\n", INV_ARGS),
    ("B-M4-omit-source-selection-binding-check", INV, "    if selection.profile != profile || selection.binding != binding {", "    if false && (selection.profile != profile || selection.binding != binding) {", INV_ARGS),
    ("B-M5-missing-reported-as-corrupt", INV, "        return Ok((Availability::Missing, None));", "        return Ok((Availability::Corrupt, None));", INV_ARGS),
    ("B-M6-omit-page-vm-configuration", INV, "        configure_read(&self.reader.ledger.conn, &work, deadline)?;\n", "", INV_ARGS),
    ("B-M7-recipe-match-ignores-completeness", INV, "frontier.through >= plan.source().through && digest == plan.source().digest", "digest == plan.source().digest || true", INV_ARGS),
    ("B-M8-omit-startup-item-budget", INV, "            add_spent(&mut items, 1, budget.items)?;\n            let record = raw_commit(row)?;", "            let record = raw_commit(row)?;", INV_ARGS),
    ("B-M9-omit-source-purpose-recheck", INV, "    purpose(&record, &verified, plan.as_ref())?;\n    let (id, length) = request_coordinate(&record)?;\n    if length > max_payload_bytes {",
     "    let (id, length) = request_coordinate(&record)?;\n    if length > max_payload_bytes {", INV_ARGS),
    ("B-M10-omit-source-scope-recheck", INV, "    if signed.request.scope != service::hex(&binding.scope) {", "    if false && signed.request.scope != service::hex(&binding.scope) {", INV_ARGS),
]


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    only = set(sys.argv[1:])
    results = []
    originals = {p: (ROOT / p).read_text() for p in (INV, ES)}
    for p in originals:
        assert sha(p) == MANIFEST[p], "pre-run tracked bytes differ " + p
    try:
        if not only or "A-REVERSION" in only:
            # Complete f656994 production reversion (reverse patch of both hunks).
            patch = (OUT / "alias-production.patch").read_text()
            r = subprocess.run(["patch", "-R", "-p1", ES], cwd=ROOT, input=patch, capture_output=True, text=True)
            assert r.returncode == 0, r.stdout + r.stderr
            args = ["--test", "evidence_copy_destination", "--no-fail-fast"]
            code, ce, failed, passed = cargo(args, "A-REVERSION-full-f656994-production.txt")
            restore(ES, originals[ES])
            named_failed = [t for t in A_TESTS if t in failed]
            results.append({"case": "A-REVERSION-full-f656994-production", "exit": code, "compile_error": ce, "failed": failed, "passed": passed,
                            "all_four_named_failed": len(named_failed) == 4})
            code, ce, failed, passed = cargo(args, "A-REVERSION-restored.txt")
            results.append({"case": "A-REVERSION-restored", "exit": code, "compile_error": ce, "failed": failed, "passed": passed})
            print(json.dumps(results[-2:]), flush=True)
        for name, path, old, new, args in CASES:
            if only and name not in only:
                continue
            mutate(path, old, new)
            try:
                code, ce, failed, passed = cargo(args, name + ".txt")
            finally:
                restore(path, originals[path])
            results.append({"case": name, "exit": code, "compile_error": ce, "failed": failed, "passed": passed,
                            "verdict": "COMPILE-ERROR" if ce else ("KILLED" if code != 0 and failed else ("SURVIVED" if code == 0 else "ERROR"))})
            print(json.dumps(results[-1]), flush=True)
    finally:
        for p, text in originals.items():
            (ROOT / p).write_text(text)
            assert sha(p) == MANIFEST[p]
    (OUT / ("summary-" + time.strftime("%H%M%S") + ".json")).write_text(json.dumps(results, indent=1))


if __name__ == "__main__":
    main()
