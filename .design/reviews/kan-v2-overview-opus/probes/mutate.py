#!/usr/bin/env python3
"""Reviewer compiled semantic mutants for 67c1263. Usage: mutate.py <export-root> <out-dir> [case...]
Each case makes one exact-count substitution, runs the named suites (--no-fail-fast), records which
named tests fail, then restores the exact original bytes (verified by SHA-256) in `finally`.
A mutant counts as KILLED only if it compiles and at least one named test fails."""
import hashlib, pathlib, re, subprocess, sys

ROOT = pathlib.Path(sys.argv[1]).resolve()
OUT = pathlib.Path(sys.argv[2]).resolve()
OUT.mkdir(parents=True, exist_ok=True)
OV = 'src/evidence_operations_collection/overview.rs'
PJ = 'src/evidence_operations/projection.rs'
DB = 'src/evidence_dashboard.rs'
JS = 'web/operations/app.js'
ST = 'src/evidence_store/attested.rs'
RUST_OV = ['evidence_operations_overview', 'zz_review_overview_probe']
RUST_ST = ['evidence_attested_store', 'evidence_attested_followups', 'surface_conformance']
NODE = ['tests/operations_ui.test.cjs', 'tests/zz_review_operations_ui.test.cjs']


def sub(text, old, new):
    assert text.count(old) == 1, f'pattern count {text.count(old)}: {old[:70]!r}'
    return text.replace(old, new)


CASES = [
    # --- overview: Rust ---
    ('OM1-drop-post-read-sealed-rehash', OV, lambda s: sub(s,
        "    if let Some(expected) = &g.sealed_sha256 {\n        if &sealed_hash(&path, flag)? != expected {\n            return Err(invalid());\n        }\n    }\n    if g.sealed_sha256.is_some() {",
        "    if g.sealed_sha256.is_some() {"), RUST_OV),
    ('OM2-drop-generation-lock-existence-check', OV, lambda s: sub(s,
        "    private(Path::new(&lock_path), false, 0)?;\n", ""), RUST_OV),
    ('OM3-drop-valid-health-in-scan', PJ, lambda s: sub(s,
        "                if !valid_health(&health)\n                    || health.attempt != id",
        "                if health.attempt != id"), RUST_OV),
    ('OM4-drop-manifest-recheck-before-publish', OV, lambda s: sub(s,
        "    if manifest_snapshot(root)?.1 != manifest_sha256 {\n        return Err(invalid());\n    }\n", ""), RUST_OV),
    ('OM5-keep-sealed-worker-sample', OV, lambda s: sub(s,
        "    if g.sealed_sha256.is_some() {\n        snapshot.worker = None;\n    }\n", ""), RUST_OV),
    ('OM6-drop-sealed-sidecar-check', OV, lambda s: sub(s,
        "        sidecars_absent(&path)?;\n        if &sealed_hash", "        if &sealed_hash"), RUST_OV),
    ('OM7-drop-projection-binding-check', PJ, lambda s: sub(s,
        "        if &self.binding()? != expected_binding {\n            return Err(invalid());\n        }\n", ""), RUST_OV),
    ('OM8-publish-despite-cancel', OV, lambda s: sub(s,
        "                if cancel.load(Ordering::Relaxed) {\n                    state.state = \"cancelled\";",
        "                if false && cancel.load(Ordering::Relaxed) {\n                    state.state = \"cancelled\";"), RUST_OV),
    ('OM9-session-dropped-may-regress', OV, lambda s: sub(s,
        ") => new >= old && (!oc || *nc),", ") => !oc || *nc,"), RUST_OV),
    ('OM10-reverse-sealed-generation-order', OV, lambda s: sub(s,
        "    for g in &m.generations[..m.generations.len() - 1] {",
        "    for g in m.generations[..m.generations.len() - 1].iter().rev() {"), RUST_OV),
    ('OM11-accept-transfer-encoding-body', DB, lambda s: sub(s,
        "            if r.headers().contains_key(\"transfer-encoding\")\n                || r.headers()",
        "            if r.headers()"), RUST_OV),
    ('OM12-u64-as-json-number', OV, lambda s: sub(s,
        "    serializer.serialize_str(&value.to_string())", "    serializer.serialize_u64(*value)"), RUST_OV),
    ('OM13-session-overflow-saturates', OV, lambda s: sub(s,
        "            add(&mut t.telemetry_dropped_lower_bound, *dropped)?;",
        "            t.telemetry_dropped_lower_bound = t.telemetry_dropped_lower_bound.saturating_add(*dropped);"), RUST_OV),
    ('OM14-no-dedup-sessions', OV, lambda s: sub(s,
        "            Observation::Session { id, .. } => (\n                id.clone(),",
        "            Observation::Session { id, .. } => (\n                format!(\"{id}:{}\", self.sessions.len()),"), RUST_OV),
    # --- overview: UI ---
    ('UM1-drop-prior-sample-label', JS, lambda s: sub(s,
        "(s.last&&s.last_job!==s.job?' · Prior sample retained; this refresh has not replaced it.':'')", "''"), NODE),
    ('UM2-error-path-ignores-generation', JS, lambda s: sub(s,
        "catch(e){if(current===generation)$('overview-state')", "catch(e){$('overview-state')"), NODE),
    ('UM3-drop-frontier-validation', JS, lambda s: sub(s,
        "  if(v.sources.at(-1).generation!==v.active||v.sources.at(-1).sealed_sha256!==null||v.sources.slice(0,-1).some(x=>x.sealed_sha256===null))throw new Error('Invalid overview frontier.');\n", ""), NODE),
    ('UM4-lock-keeps-overview', JS, lambda s: sub(s,
        "snapshot=null;clearOverview();", "snapshot=null;"), NODE),
    ('UM5-render-numbers-not-bigint', JS, lambda s: sub(s,
        "n=k=>BigInt(t[k]).toLocaleString()", "n=k=>Number(t[k]).toLocaleString()"), NODE),
    # --- storage follow-ups ---
    ('SM1-retry-receipt-error-back-to-invalid', ST, lambda s: sub(s,
        "                )\n                .map_err(|_| Error::Conflict(\"retry receipt changed\"))?;",
        "                )?;"), RUST_ST),
    ('SM2-RM1-drop-retry-envelope-compare', ST, lambda s: sub(s,
        "                    || envelope(tx, row.sequence)? != old.bytes()\n", ""), RUST_ST),
    ('SM3-RM2-drop-retry-receipt-recheck', ST, lambda s: sub(s,
        "                proof::verify_at(\n                    old.bytes(),\n                    &binding.context(),\n                    &row.manifest,\n                    &row.receipt,\n                    old.frontier(),\n                )\n                .map_err(|_| Error::Conflict(\"retry receipt changed\"))?;\n", ""), RUST_ST),
    ('SM4-RM3-drop-historical-issuer-consistency', ST, lambda s: sub(s,
        ".is_some_and(|h| h != &signed.request.audience)",
        ".is_some_and(|h| h != &signed.request.audience && false)"), RUST_ST),
    ('SM5-RM4-drop-p256-binding-check', ST, lambda s: sub(s,
        "        if algorithm != atrium_crypto::Algorithm::P256\n            || atrium",
        "        if atrium"), RUST_ST),
    ('SM6-NC5-uncatalogued-profile2-index', ST, lambda s: sub(s,
        "PRAGMA user_version=2;\n", "CREATE INDEX attestations_by_envelope ON attestations(envelope);\nPRAGMA user_version=2;\n"), RUST_ST),
    ('SM9-uncatalogued-index-on-legacy-table-in-profile2', ST, lambda s: sub(s,
        "PRAGMA user_version=2;\n", "CREATE INDEX commits_by_receipt ON commits(receipt);\nPRAGMA user_version=2;\n"), RUST_ST),
    ('SM7-NC1-raw-sql-attestation-update', ST, lambda s: sub(s,
        "                observe(Boundary::AttestationInserted);\n",
        "                tx.execute(\"UPDATE attestations SET envelope=envelope WHERE sequence=?\", [i64::try_from(row.sequence).unwrap()])?;\n                observe(Boundary::AttestationInserted);\n"), RUST_ST),
    ('SM8-set-limit-error-ignored-again', ST, lambda s: sub(s,
        "        conn.set_limit(\n            rusqlite::limits::Limit::SQLITE_LIMIT_LENGTH,\n            RECOVERY_SQLITE_LENGTH_LIMIT,\n        )?;",
        "        let _ = conn.set_limit(\n            rusqlite::limits::Limit::SQLITE_LIMIT_LENGTH,\n            RECOVERY_SQLITE_LENGTH_LIMIT,\n        );"), RUST_ST),
]


def digest(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def run_rust(suites):
    args = ['cargo', 'test', '--features', 'v2-crypto', '--no-fail-fast']
    for s in suites:
        args += ['--test', s]
    # PO1/PO1b fail on the unmutated baseline (finding F1); exclude them so they cannot
    # count as kills. `po1_`/`po1b_` do not match `po10_`.
    args += ['--', '--skip', 'po1_', '--skip', 'po1b_']
    r = subprocess.run(args, cwd=ROOT, capture_output=True, text=True)
    log = r.stdout + r.stderr
    # Only a real compiler error counts as non-compiling; cargo's 'error: test failed' does not.
    if 'could not compile' in log or re.search(r'^error\[E\d+\]', log, re.M):
        return r.returncode, log, None
    return r.returncode, log, re.findall(r'^test (\S+) \.\.\. FAILED', log, re.M)


def run_node(files):
    # UP2/UP3 fail on the unmutated baseline (finding); exclude them from kill attribution.
    r = subprocess.run(['node', '--test', '--test-skip-pattern=^UP[23] ', *files], cwd=ROOT, capture_output=True, text=True)
    log = r.stdout + r.stderr
    if 'SyntaxError' in log:
        return r.returncode, log, None
    return r.returncode, log, re.findall(r'^✖ (.+?) \(\d', log, re.M)


def main():
    only = set(sys.argv[3:])
    for name, rel, mutate, suites in CASES:
        if only and name not in only:
            continue
        path = ROOT / rel
        original = path.read_bytes()
        before = digest(path)
        changed = mutate(original.decode())
        assert changed.encode() != original, name
        try:
            path.write_text(changed)
            code, log, failed = (run_node if rel == JS else run_rust)(suites)
            (OUT / f'{name}.txt').write_text(log)
        finally:
            path.write_bytes(original)
            assert digest(path) == before, f'restore failed for {rel}'
        if failed is None:
            verdict = 'COMPILE/SYNTAX-FAILURE (not counted)'
            failed = []
        else:
            failed = sorted(set(failed))
            verdict = 'KILLED' if failed else 'SURVIVED'
        author = [t for t in failed if 'zz_review' not in t and not t.startswith(('po', 'UP', 'pm'))]
        line = f'{name}: {verdict} exit={code} author_failed={author} all_failed={failed}'
        print(line, flush=True)
        with open(OUT / 'SUMMARY.txt', 'a') as f:
            f.write(line + '\n')


if __name__ == '__main__':
    main()
