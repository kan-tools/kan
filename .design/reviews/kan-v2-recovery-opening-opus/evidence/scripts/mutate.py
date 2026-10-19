#!/usr/bin/env python3
"""Reviewer mutation driver. One mutation at a time; exact restore verified by
SHA-256; every raw log kept. Classification is manual in REPORT.txt."""
import hashlib, json, os, subprocess, sys
from pathlib import Path
EXPORT = Path(__file__).resolve().parents[2]
EV = EXPORT / 'review-evidence'
OUT = EV / 'mutations'
GEN_B = str(EV / 'probes/out-scopeB')
def T(target, name=None, exact=True, lib=False):
    a = ['cargo', 'test', '--features', 'v2-crypto'] + (['--lib'] if lib else ['--test', target])
    if name: a.append(name)
    a += ['--'] + (['--exact'] if exact and name else []) + ['--nocapture', '--test-threads=1']
    return a
PHYS = T('evidence_recovery_bundle', 'schema_marker_history_identity_and_physical_cell_damage_refuse')
BUDG = T('evidence_recovery_bundle', 'acquisition_budgets_have_exact_edges_and_replay_has_separate_limits')
PROBES = T('zz_review_bundle_probes', 'physical_probes')
GENB = T('zz_review_bundle_probes', 'generated_empty_original_probes')
CORPUS = T('evidence_recovery_replay_review_regressions', 'reviewer_probe_corpus')
B = 'src/evidence_store/bundle.rs'; RP = 'src/evidence_recovery_replay.rs'; PS = 'src/persistence.rs'
WRITER = '.map_err(|_| Error::Invalid("candidate writer request"))?;'
M = {
 'A-M01-schema': [(B, 'schema(&conn, &mut work)?;', '// omitted schema gate')], 
 'A-M02-identity': [(B, 'cell(row, 1, 32, 32, false, work)? == context.bundle', 'true || cell(row, 1, 32, 32, false, work)? == context.bundle')],
 'A-M03-canonical-key': [(B, 'value.to_string() == text', 'true || value.to_string() == text')],
 'A-M04-observation-coordinate': [(B, 'integer(row, 0, 1, MAX_SAFE)? == observations.len() as u64 + 1', 'true || integer(row, 0, 1, MAX_SAFE)? == observations.len() as u64 + 1')],
 'A-M05-pinned-snapshot': [(B, 'PRAGMA mmap_size=0; BEGIN;', 'PRAGMA mmap_size=0;')],
 'A-M06-external-checkpoint': [(B, 'replay::verify(input, &candidates, &observations, checkpoint, limits)?', 'replay::verify(input, &candidates, &observations, None, limits)?')],
 'A-M07-wrong-capability': [(B, 'crate::persistence::SurfaceWrite::EvidenceBundleSource,', 'crate::persistence::SurfaceWrite::EvidenceRecoverySource,')],
 'A-M08-no-progress-handler': [(B, 'Some(move || cancel.load(Ordering::Relaxed) || Instant::now() >= deadline),', 'None::<fn() -> bool>,')],
 'A-M09-alias-check': [(B, '!existing.iter().any(|p| same_existing_file(p, &path))', 'true')],
 'A-M10-source-bytes': [(B, 'if source_bytes > work.budget.source_bytes {', 'if false && source_bytes > work.budget.source_bytes {')],
 'A-M11-read-write-open': [(PS, 'rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)', 'rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE)')],
 'A-M12-truncation-guard': [(B, 'require(bytes.len() == len, "cell truncated")?;', 'require(true, "cell truncated")?;')],
 'A-M13-no-query-only': [(B, 'PRAGMA query_only=ON; ', '')],
 'A-M14-typeof-guard': [(B, 'row.get_ref(col)? == ValueRef::Text(if text { b"text" } else { b"blob" })', 'true')],
 'B-M01-candidate-writer': [(RP, WRITER, '.ok();')],
 'B-M02-candidate-hash': [(RP, 'work.hash(c.bytes)? == raw[4..]', 'true || work.hash(c.bytes)? == raw[4..]')],
 'B-M03-candidate-length': [(RP, 'target.length.is_none_or(|n| n == c.bytes.len() as u64)', 'true || target.length.is_none_or(|n| n == c.bytes.len() as u64)')],
 'B-M04-record-length-alone': [(RP, 'key.length = Some(length);', 'key.length = None;')],
 'B-M05-record-length-and-writer': [(RP, 'key.length = Some(length);', 'key.length = None;'), (RP, WRITER, '.ok();')],
 'B-M06-writer-pass-uncharged': [(RP, '(row.manifest.len() + row.receipt.len() + c.bytes.len()) as u64,', '0,')],
}
CMDS = {
 'A-M01-schema': [PHYS], 'A-M02-identity': [PHYS], 'A-M03-canonical-key': [PHYS, PROBES],
 'A-M04-observation-coordinate': [PHYS], 'A-M05-pinned-snapshot': [T(None, 'evidence_store::bundle::snapshot_tests::later_wal_changes_cannot_mix_into_the_pinned_snapshot', lib=True)],
 'A-M06-external-checkpoint': [T('evidence_recovery_bundle', 'foreign_external_pins_and_checkpoint_refuse')],
 'A-M07-wrong-capability': [T('surface_conformance')],
 'A-M08-no-progress-handler': [T('evidence_recovery_bundle'), T(None, 'evidence_store::bundle::snapshot_tests', exact=False, lib=True), PROBES],
 'A-M09-alias-check': [T('evidence_recovery_bundle', 'existing_sqlite_sidecar_symlink_or_hardlink_refuses_before_open')],
 'A-M10-source-bytes': [BUDG], 'A-M11-read-write-open': [T('evidence_recovery_bundle')],
 'A-M12-truncation-guard': [PHYS, PROBES], 'A-M13-no-query-only': [T('evidence_recovery_bundle')], 'A-M14-typeof-guard': [PHYS, PROBES],
 'B-M01-candidate-writer': [CORPUS, T('evidence_recovery_replay_review_regressions', 'writer_invalid_candidate_refuses_without_publication_intent'), T('evidence_recovery_replay_review_regressions', 'valid_writer_signature_with_wrong_manifest_binding_refuses'), GENB],
 'B-M02-candidate-hash': [CORPUS], 'B-M03-candidate-length': [CORPUS], 'B-M04-record-length-alone': [CORPUS],
 'B-M05-record-length-and-writer': [CORPUS], 'B-M06-writer-pass-uncharged': [T('evidence_recovery_replay_review_regressions', 'reviewer_budget_monotonicity_and_bounds'), T('evidence_recovery_replay')],
}
def sha(p): return hashlib.sha256((EXPORT / p).read_bytes()).hexdigest()
def run(name):
    edits = M[name]; files = sorted({f for f, _, _ in edits})
    orig = {f: (EXPORT / f).read_text() for f in files}; before = {f: sha(f) for f in files}
    log = [f'MUTATION {name}', json.dumps(edits)]
    try:
        cur = dict(orig)
        for f, old, new in edits:
            n = cur[f].count(old); assert n == 1, (name, f, n); cur[f] = cur[f].replace(old, new)
        for f in files: (EXPORT / f).write_text(cur[f])
        env = dict(os.environ, KAN_REVIEW_GENERATED=GEN_B)
        for cmd in CMDS[name]:
            r = subprocess.run(cmd, cwd=EXPORT, env=env, capture_output=True, text=True, timeout=3000)
            log += ['$ ' + ' '.join(cmd), r.stdout, r.stderr, f'exit={r.returncode}']
    finally:
        for f in files: (EXPORT / f).write_text(orig[f])
    after = {f: sha(f) for f in files}; ok = after == before
    log.append(f'RESTORED exact={ok} {after}')
    (OUT / f'{name}.txt').write_text('\n'.join(log) + '\n')
    assert ok, name
    print(name, 'restored', ok, flush=True)
if __name__ == '__main__':
    for n in sys.argv[1:]: run(n)
