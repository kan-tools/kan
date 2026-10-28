#!/usr/bin/env python3
"""Scope B whole-production-file reversion: replace ONLY src/evidence_recovery_replay.rs
with the explicit Git blob at 7a04798, run the two named writer-refusal regressions,
restore exactly (SHA-256 verified), and re-run them."""
import hashlib, subprocess, sys
from pathlib import Path
EXPORT = Path(__file__).resolve().parents[2]
F = EXPORT / 'src/evidence_recovery_replay.rs'
BLOB = EXPORT / 'review-evidence/mutations/replay-7a04798.rs.blob'
OUT = EXPORT / 'review-evidence/mutations'
TESTS = ['writer_invalid_candidate_refuses_without_publication_intent', 'valid_writer_signature_with_wrong_manifest_binding_refuses']
def sha(b): return hashlib.sha256(b).hexdigest()
def run(tag):
    log = []
    for t in TESTS:
        cmd = ['cargo', 'test', '--features', 'v2-crypto', '--test', 'evidence_recovery_replay_review_regressions', t, '--', '--exact', '--nocapture']
        r = subprocess.run(cmd, cwd=EXPORT, capture_output=True, text=True, timeout=3000)
        log += ['$ ' + ' '.join(cmd), r.stdout, r.stderr, f'exit={r.returncode}']
    (OUT / f'B-whole-reversion-{tag}.txt').write_text('\n'.join(log) + '\n')
original = F.read_bytes(); before = sha(original)
blob = BLOB.read_bytes()
assert sha(blob) == '4d7b5037aefd4a2ac7895d23cb974d487b676681374936fb3516bcae996f42ac'
assert before == 'b5cbabc6659d46db0734e9144c77b379e6d4cac04562c9d0323e312ebbc56c08'
try:
    F.write_bytes(blob); run('reverted')
finally:
    F.write_bytes(original)
after = sha(F.read_bytes()); print('restored exact', after == before, after); assert after == before
run('restored')
