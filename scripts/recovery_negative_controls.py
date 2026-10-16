#!/usr/bin/env python3
"""Causal recovery probes; run only in an idle worktree. Restores source in finally.

An abrupt kill can leave a mutation: retain the recovery copy printed at startup.
Only synthetic tests run. No user archive is opened. Each mutant must compile,
execute its named regression, and fail; restoring the fix must pass.
"""
import os
from pathlib import Path
import subprocess
import tempfile

if not __debug__:
    raise RuntimeError('negative controls require assertions enabled')

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'src/evidence_store.rs'


def run(suite, test):
    result = subprocess.run(['cargo', 'test', '--features', 'v2-storage', '--test', suite,
                             test, '--', '--exact'], cwd=ROOT, capture_output=True, text=True)
    print(result.stdout, result.stderr, flush=True)
    if 'running 1 test' not in result.stdout or 'could not compile' in result.stderr:
        raise RuntimeError('probe did not execute its named test')
    return result.returncode


def main():
    original = SOURCE.read_text()
    directory = ROOT / '.local-state/reviews'
    directory.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix='recovery-before-controls-', suffix='.rs', dir=directory)
    with os.fdopen(fd, 'w') as f:
        f.write(original)
    print('Recovery copy:', name, flush=True)
    cases = [
        ('derived-data-gates-raw-access', original.replace('ledger.check_schema()?;',
         'ledger.check_schema()?; ledger.verify_contents()?;', 1),
         'evidence_store', 'recovery_ignores_derived_damage_and_preserves_exact_evidence'),
        ('unpinned-source', original.replace('PRAGMA query_only=ON; BEGIN;', 'PRAGMA query_only=ON;'),
         'evidence_store', 'recovery_snapshot_is_pinned_before_concurrent_appends'),
        ('early-profile-publication', original.replace('tx.execute_batch(SCHEMA)?;',
         'tx.execute_batch(SCHEMA)?; tx.commit()?; let tx = target.conn.unchecked_transaction()?;', 1),
         'evidence_store', 'recovery_rejects_raw_damage_without_hiding_intact_records'),
        ('wrong-mutation-capability', original.replace('SurfaceWrite::EvidenceRecovery', 'SurfaceWrite::EvidenceBackup'),
         'surface_conformance', 'every_persistence_facade_call_is_independently_inventoried'),
    ]
    try:
        for label, changed, suite, test in cases:
            SOURCE.write_text(original)
            assert run(suite, test) == 0, 'fixed baseline: ' + label
            assert changed != original
            SOURCE.write_text(changed)
            assert run(suite, test) != 0, 'SURVIVED: ' + label
            print('DEMONSTRATED:', label, flush=True)
    finally:
        SOURCE.write_text(original)
    for _, _, suite, test in cases:
        assert run(suite, test) == 0, 'restored fix'
    print('All four controls fail; restored fixes pass.')


if __name__ == '__main__':
    main()
