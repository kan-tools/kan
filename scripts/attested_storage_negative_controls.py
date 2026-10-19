#!/usr/bin/env python3
"""Compiled causal probes for profile-2 storage. Run only in an idle worktree.

Uses the caller's existing Cargo cache. Saves a source recovery copy under
.local-state, restores in finally, and distinguishes assertion failure from
compile/setup failure. No production archive is opened.
"""
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
STORE = ROOT / 'src/evidence_store/attested.rs'
CODEC = ROOT / 'src/evidence_attestation.rs'
OUT = ROOT / '.local-state/reviews/storage-controls'


def run(suite, test):
    return subprocess.run(['cargo', 'test', '--features', 'v2-crypto', '--test', suite,
                           test, '--', '--exact'], cwd=ROOT, capture_output=True, text=True)


def main():
    if not __debug__:
        raise RuntimeError('assertions required')
    OUT.mkdir(parents=True, exist_ok=True)
    originals = {STORE: STORE.read_text(), CODEC: CODEC.read_text()}
    for path, source in originals.items():
        (OUT / (path.name + '.original')).write_text(source)
    s = originals[STORE]
    omit = re.sub(r'                crate::persistence::insert_evidence_proof\(.*?\n                \)\?;',
                  '                let _ = tx;', s, count=1, flags=re.S)
    cases = [
        ('omit-proof-insert', STORE, omit, 'evidence_attested_store',
         'atomic_admission_retry_and_legacy_refusal'),
        ('retry-mints-proof', STORE, s.replace('                old.clone()',
         '                proof::issue(signer, &binding.context(), &row.manifest, &row.receipt, old.previous(), Purpose::Admitted, now * 1000)?'),
         'evidence_attested_store', 'atomic_admission_retry_and_legacy_refusal'),
        ('omit-proof-frontier-fence', STORE, s.replace('if previous.through > 0 {',
         'if false && previous.through > 0 {'), 'evidence_attested_store',
         'same_height_proof_fork_between_audit_and_commit_is_rejected'),
        ('omit-purpose-order', STORE, s.replace('if admitted\n', 'if false && admitted\n'),
         'evidence_attested_store', 'purpose_order_is_a_store_invariant_not_just_a_signature_check'),
        ('wrong-proof-capability', STORE, s.replace('SurfaceWrite::EvidenceAttestation,',
         'SurfaceWrite::EvidenceArchive,'), 'surface_conformance',
         'every_persistence_facade_call_is_independently_inventoried'),
        ('omit-short-did-guard', CODEC, originals[CODEC].replace('!(56..=80).contains(&did.len()) || ', ''),
         'evidence_attestation', 'short_issuer_never_reaches_dependency_panic'),
    ]
    try:
        for name, path, changed, suite, test in cases:
            assert changed != originals[path], f'inactive mutation: {name}'
            path.write_text(changed)
            result = run(suite, test)
            (OUT / (name + '.txt')).write_text(result.stdout + result.stderr)
            assert result.returncode != 0, f'SURVIVED: {name}'
            assert 'could not compile' not in result.stderr, f'compile failure: {name}'
            assert 'running 1 test' in result.stdout and f'test {test} ... FAILED' in result.stdout, f'no named failure: {name}'
            print('DEMONSTRATED:', name, flush=True)
            path.write_text(originals[path])
    finally:
        for path, source in originals.items():
            path.write_text(source)
    suites = ['evidence_attested_store', 'evidence_attestation', 'surface_conformance']
    args = ['cargo', 'test', '--features', 'v2-crypto']
    for suite in suites:
        args += ['--test', suite]
    result = subprocess.run(args, cwd=ROOT, capture_output=True, text=True)
    (OUT / 'restored.txt').write_text(result.stdout + result.stderr)
    assert result.returncode == 0, 'restored baseline failed'
    print('Six compiled mutants fail; restored storage, codec and surface checks pass.', flush=True)


if __name__ == '__main__':
    main()
