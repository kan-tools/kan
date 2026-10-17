#!/usr/bin/env python3
"""Causal storage lifecycle probes; run only in an idle worktree. Restores source in finally.

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
    fd, name = tempfile.mkstemp(prefix='lifecycle-before-controls-', suffix='.rs', dir=directory)
    with os.fdopen(fd, 'w') as f:
        f.write(original)
    print('Recovery copy:', name, flush=True)
    cases = [
        ('no-initialization-resume', original.replace('Self::initialize_empty(root, &path, &mut |_| {})',
         'Self::open(root)'), 'evidence_store',
         'initialization_resumes_each_publication_boundary_without_resetting_evidence'),
        ('adopt-foreign-version', original.replace('if app != 0 || version != 0 || tables != 0 {',
         'if app == -1 || version == -1 || tables == -1 {'), 'evidence_store',
         'initialization_rejects_foreign_media_without_replacing_it'),
        ('no-backup-namespace-guard', original.replace('let destination = sqlite_destination(&source, destination)?;',
         'let destination = destination.to_path_buf(); let _ = source;'), 'evidence_store',
         'lifecycle_destinations_preserve_existing_sqlite_namespaces'),
        ('wrong-backup-capability', original.replace('SurfaceWrite::EvidenceBackup,',
         'SurfaceWrite::EvidenceArchive,'), 'surface_conformance',
         'every_persistence_facade_call_is_independently_inventoried'),
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
    print(f'All {len(cases)} controls fail; restored fixes pass.')


if __name__ == '__main__':
    main()
