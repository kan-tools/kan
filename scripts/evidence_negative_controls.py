#!/usr/bin/env python3
"""Exercise P2 regressions by temporarily restoring specific broken behaviors.

Run only in an idle review worktree: source is restored in finally; no git writes.
An interrupted process can leave a source mutation; retain the saved copy printed
at startup and compare git diff before continuing. No live archive is accessed.
"""
import os
from pathlib import Path
import subprocess
import tempfile

if not __debug__:
    raise RuntimeError('negative controls require Python assertions enabled')

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'src/evidence.rs'
TEST = ['cargo', 'test', '--features', 'evidence-contract', '--test', 'evidence_contract']


def run(label):
    result = subprocess.run(TEST, cwd=ROOT, text=True, capture_output=True)
    print(label, result.stdout, result.stderr, flush=True)
    if 'error: could not compile' in result.stderr or 'running 7 tests' not in result.stdout:
        raise RuntimeError('negative control did not execute the regression suite')
    return result.returncode


def main():
    original = SOURCE.read_text()
    directory = ROOT / '.local-state/reviews'
    directory.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix='evidence-before-controls-', suffix='.rs', dir=directory)
    with os.fdopen(fd, 'w') as f:
        f.write(original)
    print('Recovery copy:', name, flush=True)
    a = original.index('    let mut parser = Parser { bytes, offset: 0 };')
    b = original.index('    scalars(&value, 0)?;', a)
    old_decoder = '''    let config = atproto_dasl::drisl::DecodeConfig {
        max_depth: 32, max_alloc: MAX_RECORD_BYTES,
        max_array_elements: MAX_RECORD_BYTES, max_map_entries: MAX_RECORD_BYTES,
        no_floats: true, ..Default::default()
    };
    let value: Ipld = atproto_dasl::drisl::from_slice_with_config(bytes, config)
        .map_err(|e| Error::Canonical(e.to_string()))?;
'''
    author_start = original.index('fn author(value:')
    author_end = original.index('\nfn chain(', author_start)
    old_author = """fn author(value: &Ipld) -> Result<(), Error> {
    let encoded = atproto_dasl::to_vec(value).map_err(|e| Error::Schema(e.to_string()))?;
    let _: Author = atproto_dasl::drisl::from_slice(&encoded).map_err(|e| Error::Schema(e.to_string()))?;
    Ok(())
}
"""
    controls = {
        'old-identity-guessing-decoder': original[:author_start] + old_author + original[author_end:],
        'old-byte-guessing-decoder': original[:a] + old_decoder + original[b:],
        'no-decode-scalar-validation': original.replace('    scalars(&value, 0)?;', '', 1),
        'no-writer-or-issuer-validation': original.replace('    author(&b["writer"])?;', '').replace('    author(&b["issuer"])?;', ''),
        'no-byte-size-bound': original.replace('if bytes.len() > MAX_RECORD_BYTES {', 'if false {', 1),
    }
    try:
        assert run('fixed baseline') == 0
        for label, changed in controls.items():
            assert changed != original, label
            SOURCE.write_text(changed)
            assert run(label) != 0, 'SURVIVED: ' + label
            print('DEMONSTRATED:', label, flush=True)
    finally:
        SOURCE.write_text(original)
    assert run('restored fix') == 0
    print('All five negative controls failed as expected; restored fix passes.')


if __name__ == '__main__':
    main()
