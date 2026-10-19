#!/usr/bin/env python3
"""Exercise the independent abort-aware UI probes; restore source in finally."""
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / 'web/operations/app.js'
OUT = ROOT / '.local-state/reviews/operations-ui-controls'


def main():
    if not __debug__:
        raise RuntimeError('assertions required')
    OUT.mkdir(parents=True, exist_ok=True)
    original = APP.read_text()
    cases = [
        ('restart-cache-collision', "s.last_job+':'+JSON.stringify(v)",
         "s.last_job+':'+v.manifest_sha256", 'UPb:'),
        ('aborted-poll-clears-action',
         'finally{clearTimeout(timeout);if(current===generation&&serial===overviewSerial){',
         'finally{clearTimeout(timeout);if(current===generation){', 'UPi:'),
        ('aborted-poll-repaints-error',
         'catch(e){if(current===generation&&serial===overviewSerial){',
         'catch(e){if(current===generation){', 'UPa:'),
    ]
    try:
        for name, before, after, test in cases:
            assert original.count(before) == 1, name + ' anchor is not unique'
            APP.write_text(original.replace(before, after))
            run = subprocess.run(
                ['node', '--test', '--test-name-pattern=' + test,
                 'tests/operations_review_ui.test.cjs'],
                cwd=ROOT, capture_output=True, text=True)
            log = run.stdout + run.stderr
            (OUT / (name + '.txt')).write_text(log)
            assert run.returncode != 0, name + ' SURVIVED'
            assert 'AssertionError' in log and test in log, name + ' no assertion'
            print('DEMONSTRATED:', name, flush=True)
            APP.write_text(original)
    finally:
        APP.write_text(original)
    run = subprocess.run(
        ['node', '--test', 'tests/operations_ui.test.cjs',
         'tests/operations_review_ui.test.cjs'],
        cwd=ROOT, capture_output=True, text=True)
    (OUT / 'restored.txt').write_text(run.stdout + run.stderr)
    assert run.returncode == 0, 'restored baseline failed'
    print('Three UI mutants fail assertions; restored 36 checks pass.', flush=True)


if __name__ == '__main__':
    main()
