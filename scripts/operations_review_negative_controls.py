#!/usr/bin/env python3
"""Exercise the independent abort-aware UI probes; restore source in finally."""
from pathlib import Path
import subprocess
import os
import signal

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / 'web/operations/app.js'
OUT = ROOT / '.local-state/reviews/operations-ui-controls'


def run_bounded(command, name, timeout_seconds=60):
    process = subprocess.Popen(command, cwd=ROOT, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, text=True, start_new_session=True)
    try:
        out, err = process.communicate(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        out, err = process.communicate()
        (OUT / (name + '.timeout.txt')).write_text(out + err)
        raise RuntimeError(name + ' timed out; process group stopped; not a demonstrated assertion')
    return subprocess.CompletedProcess(command, process.returncode, out, err)


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
        ('partial-time-key', "s.last_job+':'+JSON.stringify(v)",
         "s.last_job+':'+v.built_at", 'RP2:'),
        ('omit-source-rows', 'JSON.stringify(v)',
         'JSON.stringify({...v,sources:[]})', 'RP1:'),
        ('partial-time-and-totals-key', "s.last_job+':'+JSON.stringify(v)",
         "s.last_job+':'+v.built_at+':'+JSON.stringify(v.totals)", 'RP3:'),
        ('null-keeps-key', "if(!s.last){overviewKey='';",
         'if(!s.last){', 'RP5:'),
        ('lock-keeps-key', "overviewEnabled=false;overviewKey='';",
         'overviewEnabled=false;', 'RP4:'),
        ('timeout-label-lost', "'Overview request timed out.'",
         "'Overview unavailable.'", 'RP6:'),
        ('cross-session-queued-action', "overviewSerial++;overviewQueued='';",
         'overviewSerial++;', 'RP7:'),
        ('queued-action-repeats', "const queued=overviewQueued;overviewQueued='';if(queued)",
         'const queued=overviewQueued;if(queued)', 'RP13:'),
    ]
    try:
        for name, before, after, test in cases:
            assert original.count(before) == 1, name + ' anchor is not unique'
            APP.write_text(original.replace(before, after))
            suite = 'tests/operations_restart_review.test.cjs' if test.startswith('RP') else 'tests/operations_review_ui.test.cjs'
            run = run_bounded(
                ['node', '--test', '--test-name-pattern=' + test,
                 suite], name)
            log = run.stdout + run.stderr
            (OUT / (name + '.txt')).write_text(log)
            assert run.returncode != 0, name + ' SURVIVED'
            assert 'AssertionError' in log and test in log, name + ' no assertion'
            print('DEMONSTRATED:', name, flush=True)
            APP.write_text(original)
    finally:
        APP.write_text(original)
    run = run_bounded(
        ['node', '--test', 'tests/operations_ui.test.cjs',
         'tests/operations_review_ui.test.cjs', 'tests/operations_restart_review.test.cjs'],
        'restored')
    (OUT / 'restored.txt').write_text(run.stdout + run.stderr)
    assert run.returncode == 0, 'restored baseline failed'
    print(f'{len(cases)} UI mutants fail assertions; restored 49 checks pass.', flush=True)


if __name__ == '__main__':
    main()
