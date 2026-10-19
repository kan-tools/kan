#!/usr/bin/env python3
"""Independent JS mutation run over web/operations/app.js.
Usage: python3 -I review-evidence/probes/mutate.py <export_root> <identity_manifest>
Each mutant: unique-anchor replace, run each suite separately, restore, re-hash.
Restores in finally. Writes raw logs to review-evidence/results/mutants/."""
import hashlib, json, os, subprocess, sys
root, manifest = sys.argv[1], sys.argv[2]
APP = os.path.join(root, 'web/operations/app.js')
OUT = os.path.join(root, 'review-evidence/results/mutants')
WANT = json.load(open(manifest))['files']['web/operations/app.js']
SUITES = {
    'author': 'tests/operations_ui.test.cjs',
    'imported': 'tests/operations_review_ui.test.cjs',
    'review': 'review-evidence/probes/restart_review_probes.test.cjs',
}
K = "s.last_job+':'+JSON.stringify(v)"
FIN = 'finally{clearTimeout(timeout);if(current===generation&&serial===overviewSerial){'
CAT = 'catch(e){if(current===generation&&serial===overviewSerial){'
OK = 'if(current===generation&&serial===overviewSerial)renderOverview(s);'
MUTANTS = [
    # restart key family
    ('K0-revert-to-manifest-key', K, "s.last_job+':'+v.manifest_sha256"),
    ('K1-key-built_at-only', K, "s.last_job+':'+v.built_at"),
    ('K2-key-totals-only', K, "s.last_job+':'+JSON.stringify(v.totals)"),
    ('K3-key-built_at+totals', K, "s.last_job+':'+v.built_at+JSON.stringify(v.totals)"),
    ('K4-key-all-but-sources', K, "s.last_job+':'+JSON.stringify({...v,sources:0})"),
    ('K5-key-drop-last_job[equiv?]', K, 'JSON.stringify(v)'),
    ('K6-no-early-return', 'if(key===overviewKey)return;overviewKey=key;', 'overviewKey=key;'),
    ('K7-null-last-keeps-key', "if(!s.last){overviewKey='';", 'if(!s.last){'),
    ('K8-clearOverview-keeps-key', "overviewEnabled=false;overviewKey='';", 'overviewEnabled=false;'),
    # abort / serialization family
    ('A0-finally-drop-serial(author)', FIN, 'finally{clearTimeout(timeout);if(current===generation){'),
    ('A1-catch-drop-serial(author)', CAT, 'catch(e){if(current===generation){'),
    ('A2-timeout-label-lost', "overviewError=e.name==='AbortError'?'Overview request timed out.':e.message;", 'overviewError=e.message;'),
    ('A3-preempt-no-abort', '\n  overviewRequest.controller.abort();\n', '\n'),
    ('A4-lock-no-abort', 'function clearOverview(){if(overviewRequest)overviewRequest.controller.abort();', 'function clearOverview(){'),
    ('A5-lock-keeps-queued', "overviewSerial++;overviewQueued='';", 'overviewSerial++;'),
    ('A6-no-preemption', 'if(overviewRequest.action){overviewQueued=action;', 'if(true){overviewQueued=action;'),
    ('A7-catch-drop-generation[equiv?]', CAT, 'catch(e){if(serial===overviewSerial){'),
    ('A8-finally-drop-generation[equiv?]', FIN, 'finally{clearTimeout(timeout);if(serial===overviewSerial){'),
    ('A9-success-drop-generation[equiv?]', OK, 'if(serial===overviewSerial)renderOverview(s);'),
    ('A10-success-drop-serial', OK, 'if(current===generation)renderOverview(s);'),
    ('A11-queued-never-dispatched', 'if(queued)loadOverview(queued);', ''),
    ('A12-no-clearTimeout[equiv?]', FIN, 'finally{if(current===generation&&serial===overviewSerial){'),
    ('A13-finally-keeps-queued', "const queued=overviewQueued;overviewQueued='';", 'const queued=overviewQueued;'),
]

def sha(p):
    return hashlib.sha256(open(p, 'rb').read()).hexdigest()

def run(suite):
    try:
        r = subprocess.run(['node', '--test', SUITES[suite]], cwd=root, capture_output=True, text=True, timeout=30)
    except subprocess.TimeoutExpired as e:  # child is killed by subprocess.run
        out = (e.stdout or b'').decode() if isinstance(e.stdout, bytes) else (e.stdout or '')
        return 'TIMEOUT', out + '\n[review] suite did not finish in 30 s (hang counts as non-passing)\n'
    return r.returncode, r.stdout + r.stderr

def main():
    os.makedirs(OUT, exist_ok=True)
    original = open(APP, 'rb').read()
    assert hashlib.sha256(original).hexdigest() == WANT, 'app.js not at manifest identity before mutation'
    text = original.decode()
    table = []
    try:
        only = sys.argv[3:]
        for name, before, after in MUTANTS:
            if only and not any(name.startswith(o) for o in only):
                continue
            n = text.count(before)
            assert n == 1, f'{name}: anchor count {n}'
            open(APP, 'w').write(text.replace(before, after))
            row = {'mutant': name}
            log = [f'# mutant {name}\n# before: {before!r}\n# after:  {after!r}\n']
            for suite in SUITES:
                code, out = run(suite)
                failed = [l.strip()[2:].rsplit(' (', 1)[0] for l in out.splitlines() if l.startswith('✖ ') and 'failing tests' not in l]
                failed = sorted(set(failed))
                row[suite] = 'KILLED(hang)' if code == 'TIMEOUT' else 'KILLED' if code != 0 else 'survived'
                row[suite + '_failed'] = failed
                log.append(f'\n## suite {suite} exit={code}\n{out}')
            open(os.path.join(OUT, name.replace('/', '_') + '.txt'), 'w').write(''.join(log))
            open(APP, 'wb').write(original)
            assert sha(APP) == WANT, f'restore failed after {name}'
            table.append(row)
            print(f"{name:40s} author={row['author']:8s} imported={row['imported']:8s} review={row['review']:8s}", flush=True)
            for s in SUITES:
                for t in row[s + '_failed']:
                    print(f'    {s}: {t}', flush=True)
    finally:
        open(APP, 'wb').write(original)
    assert sha(APP) == WANT
    json.dump(table, open(os.path.join(OUT, 'summary' + ('-' + '-'.join(sys.argv[3:]) if sys.argv[3:] else '') + '.json'), 'w'), indent=1)
    print('app.js restored; sha256 matches manifest:', sha(APP) == WANT)

if __name__ == '__main__':
    main()
