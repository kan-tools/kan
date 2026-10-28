#!/usr/bin/env python3
"""Reviewer mutation driver for a95f28f (adapted from the retained author
followups/mutations.py). Usage: mutations.py ROOT OUTDIR. Applies one mutation
at a time, runs the named test(s), byte-restores and re-hashes the file."""
import hashlib, re, subprocess, sys
from pathlib import Path

ROOT = Path(sys.argv[1]).resolve()
OUT = Path(sys.argv[2]).resolve()
OUT.mkdir(parents=True, exist_ok=True)
CARGO = str(ROOT / 'review-evidence/cargo.sh')
L, R, APP = 'src/evidence_library.rs', 'src/evidence_reader.rs', 'web/library/app.js'
C = 'catalog_verification_failure_is_not_an_empty_authorized_inventory'
H = 'catalog_keeps_healthy_scopes_and_recovers_without_disclosing_failed_sources'
T13 = 'library_refuses_thirteenth_socket_at_the_live_admission_boundary'
T5 = 'library_queues_a_browser_request_behind_four_idle_connections'
STYLE = 'malformed retry clears partially rendered capabilities and keeps recovery available'
old24 = '''let connection = async {
            let Ok(Ok(_request)) = tokio::time::timeout(
                Duration::from_secs(6),
                self.requests.clone().acquire_owned(),
            )
            .await
            else {
                return;
            };
            work.await;
        };
        let _ = tokio::time::timeout(Duration::from_secs(35), connection).await;'''
new24 = '''let Ok(Ok(_request)) = tokio::time::timeout(
                Duration::from_secs(6),
                self.requests.clone().acquire_owned(),
            )
            .await
            else {
                return;
            };
        let _ = tokio::time::timeout(Duration::from_secs(35), work).await;'''
serve = 'let budget = ConnectionBudget::new();\n    let mut tasks'
def serve_sockets(n):
    return ('let budget = ConnectionBudget { sockets: Arc::new(Semaphore::new(%d)), '
            'requests: Arc::new(Semaphore::new(4)) };\n    let mut tasks' % n)

# (label, file, old, new, runner, [test names], expectation)
cases = [
    ('R03', L, 'Err(Failure::AccessLimited) => {}', 'Err(Failure::AccessLimited) => partial = true,', 'evidence_reader', [C], 'kill'),
    ('R08', L, '"coverage":if partial {"partial"} else {"complete"},',
     '"coverage":if partial {"partial"} else {"complete"},"failed":configured.len()-scopes.len(),', 'evidence_reader', [C, H], 'kill'),
    ('R12', R, '.map_err(|_| Failure::Unavailable)?\n        .map_err(|failure|',
     '.map_err(|_| Failure::AccessLimited)?\n        .map_err(|failure|', 'evidence_reader', [C], 'kill'),
    ('R24', L, old24, new24, 'lib', ['evidence_library::budget_tests::whole_connection_deadline_includes_time_spent_queued'], 'kill'),
    ('R31', L, serve, serve_sockets(4096), 'evidence_reader', [T13], 'kill'),
    ('STYLE', APP, " $('catalog-status').className = ''; }", ' }', 'node', [STYLE], 'kill'),
    # Reviewer fidelity probes: does the live boundary test pin that twelve are admitted?
    ('F05-serve-sockets-5', L, serve, serve_sockets(5), 'evidence_reader', [T13, T5], 'probe'),
    ('F11-serve-sockets-11', L, serve, serve_sockets(11), 'evidence_reader', [T13, T5], 'probe'),
]
only = set(sys.argv[3:])
summary = []
for label, file, old, new, runner, names, expect in cases:
    if only and label not in only:
        continue
    p = ROOT / file
    original = p.read_bytes()
    before = hashlib.sha256(original).hexdigest()
    text = original.decode()
    assert text.count(old) == 1, (label, text.count(old))
    log = [f'{file}\nsha256-before={before}\nOLD:\n{old}\nNEW:\n{new}\n']
    results = {}
    try:
        p.write_text(text.replace(old, new))
        for name in names:
            if runner == 'node':
                cmd = ['node', '--test', '--test-name-pattern=^' + re.escape(name) + '$', 'tests/library_ui.test.cjs']
            else:
                cmd = [CARGO, 'test', '--features', 'v2-crypto'] + (['--lib'] if runner == 'lib' else ['--test', runner]) + [name, '--', '--exact']
            r = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, timeout=600)
            out = r.stdout + r.stderr
            log.append(f'$ {cmd}\nexit={r.returncode}\n{out}\n')
            compile_err = 'could not compile' in out or re.search(r'^error\[E', out, re.M)
            if runner == 'node':
                failed = re.search(r'^not ok \d+ - ' + re.escape(name), out, re.M) or re.search(r'✖ ' + re.escape(name), out)
                passed = r.returncode == 0 and re.search(r'ℹ pass 1', out)
                assertion = 'AssertionError' in out or 'ERR_ASSERTION' in out
            else:
                failed = re.search(r'^test ' + re.escape(name) + r' \.\.\. FAILED$', out, re.M)
                passed = re.search(r'^test ' + re.escape(name) + r' \.\.\. ok$', out, re.M)
                assertion = 'panicked at' in out
            if compile_err:
                results[name] = 'COMPILE-ERROR'
            elif failed and assertion:
                results[name] = 'KILLED(named assertion)'
            elif passed:
                results[name] = 'SURVIVED(passed)'
            else:
                results[name] = f'UNCLEAR(exit={r.returncode})'
    finally:
        p.write_bytes(original)
    after = hashlib.sha256(p.read_bytes()).hexdigest()
    assert after == before, (label, 'restore mismatch')
    log.append(f'sha256-after-restore={after} match={after == before}\n')
    line = f'{label} [{expect}] ' + '; '.join(f'{n}: {v}' for n, v in results.items()) + f' | restored={after == before}'
    log.append(line + '\n')
    (OUT / f'{label}.txt').write_text(''.join(log))
    print(line, flush=True)
    summary.append(line)
(OUT / ('SUMMARY-' + ('-'.join(sorted(only)) if only else 'all') + '.txt')).write_text('\n'.join(summary) + '\n')
