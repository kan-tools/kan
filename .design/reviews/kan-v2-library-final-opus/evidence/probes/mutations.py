#!/usr/bin/env python3
"""(rev2: compile-error regex fixed; all panic messages kept)
Reviewer mutation driver for 8124878 vs a95f28f.
Usage: mutations.py ROOT OUTDIR [LABEL...]
Applies one textual mutation at a time (exactly-one-match anchor), runs the
named test(s) REPEATS times, classifies each run (named-assertion kill /
compile error / survived), byte-restores and re-hashes the file.
PARENT_P4 runs the a95f28f P4 verbatim (tests/zz_review_parent_contention.rs,
copied from `git show a95f28f:tests/evidence_capture_contention.rs`)."""
import hashlib, re, subprocess, sys
from pathlib import Path

ROOT = Path(sys.argv[1]).resolve()
OUT = Path(sys.argv[2]).resolve()
OUT.mkdir(parents=True, exist_ok=True)
CARGO = str(ROOT / 'review-evidence/cargo.sh')
C = 'tests/evidence_capture_contention.rs'
L = 'src/evidence_library.rs'
S = 'src/evidence_spool.rs'
P4 = ('evidence_capture_contention', 'p4_capture_beside_brief_periodic_writer')
PARENT_P4 = ('zz_review_parent_contention', 'p4_capture_beside_brief_periodic_writer')
Q2 = ('evidence_capture_contention', 'q2_per_observation_cap_and_allowance')
T13 = ('evidence_reader', 'library_refuses_thirteenth_socket_at_the_live_admission_boundary')
T5 = ('evidence_reader', 'library_queues_a_browser_request_behind_four_idle_connections')

serve = 'let budget = ConnectionBudget::new();\n    let mut tasks'
def serve_sockets(n):
    return ('let budget = ConnectionBudget { sockets: Arc::new(Semaphore::new(%d)), '
            'requests: Arc::new(Semaphore::new(4)) };\n    let mut tasks' % n)

first_lock_old = '''        c.execute_batch("BEGIN IMMEDIATE").unwrap();
        let first_start = Instant::now();
        locked.send(()).unwrap();
        std::thread::sleep(Duration::from_millis(5));
        c.execute_batch("ROLLBACK").unwrap();
        let first_end = Instant::now();'''

cases = [
    # --- Can the first-window coordination be removed while P4 still passes?
    ('T1-window-not-installed', C,
     'Some(FirstCaptureWindow {\n            request,\n            locked: lock_ready,\n        }),',
     'None,', [P4], 3, 'kill'),
    ('T2-admit_with_wait-skips-window', C,
     '        self.first_window();\n        self.inner.admit_with_wait(operation, frame, wait)',
     '        self.inner.admit_with_wait(operation, frame, wait)', [P4], 3, 'kill'),
    ('T3-both-methods-skip-window', C,
     '    fn first_window(&mut self) {\n        if let Some(first) = self.first.take() {',
     '    fn first_window(&mut self) {\n        if let Some(first) = None::<FirstCaptureWindow> {', [P4], 3, 'kill'),
    ('T4-ack-before-lock', C, first_lock_old,
     first_lock_old.replace('        locked.send(()).unwrap();\n', '')
                   .replace('        c.execute_batch("BEGIN IMMEDIATE").unwrap();\n',
                            '        locked.send(()).unwrap();\n        c.execute_batch("BEGIN IMMEDIATE").unwrap();\n'),
     [P4], 5, 'probe'),
    ('T5-first-window-holds-no-lock', C, first_lock_old,
     first_lock_old.replace('        c.execute_batch("BEGIN IMMEDIATE").unwrap();\n', '')
                   .replace('        c.execute_batch("ROLLBACK").unwrap();\n', ''),
     [P4], 3, 'probe'),
    ('T6-no-wait-for-ack', C,
     '''            first
                .locked
                .recv_timeout(Duration::from_secs(5))
                .expect("synthetic writer must establish first contention window");''',
     '            drop(first.locked);', [P4], 3, 'kill'),
    ('T7-wrapper-discards-spent', C,
     '        self.inner.admit_with_wait(operation, frame, wait)\n    }',
     '        (self.inner.admit_with_wait(operation, frame, wait).0, Duration::ZERO)\n    }',
     [P4], 3, 'probe'),
    # --- Does the coordinated window expose (not hide) capture-wait defects?
    ('P1-capture-never-waits', S, 'if wait.remaining.is_zero() {', 'if true {',
     [P4, PARENT_P4, Q2], 10, 'kill'),
    ('P2-capture-wait-1ms', S, 'remaining: wait.min(Duration::from_millis(100)),',
     'remaining: wait.min(Duration::from_millis(1)),', [P4, PARENT_P4, Q2], 10, 'kill'),
    # --- Live socket admission bounds.
    ('S05-serve-sockets-5', L, serve, serve_sockets(5), [T13, T5], 3, 'kill'),
    ('S11-serve-sockets-11', L, serve, serve_sockets(11), [T13, T5], 3, 'kill'),
    ('S4096-serve-sockets-4096', L, serve, serve_sockets(4096), [T13, T5], 3, 'kill'),
]

only = set(sys.argv[3:])
summary = []
for label, file, old, new, tests, repeats, expect in cases:
    if only and label not in only:
        continue
    p = ROOT / file
    original = p.read_bytes()
    before = hashlib.sha256(original).hexdigest()
    text = original.decode()
    assert text.count(old) == 1, (label, text.count(old))
    log = [f'{label}\n{file}\nsha256-before={before}\nOLD:\n{old}\nNEW:\n{new}\n']
    results = {}
    try:
        p.write_text(text.replace(old, new))
        for target, name in tests:
            tally = {}
            for i in range(repeats):
                cmd = [CARGO, 'test', '--features', 'v2-crypto', '--test', target, name,
                       '--', '--exact', '--nocapture']
                r = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, timeout=900)
                out = r.stdout + r.stderr
                log.append(f'$ {" ".join(cmd)}  [run {i + 1}/{repeats}]\nexit={r.returncode}\n{out}\n')
                if 'could not compile' in out or re.search(r'^error\[E\d+\]', out, re.M):
                    v = 'COMPILE-ERROR'
                elif re.search(r'^test ' + re.escape(name) + r' \.\.\. FAILED$', out, re.M):
                    ms = re.findall(r"panicked at ([^\n]+)\n([^\n]*)", out)
                    v = 'KILLED: ' + (' | '.join(f'{a} {b}'.strip() for a, b in ms) if ms else '?')
                    v = re.sub(r'\(\d+\) ', '', v)
                    v = re.sub(r'(left|right): \d+', r'\1: N', v)
                elif re.search(r'^test ' + re.escape(name) + r' \.\.\. ok$', out, re.M):
                    v = 'SURVIVED(passed)'
                else:
                    v = f'UNCLEAR(exit={r.returncode})'
                tally[v] = tally.get(v, 0) + 1
            results[f'{target}::{name}'] = tally
    finally:
        p.write_bytes(original)
    after = hashlib.sha256(p.read_bytes()).hexdigest()
    assert after == before, (label, 'restore mismatch')
    lines = [f'{label} [{expect}] restored={after == before}']
    for t, tally in results.items():
        lines.append(f'  {t}: ' + '; '.join(f'{v} x{n}' for v, n in tally.items()))
    block = '\n'.join(lines)
    log.append(f'sha256-after-restore={after}\n{block}\n')
    (OUT / f'{label}.txt').write_text(''.join(log))
    print(block, flush=True)
    summary.append(block)
(OUT / ('SUMMARY-' + ('-'.join(sorted(only)) if only else 'all') + '.txt')).write_text('\n'.join(summary) + '\n')
