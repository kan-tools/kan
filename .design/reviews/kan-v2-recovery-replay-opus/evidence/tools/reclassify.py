#!/usr/bin/env python3
"""Re-read every RM*.txt mutation log and separate author-suite vs reviewer-probe
evidence (the driver's first-pass tags missed probe failures interleaved by
--nocapture). Writes review-evidence/mutations/RECLASSIFIED.txt."""
import re
from pathlib import Path

D = Path(__file__).resolve().parents[1] / 'mutations'
rows = []
for p in sorted(D.glob('RM*.txt')):
    log = p.read_text()
    name = p.stem
    if 'could not compile' in log:
        rows.append(f'{name}: COMPILE-FAILURE (no evidence)'); continue
    author_fail = re.findall(r'thread \'(\w+)\' \(\d+\) panicked at tests/evidence_recovery_replay\.rs:(\d+)', log)
    author_accept = 'hostile history must refuse' in log or bool(re.search(r'tests/evidence_recovery_replay\.rs:\d+:\d+:\nassertion `left == right` failed\n  left: None', log))
    labels = re.findall(r'tests/evidence_recovery_replay\.rs:170:13:\nassertion `left == right` failed: "([^"]+)"\n  left: "([^"]+)"\n right: "([^"]+)"', log)
    other_author = re.findall(r'panicked at tests/evidence_recovery_replay\.rs:(\d+):\d+:\n(.*)\n?(.*)', log)
    probe = re.findall(r'PROBE (\S+) class=(ACCEPTED_HOSTILE|PROJECTION_MISMATCH|REFUSED_POSITIVE|DIAG)', log)
    ckpt = [l for l in re.findall(r'CHECKPOINT ([\w-]+): (ACCEPT[^\n]*)', log) if l[0] != 'tip-exact']
    budget_fail = 'reviewer_budget_monotonicity_and_bounds\' ' in log and 'panicked at tests/zz_review_replay_probe.rs' in log
    if author_accept:
        a = 'AUTHOR:KILLED-ACCEPTANCE'
    elif labels:
        a = 'AUTHOR:DIAGNOSTIC-ONLY ' + '; '.join(f'{n}: {l} (want {r})' for n, l, r in labels)
    elif other_author:
        a = 'AUTHOR:FAILED ' + ' | '.join(f':{ln} {x.strip()} {y.strip()}' for ln, x, y in other_author)
    else:
        a = 'AUTHOR:SURVIVED'
    r = []
    if probe: r.append('PROBE ' + ', '.join(f'{n}={c}' for n, c in probe))
    if ckpt: r.append('CHECKPOINT-ACCEPTED ' + ', '.join(n for n, _ in ckpt))
    if 'panicked at tests/zz_review_replay_probe.rs' in log and not probe and not ckpt:
        r.append('REVIEWER-OTHER ' + ' | '.join(re.findall(r'panicked at tests/zz_review_replay_probe\.rs:\d+:\d+:\n(.*)', log)))
    rows.append(f'{name}: {a} || REVIEWER: {"; ".join(r) or "none"}')
(D / 'RECLASSIFIED.txt').write_text('\n'.join(rows) + '\n')
print('\n'.join(rows))
