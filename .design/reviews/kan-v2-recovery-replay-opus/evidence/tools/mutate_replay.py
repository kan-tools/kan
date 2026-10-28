#!/usr/bin/env python3
"""Reviewer-selected compiled guard removals for src/evidence_recovery_replay.rs.

Each mutation is applied alone, both the author replay suite and the reviewer
probe test run, the log is retained, and the exact frozen bytes are restored
and SHA256-checked against the identity manifest after every mutation.
Classification:
  KILLED-ACCEPTANCE   a hostile history was accepted (author 'hostile history must
                      refuse' / explicit test assert on Err, or probe ACCEPTED_HOSTILE)
  KILLED-PROJECTION   accepted with a wrong projection / positive refused
  DIAGNOSTIC-ONLY     only refusal labels changed (still refuses everything hostile)
  SURVIVED            all tests pass (redundant/equivalent guard under this corpus)
  COMPILE-FAILURE     did not compile (not evidence either way)
"""
import hashlib, json, os, subprocess, sys
from pathlib import Path

EXPORT = Path('/Users/m/code/kan-tools/kan/.worktrees/kan-v2-recovery-replay/.local-state/reviews/recovery-replay')
FILE = EXPORT / 'src/evidence_recovery_replay.rs'
OUT = EXPORT / 'review-evidence/mutations'
MAN = json.loads((EXPORT.parent / 'recovery-replay-identity.json').read_text())['files']
WANT = MAN['src/evidence_recovery_replay.rs']
PROBES = str(EXPORT / 'review-evidence/probes/replay-probes.json')

M = [
 ('RM01-cache-never-invalidated', '                    cached = None;\n', '', 'stale virtual-output cache'),
 ('RM02-duplicate-restoration', 'require(!selected.contains_key(&name), "duplicate restoration")',
  'require(true || !selected.contains_key(&name), "duplicate restoration")', ''),
 ('RM03-late-unavailable-accepted', '"unavailable" => return Err(Error::Invalid("late unavailable")),', '"unavailable" => {}', ''),
 ('RM04-candidate-restoration-bijection', 'selected.len() == physical.len(),', 'true || selected.len() == physical.len(),', ''),
 ('RM05-candidate-hash', 'require(work.hash(c.bytes)? == raw[4..], "candidate hash")?;',
  'require(true || work.hash(c.bytes)? == raw[4..], "candidate hash")?;', ''),
 ('RM06-candidate-expected-length', 'target.length.is_none_or(|n| n == c.bytes.len() as u64)',
  'true || target.length.is_none_or(|n| n == c.bytes.len() as u64)', ''),
 ('RM07-output-losses-empty', '        output.losses().is_empty(),\n', '        true || output.losses().is_empty(),\n', ''),
 ('RM08-partial-copy-publication-guard', '        original.recipe_metadata_complete(),\n        "partial copy publication",',
  '        true || original.recipe_metadata_complete(),\n        "partial copy publication",', 'expected redundant'),
 ('RM09-verified-requests-conjunct', '            && output.verified_requests() == original.frontier().through,', '', 'expected redundant'),
 ('RM09b-verified-requests-conjunct', '            && output.verified_requests() == original.frontier().through,', '            ,', 'expected redundant; RM09 retyped (RM09 dropped the comma -> compile failure)'),
 ('RM10-checkpoint-statement', '&pin.statement == auth.statement_cid(),', 'true || &pin.statement == auth.statement_cid(),', ''),
 ('RM11-checkpoint-context', '            p.context == *input.context\n', '            true\n', ''),
 ('RM12-restoration-length', 'integer(&b["length"])? == data.len() as u64,', 'true || integer(&b["length"])? == data.len() as u64,', ''),
 ('RM13-final-loss-coverage', '        loss_offset == original.losses().len(),\n        "initial loss incomplete",',
  '        true || loss_offset == original.losses().len(),\n        "initial loss incomplete",', ''),
 ('RM14-duplicate-intent', 'require(!attempts.contains_key(&id), "duplicate intent")', 'require(true || !attempts.contains_key(&id), "duplicate intent")', ''),
 ('RM15-observed-output', 'require(bytes::<32>(&b["output"])? == a.output, "observed output")', 'require(true || bytes::<32>(&b["output"])? == a.output, "observed output")', ''),
 ('RM16-candidate-order', 'last.as_ref().is_none_or(|old| old < &name),', 'true || last.as_ref().is_none_or(|old| old < &name),', ''),
 ('RM17-record-basis-override', '                key.basis = Basis::IssuerMetadata;\n', '', ''),
 ('RM18-record-length-override', '                key.length = Some(length);\n', '', 'partial-copy referenced length'),
 ('RM19-original-object-basis', '                basis: Basis::OriginalObject,\n', '                basis: Basis::UnverifiedMembership,\n', ''),
 ('RM20-cache-never-used', '                            cached = Some(c);\n', '                            cached = None;\n', 'expected equivalent (perf only)'),
]


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def run():
    env = dict(os.environ, REVIEW_PROBES=PROBES)
    r = subprocess.run(['cargo', 'test', '--features', 'v2-crypto', '--test', 'evidence_recovery_replay',
                        '--test', 'zz_review_replay_probe', '--no-fail-fast', '--', '--nocapture', '--test-threads=1'],
                       cwd=EXPORT, capture_output=True, text=True, timeout=900, env=env)
    return r.returncode, r.stdout + r.stderr


def classify(code, log):
    if 'could not compile' in log or 'error[E' in log:
        return 'COMPILE-FAILURE', []
    tags = []
    if 'hostile history must refuse' in log: tags.append('author-vector:accepted-hostile')
    for k in ('ACCEPTED_HOSTILE', 'PROJECTION_MISMATCH', 'REFUSED_POSITIVE', 'DIAG'):
        n = log.count('class=' + k)
        if n: tags.append(f'probe:{k}x{n}')
    if 'wrong error' in log: tags.append('author-vector:diagnostic-label-changed')
    failed = [l.split()[1] for l in log.splitlines() if l.startswith('test ') and l.rstrip().endswith('FAILED')]
    tags += ['failed:' + t for t in failed]
    if code == 0:
        return 'SURVIVED', tags
    if any(t.startswith(('author-vector:accepted', 'probe:ACCEPTED')) for t in tags):
        return 'KILLED-ACCEPTANCE', tags
    return 'KILLED-OTHER(inspect)', tags


def main():
    only = set(sys.argv[1:])
    original = FILE.read_bytes()
    assert hashlib.sha256(original).hexdigest() == WANT, 'replay source not frozen bytes'
    text = original.decode()
    summary = []
    try:
        for name, old, new, note in M:
            if only and name not in only:
                continue
            assert text.count(old) == 1, (name, text.count(old))
            FILE.write_text(text.replace(old, new))
            code, log = run()
            cls, tags = classify(code, log)
            FILE.write_bytes(original)
            assert sha(FILE) == WANT, 'restore failed'
            diff = f'--- old\n{old}\n+++ new\n{new}\n'
            (OUT / f'{name}.txt').write_text(f'{name} ({note})\n{diff}\nexit={code}\nclass={cls}\ntags={tags}\n\n{log}')
            line = f'{name}: {cls} exit={code} {tags} {note}'
            print(line, flush=True)
            summary.append(line)
    finally:
        FILE.write_bytes(original)
        print('restored sha256 ok' if sha(FILE) == WANT else 'RESTORE MISMATCH', flush=True)
    with open(OUT / 'SUMMARY.txt', 'a') as f:
        f.write('\n'.join(summary) + '\n')


if __name__ == '__main__':
    main()
