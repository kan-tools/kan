#!/usr/bin/env python3
"""Compile replay guard removals, retain assertion evidence, always restore.

Run with the shared target/four-job environment after ordinary qualification.
These are selected controls, not an exhaustive mutation score. A different
diagnostic refusal does not demonstrate semantic acceptance of hostile input.
"""
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
FILE = ROOT / 'src/evidence_recovery_replay.rs'
MEMBER = ROOT / 'src/evidence_recovery_member.rs'
OUT = ROOT / '.local-state/replay-author/controls'
VECTOR = 'independent_state_vectors_match_acceptance_commitments_attempts_and_checkpoints'
CASES = [
    ('member-commitment', 'bytes::<32>(value)? == *original.commitment()', 'true || bytes::<32>(value)? == *original.commitment()', VECTOR),
    ('frontier', 'value == &expected_frontier', 'true || value == &expected_frontier', VECTOR),
    ('loss-partition', 'b["entries"] == Ipld::List(expected.clone())', 'true || b["entries"] == Ipld::List(expected.clone())', VECTOR),
    ('historical-restorations', 'bytes::<32>(&b["restorations"])? == r1', 'true || bytes::<32>(&b["restorations"])? == r1', VECTOR),
    ('intent-output', 'bytes::<32>(&b["output"])? == o1', 'true || bytes::<32>(&b["output"])? == o1', VECTOR),
    ('intent-citation', 'link(&b["intent"])? == &a.intent', 'true || link(&b["intent"])? == &a.intent', VECTOR),
    ('terminal-attempt', 'a.observed_at_sequence.is_none()', 'true || a.observed_at_sequence.is_none()', VECTOR),
    ('external-checkpoint', 'require(checkpoint_seen, "external checkpoint absent")?', 'require(true || checkpoint_seen, "external checkpoint absent")?', 'rollback_before_external_checkpoint_and_foreign_checkpoint_refuse'),
    ('partial-candidate-length', 'length: complete_recipe.then_some(m.length)', 'length: Some(m.length)', 'partial_membership_restoration_keeps_the_original_unverified_basis'),
    ('restoration-basis', 'basis: keys[name].basis', 'basis: Basis::VerifiedCopyRecipe', 'partial_membership_restoration_keeps_the_original_unverified_basis'),
]


def run(test):
    return subprocess.run(
        ['cargo', 'test', '--features', 'v2-crypto', '--test',
         'evidence_recovery_replay', test, '--', '--exact', '--nocapture'],
        cwd=ROOT, capture_output=True, text=True, timeout=240)


def main():
    if not __debug__:
        raise RuntimeError('assertions required')
    OUT.mkdir(parents=True, exist_ok=True)
    original = FILE.read_text()
    original_member = MEMBER.read_text()
    try:
        for name, old, new, test in CASES:
            assert original.count(old) == 1, (name, original.count(old))
            FILE.write_text(original.replace(old, new))
            result = run(test)
            log = result.stdout + result.stderr
            (OUT / (name + '.txt')).write_text(log + '\nexit=' + str(result.returncode) + '\n')
            assert result.returncode != 0, name + ' SURVIVED'
            assert 'could not compile' not in log, name + ' did not compile'
            assert 'test ' + test + ' ... FAILED' in log, name + ' lacks assertion failure'
            if test == VECTOR:
                assert 'hostile history must refuse' in log, name + ' was diagnostic-only'
            elif test == 'rollback_before_external_checkpoint_and_foreign_checkpoint_refuse':
                assert 'left: None' in log, name + ' did not accept truncated history'
            else:
                assert 'candidate expected length' in log or 'assertion failed:' in log, name + ' lacks changed restoration semantics'
            print('DEMONSTRATED: ' + name, flush=True)
            FILE.write_text(original)
        old = '.map_err(|_| Error::Invalid("retained writer request"))?;'
        assert original_member.count(old) == 1
        MEMBER.write_text(original_member.replace(old, '.ok();'))
        result = run(VECTOR)
        log = result.stdout + result.stderr
        (OUT / 'virtual-output-writer.txt').write_text(log + '\nexit=' + str(result.returncode) + '\n')
        assert result.returncode != 0 and 'could not compile' not in log
        assert 'hostile history must refuse' in log, 'writer check control was diagnostic-only'
        print('DEMONSTRATED: virtual-output-writer', flush=True)
    finally:
        FILE.write_text(original)
        MEMBER.write_text(original_member)
    result = subprocess.run(
        ['cargo', 'test', '--features', 'v2-crypto', '--test', 'evidence_recovery_replay'],
        cwd=ROOT, capture_output=True, text=True, timeout=240)
    (OUT / 'restored.txt').write_text(result.stdout + result.stderr + '\nexit=' + str(result.returncode) + '\n')
    assert result.returncode == 0, 'restoration failed'
    print(f'{len(CASES) + 1} compiled semantic controls killed; restored suite passed.', flush=True)


if __name__ == '__main__':
    main()
