#!/usr/bin/env python3
"""Compiled regressions for the cold review's remaining backend seams."""
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
PROJECTION = ROOT / 'src/evidence_operations/projection.rs'
OVERVIEW = ROOT / 'src/evidence_operations_collection/overview.rs'
OUT = ROOT / '.local-state/reviews/overview-backend-controls'


def main():
    if not __debug__:
        raise RuntimeError('assertions required')
    OUT.mkdir(parents=True, exist_ok=True)
    original = {p: p.read_text() for p in (PROJECTION, OVERVIEW)}
    cases = [
        ('omit-copy-deadline', PROJECTION,
         'if std::time::Instant::now() >= deadline {',
         'if false && std::time::Instant::now() >= deadline {',
         ['--lib'], 'evidence_operations::projection::tests::copy_deadline_applies_to_contention_after_successful_source_open'),
        ('omit-copy-revalidation', PROJECTION,
         'self.schema = Self::validate_connection(&memory)?;', 'let _ = &memory;',
         ['--lib'], 'evidence_operations::projection::tests::copy_revalidates_schema_and_capacity_control_after_source_open'),
        ('use-parse-window', OVERVIEW,
         'snapshot.started_at = start;\n        snapshot.finished_at = end;',
         'let _ = (start, end);', ['--lib'],
         'evidence_operations_collection::overview::tests::active_snapshot_reports_the_copy_window_not_later_parsing'),
        ('classify-invalid-as-busy', OVERVIEW,
         'error.is::<operations::projection::SourceBusy>()',
         'true || error.is::<operations::projection::SourceBusy>()',
         ['--test', 'evidence_overview_review_regressions'],
         'corrupt_active_btree_is_invalid_not_busy_and_is_not_rewritten'),
    ]
    try:
        for name, path, before, after, suite, test in cases:
            assert original[path].count(before) == 1, name + ' anchor'
            path.write_text(original[path].replace(before, after))
            run = subprocess.run(['cargo', 'test', '--features', 'v2-crypto',
                                  *suite, test, '--', '--exact'], cwd=ROOT,
                                 capture_output=True, text=True)
            log = run.stdout + run.stderr
            (OUT / (name + '.txt')).write_text(log)
            assert run.returncode != 0, name + ' SURVIVED'
            assert 'could not compile' not in log, name + ' compile failure'
            assert 'test ' + test + ' ... FAILED' in log, name + ' no named assertion'
            print('DEMONSTRATED:', name, flush=True)
            path.write_text(original[path])
    finally:
        for path, text in original.items():
            path.write_text(text)
    suites = [
        ('projection', ['--lib', 'evidence_operations::projection::tests']),
        ('window', ['--lib', 'evidence_operations_collection::overview::tests']),
        ('integration', ['--test', 'evidence_overview_review_regressions']),
    ]
    for name, args in suites:
        run = subprocess.run(['cargo', 'test', '--features', 'v2-crypto', *args],
                             cwd=ROOT, capture_output=True, text=True)
        (OUT / ('restored-' + name + '.txt')).write_text(run.stdout + run.stderr)
        assert run.returncode == 0, 'restored ' + name + ' failed'
    print('Four compiled mutants fail assertions; restored backend checks pass.', flush=True)


if __name__ == '__main__':
    main()
