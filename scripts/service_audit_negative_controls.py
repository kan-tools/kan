#!/usr/bin/env python3
"""Idle author checkout only: audit-cache/read-pin controls, exact restoration."""
import os
from pathlib import Path
import subprocess

root = Path(__file__).resolve().parents[1]
source = root / 'src/evidence_service.rs'
original = source.read_bytes()
env = dict(os.environ, CARGO_BUILD_JOBS='4', CARGO_PROFILE_DEV_DEBUG='0',
           CARGO_PROFILE_TEST_DEBUG='0', CARGO_INCREMENTAL='0')
unit = ['--lib', 'evidence_service::audit_tests::']
integration = ['--test', 'evidence_service']
progress = '''                self.audited = Snapshot {
                    through: after,
                    tip: Some(record.manifest.cid().clone()),
                };'''
end = '''        Ok(())
    }
    pub fn issuer'''
controls = [
    ('page pin', [('if *through > self.audited.through {', 'if false && *through > self.audited.through {')],
     unit[:-1] + [unit[-1] + 'reads_cannot_cross_audited_frontier_when_raw_append_arrives_after_audit']),
    ('read pin', [('let snapshot = &self.audited;', 'let live = self.ledger.snapshot()?; let snapshot = &live;')],
     unit[:-1] + [unit[-1] + 'reads_cannot_cross_audited_frontier_when_raw_append_arrives_after_audit']),
    ('full progress-cache fix reversion', [(progress, ''), (end, '        self.audited = snapshot;\n' + end)],
     unit[:-1] + [unit[-1] + 'verified_prefix_is_retained_without_skipping_a_later_invalid_record']),
    ('snapshot tip validation', [('if self.audited.through > 0 {', 'if false && self.audited.through > 0 {')],
     integration + ['missing_committed_object_is_corrupt_on_read_and_startup']),
    ('contiguity', [('if record.sequence != after + 1 {', 'if false && record.sequence != after + 1 {')],
     integration + ['audit_pin_guards_detect_retreat_replacement_and_sequence_holes']),
    ('prior pin', [('.page(&self.audited, self.audited.through, 1)', '.page(&snapshot, snapshot.through, 1)')],
     integration + ['audit_pin_guards_detect_retreat_replacement_and_sequence_holes']),
    ('duplicate audit progress', [('if !record.duplicate {', 'if true {')],
     unit[:-1] + [unit[-1] + 'exact_retry_does_not_discard_audited_progress']),
]
for name, edits, target in controls:
    text = original.decode()
    for old, new in edits:
        if text.count(old) != 1:
            raise SystemExit(f'{name}: edit is not unique')
        text = text.replace(old, new, 1)
    command = ['cargo', 'test', '--features', 'v2-crypto', *target]
    subprocess.run(command, cwd=root, env=env, check=True)
    try:
        source.write_text(text)
        result = subprocess.run(command, cwd=root, env=env, capture_output=True, text=True, timeout=120)
        if result.returncode == 0 or 'test result: FAILED' not in result.stdout:
            raise SystemExit(f'{name}: runtime failure absent\n{result.stdout}\n{result.stderr}')
        print(f'{name}: detected runtime failure', flush=True)
    finally:
        source.write_bytes(original)
    subprocess.run(command, cwd=root, env=env, check=True)
