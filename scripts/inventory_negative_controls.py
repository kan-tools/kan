#!/usr/bin/env python3
"""Compiled inventory controls; run alone using the explicitly shared Cargo target."""
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / '.local-state/reviews/inventory-controls'
FILE = ROOT / 'src/evidence_store/inventory.rs'
CASES = [
    ('indexed-large-row-materialization', 'SELECT length(bytes) FROM objects NOT INDEXED WHERE +cid=?', 'SELECT length(bytes) FROM objects WHERE cid=?', 'inventory_large_rows_stay_below_the_materialization_memory_ceiling'),
    ('omit-sqlite-vm-callback', '        1000,\n', '        0,\n', 'evidence_store::inventory::tests::sqlite_vm_deadline_and_cancel_interrupt_unyielding_queries'),
    ('require-payloads-at-startup', '        let plan = plan(&reader, profile, &binding)?;', '        reader.ledger.verify_contents()?;\n        let plan = plan(&reader, profile, &binding)?;', 'missing_and_corrupt_tip_or_middle_remain_visible_after_restart_with_healthy_neighbours'),
    ('omit-payload-hash', 'bytes.len() != expected || ciphertext_cid(&bytes) != *id', 'bytes.len() != expected', 'missing_and_corrupt_tip_or_middle_remain_visible_after_restart_with_healthy_neighbours'),
    ('omit-retained-position', 'if record.sequence > p.source().through {', 'if false && record.sequence > p.source().through {', 'inventory_purpose_checks_pin_specific_refusals_before_recipe_digest_checks'),
    ('omit-admitted-prefix-guard', 'if plan.is_some_and(|p| record.sequence <= p.source().through) {', 'if false && plan.is_some_and(|p| record.sequence <= p.source().through) {', 'inventory_purpose_checks_pin_specific_refusals_before_recipe_digest_checks'),
    ('omit-historical-issuer', 'if record.receipt.body()["issuer"] != historical {', 'if false && record.receipt.body()["issuer"] != historical {', 'inventory_purpose_checks_pin_specific_refusals_before_recipe_digest_checks'),
    ('omit-metadata-digest-refusal', '            if !matches\n', '            if false && !matches\n', 'complete_retained_metadata_requires_exact_original_inventory_and_recipe'),
    ('ignore-page-row-limit', 'records.len() < limit.rows', 'records.len() < 40', 'descending_pages_and_budgets_preserve_exact_frontiers'),
    ('omit-writer-verification', '    let signed = service::verify_retained_request(&record, &bytes)\n        .map_err(|_| corrupt("selected writer request"))?;', '    let signed: service::SignedRequest = serde_json::from_slice(&bytes).map_err(|_| corrupt("selected writer request"))?;', 'issuer_attested_available_metadata_does_not_replace_original_writer_verification'),
]


def main():
    if not __debug__:
        raise RuntimeError('assertions required')
    OUT.mkdir(parents=True, exist_ok=True)
    original = FILE.read_text()
    try:
        for name, old, new, test in CASES:
            assert original.count(old) == 1, (name, original.count(old))
            FILE.write_text(original.replace(old, new))
            command = ['cargo', 'test', '--features', 'v2-crypto'] + (['--lib'] if '::' in test else ['--test', 'evidence_inventory']) + [test, '--', '--exact']
            run = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=180)
            log = run.stdout + run.stderr
            (OUT / (name + '.txt')).write_text(log)
            assert run.returncode != 0, name + ' SURVIVED'
            assert 'could not compile' not in log, name + ' compile error'
            assert 'test ' + test + ' ... FAILED' in log, name + ' no named assertion failure'
            print('DEMONSTRATED:', name, flush=True)
            FILE.write_text(original)
    finally:
        FILE.write_text(original)
    run = subprocess.run(['cargo', 'test', '--features', 'v2-crypto', '--test', 'evidence_inventory'], cwd=ROOT, capture_output=True, text=True, timeout=180)
    (OUT / 'restored.txt').write_text(run.stdout + run.stderr)
    assert run.returncode == 0, 'restored baseline failed'
    print(str(len(CASES)) + ' controls; restored suite passed.', flush=True)


if __name__ == '__main__':
    main()
