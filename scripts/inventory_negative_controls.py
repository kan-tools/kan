#!/usr/bin/env python3
"""Compiled inventory controls; run alone using the explicitly shared Cargo target."""
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / '.local-state/reviews/inventory-controls'
FILE = ROOT / 'src/evidence_store/inventory.rs'
CASES = [
    ('omit-payload-storage-class', "CASE WHEN typeof(bytes)='blob' THEN length(bytes) ELSE -1 END", 'length(bytes)', 'wrong_sql_payload_types_are_corrupt_without_failing_healthy_neighbours'),
    ('omit-page-vm-configuration', '        configure_read(&self.reader.ledger.conn, &work, deadline)?;\n', '', 'evidence_store::inventory::tests::page_installs_vm_limits_after_startup_removes_its_handler'),
    ('omit-startup-record-budget', '            add_spent(&mut items, 1, budget.items)?;\n            let record = raw_commit(row)?;', '            let record = raw_commit(row)?;', 'startup_item_budget_counts_each_metadata_record_before_accepting_a_snapshot'),
    ('indexed-large-row-materialization', "SELECT CASE WHEN typeof(bytes)='blob' THEN length(bytes) ELSE -1 END FROM objects NOT INDEXED WHERE +cid=?", "SELECT CASE WHEN typeof(bytes)='blob' THEN length(bytes) ELSE -1 END FROM objects WHERE cid=?", 'inventory_large_rows_stay_below_the_materialization_memory_ceiling'),
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
    selected = set(sys.argv[1:])
    assert selected <= {case[0] for case in CASES}, "unknown control"
    cases = [case for case in CASES if not selected or case[0] in selected]
    OUT.mkdir(parents=True, exist_ok=True)
    original = FILE.read_text()
    try:
        for name, old, new, test in cases:
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
    run = subprocess.run(['cargo', 'test', '--features', 'v2-crypto', '--lib', 'evidence_store::inventory::tests'], cwd=ROOT, capture_output=True, text=True, timeout=180)
    (OUT / 'restored-vm.txt').write_text(run.stdout + run.stderr)
    assert run.returncode == 0, 'restored VM baseline failed'
    print(str(len(cases)) + ' controls; restored integration and VM suites passed.', flush=True)


if __name__ == '__main__':
    main()
