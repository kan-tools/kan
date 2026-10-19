#!/usr/bin/env python3
"""Compiled overview regressions; run only in an idle worktree. Restores in finally."""
from pathlib import Path
import subprocess
ROOT=Path(__file__).resolve().parents[1]
SOURCE=ROOT/'src/evidence_operations_collection/overview.rs'
JS=ROOT/'web/operations/app.js'
PROJECTION=ROOT/'src/evidence_operations/projection.rs'
OUT=ROOT/'.local-state/reviews/overview-controls'
def main():
    if not __debug__: raise RuntimeError('assertions required')
    OUT.mkdir(parents=True,exist_ok=True)
    originals={SOURCE:SOURCE.read_text(),JS:JS.read_text(),PROJECTION:PROJECTION.read_text()}
    for path,value in originals.items(): (OUT/(path.name+'.original')).write_text(value)
    s=originals[SOURCE]
    cases=[
      ('no-deduplication',SOURCE,s.replace('        if let Some(old) = map.get(&key) {','        let key = format!("{key}:{}",map.len());\n        if let Some(old) = map.get(&key) {'),'cumulative_rows_are_deduplicated_without_rewriting_sources'),
      ('no-dominance',SOURCE,s.replace('if !dominates {','if false && !dominates {'),'intermediate_regressions_conflicting_observers_and_terminals_refuse_publication'),
      ('no-sealed-hash',SOURCE,s.replace('if &sealed_hash(&path, flag)? != expected {','if false && &sealed_hash(&path, flag)? != expected {'),'changed_missing_sources_binding_and_membership_fail_visibly'),
      ('no-memory-cap',SOURCE,s.replace('if next > self.limit {','if false && next > self.limit {'),'bounds_cancellation_and_checked_sum_never_publish_partial_totals'),
      ('no-cancellation',SOURCE,s.replace('if flag.load(Ordering::Relaxed) {','if false && flag.load(Ordering::Relaxed) {'),'bounds_cancellation_and_checked_sum_never_publish_partial_totals'),
      ('omit-post-read-sealed-hash',SOURCE,'if false && &sealed_hash(&path, flag)? != expected {'.join(s.rsplit('if &sealed_hash(&path, flag)? != expected {',1)),'sealed_change_after_row_scan_is_not_published'),
      ('omit-unique-health-validation',PROJECTION,originals[PROJECTION].replace('!valid_health(&health)', 'false'),'ignored_sqlite_sidecars_and_invalid_unique_health_rows_refuse'),
      ('promote-historical-worker',SOURCE,s.replace('snapshot.worker = None;', 'let _ = &snapshot;'),'historical_worker_is_hashed_but_not_promoted_to_current_health'),
      ('omit-sealed-sidecar-check',SOURCE,s.replace('sidecars_absent(&path)?;', 'let _ = &path;'),'ignored_sqlite_sidecars_and_invalid_unique_health_rows_refuse'),
      ('discard-action-during-poll',JS,originals[JS].replace('if(!action)return;', 'if(overviewRequest)return;'),'build preempts an in-flight overview poll and ignores its stale reply'),
      ('hold-active-read-through-parse',SOURCE,s.replace('let (copy, window) = journal.projection_copy(&mut || cancel(flag))?;', 'let (copy, window) = (journal, (operations::now(), operations::now()));'),'active_snapshot_parsing_does_not_exclude_health_writes'),
      ('late-overview-repaint',JS,originals[JS].replace('if(current===generation&&serial===overviewSerial)renderOverview(s);','renderOverview(s);'),'lock clears overview and prevents a late result from repainting'),
    ]
    try:
      for name,path,changed,test in cases:
        assert changed!=originals[path],f'inactive: {name}'
        path.write_text(changed)
        command=['node','--test','--test-name-pattern='+test,'tests/operations_ui.test.cjs'] if path==JS else ['cargo','test','--features','v2-crypto','--test','evidence_operations_overview',test,'--','--exact']
        result=subprocess.run(command,cwd=ROOT,capture_output=True,text=True)
        (OUT/(name+'.txt')).write_text(result.stdout+result.stderr)
        assert result.returncode!=0,f'SURVIVED: {name}'
        if path!=JS:
          assert 'could not compile' not in result.stderr,f'compile failure: {name}'
          assert 'running 1 test' in result.stdout and f'test {test} ... FAILED' in result.stdout,f'no named failure: {name}'
        else: assert 'AssertionError' in result.stdout+result.stderr,f'no assertion: {name}'
        print('DEMONSTRATED:',name,flush=True)
        path.write_text(originals[path])
    finally:
      for path,value in originals.items(): path.write_text(value)
    for name,command in [('rust',['cargo','test','--features','v2-crypto','--test','evidence_operations_overview']),('ui',['node','--test','tests/operations_ui.test.cjs'])]:
      result=subprocess.run(command,cwd=ROOT,capture_output=True,text=True)
      (OUT/('restored-'+name+'.txt')).write_text(result.stdout+result.stderr)
      assert result.returncode==0,f'restored {name} failed'
    print('Five compiled Rust mutants and one UI mutant fail; restored checks pass.',flush=True)
if __name__=='__main__': main()
