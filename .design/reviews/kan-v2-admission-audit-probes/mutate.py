#!/usr/bin/env python3
"""Reviewer mutation driver. Each mutant: exact single-occurrence replace, run named
tests, classify, restore original bytes with a fresh mtime. Run from export root."""
import hashlib, json, os, re, signal, subprocess, sys, time
from pathlib import Path

ROOT = Path.cwd()
EV = ROOT / 'review-evidence' / 'mutants'
EV.mkdir(parents=True, exist_ok=True)
ENV = dict(os.environ, CARGO_TARGET_DIR=str(ROOT / 'target'), CARGO_BUILD_JOBS='4',
           CARGO_INCREMENTAL='0', CARGO_PROFILE_DEV_DEBUG='0', CARGO_PROFILE_TEST_DEBUG='0')
RS = 'src/evidence_operations.rs'
COL = 'src/evidence_operations_collection.rs'
PY = 'scripts/revert_v2.py'
JS = 'web/operations/app.js'

def lib(name): return ['cargo', 'test', '--features', 'v2-crypto', '--lib', name, '--', '--exact', name]
def integ(target, name): return ['cargo', 'test', '--features', 'v2-crypto', '--test', target, '--', '--exact', name]
def suite(target): return ['cargo', 'test', '--features', 'v2-crypto', '--test', target]
LIB_ALL = ['cargo', 'test', '--features', 'v2-crypto', '--lib', 'evidence_operations']
def pyt(name): return [sys.executable, '-I', 'tests/test_revert_v2.py', '-v', name]
def node(pattern): return ['node', '--test', '--test-name-pattern=' + pattern, 'tests/operations_ui.test.cjs']
NODE_ALL = ['node', '--test', 'tests/operations_ui.test.cjs']
U = 'evidence_operations::tests::'

MUTANTS = [
 ('R01-wouldblock-immediate-refusal', RS, 'contended();\n            None', 'contended();\n            Some(false)', [lib(U+'actual_shard_contention_retries_after_release_without_loss')]),
 ('R02-callsite-single-try-bypass', RS, 'offer_pending_observed(pending, h, || {})',
  '{ if !valid_health(h) { return false; } match pending.shards[pending.shard(h)].try_lock() { Ok(mut p) => p.offer(h, &pending.count), Err(_) => false } }',
  [LIB_ALL, suite('evidence_operations')]),
 ('R03-cas-budget-one', RS, 'for _ in 0..64 {', 'for _ in 0..1 {', [lib(U+'reservation_retries_spurious_failure_and_stops_at_its_finite_budget')]),
 ('R04-reserve-production-single-try', RS,
  'reserve_attempt_observed(count, |current| {\n        count.compare_exchange_weak(current, current + 1, Ordering::Relaxed, Ordering::Relaxed)\n    })',
  '{ let current = count.load(Ordering::Relaxed); current < 256 && count.compare_exchange_weak(current, current + 1, Ordering::Relaxed, Ordering::Relaxed).is_ok() }',
  [LIB_ALL, suite('evidence_operations')]),
 ('R05-no-capacity-precheck', RS, '        if current >= 256 {\n            return false;\n        }\n        match compare(current)', '        match compare(current)',
  [lib(U+'reservation_retries_spurious_failure_and_stops_at_its_finite_budget'), lib(U+'sharded_admission_is_independent_and_globally_bounded')]),
 ('R06-always-rewrite-control', RS, '                if exhausted\n                    && !(prior == "session_limit"', '                if false\n                    && !(prior == "session_limit"',
  [integ('evidence_operations', 'sealed_record_refusals_do_not_rewrite_control'), integ('evidence_operations', 'session_exhaustion_escalates_when_attempt_capacity_is_reached')]),
 ('R07-no-escalation', RS, '                if exhausted\n                    && !(prior == "session_limit"\n                        && matches!(reason, "attempt_limit" | "sqlite_full"))', '                if exhausted',
  [integ('evidence_operations', 'session_exhaustion_escalates_when_attempt_capacity_is_reached'), lib(U+'worker_full_failure_marks_capacity_and_retains_recovery_space')]),
 ('R08-session-releases-reserve', RS, 'if reason != "session_limit" {\n                    tx.execute("DELETE FROM reserve"', 'if true {\n                    tx.execute("DELETE FROM reserve"',
  [integ('evidence_operations', 'journal_session_exhaustion_is_visible_without_refusing_reporter_start'), lib(U+'session_capacity_is_sticky_and_existing_control_still_updates')]),
 ('R09-session-seals-record', RS, 'if exhausted && reason != "session_limit" {', 'if exhausted {',
  [integ('evidence_operations', 'journal_session_exhaustion_is_visible_without_refusing_reporter_start'), lib(U+'session_capacity_is_sticky_and_existing_control_still_updates')]),
 ('R10-no-sealed-filter', RS, 'reason.filter(|reason| *reason != "sealed_for_capacity")', 'reason',
  [integ('evidence_operations', 'sealed_record_refusals_do_not_rewrite_control'), LIB_ALL]),
 ('R11-old-session-reserve-refused', RS, '"session_limit" => !(reserved == 0 || (reserved == 64 && valid == 64)),', '"session_limit" => reserved != 64 || valid != 64,',
  [lib(U+'session_capacity_is_sticky_and_existing_control_still_updates')]),
 ('R12-session-requires-released-reserve', RS, '"session_limit" => !(reserved == 0 || (reserved == 64 && valid == 64)),', '"session_limit" => reserved != 0,',
  [lib(U+'session_capacity_is_sticky_and_existing_control_still_updates'), integ('evidence_operations', 'journal_session_exhaustion_is_visible_without_refusing_reporter_start')]),
 ('R13-no-wal-byte-check', RS, ' || header[18..20] != [1, 1]', '',
  [integ('evidence_operations_collection', 'wal_format_is_refused_before_sqlite_can_create_untracked_sidecars')]),
 ('R14-header-check-after-lock-sidecar', RS, None, None,
  [integ('evidence_operations_collection', 'wal_format_is_refused_before_sqlite_can_create_untracked_sidecars')]),
 ('R15-timestamp-before-validation', RS, '        let result = self.record_inner(h);', '        let _ = successful(&self.conn, self.schema);\n        let result = self.record_inner(h);',
  [lib(U+'successful_write_is_observed_only_after_commit')]),
 ('R16-timestamp-after-commit', RS, '        successful(&tx, self.schema)?;\n        tx.commit()?;\n        Ok(())\n    }\n    fn session(', '        tx.commit()?;\n        successful(&self.conn, self.schema)?;\n        Ok(())\n    }\n    fn session(',
  [lib(U+'successful_write_is_observed_only_after_commit')]),
 ('R17-never-last-success', RS, '"UPDATE control SET last_success=? WHERE singleton=1",\n            [now() as i64],\n        )?;', '"UPDATE control SET last_success=last_success WHERE ?=?",\n            [0, 0],\n        )?;',
  [lib(U+'successful_write_is_observed_only_after_commit'), LIB_ALL]),
 ('R18-worker-no-capacity-mark', RS, '        j.note_capacity_failure(&result);\n        result.is_err()', '        result.is_err()',
  [lib(U+'worker_full_failure_marks_capacity_and_retains_recovery_space')]),
 ('R19-manifest-active-any-member', COL, 'if g.id != m.active || g.sealed_sha256.is_some() {', 'if g.sealed_sha256.is_some() {',
  [integ('evidence_operations_collection', 'malformed_membership_and_bounds_are_rejected_without_repair')]),
 ('P01-unbounded-drain', PY, 'process.communicate(timeout=1)', 'process.communicate()', [pyt('Execution.test_detached_pipe_holder_cannot_hang_timeout_cleanup')]),
 ('P02-no-pipe-close', PY, '            process.stdout.close()\n            process.stderr.close()\n', '',
  [pyt('Execution.test_detached_pipe_holder_cannot_hang_timeout_cleanup'), pyt('Execution.test_timeout_stops_descendant_writes')]),
 ('P03-kill-direct-child-only', PY, 'os.killpg(process.pid, signal.SIGKILL)', 'process.kill()', [pyt('Execution.test_timeout_stops_descendant_writes')]),
 ('P04-error-accepted', PY, "        raise ValueError('named Python test errored rather than failing an assertion')\n", "        pass\n",
  [pyt('Results.test_python_assertions_are_distinct_from_errors_and_skips')]),
 ('P05-error-counted-as-fail', PY, "    if hits[0] == 'ERROR':\n", "    if False:\n",
  [pyt('Results.test_python_assertions_are_distinct_from_errors_and_skips')]),
 ('P06-no-py311-format', PY, r"(?:\.\1)?", '', [pyt('Results.test_python_assertions_are_distinct_from_errors_and_skips')]),
 ('P07-any-module-class', PY, r"\(__main__\.(\w+)", r"\((?:\w+\.)*?(\w+)", [pyt('Results.test_python_assertions_are_distinct_from_errors_and_skips')]),
 ('P08-unknown-python-alias-allowed', PY, "            if name.startswith('python::') and name[8:] not in PYTHON_TESTS:\n                raise ValueError(f'unknown Python test alias: {name}')\n", '', [[sys.executable, '-I', 'tests/test_revert_v2.py', '-v']]),
 ('U01-no-session-threshold', JS, "nearCauses.push('reporter sessions');", ';', [node('reporter and attempt limits')]),
 ('U02-no-attempt-threshold', JS, "if(j.attempts_used>=j.attempts_limit*0.9)nearCauses.push('attempts');", '', [node('reporter and attempt limits')]),
 ('U03-attempt-threshold-0.99', JS, 'j.attempts_used>=j.attempts_limit*0.9', 'j.attempts_used>=j.attempts_limit*0.99', [NODE_ALL]),
 ('U04-no-session-exhausted-branch', JS, "if(storage.sessionsExhausted)notice(", "if(false)notice(", [node('reporter and attempt limits')]),
 ('U05-future-clock-guard', JS, '&&j.last_success_at<=now+5&&', '&&', [node('future persistence timestamps')]),
 ('U06-row-focus-not-restored', JS, 'if(attemptButtons.has(focused))attemptButtons.get(focused).focus();else', 'if(false)attemptButtons.get(focused).focus();else', [node('polling preserves')]),
 ('U07-notice-rewritten', JS, "if($('notice').textContent!==text)$('notice').textContent=text;", "$('notice').textContent=text;", [node('unchanged notices')]),
 ('U08-polling-steals-modal-focus', JS, "if(focused){if(attemptButtons.has(focused))attemptButtons.get(focused).focus();else $('search').focus();}",
  "if(focused){if(attemptButtons.has(focused))attemptButtons.get(focused).focus();else $('search').focus();}else $('search').focus();", [NODE_ALL]),
 ('U09-close-ignores-replacement', JS, "inspectorTrigger?.isConnected?inspectorTrigger:attemptButtons.get(inspectorAttempt)", "inspectorTrigger", [node('polling preserves')]),
('R06b-always-rewrite-control-wide', RS, '                if exhausted\n                    && !(prior == "session_limit"', '                if false\n                    && !(prior == "session_limit"',
  [LIB_ALL, suite('evidence_operations'), suite('evidence_operations_collection'), ['cargo', 'test', '--features', 'v2-crypto', '--test', 'zz_review_probe', '--', '--test-threads=1', '--nocapture']]),
 ('R20-guard-and-filter-both-removed', RS, [('                if exhausted\n                    && !(prior == "session_limit"', '                if false\n                    && !(prior == "session_limit"'), ('reason.filter(|reason| *reason != "sealed_for_capacity")', 'reason')], None,
  [integ('evidence_operations', 'sealed_record_refusals_do_not_rewrite_control')]),
 ('R21-attempt-escalation-only-sqlite', RS, 'matches!(reason, "attempt_limit" | "sqlite_full"))', 'matches!(reason, "sqlite_full"))',
  [integ('evidence_operations', 'session_exhaustion_escalates_when_attempt_capacity_is_reached'), ['cargo', 'test', '--features', 'v2-crypto', '--test', 'zz_review_probe', '--', '--test-threads=1']]),
 ('R22-wouldblock-callback-skipped', RS, 'Err(std::sync::TryLockError::WouldBlock) => {\n            contended();\n            None\n        }', 'Err(std::sync::TryLockError::WouldBlock) => None',
  [lib(U+'actual_shard_contention_retries_after_release_without_loss')]),
 ('R06c-always-rewrite-reason-probe', RS, '                if exhausted\n                    && !(prior == "session_limit"', '                if false\n                    && !(prior == "session_limit"',
  [['cargo', 'test', '--features', 'v2-crypto', '--test', 'zz_review_probe', 'probe_attempt_limit', '--', '--nocapture']]),
]

def r14(text):
    start = text.index('        // This profile owns rollback-journal files only.')
    end = text.index('        // flock and SQLite fcntl locks')
    block = text[start:end]
    text = text[:start] + text[end:]
    anchor = '        let file_lock = std::fs::File::open(lock_path)?;\n'
    assert text.count(anchor) == 1
    return text.replace(anchor, block + anchor)

def run(cmd, log, timeout=420):
    p = subprocess.Popen(cmd, cwd=ROOT, env=ENV, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True)
    try:
        out, _ = p.communicate(timeout=timeout)
        timed = False
    except subprocess.TimeoutExpired:
        os.killpg(p.pid, signal.SIGKILL)
        try: out, _ = p.communicate(timeout=5)
        except subprocess.TimeoutExpired: out = b''
        timed = True
    out = out.decode(errors='replace')
    if len(out) > 400_000:
        out = out[:200_000] + '\n...[reviewer truncated oversized output]...\n' + out[-200_000:]
    log.write('$ ' + ' '.join(cmd) + f'\n[exit={p.returncode} timeout={timed}]\n' + out + '\n')
    return p.returncode, timed, out

def classify(rc, timed, out, kind):
    if timed: return 'TIMEOUT'
    if kind == 'rust':
        if re.search(r'^error(\[E\d+\])?:', out, re.M) and 'could not compile' in out: return 'COMPILE-FAIL'
        if 'test result: FAILED' in out:
            return 'ASSERT-KILL' if 'panicked at' in out else 'FAIL-OTHER'
        m = re.findall(r'test result: ok\. (\d+) passed', out)
        if rc == 0 and m and all(int(x) > 0 for x in m): return 'PASS'
        return f'UNCLEAR(rc={rc})'
    if kind == 'py':
        if re.search(r'\.\.\. ERROR$', out, re.M): return 'ERROR(not-assert)'
        if re.search(r'\.\.\. FAIL$', out, re.M): return 'ASSERT-KILL'
        return 'PASS' if rc == 0 and re.search(r'^OK', out, re.M) else f'UNCLEAR(rc={rc})'
    fails = re.search(r'ℹ fail (\d+)', out); passes = re.search(r'ℹ pass (\d+)', out)
    if fails and int(fails.group(1)) > 0: return 'ASSERT-KILL' if 'AssertionError' in out or 'ERR_ASSERTION' in out else 'FAIL-OTHER'
    return 'PASS' if rc == 0 and passes and int(passes.group(1)) > 0 else f'UNCLEAR(rc={rc})'

def main():
    only = set(sys.argv[1:])
    results = []
    for mid, path, old, new, cmds in MUTANTS:
        if only and mid not in only: continue
        f = ROOT / path
        original = f.read_bytes()
        digest = hashlib.sha256(original).hexdigest()
        text = original.decode()
        if mid.startswith('R14'):
            mutated = r14(text)
        elif isinstance(old, list):
            mutated = text
            for o, n in old:
                assert mutated.count(o) == 1, (mid, o)
                mutated = mutated.replace(o, n)
        else:
            assert text.count(old) == 1, (mid, text.count(old))
            mutated = text.replace(old, new)
        kind = 'rust' if path.endswith('.rs') else 'py' if path.endswith('.py') else 'node'
        verdicts = []
        with open(EV / f'{mid}.txt', 'w') as log:
            log.write(f'mutant {mid} on {path}\n--- old\n{old}\n+++ new\n{new}\n\n')
            try:
                f.write_bytes(mutated.encode())
                for cmd in cmds:
                    rc, timed, out = run(cmd, log)
                    v = classify(rc, timed, out, kind)
                    names = re.findall(r'^test (\S+) \.\.\. FAILED$', out, re.M) + re.findall(r'^(\S+ \(__main__\.\S+\)) \.\.\. FAIL$', out, re.M) + re.findall(r'^✖ (.+?) \(', out, re.M)
                    panics = re.findall(r'panicked at (.+)\n(.+)', out)[:3]
                    verdicts.append({'cmd': cmd[-1], 'verdict': v, 'failed': sorted(set(names))[:8], 'panic': panics})
            finally:
                f.write_bytes(original)
                os.utime(f, None)
                assert hashlib.sha256(f.read_bytes()).hexdigest() == digest, f'restore failed {path}'
            log.write('RESULT ' + json.dumps(verdicts) + '\n')
        results.append({'id': mid, 'results': verdicts})
        print(mid, json.dumps(verdicts), flush=True)
    with open(EV / ('summary-' + str(int(time.time())) + '.json'), 'w') as s:
        json.dump(results, s, indent=1)

if __name__ == '__main__':
    main()
