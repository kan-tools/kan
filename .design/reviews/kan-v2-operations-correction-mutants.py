#!/usr/bin/env python3
"""Reviewer mutation driver (claude-opus-5-5), re-targeted at e95a3ec by the correction reviewer. Applies one textual mutant at a
time to the export, runs the named test set, restores the original bytes.
Usage: mutate.py <export-root> [mutant-id ...]"""
import os, signal, subprocess, sys, time

ROOT = sys.argv[1]
SRC = os.path.join(ROOT, "src")
ENV = dict(os.environ)
ENV.pop("CARGO_TARGET_DIR", None)
ENV.update(CARGO_NET_OFFLINE="true", CARGO_TARGET_DIR=os.path.join(ROOT, "target"), CARGO_INCREMENTAL="0",
           CARGO_PROFILE_DEV_DEBUG="0", CARGO_PROFILE_TEST_DEBUG="0", CARGO_BUILD_JOBS="4",
           GIT_CONFIG_COUNT="1", GIT_CONFIG_KEY_0="commit.gpgsign", GIT_CONFIG_VALUE_0="false",
           KAN_TLS_ORACLE_PYTHON="/opt/homebrew/bin/python3")
GW = ["cargo", "test", "-j4", "--features", "v2-crypto", "--test", "evidence_gateway"]
OPS = ["cargo", "test", "-j4", "--features", "v2-crypto", "--test", "evidence_operations"]
GWU = ["cargo", "test", "-j4", "--features", "v2-crypto", "--lib", "--", "evidence_gateway::admission_tests"]
LIB = ["cargo", "test", "-j4", "--features", "v2-crypto", "--lib", "--", "evidence_operations::tests"]
PROBE = ["cargo", "test", "-j4", "--features", "v2-crypto", "--test", "review_probes_e95", "--", "p2", "p3", "p4"]
NODE = ["node", "--test", "tests/operations_ui.test.cjs"]
G, O, D, A = "src/evidence_gateway.rs", "src/evidence_operations.rs", "src/evidence_dashboard.rs", "web/operations/app.js"
MUTANTS = {
    "M1-no-v6-64-grouping": (G, "octets[8..].fill(0);", "", [GW, GWU]),
    "M2-no-v4-mapped-normalize": (G, "if let Some(v4) = v.to_ipv4_mapped() {\n                return IpAddr::V4(v4);\n            }", "", [GW, GWU]),
    "M3-per-peer-cap-off": (G, ".count()>=8 {continue;}", ".count()>=32 {continue;}", [GW]),
    "M4-global-cap-64": (G, "if pending.len()>=32 ||", "if pending.len()>=64 ||", [GW]),
    "M5-no-retry-backoff": (O, "tokio::time::sleep(Duration::from_secs(status.retry_seconds)).await;", "", [OPS]),
    "M6-nonempty-since-reset": (O, "status.nonempty_since.get_or_insert(now());", "status.nonempty_since = Some(now());", [OPS]),
    "M7-crash-reads-clean": (O, ".is_some_and(|j| j.session(&id, 0, false).is_err()),", ".is_some_and(|j| j.session(&id, 0, true).is_err()),", [OPS, LIB]),
    "M8-blocking-send": (O, "if tx.try_send(h.clone()).is_err() {", "if tx.send(h.clone()).is_err() {", [OPS]),
    "M9-no-page-cap-on-open": (O, "\"PRAGMA synchronous=FULL; PRAGMA fullfsync=ON; PRAGMA max_page_count=8192;\",", "\"PRAGMA synchronous=FULL; PRAGMA fullfsync=ON;\",", [OPS, LIB]),
    "M11-dup-auth-allowed": (D, "if r.headers().get_all(\"authorization\").iter().count() != 1\n                ||", "if", [OPS]),
    "M13-nonloopback-dashboard": (D, "if !addr.ip().is_loopback()\n        ||", "if", [OPS]),
    "M16-unclosed-always-zero": (O, "coalesce(sum(clean=0),0)", "0", [OPS]),
    "M18-no-owner-only-check": (O, "if meta.permissions().mode() & 0o077 != 0 {", "if false {", [OPS, LIB]),
    "M21-drop-not-counted": (O, "dropped.fetch_add(1, Ordering::Relaxed);\n        }", "\n        }", [OPS]),
    "M22-ui-stale-reporter-off": (A, "Date.now()/1000-r.updated_at>5", "false", [NODE]),
    "C1-lazy-open-skips-binding": (O, "j.check_binding(spool, Some(writer))?;", "", [OPS, GW]),
    "C2-no-loss-when-journal-absent": (O, "if journal.as_mut().is_none_or(|j| j.record(&h).is_err()) {", "if journal.as_mut().is_some_and(|j| j.record(&h).is_err()) {", [OPS, GW]),
    "C3-no-initial-loss": (O, "let dropped = Arc::new(AtomicU64::new(initial_loss));", "let dropped = Arc::new(AtomicU64::new(0 * initial_loss));", [OPS]),
    "C4-worker-never-reloads": (O, "*journal = load().ok();", "let _ = load;", [OPS]),
    "C5-worker-failures-not-counted": (O, "status.telemetry_failures = status.telemetry_failures.saturating_add(1);", "", [OPS]),
    "C6-worker-skips-binding": (O, "j.check_binding(spool_path, None)?;\n", "\n", [OPS]),
    "C7-worker-skips-queue-check": (O, "j.check_queue(&binding)?;", "", [OPS]),
    "C8-prior-failures-dropped": (O, "telemetry_failures: prior.map(|s| s.telemetry_failures).unwrap_or(0),", "telemetry_failures: { let _ = prior; 0 },", [OPS]),
    "C9-missing-spool-binding-fails": (O, "Err(e) if e.kind() == std::io::ErrorKind::NotFound => spool", "Err(e) if false && e.kind() == std::io::ErrorKind::NotFound => spool", [OPS]),
    "C10-session-update-skipped": (O, "let _ = j.session(&id, losses.load(Ordering::Relaxed), disconnected);", "let _ = (j, disconnected);", [OPS, GW]),
    "C11-ui-no-worker-failure-notice": (A, "else if(w?.telemetry_failures)notice(", "else if(false)notice(", [NODE]),
    "C12-ui-no-absent-reporter-notice": (A, "else if(!(s.reporters||[]).some(r=>!r.clean))notice(", "else if(false)notice(", [NODE]),
    "C1P-lazy-open-skips-binding": (O, "j.check_binding(spool, Some(writer))?;", "", [PROBE]),
    "C2P-no-loss-when-journal-absent": (O, "if journal.as_mut().is_none_or(|j| j.record(&h).is_err()) {", "if journal.as_mut().is_some_and(|j| j.record(&h).is_err()) {", [PROBE]),
    "C13-ui-worker-failure-count-hidden": (A, "count(w?.telemetry_failures)+' worker reports failed'", "'0 worker reports failed'", [NODE]),
}

def run(cmd):
    if cmd[0] == "cargo": cmd = cmd[:2] + ["--target-dir", ENV["CARGO_TARGET_DIR"]] + cmd[2:]
    p = subprocess.Popen(cmd, cwd=SRC, env=ENV, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                         start_new_session=True, text=True)
    try:
        out, _ = p.communicate(timeout=180)
    except subprocess.TimeoutExpired:
        os.killpg(p.pid, signal.SIGKILL)
        out, _ = p.communicate()
        return "TIMEOUT", out
    return p.returncode, out

def classify(code, out):
    if code == "TIMEOUT":
        return "timeout(not a kill)"
    if "error[E" in out or "could not compile" in out:
        return "compile-error(not a kill)"
    if code == 0:
        return "pass"
    if "running 0 tests" in out:
        return "zero-tests"
    return "FAIL"

ids = sys.argv[2:] or list(MUTANTS)
for mid in ids:
    path, old, new, suites = MUTANTS[mid]
    full = os.path.join(SRC, path)
    original = open(full, encoding="utf-8").read()
    if original.count(old) != 1:
        print(f"{mid}: PATTERN-NOT-UNIQUE ({original.count(old)})", flush=True)
        continue
    try:
        open(full, "w", encoding="utf-8").write(original.replace(old, new))
        results = []
        for s in suites:
            t = time.time()
            code, out = run(s)
            kind = classify(code, out)
            failed = [l.split()[1] for l in out.splitlines() if l.startswith("test ") and l.endswith("FAILED")]
            failed += [l.split("not ok")[1].strip() for l in out.splitlines() if l.startswith("not ok")]
            results.append(f"{' '.join(s[-1:])}={kind}{failed if failed else ''}({time.time()-t:.0f}s)")
        killed = any("FAIL" in r for r in results)
        print(f"{mid}: {'KILLED' if killed else 'SURVIVED'} :: {'; '.join(results)}", flush=True)
    finally:
        open(full, "w", encoding="utf-8").write(original)
