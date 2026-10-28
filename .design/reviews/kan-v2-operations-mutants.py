#!/usr/bin/env python3
"""Reviewer mutation driver (claude-opus-5-5). Applies one textual mutant at a
time to the export, runs the named test set, restores the original bytes.
Usage: mutate.py <export-root> [mutant-id ...]"""
import os, signal, subprocess, sys, time

ROOT = sys.argv[1]
SRC = os.path.join(ROOT, "src")
ENV = dict(os.environ)
ENV.pop("CARGO_TARGET_DIR", None)
ENV.update(CARGO_TARGET_DIR=os.path.join(ROOT, "target"), CARGO_INCREMENTAL="0",
           CARGO_PROFILE_DEV_DEBUG="0", CARGO_PROFILE_TEST_DEBUG="0", CARGO_BUILD_JOBS="4",
           GIT_CONFIG_COUNT="1", GIT_CONFIG_KEY_0="commit.gpgsign", GIT_CONFIG_VALUE_0="false",
           KAN_TLS_ORACLE_PYTHON="/opt/homebrew/bin/python3")
GW = ["cargo", "test", "-j4", "--features", "v2-crypto", "--test", "evidence_gateway"]
OPS = ["cargo", "test", "-j4", "--features", "v2-crypto", "--test", "evidence_operations"]
LIB = ["cargo", "test", "-j4", "--features", "v2-crypto", "--lib", "evidence_operations::tests"]
NODE = ["node", "--test", "tests/operations_ui.test.cjs"]
G, O, D, A = "src/evidence_gateway.rs", "src/evidence_operations.rs", "src/evidence_dashboard.rs", "web/operations/app.js"
MUTANTS = {
    "M1-no-v6-64-grouping": (G, "octets[8..].fill(0);", "", [GW]),
    "M2-no-v4-mapped-normalize": (G, "if let Some(v4) = v.to_ipv4_mapped() {\n                return IpAddr::V4(v4);\n            }", "", [GW]),
    "M3-per-peer-cap-off": (G, ".count()>=8 {continue;}", ".count()>=32 {continue;}", [GW]),
    "M4-global-cap-64": (G, "if pending.len()>=32 ||", "if pending.len()>=64 ||", [GW]),
    "M5-no-retry-backoff": (O, "tokio::time::sleep(Duration::from_secs(status.retry_seconds)).await;", "", [OPS]),
    "M6-nonempty-since-reset": (O, "status.nonempty_since.get_or_insert(now());", "status.nonempty_since = Some(now());", [OPS]),
    "M7-crash-reads-clean": (O, "journal.session(&id, 0, false)?;", "journal.session(&id, 0, true)?;", [OPS, LIB]),
    "M8-blocking-send": (O, "if tx.try_send(h.clone()).is_err() {", "if tx.send(h.clone()).is_err() {", [OPS]),
    "M9-no-page-cap-on-open": (O, "\"PRAGMA synchronous=FULL; PRAGMA fullfsync=ON; PRAGMA max_page_count=8192;\",", "\"PRAGMA synchronous=FULL; PRAGMA fullfsync=ON;\",", [OPS, LIB]),
    "M10-no-monotone-check": (O, "if old.is_some_and(|(o, q, u)| h.observed < o || h.locally_queued < q || h.unconfirmed < u)", "if old.is_some_and(|(o, q, u)| false && (h.observed < o || h.locally_queued < q || h.unconfirmed < u))", [OPS]),
    "M11-dup-auth-allowed": (D, "if r.headers().get_all(\"authorization\").iter().count() != 1\n                ||", "if", [OPS]),
    "M12-no-origin-check": (D, ".is_some_and(|v| v.to_str().ok() != Some(format!(\"http://{host}\").as_str()))", ".is_some_and(|_| false)", [OPS]),
    "M13-nonloopback-dashboard": (D, "if !addr.ip().is_loopback()\n        ||", "if", [OPS]),
    "M14-ui-never-stale": (A, "if(age>45)notice(", "if(age>1e12)notice(", [NODE]),
    "M15-ui-no-generation-gate": (A, "if(current===generation)render(s);", "render(s);", [NODE]),
    "M16-unclosed-always-zero": (O, "coalesce(sum(clean=0),0)", "0", [OPS]),
    "M17-no-store-dropped": (D, "(\"cache-control\",\"no-store\"),", "", [OPS]),
    "M18-no-owner-only-check": (O, "if meta.permissions().mode() & 0o077 != 0 {", "if false {", [OPS, LIB]),
    "M19-writer-binding-ignored": (O, "|| writer.is_some_and(|w| w != owner)", "", [OPS]),
    "M20-ui-token-retained-in-input": (A, "token=$('token').value;$('token').value='';", "token=$('token').value;", [NODE]),
    "M21-drop-not-counted": (O, "dropped.fetch_add(1, Ordering::Relaxed);\n        }", "\n        }", [OPS]),
    "M22-ui-stale-reporter-off": (A, "Date.now()/1000-r.updated_at>5", "false", [NODE]),
}

def run(cmd):
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
