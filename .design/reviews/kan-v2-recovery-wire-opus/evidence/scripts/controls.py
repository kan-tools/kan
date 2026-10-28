#!/usr/bin/env python3
"""Reviewer compiled controls: mutate one export source file, run named test targets,
record raw output, always restore and verify the original hash. Usage:
  controls.py <cases.json> <outdir>
cases.json: [{"name","file","old","new","tests":[target,...]}]"""
import hashlib, json, os, subprocess, sys
EXPORT = "/Users/m/code/kan-tools/kan/.worktrees/kan-v2-recovery-bundle-codec/.local-state/reviews/recovery-wire"
cases = json.load(open(sys.argv[1])); out = sys.argv[2]; os.makedirs(out, exist_ok=True)
summary = []
for c in cases:
    path = os.path.join(EXPORT, c["file"]); original = open(path, "rb").read()
    h = hashlib.sha256(original).hexdigest(); text = original.decode()
    assert text.count(c["old"]) == 1, (c["name"], text.count(c["old"]))
    try:
        open(path, "w").write(text.replace(c["old"], c["new"]))
        cmd = ["cargo", "test", "--offline", "--locked", "--features", "v2-crypto"]
        for t in c["tests"]: cmd += ["--test", t]
        cmd += ["--no-fail-fast"]
        env = dict(os.environ, REVIEW_OUT=os.path.join(out, c["name"] + "-probe-out"))
        os.makedirs(env["REVIEW_OUT"], exist_ok=True)
        r = subprocess.run(cmd, cwd=EXPORT, capture_output=True, text=True, timeout=900, env=env)
        log = "$ " + " ".join(cmd) + "\n" + r.stdout + r.stderr + f"\nexit={r.returncode}\n"
        open(os.path.join(out, c["name"] + ".txt"), "w").write(log)
        failed = sorted({l.split()[1] for l in log.splitlines() if l.startswith("test ") and l.endswith("FAILED")})
        compiled = "could not compile" not in log
        status = "NOCOMPILE" if not compiled else ("KILLED" if failed else ("SURVIVED" if r.returncode == 0 else "ERROR"))
        summary.append(f"{c['name']}\t{status}\tfailed={','.join(failed)}")
        print(summary[-1], flush=True)
    finally:
        open(path, "wb").write(original)
        assert hashlib.sha256(open(path, "rb").read()).hexdigest() == h, "restore failed " + c["name"]
open(os.path.join(out, "SUMMARY.txt"), "a").write("\n".join(summary) + "\n")
