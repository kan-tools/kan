"""Reviewer mutation driver. Usage: python3 -I mutate.py <spec.json> <outdir>
spec: [{"name","file","old","new","tests":[[suite, filter-or-null], ...]}]
Each mutant: exact single-occurrence replacement, run tests, record, restore, verify sha256."""
import hashlib, json, os, subprocess, sys, time
spec = json.load(open(sys.argv[1])); out = sys.argv[2]; os.makedirs(out, exist_ok=True)
summary = []
for m in spec:
    path = m["file"]; orig = open(path, "rb").read(); h = hashlib.sha256(orig).hexdigest()
    text = orig.decode()
    n = text.count(m["old"])
    if n != 1:
        summary.append(f'{m["name"]}: SKIPPED old-text count={n}'); continue
    try:
        open(path, "w").write(text.replace(m["old"], m["new"], 1))
        lines = []
        for suite, filt in m["tests"]:
            cmd = ["cargo", "test", "--features", "v2-crypto"] + (["--lib"] if suite == "lib" else ["--test", suite])
            if filt: cmd += [filt]
            cmd += ["--", "--test-threads=1"]
            t0 = time.time()
            try:
                r = subprocess.run(cmd, capture_output=True, text=True, timeout=m.get("timeout", 600))
                txt = r.stdout + r.stderr; rc = r.returncode
            except subprocess.TimeoutExpired as e:
                txt = f"TIMEOUT after {m.get('timeout',600)}s\n" + str(e.stdout or "") + str(e.stderr or ""); rc = "timeout"
            safe = (filt or "all").replace(":", "_")
            open(f'{out}/{m["name"]}--{suite}--{safe}.txt', "w").write(" ".join(cmd) + "\n" + txt)
            failed = [l.split()[1] for l in txt.splitlines() if l.startswith("test ") and l.rstrip().endswith("FAILED")]
            compile_err = "could not compile" in txt
            res = [l for l in txt.splitlines() if l.startswith("test result")]
            lines.append(f'  {suite}/{filt}: rc={rc} compile_error={compile_err} failed={failed} {res[-1] if res else ""} ({time.time()-t0:.1f}s)')
        status = "KILLED" if any("failed=[]" not in l or "compile_error=True" in l for l in lines) else "SURVIVED"
        summary.append(f'{m["name"]}: {status}\n' + "\n".join(lines))
    finally:
        open(path, "wb").write(orig)
        assert hashlib.sha256(open(path, "rb").read()).hexdigest() == h, "restore failed " + path
print("\n".join(summary))
open(f"{out}/SUMMARY.txt", "w").write("\n".join(summary) + "\n")
