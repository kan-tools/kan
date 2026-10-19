import hashlib, json, os, sys
root = sys.argv[1]; manifest = json.load(open(sys.argv[2]))
files = manifest["files"]; bad = []; missing = []
for rel, h in files.items():
    p = os.path.join(root, rel)
    if not os.path.isfile(p): missing.append(rel); continue
    if hashlib.sha256(open(p,'rb').read()).hexdigest() != h: bad.append(rel)
extra = []
for d, dn, fn in os.walk(root):
    rd = os.path.relpath(d, root)
    if rd.split(os.sep)[0] in ("review-evidence",): dn[:] = []; continue
    for f in fn:
        rel = os.path.normpath(os.path.join(rd, f))
        if rel not in files: extra.append(rel)
print(json.dumps({"commit": manifest["commit"], "count": len(files), "mismatch": bad, "missing": missing, "extra": extra[:50], "extra_count": len(extra)}, indent=1))
