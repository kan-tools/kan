import hashlib, json, os, subprocess, sys
exp, repo, man, label = sys.argv[1:5]
d = json.load(open(man))
commit = d["commit"]; files = d["files"]
tree = subprocess.run(["git","-C",repo,"ls-tree","--full-tree","-r","-z",commit],capture_output=True,check=True).stdout.split(b"\0")
blob = {}
for e in tree:
    if not e: continue
    meta, path = e.split(b"\t",1)
    mode, typ, oid = meta.split()
    blob[path.decode()] = (mode.decode(), typ.decode(), oid.decode())
print(label, "commit", commit, "manifest", len(files), "tree", len(blob))
print("manifest==tree set:", set(files)==set(blob))
bad = 0
for p, h in sorted(files.items()):
    fp = os.path.join(exp, p)
    if os.path.islink(fp):
        data = os.readlink(fp).encode()
    else:
        try: data = open(fp,"rb").read()
        except Exception as ex: print("MISSING", p, ex); bad += 1; continue
    if hashlib.sha256(data).hexdigest() != h: print("HASH MISMATCH", p); bad += 1
    # blob equality
    g = "blob %d\0" % len(data)
    if blob.get(p,("","",""))[1]=="blob" and hashlib.sha1(g.encode()+data).hexdigest()!=blob[p][2]:
        print("BLOB MISMATCH", p); bad += 1
actual = set()
for root, dirs, fs in os.walk(exp):
    rel = os.path.relpath(root, exp)
    if rel == "review-evidence" or rel.startswith("review-evidence/"):
        dirs[:] = []; continue
    for f in fs:
        actual.add(os.path.normpath(os.path.join(rel, f)) if rel != "." else f)
    for dn in list(dirs):
        dp = os.path.join(root, dn)
        if os.path.islink(dp): actual.add(os.path.normpath(os.path.relpath(dp, exp)))
extra = sorted(actual - set(files)); missing = sorted(set(files) - actual)
print("extra files:", extra)
print("missing files:", missing)
print("hash/blob mismatches:", bad)
print("RESULT", "OK" if bad==0 and not missing and extra==["north-star.json"] else "FAIL")
