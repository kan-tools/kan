import hashlib, json, os, subprocess, sys
exp = os.path.abspath(sys.argv[1]); ident = json.load(open(sys.argv[2]))
files = ident["files"]; bad = []
for p, h in sorted(files.items()):
    fp = os.path.join(exp, p)
    if not os.path.isfile(fp): bad.append(("missing", p)); continue
    if hashlib.sha256(open(fp, "rb").read()).hexdigest() != h: bad.append(("hash", p))
# git tree comparison
out = subprocess.run(["git", "-C", exp, "ls-tree", "-r", "--full-tree", "-z", ident["commit"]], capture_output=True, check=True).stdout
tree = {}
for ent in out.split(b"\0"):
    if not ent: continue
    meta, path = ent.split(b"\t", 1); mode, typ, oid = meta.split()
    tree[path.decode()] = (mode.decode(), typ.decode(), oid.decode())
blobs = {p for p, (m, t, o) in tree.items() if t == "blob"}
nonblob = {p: v for p, v in tree.items() if v[1] != "blob"}
gitbad = []
for p in sorted(blobs):
    fp = os.path.join(exp, p)
    if tree[p][0] == "120000":
        if not os.path.islink(fp): gitbad.append(("symlink-missing", p))
        continue
    if not os.path.isfile(fp): gitbad.append(("git-missing", p)); continue
    oid = subprocess.run(["git", "hash-object", "--no-filters", fp], capture_output=True, text=True, cwd="/", check=True).stdout.strip() if False else None
    data = open(fp, "rb").read()
    h = hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()
    if h != tree[p][2]: gitbad.append(("git-oid", p))
# extra files in export not in tree (excluding review-evidence, target)
extra = []
for dp, dns, fns in os.walk(exp):
    rel = os.path.relpath(dp, exp)
    if rel == "review-evidence" or rel.startswith("review-evidence" + os.sep): dns[:] = []; continue
    for f in fns:
        r = os.path.normpath(os.path.join(rel, f))
        if r not in blobs: extra.append(r)
print("commit", ident["commit"])
print("identity_files", len(files), "identity_bad", len(bad), bad[:20])
print("tree_blobs", len(blobs), "nonblob", nonblob, "git_bad", len(gitbad), gitbad[:20])
print("identity_not_in_tree", sorted(set(files) - blobs)[:20], "tree_not_in_identity", len(blobs - set(files)), sorted(blobs - set(files))[:20])
print("extra_untracked_in_export", len(extra), extra[:40])
sys.exit(1 if bad or gitbad or extra else 0)
