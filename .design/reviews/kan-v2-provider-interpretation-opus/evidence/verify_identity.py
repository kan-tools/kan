#!/usr/bin/env python3
"""Verify frozen export + source worktree + commit tree against identity manifest.
Usage: verify_identity.py MANIFEST EXPORT_DIR SOURCE_REPO LABEL
Allowed extra paths in EXPORT_DIR: north-star.json and review-evidence/** (review output)."""
import hashlib, json, os, subprocess, sys
man_path, export, repo, label = sys.argv[1:5]
m = json.load(open(man_path))
files, blobs, commit = m["files"], m["git_blobs"], m["commit"]
def sha(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for c in iter(lambda: f.read(1 << 20), b""): h.update(c)
    return h.hexdigest()
def gitblob(p):
    data = open(p, "rb").read() if not os.path.islink(p) else os.readlink(p).encode()
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()
def walk(root, skip_top=()):
    out = set()
    for d, dn, fn in os.walk(root):
        rel = os.path.relpath(d, root)
        if rel == ".":
            dn[:] = [x for x in dn if x not in skip_top]
        for f in fn:
            out.add(os.path.normpath(os.path.join(rel, f)) if rel != "." else f)
        for x in dn:
            if os.path.islink(os.path.join(d, x)): out.add(os.path.normpath(os.path.join(rel, x)))
    return out
fail = []
# 1. export dir
present = walk(export, skip_top=("review-evidence",))
extra = sorted(present - set(files) - {"north-star.json"})
missing = sorted(set(files) - present)
if extra: fail.append(f"export extra paths: {extra[:20]} (n={len(extra)})")
if missing: fail.append(f"export missing paths: {missing[:20]} (n={len(missing)})")
bad = [p for p in sorted(set(files) & present) if sha(os.path.join(export, p)) != files[p] or gitblob(os.path.join(export, p)) != blobs[p]]
if bad: fail.append(f"export hash/blob mismatch: {bad[:20]} (n={len(bad)})")
# 2. commit tree
ls = subprocess.run(["git", "-C", repo, "ls-tree", "-r", "-z", "--full-tree", commit], capture_output=True, check=True).stdout.split(b"\0")
tree = {}
for e in ls:
    if not e: continue
    meta, path = e.split(b"\t", 1); tree[path.decode()] = meta.split()[2].decode()
if set(tree) != set(files): fail.append(f"commit tree path set differs: +{sorted(set(tree)-set(files))[:10]} -{sorted(set(files)-set(tree))[:10]}")
tb = [p for p in tree if p in blobs and tree[p] != blobs[p]]
if tb: fail.append(f"commit tree blob mismatch: {tb[:20]}")
head = subprocess.run(["git", "-C", repo, "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
if head != commit: fail.append(f"source HEAD {head} != pinned {commit}")
st = subprocess.run(["git", "-C", repo, "status", "--porcelain", "--untracked-files=all"], capture_output=True, text=True).stdout
if st.strip(): fail.append(f"source worktree not clean:\n{st[:2000]}")
# 3. source worktree bytes
sb = [p for p in files if not os.path.lexists(os.path.join(repo, p)) or sha(os.path.join(repo, p)) != files[p]]
if sb: fail.append(f"source worktree sha mismatch: {sb[:20]} (n={len(sb)})")
print(f"[{label}] commit={commit} head={head} manifest_paths={len(files)} export_paths={len(present)} tree_paths={len(tree)}")
print(f"[{label}] north-star.json sha256={sha(os.path.join(export,'north-star.json'))}")
print(f"[{label}] manifest sha256={sha(man_path)}")
if fail:
    print(f"[{label}] FAIL"); [print(" -", f) for f in fail]; sys.exit(1)
print(f"[{label}] PASS: export path set == manifest + north-star.json; all sha256+git-blob match; commit tree blobs match; source HEAD pinned, clean, bytes match")
