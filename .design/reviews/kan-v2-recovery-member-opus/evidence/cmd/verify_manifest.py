#!/usr/bin/env python3
"""Verify export tracked set/hashes vs identity manifest AND git blobs at pinned commit.
Usage: verify_manifest.py <label>. Uses explicit --git-dir/-C repo, never discovery from export."""
import hashlib, json, os, subprocess, sys
EXPORT = "/Users/m/code/kan-tools/kan/.worktrees/kan-v2-recovery-member/.local-state/reviews/recovery-member"
REPO = "/Users/m/code/kan-tools/kan/.worktrees/kan-v2-recovery-member"
IDENT = os.path.join(os.path.dirname(EXPORT), "recovery-member-identity.json")
ALLOWED_EXTRA_TOP = {"north-star.json", "review-evidence"}
label = sys.argv[1] if len(sys.argv) > 1 else "check"
ident = json.load(open(IDENT))
commit = ident["commit"]; files = ident["files"]
problems = []
# 1. export tree hashes vs manifest
seen = set()
for root, dirs, fnames in os.walk(EXPORT):
    rel_root = os.path.relpath(root, EXPORT)
    if rel_root == ".":
        dirs[:] = [d for d in dirs if d != "review-evidence"]
    for f in fnames:
        rel = os.path.normpath(os.path.join(rel_root, f))
        if rel in ALLOWED_EXTRA_TOP:
            continue
        p = os.path.join(root, f)
        if os.path.islink(p):
            problems.append(f"symlink {rel}"); continue
        seen.add(rel)
        if rel not in files:
            problems.append(f"EXTRA {rel}"); continue
        h = hashlib.sha256(open(p, "rb").read()).hexdigest()
        if h != files[rel]:
            problems.append(f"HASH {rel} {h} != {files[rel]}")
for rel in files:
    if rel not in seen:
        problems.append(f"MISSING {rel}")
# 2. manifest vs git blobs at pinned commit (explicit repo)
git = ["git", "-C", REPO]
head = subprocess.run(git + ["rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
ls = subprocess.run(git + ["ls-tree", "-r", "-z", commit], capture_output=True).stdout.split(b"\0")
tree = {}
for ent in ls:
    if not ent: continue
    meta, path = ent.split(b"\t", 1)
    mode, typ, oid = meta.split()
    tree[path.decode()] = (mode.decode(), typ.decode(), oid.decode())
if set(tree) != set(files):
    problems.append(f"TREESET diff only_tree={sorted(set(tree)-set(files))[:20]} only_manifest={sorted(set(files)-set(tree))[:20]}")
# batch blob content sha256
oids = [tree[p][2] for p in sorted(files) if p in tree and tree[p][1] == "blob"]
paths = [p for p in sorted(files) if p in tree and tree[p][1] == "blob"]
proc = subprocess.run(git + ["cat-file", "--batch"], input=("\n".join(oids) + "\n").encode(), capture_output=True)
out = proc.stdout; pos = 0; mism = 0
for p, oid in zip(paths, oids):
    nl = out.index(b"\n", pos); hdr = out[pos:nl].split(); size = int(hdr[2])
    body = out[nl+1: nl+1+size]; pos = nl + 1 + size + 1
    if hashlib.sha256(body).hexdigest() != files[p]:
        mism += 1; problems.append(f"BLOB {p}")
print(f"[{label}] commit={commit} repo_HEAD={head} manifest_files={len(files)} export_files_checked={len(seen)} git_tree_entries={len(tree)} blob_mismatches={mism}")
print(f"[{label}] extras_allowed_present={[x for x in ALLOWED_EXTRA_TOP if os.path.exists(os.path.join(EXPORT,x))]}")
print(f"[{label}] problems={len(problems)}")
for x in problems[:50]: print("  ", x)
sys.exit(1 if problems else 0)
