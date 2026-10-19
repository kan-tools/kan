"""Verify the export against the frozen manifest and against Git blobs at the pinned commit.

usage: python3 -I identity_check.py <export_dir> <manifest.json> <repo> <label>
Read-only: uses `git -C <repo> ls-tree -r` and `git cat-file --batch`; no Git writes.
"""
import hashlib
import json
import os
import subprocess
import sys

export, manifest_path, repo, label = sys.argv[1:5]
ALLOWED_EXTRA_TOP = {"north-star.json", "review-evidence"}

manifest = json.load(open(manifest_path))
commit = manifest["commit"]
files = manifest["files"]
problems = []


def sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# 1. export vs manifest
on_disk = set()
for root, dirs, names in os.walk(export):
    rel_root = os.path.relpath(root, export)
    if rel_root == ".":
        dirs[:] = [d for d in dirs if d not in ALLOWED_EXTRA_TOP]
    for n in names:
        rel = os.path.normpath(os.path.join(rel_root, n))
        if rel in ALLOWED_EXTRA_TOP:
            continue
        on_disk.add(rel)
missing = sorted(set(files) - on_disk)
extra = sorted(on_disk - set(files))
mismatch = sorted(p for p in files if p in on_disk and sha(os.path.join(export, p)) != files[p])
problems += [f"missing {p}" for p in missing] + [f"extra {p}" for p in extra] + [f"sha {p}" for p in mismatch]

# 2. manifest vs git tree at the pinned commit (read-only plumbing)
head = subprocess.run(["git", "-C", repo, "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
tree = subprocess.run(["git", "-C", repo, "ls-tree", "-r", "-z", commit], capture_output=True).stdout
entries = {}
for rec in tree.split(b"\0"):
    if not rec:
        continue
    meta, path = rec.split(b"\t", 1)
    mode, typ, oid = meta.split()
    entries[path.decode()] = (mode.decode(), typ.decode(), oid.decode())
not_in_tree = sorted(set(files) - set(entries))
not_in_manifest = sorted(set(entries) - set(files))
problems += [f"manifest-not-in-tree {p}" for p in not_in_tree] + [f"tree-not-in-manifest {p}" for p in not_in_manifest]

blob_mismatch = []
proc = subprocess.Popen(["git", "-C", repo, "cat-file", "--batch"], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
for p in sorted(set(files) & set(entries)):
    mode, typ, oid = entries[p]
    if typ != "blob":
        problems.append(f"non-blob {p} {typ}")
        continue
    proc.stdin.write(oid.encode() + b"\n")
    proc.stdin.flush()
    header = proc.stdout.readline().split()
    size = int(header[2])
    data = proc.stdout.read(size)
    proc.stdout.read(1)
    if mode == "120000":
        # symlink: compare link target bytes
        local = os.readlink(os.path.join(export, p)).encode() if os.path.islink(os.path.join(export, p)) else None
        if local != data:
            blob_mismatch.append(p)
        continue
    if hashlib.sha256(data).hexdigest() != files[p]:
        blob_mismatch.append(p)
proc.stdin.close()
proc.wait()
problems += [f"blob {p}" for p in blob_mismatch]

top_extras = sorted(n for n in os.listdir(export) if n in ALLOWED_EXTRA_TOP)
print(f"[{label}] commit={commit} repo_HEAD={head} manifest_files={len(files)} export_files_checked={len(on_disk)} "
      f"git_tree_entries={len(entries)} blob_mismatches={len(blob_mismatch)}")
print(f"[{label}] extras_allowed_present={top_extras}")
print(f"[{label}] problems={len(problems)}")
for p in problems[:200]:
    print(f"[{label}]   {p}")
sys.exit(1 if problems else 0)
