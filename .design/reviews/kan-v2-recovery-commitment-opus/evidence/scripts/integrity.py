#!/usr/bin/env python3
"""Integrity check: export tree vs frozen manifest vs git blobs at manifest commit.

Usage: integrity.py <export_dir> <manifest.json> <repo> <out_label>
Excludes review-evidence/ (reviewer output) and reports any other extras.
"""
import hashlib, json, os, subprocess, sys

export, manifest_path, repo, label = sys.argv[1:5]
manifest = json.load(open(manifest_path))
commit = manifest["commit"]
files = manifest["files"]

def sha(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

on_disk = set()
for root, dirs, fnames in os.walk(export):
    rel_root = os.path.relpath(root, export)
    if rel_root == "review-evidence" or rel_root.startswith("review-evidence" + os.sep):
        dirs[:] = []
        continue
    for fn in fnames:
        rel = os.path.normpath(os.path.join(rel_root, fn))
        on_disk.add(rel)

expected = set(files)
missing = sorted(expected - on_disk)
extra = sorted(on_disk - expected)
mismatch = sorted(p for p in expected & on_disk if sha(os.path.join(export, p)) != files[p])

# git tracked set + blob hashes at commit, explicit repo
ls = subprocess.run(["git", "-C", repo, "ls-tree", "-r", "-z", "--full-tree", commit],
                    capture_output=True, check=True).stdout.split(b"\0")
git_entries = {}
for ent in ls:
    if not ent:
        continue
    meta, path = ent.split(b"\t", 1)
    mode, typ, oid = meta.split()
    git_entries[path.decode()] = (mode.decode(), typ.decode(), oid.decode())
git_set = set(p for p, (m, t, o) in git_entries.items() if t == "blob")
git_only = sorted(git_set - expected)
manifest_only = sorted(expected - git_set)

# compare blob content hash (sha256 of blob) to manifest
blob_mismatch = []
batch_in = "".join(f"{commit}:{p}\n" for p in sorted(expected & git_set)).encode()
proc = subprocess.run(["git", "-C", repo, "cat-file", "--batch"], input=batch_in,
                      capture_output=True, check=True)
out = proc.stdout
pos = 0
for p in sorted(expected & git_set):
    nl = out.index(b"\n", pos)
    header = out[pos:nl].split()
    size = int(header[2])
    body = out[nl + 1: nl + 1 + size]
    pos = nl + 1 + size + 1
    if hashlib.sha256(body).hexdigest() != files[p]:
        blob_mismatch.append(p)

# git hash-object of disk bytes vs tree oid (independent check)
oid_mismatch = []
paths = sorted(expected & git_set & on_disk)
proc = subprocess.run(["git", "-C", repo, "hash-object", "--no-filters", "--stdin-paths"],
                      input="".join(os.path.join(export, p) + "\n" for p in paths).encode(),
                      capture_output=True, check=True)
for p, oid in zip(paths, proc.stdout.decode().split()):
    if git_entries[p][2] != oid:
        oid_mismatch.append(p)

report = {
    "label": label,
    "commit": commit,
    "manifest_files": len(expected),
    "git_blobs_at_commit": len(git_set),
    "on_disk_files_excluding_review_evidence": len(on_disk),
    "missing_from_disk": missing,
    "extra_on_disk": extra,
    "disk_sha256_mismatch": mismatch,
    "git_only_not_in_manifest": git_only,
    "manifest_only_not_in_git": manifest_only,
    "git_blob_sha256_vs_manifest_mismatch": blob_mismatch,
    "disk_git_oid_mismatch": oid_mismatch,
}
print(json.dumps(report, indent=2))
ok = not (missing or mismatch or git_only or manifest_only or blob_mismatch or oid_mismatch) and extra == ["north-star.json"]
print("RESULT:", "OK (only extra: north-star.json)" if ok else "DEVIATION")
sys.exit(0 if ok else 1)
