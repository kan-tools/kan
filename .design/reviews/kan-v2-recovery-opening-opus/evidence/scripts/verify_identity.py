import hashlib, json, os, subprocess, sys
REPO = "/Users/m/code/kan-tools/kan/.worktrees/kan-v2-recovery-opening"
EXPORT = REPO + "/.local-state/reviews/recovery-opening"
IDENT = REPO + "/.local-state/reviews/recovery-opening-identity.json"
ident = json.load(open(IDENT))
commit = ident["commit"]
files = ident["files"]
def walk():
    out = set()
    for root, dirs, fs in os.walk(EXPORT):
        rel = os.path.relpath(root, EXPORT)
        if rel == "review-evidence" or rel.startswith("review-evidence" + os.sep):
            dirs[:] = []; continue
        for f in fs:
            p = os.path.join(root, f)
            out.add(os.path.normpath(os.path.relpath(p, EXPORT)))
        # symlinked dirs not followed by default
    return out
present = walk()
extra = sorted(present - set(files))
missing = sorted(set(files) - present)
bad = []
for rel, h in files.items():
    p = os.path.join(EXPORT, rel)
    if os.path.islink(p) or not os.path.isfile(p):
        if rel not in missing: bad.append((rel, "not-regular")); continue
        continue
    if hashlib.sha256(open(p, "rb").read()).hexdigest() != h:
        bad.append((rel, "sha256"))
# git blobs
lt = subprocess.run(["git", "-C", REPO, "ls-tree", "-r", "-z", "--full-tree", commit], capture_output=True, check=True).stdout
blobs = {}
for ent in lt.split(b"\0"):
    if not ent: continue
    meta, path = ent.split(b"\t", 1)
    mode, typ, oid = meta.split()
    blobs[path.decode()] = (mode.decode(), oid.decode())
gmiss = sorted(set(files) ^ set(blobs))
gbad = []
for rel in files:
    if rel not in blobs: continue
    p = os.path.join(EXPORT, rel)
    if not os.path.isfile(p): continue
    data = open(p, "rb").read()
    oid = hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()
    if oid != blobs[rel][1]: gbad.append(rel)
    # also check that git blob sha256 equals manifest (independent of export)
head = subprocess.run(["git", "-C", REPO, "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
print("commit", commit, "repo HEAD", head)
print("manifest files", len(files), "export files", len(present), "git tree", len(blobs))
print("extra", extra); print("missing", missing); print("sha256 mismatch", bad)
print("manifest-vs-git path diff", gmiss[:20]); print("git blob mismatch", gbad)
ok = (head == commit and extra in ([], ["north-star.json"]) and not missing and not bad and not gmiss and not gbad)
print("IDENTITY", "OK" if ok else "FAIL")
sys.exit(0 if ok else 1)
