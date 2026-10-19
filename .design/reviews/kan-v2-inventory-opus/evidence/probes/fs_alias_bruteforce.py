# Brute-force which single-codepoint substitutions (replacing 1 or 2 ASCII chars)
# of "x.sqlite-<suffix>" the host filesystem resolves to the same existing file.
# Then compare with a Python model of the Rust helper (upper->lower full mapping).
import json, os, sys, tempfile, unicodedata
d = tempfile.mkdtemp(prefix="kanrev-fsalias-")
out = {"dir": d, "volume_case_insensitive": None, "aliases": {}}
open(os.path.join(d, "probe"), "w").close()
out["volume_case_insensitive"] = os.path.exists(os.path.join(d, "PROBE"))
def model_eq(a, b):
    return a.upper().lower() == b.upper().lower()
ranges = list(range(0x20, 0x30000))
for suffix in ["shm", "wal", "journal"]:
    name = "x.sqlite-" + suffix
    p = os.path.join(d, name); open(p, "w").close()
    ino = os.stat(p).st_ino
    found = []
    for i in range(len(suffix)):
        for l in (1, 2):
            if i + l > len(suffix): continue
            for cp in ranges:
                c = chr(cp)
                if c in "/\0": continue
                if 0xD800 <= cp <= 0xDFFF: continue
                cand = suffix[:i] + c + suffix[i + l:]
                if cand == suffix: continue
                try:
                    st = os.stat(os.path.join(d, "x.sqlite-" + cand))
                except (FileNotFoundError, OSError, UnicodeEncodeError, ValueError):
                    continue
                if st.st_ino == ino:
                    found.append({"cand": cand, "codepoints": [hex(ord(ch)) for ch in cand],
                                  "replaced": suffix[i:i + l], "model_refuses": model_eq(cand, suffix)})
    # Also: does the separator '-' have any alias?
    for cp in ranges:
        c = chr(cp)
        if c in "/\0-" or 0xD800 <= cp <= 0xDFFF: continue
        try:
            st = os.stat(os.path.join(d, "x.sqlite" + c + suffix))
        except (FileNotFoundError, OSError, UnicodeEncodeError, ValueError):
            continue
        if st.st_ino == ino:
            found.append({"cand": "SEP:" + c, "codepoints": [hex(cp)], "model_refuses": False})
    out["aliases"][suffix] = found
    os.unlink(p)
print(json.dumps(out, ensure_ascii=False, indent=1))
unaccounted = [a for s in out["aliases"].values() for a in s if not a["model_refuses"]]
print("UNACCOUNTED (fs alias not refused by name model):", json.dumps(unaccounted, ensure_ascii=False))
os.unlink(os.path.join(d, "probe")); os.rmdir(d)
