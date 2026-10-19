"""Compare promoted rp* test functions with the retained reviewer originals.
Whitespace-normalised; reports identical / differing functions and a unified diff of differences.
usage: python3 promotion_diff.py <promoted.rs> <original1.rs> [original2.rs ...]
"""
import difflib
import re
import sys


def functions(text):
    out = {}
    for m in re.finditer(r"\n(?:#\[test\]\n)?fn (\w+)\s*\(", text):
        name = m.group(1)
        start = text.index("{", m.end())
        depth = 0
        for i in range(start, len(text)):
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
                if depth == 0:
                    out[name] = text[m.start():i + 1]
                    break
    return out


def norm(s):
    return re.sub(r"\s+", " ", s).strip()


promoted = functions(open(sys.argv[1]).read())
original = {}
for p in sys.argv[2:]:
    original.update(functions(open(p).read()))
for name in sorted(original):
    if name not in promoted:
        print(f"NOT-PROMOTED {name}")
        continue
    if norm(original[name]) == norm(promoted[name]):
        print(f"IDENTICAL {name}")
    else:
        a = re.sub(r"\s+", " ", original[name]).replace("; ", ";\n").replace("{ ", "{\n").splitlines()
        b = re.sub(r"\s+", " ", promoted[name]).replace("; ", ";\n").replace("{ ", "{\n").splitlines()
        print(f"DIFFERS {name}")
        for line in difflib.unified_diff(a, b, "original", "promoted", n=0, lineterm=""):
            print("    " + line)
for name in sorted(set(promoted) - set(original)):
    print(f"PROMOTED-ONLY {name}")
