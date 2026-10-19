#!/usr/bin/env python3
"""For each mutation log, print per failing test: panic site and left/right/message lines."""
import os, re, sys
D = sys.argv[1]
for f in sorted(os.listdir(D)):
    if not f.endswith('.txt'): continue
    s = open(os.path.join(D, f)).read()
    print(f"=== {f[:-4]}")
    for m in re.finditer(r"thread '([^']+)' \(\d+\) panicked at ([^\n]+):\n((?:[^\n]*\n){1,4})", s):
        test, site, rest = m.groups()
        rest = " | ".join(l.strip() for l in rest.splitlines() if l.strip() and not l.startswith('note:') and not l.startswith('stack'))
        print(f"  {test} @ {site}\n      {rest[:400]}")
