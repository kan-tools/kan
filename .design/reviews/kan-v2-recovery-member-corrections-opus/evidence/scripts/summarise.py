"""Re-summarise mutation logs by `panicked at tests/<file>.rs:<line>` plus the panic message.
(mutate.py's inline summary mis-attributed failures because cargo prints `Running` on stderr.)
usage: python3 summarise.py <mutations_dir>
"""
import re
import sys
from pathlib import Path

d = Path(sys.argv[1])
for log in sorted(d.glob("[MW]*.txt")):
    text = log.read_text()
    head = text.splitlines()[0] if text else ""
    compile_fail = "could not compile" in text
    exit_m = re.search(r"# exit=(\d+)", text)
    print(f"== {log.stem} {head} exit={exit_m.group(1) if exit_m else '?'} compile_fail={compile_fail}")
    lines = text.splitlines()
    for i, line in enumerate(lines):
        m = re.search(r"thread '([^']+)' .*panicked at tests/(\w+)\.rs:(\d+)", line)
        if m:
            msg = " | ".join(l.strip() for l in lines[i + 1:i + 4] if l.strip() and not l.startswith("note:"))
            origin = "REVIEWER-PROBE" if m.group(2).startswith("zz_") else "author-suite"
            print(f"   [{origin}] {m.group(2)}::{m.group(1)} @{m.group(3)} :: {msg[:300]}")
    if compile_fail:
        for line in lines:
            if line.startswith("error"):
                print("   COMPILE " + line[:200])
