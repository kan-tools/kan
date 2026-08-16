#!/usr/bin/env python3
"""Compare RFC 2's vendored Lexicons with a pinned kan-lexicon checkout."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "tests/fixtures/uri-v1/manifest.json"
SOURCE = json.loads(MANIFEST.read_text(encoding="utf-8"))["lexiconSource"]
UPSTREAM = Path(os.environ.get("KAN_LEXICON_CHECKOUT", ROOT.parent / "kan-lexicon"))


def fail(message: str) -> None:
    raise SystemExit(f"KAN LEXICON SYNC FAILED: {message}")


if not (UPSTREAM / ".git").exists():
    fail(f"no upstream checkout at {UPSTREAM}; set KAN_LEXICON_CHECKOUT")

revision = subprocess.run(
    ["git", "-C", str(UPSTREAM), "rev-parse", "HEAD"],
    check=True,
    text=True,
    capture_output=True,
).stdout.strip()
if revision != SOURCE["revision"]:
    fail(f"upstream HEAD is {revision}, pin is {SOURCE['revision']}")

for nsid in ("tools.kan.claim", "tools.kan.defs", "tools.kan.getClaim", "tools.kan.getSubject", "tools.kan.getIdentity"):
    name = nsid.removeprefix("tools.kan.")
    canonical = UPSTREAM / SOURCE["root"] / f"{name}.json"
    snapshot = ROOT / SOURCE["snapshots"] / f"{nsid}.json"
    if canonical.read_bytes() != snapshot.read_bytes():
        fail(f"snapshot drift: {snapshot.relative_to(ROOT)}")

print(f"kan Lexicon sync: 5 schemas match {revision}")
