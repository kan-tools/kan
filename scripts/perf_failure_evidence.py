#!/usr/bin/env python3
"""Retain bounded synthetic perf log bytes before scratch cleanup, never keys."""
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

MAX_BYTES = 64 * 1024 * 1024
FILES = ("repo.car", "HEAD")


def collect(work, destination, claims, subjects, failed_claim):
    work, destination = Path(work), Path(destination)
    if not destination.is_absolute():
        raise ValueError("failure evidence destination must be absolute")
    destination.mkdir(parents=True, exist_ok=True)
    # Never overwrite earlier evidence, including a previous attempt at this point.
    output = destination / f"claims-{claims}-subjects-{subjects}-failed-{failed_claim}"
    output.mkdir(mode=0o700)
    manifest = {"claims": claims, "subjects": subjects, "failed_claim": failed_claim,
                "kind": "synthetic-perf-only", "files": {}}
    remaining = MAX_BYTES
    for name in FILES:
        source = work / ".kan" / "log" / name
        # The perf runner owns this disposable workspace. Do not follow a
        # substituted final component or copy non-regular files.
        try:
            fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except FileNotFoundError:
            manifest["files"][name] = {"state": "absent"}
            continue
        with os.fdopen(fd, "rb") as handle:
            info = os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode):
                raise ValueError("failure evidence must be a regular file")
            if info.st_size > remaining:
                manifest["files"][name] = {"state": "over-budget", "bytes": info.st_size}
                continue
            data = handle.read(remaining + 1)
            if len(data) != info.st_size or len(data) > remaining:
                raise ValueError("failure evidence changed during acquisition")
        with (output / name).open("xb") as handle:
            handle.write(data)
        remaining -= len(data)
        manifest["files"][name] = {"state": "retained", "bytes": len(data),
                                    "sha256": hashlib.sha256(data).hexdigest()}
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return output


if __name__ == "__main__":
    if len(sys.argv) != 6:
        raise SystemExit("usage: perf_failure_evidence.py scratch absolute-output claims subjects failed-claim")
    print(collect(sys.argv[1], sys.argv[2], *(int(x) for x in sys.argv[3:])))
