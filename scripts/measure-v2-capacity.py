#!/usr/bin/env python3
"""Measure an already compiled Linux evidence_inventory test executable.

No builds, fixture reuse, sparse files, cache dropping, or automatic cleanup.
The destination must not exist. Keep results/worker logs even on failure.
"""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import shutil
import subprocess
import time

GIB = 1024 ** 3


def distribution(values):
    values = sorted(values)
    return {
        "count": len(values),
        **{f"p{p}": values[max(0, math.ceil(len(values) * p / 100) - 1)]
           for p in (50, 95, 99)},
        "max": values[-1],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--directory", required=True, type=Path)
    parser.add_argument("--gib", required=True, type=int, choices=(10, 100))
    parser.add_argument("--samples", type=int, default=32)
    args = parser.parse_args()
    if platform.system() != "Linux":
        parser.error("Linux /proc accounting is required; do not run large fixtures on the laptop")
    if not 8 <= args.samples <= 256:
        parser.error("--samples must be between 8 and 256")
    binary = args.binary.resolve(strict=True)
    binary_digest = hashlib.sha256()
    with binary.open("rb") as executable:
        for block in iter(lambda: executable.read(1024 * 1024), b""):
            binary_digest.update(block)
    directory = args.directory.absolute()
    if directory.exists() or directory.is_symlink():
        parser.error("--directory must be a new destination (existing evidence is never replaced)")
    parent = directory.parent.resolve(strict=True)
    # The wire stores payload hex. Allow 3x opaque bytes plus 2 GiB for the
    # immutable map, SQLite indexes/journal and measured append operations.
    required = args.gib * GIB * 3 + 2 * GIB
    free = shutil.disk_usage(parent).free
    if free < required:
        parser.error(f"need {required / GIB:.1f} GiB free; found {free / GIB:.1f} GiB")
    directory.mkdir(mode=0o700)
    archive = directory / "archive"
    report = {
        "version": 1, "status": "running", "opaque_payload_gib": args.gib,
        "chunk_bytes": 1024 ** 2, "concurrency": 1, "page_rows": 1,
        "memory_limit_bytes": 512 * 1024 ** 2, "samples_per_operation": args.samples,
        "binary": str(binary), "binary_sha256": binary_digest.hexdigest(),
        "platform": platform.platform(),
        "cache_policy": "OS cache retained; each operation uses a fresh process",
        "read_accounting": "Linux rchar includes small harness reads; read_bytes is physical I/O",
        "scope": "indexed admitted storage; excludes HTTP, encryption and control history",
        "samples": [],
    }

    def save():
        (directory / "report.json").write_text(json.dumps(report, indent=2) + "\n")

    def worker(operation, number):
        env = dict(os.environ, KAN_CAPACITY_ARCHIVE=str(archive),
                   KAN_CAPACITY_OPERATION=operation,
                   KAN_CAPACITY_CHUNKS=str(args.gib * 1024))
        path = directory / f"{operation}-{number}.log"
        with path.open("w") as log:
            subprocess.run([str(binary), "--ignored", "--exact",
                            "capacity_measurements::capacity_worker", "--nocapture",
                            "--test-threads=1"], env=env, stdout=log,
                           stderr=subprocess.STDOUT, check=True, timeout=6 * 3600)
        lines = path.read_text().splitlines()
        samples = [json.loads(line.split("KAN_CAPACITY_SAMPLE=", 1)[1])
                   for line in lines if "KAN_CAPACITY_SAMPLE=" in line]
        if operation != "seed":
            if len(samples) != 1 or samples[0]["operation"] != operation:
                raise ValueError(f"missing or mismatched sample in {path}")
            report["samples"].append(samples[0])
            save()

    save()
    try:
        start = time.monotonic()
        worker("seed", 0)
        report["fixture_seconds"] = time.monotonic() - start
        stat = (archive / "archive.sqlite").stat()
        report["fixture_file_bytes"] = stat.st_size
        report["fixture_allocated_bytes"] = stat.st_blocks * 512
        if stat.st_blocks * 512 < args.gib * GIB:
            raise ValueError("fixture has fewer allocated bytes than the requested opaque payload")
        for number in range(args.samples):
            for operation in ("open", "append", "page", "source"):
                worker(operation, number)
        report["distributions"] = {
            operation: {metric: distribution([sample[metric] for sample in report["samples"]
                                               if sample["operation"] == operation])
                        for metric in ("latency_us", "syscall_read_bytes", "physical_read_bytes",
                                       "process_peak_rss_kib")}
            for operation in ("open", "append", "page", "source")
        }
        report["status"] = "complete"
    except BaseException as error:
        report["status"] = "failed"
        report["error"] = str(error)
        raise
    finally:
        save()
        print(f"Results and raw logs retained: {directory}", flush=True)


if __name__ == "__main__":
    main()
