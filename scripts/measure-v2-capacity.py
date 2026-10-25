#!/usr/bin/env python3
"""Measure an already compiled Linux evidence_inventory test executable.

No builds, sparse files, cache dropping, or automatic cleanup.
Explicit resume retains prior attempt logs and derives progress from the archive.
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

from capacity_evidence import atomic_json, prepare_attempt, validate_report

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
    parser.add_argument("--storage-backend", choices=("local-disk", "modal-volume"),
                        default="local-disk")
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--adopt-seed-prefix", action="store_true")
    parser.add_argument("--revision", default="unspecified")
    parser.add_argument("--checkpoint-volume")
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
    if directory.is_symlink() or (directory.exists() and not args.resume):
        parser.error("--directory must be a new destination (existing evidence is never replaced)")
    parent = directory.parent.resolve(strict=True)
    # The wire stores payload hex. Allow 3x opaque bytes plus 2 GiB for the
    # immutable map, SQLite indexes/journal and measured append operations.
    required = args.gib * GIB * 3 + 2 * GIB
    # Modal Volumes expose placeholder statfs capacity, not reserved device space.
    free = shutil.disk_usage(parent).free if args.storage_backend == "local-disk" else None
    if free is not None and free < required:
        parser.error(f"need {required / GIB:.1f} GiB free; found {free / GIB:.1f} GiB")
    directory.mkdir(mode=0o700, exist_ok=args.resume)
    archive = directory / "archive"
    volume = None
    if args.checkpoint_volume:
        import modal
        volume = modal.Volume.from_name(args.checkpoint_volume)
    attempt = prepare_attempt(directory, args.revision, args.gib, args.samples,
                              args.resume, args.adopt_seed_prefix)
    if attempt is None:
        print("Retained completed measurement verified; no samples rerun.", flush=True)
        return
    report = {
        "version": 3, "status": "running", "phase": "seeding",
        "source_revision": args.revision, "attempt_id": attempt.name,
        "storage_backend": args.storage_backend,
        "free_space_preflight": free,
        "allocation_semantics": ("local filesystem allocated blocks" if free is not None
                                 else "Modal managed volume; physical allocation not observable"),
        "opaque_payload_gib": args.gib,
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
        atomic_json(directory / "report.json", report)

    def commit():
        if volume:
            volume.commit()

    def worker(operation, number):
        env = dict(os.environ, KAN_CAPACITY_ARCHIVE=str(archive),
                   KAN_CAPACITY_OPERATION=operation,
                   KAN_CAPACITY_CHUNKS=str(args.gib * 1024), KAN_CAPACITY_BATCH="256")
        path = attempt / f"{operation}-{number}.log"
        with path.open("x") as log:
            subprocess.run([str(binary), "--ignored", "--exact",
                            "capacity_measurements::capacity_worker", "--nocapture",
                            "--test-threads=1"], env=env, stdout=log,
                           stderr=subprocess.STDOUT, check=True, timeout=45 * 60)
        lines = path.read_text().splitlines()
        samples = [json.loads(line.split("KAN_CAPACITY_SAMPLE=", 1)[1])
                   for line in lines if "KAN_CAPACITY_SAMPLE=" in line]
        if operation == "seed-batch":
            frontiers = [int(line.split("=", 1)[1]) for line in lines
                         if line.startswith("KAN_CAPACITY_FRONTIER=")]
            if len(frontiers) != 1:
                raise ValueError("missing authenticated seed frontier")
            return frontiers[0]
        if operation != "seed":
            if len(samples) != 1 or samples[0]["operation"] != operation:
                raise ValueError(f"missing or mismatched sample in {path}")
            report["samples"].append(samples[0])
            save()
            commit()

    save()
    try:
        start = time.monotonic()
        # Work loop, not status polling: each subprocess admits up to 256 MiB,
        # closes SQLite, and commits a durable filesystem checkpoint.
        number = 0
        previous = -1
        while True:
            through = worker("seed-batch", number)
            if through <= previous or through > args.gib * 1024 + 4096:
                raise ValueError("invalid seed progress or excessive interrupted appends")
            report["seeded_records"] = min(through, args.gib * 1024)
            report["archive_frontier"] = through
            save()
            commit()
            print(f"Seed frontier: {through}/{args.gib * 1024}", flush=True)
            if through >= args.gib * 1024:
                break
            previous = through
            number += 1
        report["baseline_records"] = through
        report["unmeasured_append_records"] = through - args.gib * 1024
        report["expected_records"] = through + args.samples
        report["phase"] = "sampling"
        report["fixture_seconds"] = time.monotonic() - start
        stat = (archive / "archive.sqlite").stat()
        report["fixture_file_bytes"] = stat.st_size
        report["filesystem_reported_blocks_bytes"] = stat.st_blocks * 512
        report["fixture_allocated_bytes"] = (stat.st_blocks * 512
                                             if args.storage_backend == "local-disk" else None)
        if stat.st_size < args.gib * GIB:
            raise ValueError("fixture file is smaller than the requested payload")
        if args.storage_backend == "local-disk" and stat.st_blocks * 512 < args.gib * GIB:
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
        report["phase"] = "sampled"
        validate_report(report, args.gib, args.samples)
    except BaseException as error:
        report["status"] = "failed"
        report["error"] = f"{type(error).__name__}: {error}"
        raise
    finally:
        save()
        print(f"Results and raw logs retained: {directory}", flush=True)


if __name__ == "__main__":
    main()
