"""Remote-only real-byte Kan capacity measurement; see docs/V2-DEPLOYMENT.md.

Only this runner is uploaded. The measured code is fetched from public Git by
full commit SHA. Importing this module does not create a cloud job or Volume.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import threading
import time
import uuid

import modal

from capacity_evidence import atomic_json, digest, inspect_archive, snapshot, validate_report, verify_snapshot, retain_logs

GIB = 1024 ** 3
VOLUME = "kan-v2-capacity-results"
RUST = "1.99.1"
app = modal.App("kan-v2-capacity", include_source=False)
results = modal.Volume.from_name(VOLUME, create_if_missing=True)
image = (
    modal.Image.from_registry(f"rust:{RUST}-bookworm", add_python="3.12")
    .apt_install("git", "pkg-config", "libssl-dev")
    .add_local_file(Path(__file__).resolve(), "/root/modal_v2_capacity.py", copy=True)
    .add_local_file(Path(__file__).with_name("capacity_evidence.py"),
                    "/root/capacity_evidence.py", copy=True)
)


def validate(revision, gib, samples, run_id):
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ValueError("revision must be a full lowercase Git commit SHA")
    if gib not in (10, 100) or not 8 <= samples <= 256:
        raise ValueError("gib must be 10 or 100; samples must be 8..256")
    if not re.fullmatch(r"[0-9a-f]{32}", run_id):
        raise ValueError("run_id must be a UUID hex string")


def executable_from(log):
    found = []
    for line in log.read_text().splitlines():
        event = json.loads(line)
        if (event.get("reason") == "compiler-artifact"
                and event.get("target", {}).get("name") == "evidence_inventory"
                and event.get("executable")):
            found.append(event["executable"])
    if len(found) != 1:
        raise ValueError("expected one compiled evidence_inventory executable")
    return found[0]


def run_command(argv, cwd, stdout, stderr, timeout):
    # A timed-out harness must not leave its seed worker consuming remote disk.
    with stdout.open("wb") as out, stderr.open("wb") as err:
        child = subprocess.Popen(argv, cwd=cwd, stdout=out, stderr=err,
                                 start_new_session=True)
        try:
            code = child.wait(timeout=timeout)
        except BaseException:
            os.killpg(child.pid, signal.SIGKILL)
            child.wait()
            raise
        if code:
            raise RuntimeError(f"{argv[0]} exited {code}; see {stdout.name}/{stderr.name}")


@app.function(
    image=image, cpu=(4.0, 4.0), memory=(18 * 1024, 24 * 1024),
    timeout=24 * 3600, retries=0,
    max_containers=1, single_use_containers=True, volumes={"/results": results},
    env={"CARGO_BUILD_JOBS": "4", "CARGO_INCREMENTAL": "0"},
)
def measure(revision: str, gib: int, samples: int, run_id: str, origin_revision: str) -> dict:
    validate(revision, gib, samples, run_id)
    output = Path("/results") / f"{revision[:12]}-{gib}g-{run_id}"
    validate(origin_revision, gib, samples, run_id)
    fixture_volume = fixture_name(origin_revision, run_id)
    identity = {"revision": revision, "gib": gib, "samples": samples,
                "run_id": run_id, "fixture_volume": fixture_volume,
                "seed_origin_revision": origin_revision}
    output.mkdir(mode=0o700, exist_ok=True)
    identity_path = output / "identity.json"
    if identity_path.exists() and json.loads(identity_path.read_text()) != identity:
        raise ValueError("run identity differs from retained results")
    atomic_json(identity_path, identity)
    previous = json.loads((output / "run.json").read_text()) if (output / "run.json").exists() else None
    if previous:
        if any(previous.get(key) != value for key, value in identity.items()):
            raise ValueError("retained run state identity mismatch")
        if previous["status"] in ("measured", "complete", "validation_failed"):
            return {"status": previous["status"], "volume": VOLUME, "directory": output.name,
                    "fixture_volume": fixture_volume, "manifest_sha256": previous["manifest_sha256"]}
        if previous.get("attempt_number", 0) >= 12 or time.time() > previous["deadline_unix"]:
            raise RuntimeError("resume attempt or 24-hour elapsed budget exhausted")
    elif origin_revision != revision:
        prior = Path("/results") / f"{origin_revision[:12]}-{gib}g-{run_id}" / "run.json"
        old = json.loads(prior.read_text())
        if (old.get("status") not in ("failed", "interrupted")
                or any(old.get(k) != identity[k] for k in ("gib", "samples", "run_id", "fixture_volume"))
                or old.get("actual_revision") != origin_revision):
            raise ValueError("only the identified stopped seed run may be adopted")
    attempt_id = uuid.uuid4().hex
    attempt_output = output / "attempts" / attempt_id
    attempt_output.mkdir(parents=True)
    if previous:
        atomic_json(attempt_output / "prior-run.json", previous)
    scratch = Path("/tmp") / f"kan-capacity-{attempt_id}"
    scratch.mkdir(mode=0o700)
    logs = scratch / "logs"
    logs.mkdir()
    checkout = scratch / "source"
    checkout.mkdir()
    fixture_store = modal.Volume.from_name(fixture_volume)
    fixture = Path("/fixture/measurement")
    state = {
        **identity, "status": "running", "phase": "building",
        "started_unix": previous["started_unix"] if previous else time.time(),
        "deadline_unix": previous["deadline_unix"] if previous else time.time() + 24 * 3600,
        "attempt_number": previous.get("attempt_number", 0) + 1 if previous else 1,
        "attempt_id": attempt_id, "rust": RUST,
        "storage_backend": "modal-volume-v2", "fixture_volume": fixture_volume,
        "cpu_limit": 4, "memory_limit_mib": 24 * 1024,
        "runner_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "evidence_helper_sha256": digest(Path(__file__).with_name("capacity_evidence.py")),
        "scope": "indexed admitted storage; single worker; OS cache retained; no HTTP or encryption",
        "fixture_retention": "unique persistent volume; remove only after read-only remount validation and evidence retrieval",
        "comparison": "Modal distributed filesystem; not a directly comparable local-SSD latency point",
    }
    stop = threading.Event()
    checkpoint_errors = []

    checkpoint_lock = threading.Lock()

    def checkpoint():
        # Periodic and phase-transition checkpoints share atomic output names.
        with checkpoint_lock:
            retain_logs(logs, attempt_output)
            retain_logs(fixture, output)
            if state.get("phase") in ("seeding", "sampling") and (fixture / "report.json").exists():
                progress = json.loads((fixture / "report.json").read_text())
                state["phase"] = progress.get("phase", state["phase"])
                state["seeded_records"] = progress.get("seeded_records")
                state["samples_completed"] = len(progress.get("samples", []))
            state["checkpoint_unix"] = time.time()
            atomic_json(output / "run.json", state)
            results.commit()

    def periodic_checkpoint():
        while not stop.wait(300):
            try:
                checkpoint()
            except Exception as error:
                checkpoint_errors.append(str(error))

    checkpoint()
    thread = threading.Thread(target=periodic_checkpoint, daemon=True)
    thread.start()
    try:
        free = shutil.disk_usage(scratch).free
        state["free_before_build_bytes"] = free
        if free < 15 * GIB:
            raise RuntimeError("insufficient remote scratch space before build")
        commands = [
            ["git", "init", "."],
            ["git", "remote", "add", "origin", "https://github.com/kan-tools/kan.git"],
            ["git", "fetch", "--depth=1", "origin", revision],
            ["git", "checkout", "--detach", "FETCH_HEAD"],
        ]
        for index, command in enumerate(commands):
            run_command(command, checkout, logs / f"git-{index}.log",
                        logs / f"git-{index}-stderr.log", 300)
        actual = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=checkout, text=True).strip()
        if actual != revision:
            raise RuntimeError("fetched checkout does not match requested revision")
        if origin_revision != revision:
            run_command(["git", "fetch", "--depth=1", "origin", origin_revision], checkout,
                        logs / "origin-fetch.log", logs / "origin-fetch-stderr.log", 300)
            run_command(["git", "diff", "--exit-code", origin_revision, revision, "--",
                         "src", "Cargo.toml", "Cargo.lock"], checkout,
                        logs / "production-equivalence.log", logs / "production-equivalence-stderr.log", 300)
        state["actual_revision"] = actual
        state["compiler"] = subprocess.check_output(["rustc", "--version"], text=True).strip()
        state["driver_sha256"] = hashlib.sha256(
            (checkout / "scripts/measure-v2-capacity.py").read_bytes()).hexdigest()
        run_command(["cargo", "test", "--release", "--locked", "--features", "v2-crypto",
                     "--test", "evidence_inventory", "--no-run", "--message-format=json"],
                    checkout, logs / "build.jsonl", logs / "build-stderr.log", 3600)
        binary = executable_from(logs / "build.jsonl")
        # Prove actual abrupt-worker recovery on a tiny temporary archive before
        # touching the retained large fixture. No additional local build.
        run_command([binary, "--exact",
                     "capacity_measurements::capacity_seed_resume_preserves_prefix_and_rejects_bad_checkpoint",
                     "--nocapture"], checkout, logs / "resume-regression.log",
                    logs / "resume-regression-stderr.log", 300)
        # Volume statfs does not describe physical capacity. The driver records
        # logical size and enforces every serving process's 512 MiB RSS gate.
        state["phase"] = "seeding"
        checkpoint()
        run_command(["python3", "scripts/measure-v2-capacity.py", "--binary", binary,
                     "--directory", str(fixture), "--gib", str(gib), "--samples", str(samples),
                     "--storage-backend", "modal-volume", "--resume", "--adopt-seed-prefix",
                     "--revision", revision, "--checkpoint-volume", fixture_volume],
                    checkout, logs / "measurement.log", logs / "measurement-stderr.log",
                    max(1, state["deadline_unix"] - time.time()))
        report = json.loads((fixture / "report.json").read_text())
        validate_report(report, gib, samples)
        state["phase"] = "hashing_retained_fixture"
        checkpoint()
        manifest = {"revision": revision, "run_id": run_id, "gib": gib,
                    "samples": samples, "fixture_volume": fixture_volume,
                    "files": snapshot(fixture)}
        manifest_path = Path("/fixture/manifest.json")
        manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
        state["manifest_sha256"] = digest(manifest_path)
        (output / "manifest.json").write_text(manifest_path.read_text())
        fixture_store.commit()
        state["status"] = "measured"
        state["phase"] = "awaiting_read_only_remount_validation"
    except BaseException as error:
        state["status"] = "failed"
        state["error"] = f"{type(error).__name__}: {error}"
        # The child process group is already stopped; retain its recoverable
        # SQLite journal and completed batch checkpoints before a Modal retry.
        try:
            fixture_store.commit()
        except Exception as commit_error:
            state["fixture_commit_error"] = repr(commit_error)
        raise
    finally:
        stop.set()
        thread.join()
        state["finished_unix"] = time.time()
        state["checkpoint_errors"] = checkpoint_errors
        checkpoint()
        print(f"Evidence: modal volume get {VOLUME} {output.name} ./capacity-results")
    return {"status": state["status"], "volume": VOLUME, "directory": output.name,
            "fixture_volume": fixture_volume, "manifest_sha256": state["manifest_sha256"]}


def fixture_name(revision, run_id):
    validate(revision, 100, 32, run_id)
    return f"kan-v2-fixture-{revision[:12]}-{run_id}"


@app.function(image=image, cpu=2, memory=1024, timeout=6 * 3600, retries=0,
              max_containers=1, single_use_containers=True)
def verify_retained(revision: str, gib: int, samples: int, run_id: str,
                    manifest_sha256: str, origin_revision: str) -> dict:
    validate(revision, gib, samples, run_id)
    output = Path("/results") / f"{revision[:12]}-{gib}g-{run_id}"
    state = json.loads((output / "run.json").read_text())
    verification = {"status": "running", "revision": revision, "run_id": run_id,
                    "fixture_volume": fixture_name(origin_revision, run_id),
                    "mount": "read-only in separate single-use container"}
    try:
        manifest_path = Path("/fixture/manifest.json")
        if state["status"] not in ("measured", "complete", "validation_failed") or digest(manifest_path) != manifest_sha256:
            raise ValueError("measurement state or manifest digest mismatch")
        manifest = json.loads(manifest_path.read_text())
        for key, expected in (("revision", revision), ("run_id", run_id), ("gib", gib),
                              ("samples", samples), ("fixture_volume", fixture_name(origin_revision, run_id))):
            if manifest[key] != expected or state[key] != expected:
                raise ValueError(f"retained run identity mismatch: {key}")
        report = json.loads(Path("/fixture/measurement/report.json").read_text())
        validate_report(report, gib, samples)
        verification["archive"] = inspect_archive(
            Path("/fixture/measurement/archive/archive.sqlite"),
            report["expected_records"], gib * GIB * 2)
        verification.update(verify_snapshot(Path("/fixture/measurement"), manifest["files"]))
        verification["manifest_sha256"] = manifest_sha256
        verification["status"] = "complete"
        state["status"] = "complete"
        state["phase"] = "validated_retained_fixture"
    except BaseException as error:
        verification.update(status="failed", error=f"{type(error).__name__}: {error}")
        state["status"] = "validation_failed"
        raise
    finally:
        atomic_json(output / "verification.json", verification)
        atomic_json(output / "run.json", state)
        results.commit()
    return verification


@app.local_entrypoint()
def main(revision: str, gib: int = 100, samples: int = 32,
         resume_revision: str = "", resume_run_id: str = ""):
    if bool(resume_revision) != bool(resume_run_id):
        raise ValueError("resume requires both original revision and run ID")
    origin_revision = resume_revision or revision
    run_id = resume_run_id or uuid.uuid4().hex
    validate(revision, gib, samples, run_id)
    print(f"Run {run_id}: {revision}, {gib} GiB; artifacts in {VOLUME}", flush=True)
    name = fixture_name(origin_revision, run_id)
    print(f"Persistent fixture: {name} (retained until validated cleanup)", flush=True)
    # Fail on collision: never attach an existing test volume by accident.
    if not resume_run_id:
        modal.Volume.objects.create(name, version=2, allow_existing=False)
    volume = modal.Volume.from_name(name)
    measured = measure.with_options(volumes={"/results": results, "/fixture": volume}).remote(
        revision, gib, samples, run_id, origin_revision)
    print(json.dumps(measured), flush=True)
    verified = verify_retained.with_options(volumes={
        "/results": results, "/fixture": volume.with_mount_options(read_only=True),
    }).remote(revision, gib, samples, run_id, measured["manifest_sha256"], origin_revision)
    print(json.dumps(verified), flush=True)
    print(f"Fixture retained for owner inspection: {name}. Retrieve evidence before deleting it.", flush=True)
