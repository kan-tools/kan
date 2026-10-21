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

GIB = 1024 ** 3
VOLUME = "kan-v2-capacity-results"
RUST = "1.99.1"
app = modal.App("kan-v2-capacity", include_source=False)
results = modal.Volume.from_name(VOLUME, create_if_missing=True)
image = (
    modal.Image.from_registry(f"rust:{RUST}-bookworm", add_python="3.12")
    .apt_install("git", "pkg-config", "libssl-dev")
    .add_local_file(Path(__file__).resolve(), "/root/modal_v2_capacity.py", copy=True)
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
    ephemeral_disk=350 * 1024, timeout=8 * 3600, retries=0,
    max_containers=1, single_use_containers=True, volumes={"/results": results},
    env={"CARGO_BUILD_JOBS": "4", "CARGO_INCREMENTAL": "0"},
)
def measure(revision: str, gib: int, samples: int, run_id: str) -> dict:
    validate(revision, gib, samples, run_id)
    output = Path("/results") / f"{revision[:12]}-{gib}g-{run_id}"
    # A retry/restart with this run ID must never replace prior evidence.
    output.mkdir(mode=0o700)
    scratch = Path("/tmp") / f"kan-capacity-{run_id}"
    scratch.mkdir(mode=0o700)
    logs = scratch / "logs"
    logs.mkdir()
    checkout = scratch / "source"
    checkout.mkdir()
    fixture = scratch / "measurement"  # Must not exist before the driver starts.
    state = {
        "revision": revision, "gib": gib, "samples": samples, "run_id": run_id,
        "status": "running", "started_unix": time.time(), "rust": RUST,
        "disk_mib": 350 * 1024, "cpu_limit": 4, "memory_limit_mib": 24 * 1024,
        "runner_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "scope": "indexed admitted storage; single worker; OS cache retained; no HTTP or encryption",
        "fixture_retention": "synthetic archive on ephemeral disk; only logs/reports retained",
    }
    stop = threading.Event()
    checkpoint_errors = []

    def checkpoint():
        for directory in (logs, fixture):
            if directory.exists():
                for source in directory.iterdir():
                    if source.is_file() and source.suffix in (".json", ".jsonl", ".log"):
                        temporary = output / (source.name + ".pending")
                        shutil.copyfile(source, temporary)
                        temporary.replace(output / source.name)
        temporary = output / "run.json.pending"
        temporary.write_text(json.dumps(state, indent=2) + "\n")
        temporary.replace(output / "run.json")
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
        if free < (gib * 3 + 20) * GIB:
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
        state["actual_revision"] = actual
        state["compiler"] = subprocess.check_output(["rustc", "--version"], text=True).strip()
        state["driver_sha256"] = hashlib.sha256(
            (checkout / "scripts/measure-v2-capacity.py").read_bytes()).hexdigest()
        run_command(["cargo", "test", "--release", "--locked", "--features", "v2-crypto",
                     "--test", "evidence_inventory", "--no-run", "--message-format=json"],
                    checkout, logs / "build.jsonl", logs / "build-stderr.log", 3600)
        binary = executable_from(logs / "build.jsonl")
        # The existing driver independently checks 302 GiB free after compilation,
        # actual allocated fixture bytes and each serving process's 512 MiB RSS gate.
        run_command(["python3", "scripts/measure-v2-capacity.py", "--binary", binary,
                     "--directory", str(fixture), "--gib", str(gib), "--samples", str(samples)],
                    checkout, logs / "measurement.log", logs / "measurement-stderr.log", 6 * 3600)
        report = json.loads((fixture / "report.json").read_text())
        if report["status"] != "complete" or len(report["samples"]) != samples * 4:
            raise RuntimeError("incomplete measurement report")
        state["status"] = "complete"
    except BaseException as error:
        state["status"] = "failed"
        state["error"] = str(error)
        raise
    finally:
        stop.set()
        thread.join()
        state["finished_unix"] = time.time()
        state["checkpoint_errors"] = checkpoint_errors
        checkpoint()
        print(f"Evidence: modal volume get {VOLUME} {output.name} ./capacity-results")
    return {"status": state["status"], "volume": VOLUME, "directory": output.name}


@app.local_entrypoint()
def main(revision: str, gib: int = 100, samples: int = 32):
    run_id = uuid.uuid4().hex
    validate(revision, gib, samples, run_id)
    print(f"Run {run_id}: {revision}, {gib} GiB; artifacts in {VOLUME}", flush=True)
    print(json.dumps(measure.remote(revision, gib, samples, run_id)))
