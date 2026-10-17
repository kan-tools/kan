#!/usr/bin/env python3
"""Isolated source export; bounded baseline/mutant/restoration commands.

No Git worktree and no mutation of the invoking checkout. APFS-clone the caller's
build dependencies, rebuild this package, retain logs/source, remove scratch target.
"""
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
if shutil.disk_usage(root).free < 15 * 1024**3:
    raise SystemExit('need at least 15 GiB free for scratch build')
scratch = Path(tempfile.mkdtemp(prefix='kan-restore-controls-'))
print(f'scratch: {scratch}', flush=True)
env = dict(os.environ, CARGO_BUILD_JOBS='4', CARGO_PROFILE_DEV_DEBUG='0',
           CARGO_PROFILE_TEST_DEBUG='0', CARGO_INCREMENTAL='0', CARGO_TARGET_DIR=str(scratch / 'target'))

def run(args, name, timeout=180):
    with (scratch / (name + '.log')).open('w') as out:
        child = subprocess.Popen(args, cwd=scratch, env=env, stdout=out, stderr=subprocess.STDOUT, start_new_session=True)
        try:
            code = child.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            os.killpg(child.pid, signal.SIGKILL)
            child.wait()
            raise SystemExit(f'{name}: timeout (not a runtime kill)')
    return code, (scratch / (name + '.log')).read_text()

paths = subprocess.check_output(['git', 'ls-files', '-z', '--cached', '--others', '--exclude-standard'], cwd=root).split(b'\0')
for raw in paths:
    if not raw:
        continue
    path = Path(os.fsdecode(raw))
    if path.parts[0] in ('.kan', '.day', '.local-state', 'target'):
        continue
    if (root / path).is_file() and not (root / path).is_symlink():
        (scratch / path).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(root / path, scratch / path)
try:
    subprocess.run(['cp', '-cR', str(root / 'target'), str(scratch / 'target')], check=True, timeout=60)
    code, output = run(['cargo', 'clean', '-p', 'kan'], 'clean', 60)
    if code:
        raise SystemExit(output)
    source = scratch / 'src/evidence_restore.rs'
    original = source.read_text()
    controls = [
        ('plan-pin', 'service::hex(&hash.finalize()) == pins.expected_plan', 'true', 'signed_hostile_frames_and_plans_never_publish_success'),
        ('chunk-hash', 'bytes.len() == part.length && digest(&bytes) == part.sha256', 'bytes.len() == part.length', 'signed_hostile_frames_and_plans_never_publish_success'),
        ('file-hash', 'service::hex(&full.finalize()) == source.sha256', 'true', 'signed_hostile_frames_and_plans_never_publish_success'),
        ('duplicate', 'found[ordinal].replace(seq).is_none()', '{ found[ordinal] = Some(seq); true }', 'missing_duplicate_and_corrupt_evidence_rejected'),
        ('path-safety', 'safe_path(&file.path) && paths.insert(file.path.as_str())', 'paths.insert(file.path.as_str())', 'unsafe_paths_prefixes_and_filesystem_collisions_rejected'),
        ('early-report', 'observe(Boundary::DirectoryCreated);', 'observe(Boundary::DirectoryCreated);\n crate::persistence::write_new_owner_only(crate::persistence::SurfaceWrite::EvidenceRestore, &destination.join("report.json"), b"{}").unwrap();', 'signed_hostile_frames_and_plans_never_publish_success'),
    ]
    command = ['cargo', 'test', '--features', 'v2-crypto', '--test', 'evidence_restore']
    code, output = run(command, 'baseline')
    if code or '9 passed' not in output:
        raise SystemExit('baseline failed\n' + output)
    for name, old, new, test in controls:
        if original.count(old) != 1:
            raise SystemExit(f'{name}: edit is not unique')
        try:
            source.write_text(original.replace(old, new, 1))
            code, output = run(command + [test, '--', '--exact'], name)
            if code == 0 or 'test result: FAILED' not in output or '1 failed' not in output:
                raise SystemExit(f'{name}: no named runtime failure\n{output}')
            print(f'{name}: runtime failure observed', flush=True)
        finally:
            source.write_text(original)
        code, output = run(command + [test, '--', '--exact'], name + '-restored')
        if code or '1 passed' not in output:
            raise SystemExit(f'{name}: restoration failed\n{output}')
    print('six controls killed at runtime and restored', flush=True)
finally:
    if (scratch / 'target').exists():
        shutil.rmtree(scratch / 'target')
        print('removed scratch target; source and logs retained', flush=True)
