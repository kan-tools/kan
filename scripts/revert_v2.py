#!/usr/bin/env python3
"""Replay v2 Rust/Node/Python correction evidence using the bundled day reversion engine.

Required: --helper /absolute/path/to/day/scripts/revert-demo.py
Working diff: --tests target::exact_name,node::summary_loss_units
History: --verify COMMIT (reads that commit's actual Demonstrated-by trailer).

Runs in a permanent source export under .local-state/reversion, never in a Git
worktree; the caller's tracked source is never changed. Exports are inside its
gitignored scratch directory. Uses CARGO_TARGET_DIR only when explicitly
set by the caller; run sequentially with other Cargo jobs. Retains raw test logs.
This is the explicit mixed-language adapter; vanilla day --verify is Rust-only.
"""
from __future__ import annotations
import argparse
import importlib.util
import io
import os
from pathlib import Path
import re
import signal
import shutil
import subprocess
import sys
import tarfile
import uuid

NODE_TESTS = {
    'library_scope_shapes': ('tests/library_ui.test.cjs', 'malformed scope catalogs are rejected before any option or page request'),
    'library_retry_style': ('tests/library_ui.test.cjs', 'malformed retry clears partially rendered capabilities and keeps recovery available'),
    'library_partial_catalog': ('tests/library_ui.test.cjs', 'partial catalog coverage persists while browsing and retry clears old authority'),
    'library_capabilities': ('tests/library_ui.test.cjs', 'capability matrix renders actual service capabilities without claiming unknown support'),
    'library_unavailable': ('tests/library_ui.test.cjs', 'unavailable or unverifiable source clears plaintext but preserves other browsing'),
    'library_directional': ('tests/library_ui.test.cjs', 'directional format controls default to exact hex and permit explicit UTF-8'),
    'library_scope_switch': ('tests/library_ui.test.cjs', 'scope changes remove old-scope rows before a new pin is used'),
    'future_clock_badge': ('tests/operations_ui.test.cjs', 'future clock samples produce consistent badges and retain uncertain reporter history'),
    'summary_loss_units': ('tests/operations_ui.test.cjs', 'unsampled sessions and summary loss units are explicit'),
}
PYTHON_TESTS = {
    'recovery_identifier_bytes': ('.design/tools/recovery_bundle_schema.py', 'DraftSchema.test_identifier_byte_bounds_ascii_and_embedded_nul'),
    'bounded_pipe_cleanup': ('tests/test_revert_v2.py', 'Execution.test_detached_pipe_holder_cannot_hang_timeout_cleanup'),
}



def run_process(command, cwd, timeout):
    """Kill our POSIX group and bound pipe cleanup, including escaped pipe owners.

    Deliberately detached descendants are outside our kill group; never wait
    indefinitely for their inherited pipes or claim to have terminated them.
    """
    if os.name != 'posix':
        raise ValueError('the reversion runner requires POSIX process-group cleanup')
    process = subprocess.Popen(command, cwd=cwd, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, text=True, start_new_session=True)
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except (subprocess.TimeoutExpired, KeyboardInterrupt):
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            process.communicate(timeout=1)
        except subprocess.TimeoutExpired:
            # A descendant may leave the group while retaining our pipe. Close
            # our handles; the already-killed direct child can still be reaped.
            process.stdout.close()
            process.stderr.close()
            process.wait(timeout=1)
        raise
    return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)


def parse_result(kind, name, output, returncode):
    """One exact executed result; skips, duplicates, crashes and empty runs fail closed."""
    expression = (r'^(ok|not ok) \d+ - (.+)$' if kind == 'node' else
                  r'^(\w+) \(__main__\.(\w+)(?:\.\1)?\) \.\.\. (ok|FAIL|ERROR)$' if kind == 'python' else
                  r'^test (.+) \.\.\. (ok|FAILED)$')
    hits = []
    for line in output.splitlines():
        m = re.fullmatch(expression, line)
        if m:
            if kind == 'python':
                method, cls, verdict = m.groups()
                actual = cls + '.' + method
            else:
                verdict, actual = m.groups() if kind == 'node' else m.groups()[::-1]
            if actual == name:
                hits.append(verdict)
    if len(hits) != 1:
        return set(), set()
    if hits[0] == 'ERROR':
        raise ValueError('named Python test errored rather than failing an assertion')
    failed = hits[0] in ('not ok', 'FAILED', 'FAIL')
    if (returncode != 0) != failed:
        raise ValueError('exit status and named assertion result disagree')
    return {name}, {name} if failed else set()


def git(root, *args):
    return subprocess.check_output(['git', *args], cwd=root)


def export(root, dest, revision):
    if revision:
        raw = git(root, 'archive', revision)
        with tarfile.open(fileobj=io.BytesIO(raw)) as archive:
            # Python 3.9 has no extraction filter. Copy regular files ourselves;
            # never let tar create links, device nodes or paths outside the export.
            for member in archive:
                relative = Path(member.name)
                if relative.is_absolute() or '..' in relative.parts or not relative.parts:
                    raise ValueError('unsafe archive path')
                path = dest / relative
                if member.isdir():
                    path.mkdir(parents=True, exist_ok=True)
                elif member.isfile():
                    path.parent.mkdir(parents=True, exist_ok=True)
                    with archive.extractfile(member) as source, path.open('xb') as output:
                        shutil.copyfileobj(source, output)
                    path.chmod(member.mode & 0o777)
                else:
                    raise ValueError('source archive contains a link or special file')
    else:
        for item in git(root, 'ls-files', '-z', '--cached', '--others', '--exclude-standard').split(b'\0'):
            if not item:
                continue
            relative = Path(os.fsdecode(item))
            if relative.parts[0] in ('.kan', '.day', '.local-state', 'target'):
                continue
            source = root / relative
            if source.is_symlink():
                raise ValueError(f'refusing source symlink: {relative}')
            if source.is_file():
                target = dest / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, target)
                target.chmod(source.stat().st_mode & 0o777)
    # A self-contained scratch repository makes git apply path resolution local.
    subprocess.run(['git', 'init', '-q', str(dest)], check=True)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--helper', type=Path, required=True)
    select = ap.add_mutually_exclusive_group(required=True)
    select.add_argument('--tests')
    select.add_argument('--verify')
    ap.add_argument('--production', action='append', default=[])
    args = ap.parse_args()
    root = Path(subprocess.check_output(['git', 'rev-parse', '--show-toplevel'], text=True).strip())
    spec = importlib.util.spec_from_file_location('day_reversion', args.helper.resolve())
    engine = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(engine)
    try:
        revision = git(root, 'rev-parse', '--verify', f'{args.verify}^{{commit}}').decode().strip() if args.verify else None
        if revision:
            trailer = engine.read_trailer(revision, root)
            if trailer is None:
                raise ValueError('commit has no Demonstrated-by trailer')
            _, names, claimed = trailer
            if claimed != engine.DEMONSTRATED:
                raise ValueError('only DEMONSTRATED trailers can be verified')
            patch = engine.patch_for_rev(revision, root)
        else:
            names = args.tests.split(',')
            patch = git(root, 'diff', '--unified=0', 'HEAD').decode()
        for name in names:
            if name.startswith('node::') and name[6:] not in NODE_TESTS:
                raise ValueError(f'unknown Node test alias: {name}')
            if name.startswith('python::') and name[8:] not in PYTHON_TESTS:
                raise ValueError(f'unknown Python test alias: {name}')
            if not re.fullmatch(r'[A-Za-z0-9_]+::[A-Za-z0-9_:]+', name):
                raise ValueError(f'expected exact qualified test name: {name}')
        dest = root / '.local-state/reversion' / uuid.uuid4().hex
        dest.mkdir(parents=True, mode=0o700)
        export(root, dest, revision)
        logs = dest / 'reversion-logs'
        logs.mkdir()
        (logs / 'production.patch').write_text(patch)
        print(f'Source export and logs: {dest}', flush=True)
        counter = 0
        def run_tests(tests, cwd, target_dir):
            nonlocal counter
            results = {}
            for test in tests:
                target, exact = test.split('::', 1)
                if target == 'node':
                    path, exact = NODE_TESTS[exact]
                    command = ['node', '--test', '--test-reporter=tap', '--test-name-pattern=^'+re.escape(exact)+'$', path]
                elif target == 'python':
                    path, exact = PYTHON_TESTS[exact]
                    command = [sys.executable, path, '-v', exact]
                else:
                    command = ['cargo', 'test', '--features', 'v2-crypto']
                    command += ['--lib'] if target == 'lib' else ['--test', target]
                    command += [exact, '--', '--exact']
                counter += 1
                try:
                    run = run_process(command, cwd, timeout=240)
                except subprocess.TimeoutExpired as exc:
                    (logs / f'{counter:02d}-timeout.txt').write_text(str(exc))
                    raise engine.CouldNotCheck('RUNNER-TIMEOUT', test) from exc
                output = run.stdout + run.stderr
                (logs / f'{counter:02d}-{target}.txt').write_text(output)
                if 'could not compile' in output or '\nerror[' in output:
                    return results, False
                try:
                    results[test] = parse_result(target, exact, output, run.returncode)
                except ValueError as exc:
                    raise engine.CouldNotCheck('RUNNER-ERROR', f'{test}: {exc}') from exc
            return results, True
        engine.run_tests = run_tests
        # Restrict only when the caller explicitly supplies production paths;
        # the engine's normal test-half filtering otherwise remains unchanged.
        if revision:
            outcome, caught = engine.demonstrate(dest, patch, names, revision, args.production, [], None)
            ok = outcome == engine.DEMONSTRATED and sorted(caught) == sorted(names)
            print(f'{revision}: {outcome}; all trailer tests reproduced={ok}')
            return 0 if ok else 1
        original_git = engine.git
        untracked = git(root, 'ls-files', '--others', '--exclude-standard').decode()
        def exported_git(*argv, **kwargs):
            if argv == ('rev-parse', '--show-toplevel'):
                return str(dest)
            if argv == ('diff', '--unified=0', 'HEAD'):
                return patch
            if argv and argv[0] == 'ls-files':
                return untracked
            return original_git(*argv, **kwargs)
        engine.git = exported_git
        sys.argv = [str(args.helper), '--tests', ','.join(names)]
        for path in args.production:
            sys.argv += ['--include', path]
        return engine.main()
    except (ValueError, OSError, subprocess.CalledProcessError, engine.CouldNotCheck) as exc:
        print(f'Could not demonstrate: {exc}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
