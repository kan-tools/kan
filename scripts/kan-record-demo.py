#!/usr/bin/env python3
"""Freeze a comparative documentation exercise, then explicitly extract/read it.

Uses normal Kan commands. Never launches an agent, starts a service, finds keys,
retries a model call, promotes a report, or treats exit zero as task acceptance.
Agent sessions use the maintained project integration and typed MCP separately.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def private_json(path):
    if not path.is_absolute() or path.is_symlink():
        raise ValueError('expected an absolute private regular file')
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_uid != os.getuid() or info.st_size > 2 * 1024 * 1024:
        raise ValueError('invalid private input file')
    return json.loads(path.read_text())


def retain(path, value):
    # Create-new is deliberate: an old failed/unknown attempt is not permission
    # to rerun or overwrite the original evidence.
    with path.open('x', encoding='utf-8') as out:
        json.dump(value, out, ensure_ascii=False, indent=2)
        out.write('\n')
        out.flush()
        os.fsync(out.fileno())


class Demo:
    def __init__(self, binary, profile, output, cwd=None):
        self.binary, self.profile, self.output = map(Path, (binary, profile, output))
        self.cwd = Path(cwd or Path.cwd()).resolve(strict=True)
        if not self.binary.is_absolute() or not self.binary.is_file():
            raise ValueError('use the exact qualified private Kan binary')
        config = private_json(self.profile)
        roots = [Path(p).resolve(strict=True) for p in config['allowed_worktrees']]
        if not any(self.cwd.is_relative_to(root) for root in roots):
            raise ValueError('run inside an explicitly authorized demo worktree')
        if not self.output.is_absolute() or self.output.resolve() != self.output or any(self.output.is_relative_to(root) for root in roots):
            raise ValueError('private operator evidence must be outside agent worktrees')
        if self.output.exists():
            info = self.output.stat()
            if not self.output.is_dir() or info.st_mode & 0o077 or info.st_uid != os.getuid():
                raise ValueError('output must be an owned private directory')
        self.identity = {'binary_sha256': digest(self.binary), 'profile_sha256': digest(self.profile)}

    def call(self, *args):
        try:
            result = subprocess.run([str(self.binary), '--no-migration-notice', *map(str, args), '--profile', str(self.profile)],
                                    cwd=self.cwd, capture_output=True, timeout=180)
        except subprocess.TimeoutExpired as error:
            index = len(list(self.output.glob('command-*.json')))
            retain(self.output / ('command-%04d.json' % index), {'arguments': list(map(str, args)), 'outcome': 'timeout; provider outcome may be unknown',
                   'stdout': (error.stdout or b'')[:2 * 1024 * 1024].decode(errors='replace'), 'stderr': (error.stderr or b'')[:2 * 1024 * 1024].decode(errors='replace')})
            raise RuntimeError('command deadline; inspect retained diagnostics, never retry automatically') from error
        if len(result.stdout) > 2 * 1024 * 1024 or len(result.stderr) > 2 * 1024 * 1024:
            raise ValueError('command diagnostics exceeded the declared bound')
        # Exact diagnostics can contain source material. Retain privately,
        # never echo them into agent prompts or terminal reports.
        index=len(list(self.output.glob('command-*.json')))
        retain(self.output / ('command-%04d.json' % index), {'arguments': list(map(str,args)),
               'returncode': result.returncode, 'stdout': result.stdout.decode(errors='replace'),
               'stderr': result.stderr.decode(errors='replace')})
        if result.returncode:
            raise RuntimeError('Kan command failed; inspect retained exact command diagnostics, never retry automatically')
        return json.loads(result.stdout)

    def freeze(self, first, through):
        if self.output.exists() and any(self.output.iterdir()):
            raise ValueError('exercise already exists; do not freeze it again')
        self.output.mkdir(mode=0o700, exist_ok=True)
        plan = self.call('extract', '--from', first, '--through', through)
        retain(self.output / 'plan.json', plan)
        retain(self.output / 'frozen.json', {'version': 1, **self.identity, 'plan_sha256': digest(self.output / 'plan.json'),
               'selection': plan['selection'], 'model': plan['model'], 'recipe': plan['recipe'],
               'boundary': 'Freeze BEFORE the explicit documentation arm. This pinned interval, not later notes or doc sessions, is the extraction input.',
               'acceptance': 'not-assessed', 'provider_called': False})
        return {'state': 'frozen', 'provider_called': False}

    def check(self):
        frozen = private_json(self.output / 'frozen.json')
        if any(frozen[k] != v for k, v in self.identity.items()) or frozen['plan_sha256'] != digest(self.output / 'plan.json'):
            raise ValueError('frozen binary, profile or plan changed')
        return frozen

    def extract(self):
        self.check()
        retain(self.output / 'extraction-start.json', {'state': 'starting', 'automatic_retry': False})
        try:
            result = self.call('extract', '--plan', self.output / 'plan.json', '--run')
        except BaseException:
            retain(self.output / 'extraction-terminal.json', {'state': 'failed-or-unknown', 'automatic_retry': False})
            raise
        retain(self.output / 'extraction-terminal.json', result)
        return result

    def read(self, arm, subject=None):
        self.check()
        if (self.output / (arm + '-readback.json')).exists():
            raise ValueError('this readback is already retained')
        if arm == 'explicit':
            if not subject:
                raise ValueError('explicit readback requires its subject address, never an expected answer')
            command = ['show', subject, '--json']
        else:
            job = private_json(self.output / 'extraction-terminal.json')
            if job.get('state') != 'succeeded':
                raise ValueError('no successful derived report; preserve the failed outcome')
            command = ['report', job['id'], '--json']
        pages, cursor = [], None
        for _ in range(100):
            args = command + (['--cursor', json.dumps(cursor)] if cursor else [])
            value = self.call(*args)
            if len(json.dumps(value, ensure_ascii=False, separators=(',', ':')).encode()) > 12 * 1024:
                raise ValueError('normal presentation budget exceeded')
            pages.append(value)
            cursor = value.get('next')
            if cursor is None:
                retain(self.output / (arm + '-readback.json'), {'pages': pages, 'acceptance': 'requires actual fresh-agent result inspection'})
                return {'state': 'readback-retained', 'pages': len(pages), 'task_acceptance': 'not-assessed'}
        raise ValueError('readback exceeded its declared page bound; no silent prefix success')


def main(argv=None):
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ('binary', 'profile', 'output'):
        parser.add_argument('--' + key, required=True, type=Path)
    sub = parser.add_subparsers(dest='phase', required=True)
    freeze = sub.add_parser('freeze')
    freeze.add_argument('--from', dest='first', type=int, required=True)
    freeze.add_argument('--through', type=int, required=True)
    sub.add_parser('extract', help='explicit provider submission of the frozen plan; never an automatic retry')
    read = sub.add_parser('readback')
    read.add_argument('--arm', choices=('explicit', 'derived'), required=True)
    read.add_argument('--subject')
    args = parser.parse_args(argv)
    demo = Demo(args.binary, args.profile, args.output)
    result = demo.freeze(args.first, args.through) if args.phase == 'freeze' else demo.extract() if args.phase == 'extract' else demo.read(args.arm, args.subject)
    print(json.dumps(result))


if __name__ == '__main__':
    main()
