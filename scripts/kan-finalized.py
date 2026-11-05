#!/usr/bin/env python3
"""Opt-in operational queue for frozen post-finalization consolidation.

No daemon, agent, model download or credential discovery. Capture only enqueues;
an explicit bounded drain uses the existing Kan analysis job engine. Interrupted
submission is never automatically repeated.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time

RECIPES = {'session-brief', 'decisions-and-questions', 'project-consolidation',
           'handoff-context', 'relation-suggestions'}


def policy(project):
    value = project.c.get('consolidation')
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) != {'profile', 'recipes', 'max_jobs'}:
        raise ValueError('invalid consolidation policy')
    if (not Path(value['profile']).is_absolute() or not isinstance(value['recipes'], list)
            or not 1 <= len(value['recipes']) <= 5
            or len(set(value['recipes'])) != len(value['recipes'])
            or not set(value['recipes']) <= RECIPES
            or type(value['max_jobs']) is not int or not 1 <= value['max_jobs'] <= 100):
        raise ValueError('invalid consolidation limits')
    return value


def create(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(value, stream)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())


def queue(project, record):
    config = policy(project)
    if config is None:
        return {'state': 'disabled'}
    # Stop/compaction are snapshots, not a session-finalization boundary. No
    # model execution is triggered by notes, retained reports or this queue.
    if record.get('hook_event') not in {'SessionEnd', 'KanFinalSnapshot'}:
        return {'state': 'not-finalization'}
    health = record.get('capture', {}).get('transcript', {}).get('health', {})
    attempt = health.get('attempt', '')
    if (record.get('status') != 'acknowledged' or health.get('recording_gap') is not False
            or not isinstance(attempt, str) or len(attempt) != 64
            or any(c not in '0123456789abcdef' for c in attempt)
            or type(health.get('observed')) is not int or not 1 <= health['observed'] <= 8):
        return {'state': 'not-scheduled', 'reason': 'Missing, unacknowledged, incomplete or oversized selected snapshot.'}
    session = record['session_sha256']
    key = hashlib.sha256(json.dumps([session, attempt, config], sort_keys=True).encode()).hexdigest()
    directory = project.runtime / 'consolidation'
    directory.mkdir(mode=0o700, exist_ok=True)
    project.private_directory(directory)
    # Under the maintained project's operation lock. This is an operational
    # receipt, not the encrypted source or analysis authority.
    path = directory / (key + '.json')
    if path.exists():
        return {'state': 'already-queued', 'id': key}
    reserved = sum(len(project.private_json(p)['policy']['recipes']) for p in directory.glob('*.json'))
    if reserved + len(config['recipes']) > config['max_jobs']:
        return {'state': 'quota-exhausted'}
    create(path, {'version': 1, 'id': key, 'session': session, 'attempt': attempt,
                  'observed': health['observed'], 'policy': config})
    return {'state': 'queued', 'id': key, 'model_execution': 'not-performed'}


def command(project, args, cwd, receipt, timeout=120):
    # Receipt directories and worker subprocesses contain no raw transcript or
    # key bytes. Keep stdout/stderr private for diagnostics, not in hook output.
    out = receipt.with_suffix('.stdout')
    err = receipt.with_suffix('.stderr')
    with os.fdopen(os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), 'wb') as stdout, os.fdopen(os.open(err, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), 'wb') as stderr:
        try:
            result = subprocess.run([str(project.binary), '--no-migration-notice', *map(str, args)],
                                    cwd=cwd, stdout=stdout, stderr=stderr, timeout=timeout)
        except subprocess.TimeoutExpired:
            create(receipt, {'state': 'interrupted', 'provider_outcome': 'unknown; no automatic retry'})
            raise ValueError('consolidation deadline exceeded') from None
    create(receipt, {'exit': result.returncode})
    if result.returncode or out.stat().st_size > 2 * 1024 * 1024:
        raise ValueError('consolidation command failed; inspect private receipts')
    return json.loads(out.read_bytes())


def interval(records, attempt, observed):
    selected = [row for row in records if row['description'].get('attempt') == attempt]
    if len(selected) != observed:
        raise ValueError('full finalized attempt not found within scan budget')
    ordinals = sorted(int(row['description']['ordinal']) for row in selected)
    if ordinals != list(range(observed)):
        raise ValueError('missing or repeated finalized ordinal')
    sequences = sorted(int(row['record']['sequence']) for row in selected)
    if sequences != list(range(sequences[0], sequences[-1] + 1)):
        raise ValueError('interleaved attempt requires an explicit selection; no automatic widening')
    return sequences[0], sequences[-1]


def process(project):
    config = policy(project)
    if config is None:
        return {'state': 'disabled'}
    deadline = time.monotonic() + 120
    def invoke(args, cwd, receipt):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ValueError('finalization processing budget exhausted')
        return command(project, args, cwd, receipt, timeout=remaining)
    # Only one queue event per invocation; the engine's lifetime quota remains
    # a separate, additional bound. No retry, sleep or background worker.
    directory = project.runtime / 'consolidation'
    if not directory.exists():
        return {'state': 'empty'}
    project.private_directory(directory)
    for event in sorted(directory.glob('*.json')):
        destination = directory / event.stem
        if destination.exists():
            continue  # includes failed/ambiguous outcomes; never resubmit
        destination.mkdir(mode=0o700)
        try:
            receipt = project.private_json(event)
            if receipt['policy'] != config:
                raise ValueError('queued policy changed; explicit new planning required')
            profile_path = Path(config['profile'])
            # Reuse the maintained private-file/path validators.
            profile = project.private_json(profile_path)
            cwd = Path.cwd().resolve(strict=True)
            if not any(cwd.is_relative_to(Path(root)) for root in profile['allowed_worktrees']):
                raise ValueError('current worktree not allowed by consolidation profile')
            base = ['library', '--config', profile['reader_config'], '--signing-key', profile['signing_key']]
            def read(query, name):
                request = destination / (name + '-request.json')
                create(request, query)
                return invoke(base + ['--request', request], cwd, destination / (name + '.json'))
            pin = read({'action': 'proof-snapshot', 'source': profile['source']}, 'snapshot')
            pin_file = destination / 'pin.json'
            create(pin_file, pin)
            rows, cursor = [], None
            for index in range(32):
                page = read({'action': 'proof-discover', 'source': profile['source'], 'pin': pin,
                             'cursor': cursor, 'limit': 8}, 'discovery-' + str(index))
                rows.extend(page['records'])
                if sum(r['description'].get('attempt') == receipt['attempt'] for r in rows) >= receipt['observed']:
                    break
                cursor = page.get('next')
                if cursor is None:
                    break
            start, end = interval(rows, receipt['attempt'], receipt['observed'])
            results = []
            for index, recipe in enumerate(config['recipes']):
                plan = invoke(['extract', '--profile', profile_path, '--from', start, '--through', end,
                               '--pin-file', pin_file, '--recipe', recipe, '--finalized-session', receipt['session'], '--finalized-attempt', receipt['attempt']],
                               cwd, destination / ('plan-' + str(index) + '.json'))
                # Freeze to the original discovery frontier, never a later note.
                if plan['selection']['pin'] != pin:
                    raise ValueError('finalization requires a plan at the frozen discovery pin')
                frozen = destination / ('frozen-' + str(index) + '.json')
                create(frozen, plan)
                results.append(invoke(['extract', '--profile', profile_path, '--plan', frozen, '--run'],
                                       cwd, destination / ('submit-' + str(index) + '.json')))
            create(destination / 'result.json', {'state': 'submitted', 'jobs': results})
            return {'state': 'processed', 'id': event.stem, 'jobs': len(results)}
        except Exception:
            create(destination / 'failure.json', {'state': 'not-completed', 'retry': 'explicit only; no automatic resubmission'})
            return {'state': 'not-completed', 'id': event.stem, 'diagnostics': 'private receipts retained'}
    return {'state': 'no-unstarted-events'}
