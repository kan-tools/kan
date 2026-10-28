"""Verify an existing measured fixture read-only; never seed or benchmark.

A distinct output directory preserves the original failure and measurement SHA.
"""
import json
from pathlib import Path
import re
import uuid
import modal

app = modal.App('kan-v2-retained-verification', include_source=False)
image = (modal.Image.debian_slim(python_version='3.12')
         .add_local_file(Path(__file__).resolve(), '/root/modal_verify_v2_capacity.py', copy=True)
         .add_local_file(Path(__file__).with_name('capacity_evidence.py'), '/root/capacity_evidence.py', copy=True))
results = modal.Volume.from_name('kan-v2-capacity-results')


def validate_request(request):
    for key in ('measured_revision', 'verifier_revision', 'seed_origin_revision'):
        if not re.fullmatch('[0-9a-f]{40}', request[key]):
            raise ValueError('invalid revision')
    if not re.fullmatch('[0-9a-f]{32}', request['run_id']):
        raise ValueError('invalid run ID')
    if not re.fullmatch('[0-9a-f]{64}', request['manifest_sha256']):
        raise ValueError('invalid manifest SHA')
    name = f"kan-v2-fixture-{request['seed_origin_revision'][:12]}-{request['run_id']}"
    if request['fixture_volume'] != name:
        raise ValueError('fixture identity mismatch')
    if request['gib'] not in (10, 100) or not 8 <= request['samples'] <= 256:
        raise ValueError('invalid sample parameters')


@app.function(image=image, cpu=2, memory=1024, timeout=6*3600, retries=0, single_use_containers=True)
def verify(request, verification_id):
    from capacity_evidence import atomic_json, digest, inspect_archive, validate_report, verify_snapshot
    validate_request(request)
    if not re.fullmatch('[0-9a-f]{32}', verification_id):
        raise ValueError('invalid verification ID')
    measured = request['measured_revision']
    prior = Path('/results') / f"{measured[:12]}-{request['gib']}g-{request['run_id']}"
    out = Path('/results') / f"verification-{request['verifier_revision'][:12]}-{verification_id}"
    out.mkdir(exist_ok=False)
    state = dict(request, status='running', phase='identity', verification_id=verification_id,
                 evidence_helper_sha256=digest(Path('/root/capacity_evidence.py')),
                 mount='read-only in separate single-use container')

    def save(phase, detail=None):
        state.update(phase=phase, progress=detail)
        atomic_json(out/'verification.json', state)
        results.commit()
        print(phase, flush=True)

    try:
        save('identity')
        old = json.loads((prior/'run.json').read_text())
        for key, expected in (('revision', measured), ('run_id', request['run_id']),
                              ('seed_origin_revision', request['seed_origin_revision']),
                              ('fixture_volume', request['fixture_volume']),
                              ('gib', request['gib']), ('samples', request['samples']),
                              ('manifest_sha256', request['manifest_sha256'])):
            if old.get(key) != expected:
                raise ValueError(f'measured run identity mismatch: {key}')
        if old['status'] not in ('measured','validation_failed','complete'):
            raise ValueError('measurement not complete')
        path = Path('/fixture/manifest.json')
        if digest(path) != request['manifest_sha256']:
            raise ValueError('manifest SHA mismatch')
        manifest = json.loads(path.read_text())
        for key in ('revision','run_id','gib','samples','fixture_volume'):
            if manifest[key] != old[key]:
                raise ValueError(f'manifest identity mismatch: {key}')
        root = Path('/fixture/measurement')
        report = json.loads((root/'report.json').read_text())
        if report['source_revision'] != measured:
            raise ValueError('report source mismatch')
        validate_report(report, request['gib'], request['samples'])
        atomic_json(out/'report.json', report)
        atomic_json(out/'manifest.json', manifest)
        atomic_json(out/'prior-run.json', old)
        state['samples_completed'] = len(report['samples'])
        save('archive_accounting')
        state['archive'] = inspect_archive(root/'archive/archive.sqlite', report['expected_records'],
                                           request['gib']*1024**3*2,
                                           expected_staged=request['expected_staged'], progress=save)
        save('full_file_hash_verification')
        state.update(verify_snapshot(root, manifest['files']))
        state['status'] = 'complete'
        save('validated_retained_fixture')
    except BaseException as error:
        state.update(status='failed', error=f'{type(error).__name__}: {error}')
        save(state['phase'], state.get('progress'))
        raise
    return {'directory': out.name, 'status': state['status']}


@app.local_entrypoint()
def main(request_file: str):
    request = json.loads(Path(request_file).read_text())
    validate_request(request)
    verification_id = uuid.uuid4().hex
    print(json.dumps({'verification_id': verification_id, 'request': request}), flush=True)
    volume = modal.Volume.from_name(request['fixture_volume'])
    print(json.dumps(verify.with_options(volumes={'/results':results,
        '/fixture':volume.with_mount_options(read_only=True)}).remote(request, verification_id)), flush=True)
