"""One fresh 10 GiB Modal Volume probe of the first two remounted appends.

Uses existing admission boundary observers. Does not modify production storage,
reuse/reseed the retired 100 GiB fixture, or retry failed work automatically.
"""
import json
from pathlib import Path
import re
import shutil
import subprocess
import time
import uuid
import modal
from capacity_evidence import atomic_json, digest

app = modal.App('kan-v2-first-append-probe', include_source=False)
results = modal.Volume.from_name('kan-v2-capacity-results')
image = (modal.Image.from_registry('rust:1.99.1-bookworm', add_python='3.12')
         .apt_install('git', 'pkg-config', 'libssl-dev', 'strace')
         .add_local_file(Path(__file__).resolve(), '/root/modal_append_probe.py', copy=True)
         .add_local_file(Path(__file__).with_name('capacity_evidence.py'), '/root/capacity_evidence.py', copy=True))


def identity(revision, run_id):
    if not re.fullmatch('[0-9a-f]{40}', revision) or not re.fullmatch('[0-9a-f]{32}', run_id):
        raise ValueError('invalid pinned run identity')
    return f'kan-v2-probe-{revision[:12]}-{run_id}'


def run(argv, output, cwd=None, env=None, timeout=3600):
    with output.open('wb') as log:
        subprocess.run(argv, cwd=cwd, env=env, stdout=log, stderr=subprocess.STDOUT,
                       timeout=timeout, check=True)


@app.function(image=image, cpu=4, memory=24576, timeout=6*3600, retries=0,
              single_use_containers=True, env={'CARGO_BUILD_JOBS':'4','CARGO_INCREMENTAL':'0'})
def seed(revision, run_id):
    import os
    name = identity(revision, run_id)
    fixture = modal.Volume.from_name(name)
    out = Path('/results') / name
    out.mkdir(exist_ok=False)
    state = {'revision':revision,'run_id':run_id,'fixture_volume':name,'status':'running',
             'phase':'build','gib':10,'started_unix':time.time(),
             'scope':'first two remounted appends; opaque indexed storage; no latency comparison with local SSD'}
    def save():
        atomic_json(out/'run.json', state); results.commit()
    save()
    try:
        if shutil.disk_usage('/tmp').free < 15*1024**3:
            raise RuntimeError('insufficient remote build scratch')
        checkout = Path('/tmp/append-source'); checkout.mkdir()
        for n, cmd in enumerate([['git','init','.'],['git','remote','add','origin','https://github.com/kan-tools/kan.git'],
                                 ['git','fetch','--depth=1','origin',revision],['git','checkout','--detach','FETCH_HEAD']]):
            run(cmd,out/f'git-{n}.log',checkout,timeout=300)
        if subprocess.check_output(['git','rev-parse','HEAD'],cwd=checkout,text=True).strip()!=revision:
            raise ValueError('source revision mismatch')
        run(['cargo','test','--release','--locked','--features','v2-crypto','--test','evidence_inventory','--no-run','--message-format=json'],out/'build.jsonl',checkout)
        events=[]
        for line in (out/'build.jsonl').read_text().splitlines():
            try: event=json.loads(line)
            except json.JSONDecodeError: continue
            if event.get('reason')=='compiler-artifact' and event.get('target',{}).get('name')=='evidence_inventory' and event.get('executable'):
                events.append(event['executable'])
        if len(events)!=1: raise ValueError('expected exactly one test executable')
        binary=Path('/fixture/worker');shutil.copy2(events[0],binary)
        state.update(phase='seed',binary_sha256=digest(binary));save()
        env=dict(os.environ,KAN_CAPACITY_ARCHIVE='/fixture/archive',KAN_CAPACITY_OPERATION='seed-batch',KAN_CAPACITY_CHUNKS='10240',KAN_CAPACITY_BATCH='256')
        for batch in range(40):
            log=out/f'seed-{batch:02}.log'
            run([str(binary),'--ignored','--exact','capacity_measurements::capacity_worker','--nocapture','--test-threads=1'],log,env=env)
            matches=re.findall(r'KAN_CAPACITY_FRONTIER=(\d+)',log.read_text())
            if len(matches)!=1 or int(matches[0])!=(batch+1)*256: raise ValueError('seed frontier mismatch')
            fixture.commit();state['seeded_records']=int(matches[0]);save()
        state.update(phase='awaiting-remount',status='seeded');save()
    except BaseException as error:
        state.update(status='failed',error=f'{type(error).__name__}: {error}');save();raise
    return state


@app.function(image=image, cpu=2, memory=2048, timeout=2*3600, retries=0, single_use_containers=True)
def measure(revision, run_id):
    import os
    name=identity(revision,run_id);out=Path('/results')/name
    state=json.loads((out/'run.json').read_text())
    def save():
        atomic_json(out/'run.json',state);results.commit()
    try:
        if state['status']!='seeded' or state['seeded_records']!=10240 or state['revision']!=revision or state['run_id']!=run_id or state['binary_sha256']!=digest(Path('/fixture/worker')):
            raise ValueError('seed or executable identity mismatch')
        state.update(status='running',phase='remounted-appends');save()
        # Probe tracing support without touching the archive. Unsupported ptrace
        # is disclosed; it never causes a second measurement of the first append.
        check=subprocess.run(['strace','-o','/tmp/strace-check.log','true'],capture_output=True,timeout=30)
        state['strace_supported']=check.returncode==0
        state['strace_diagnostic']=check.stderr.decode(errors='replace')[-2048:]
        state['appends']=[]
        env=dict(os.environ,KAN_CAPACITY_ARCHIVE='/fixture/archive',KAN_CAPACITY_OPERATION='append-phases')
        for number in (1,2):
            cmd=['/fixture/worker','--ignored','--exact','capacity_measurements::capacity_worker','--nocapture','--test-threads=1']
            if state['strace_supported']:
                cmd=['strace','-tt','-T','-f','-e','trace=fsync,fdatasync,pwrite64,fcntl','-o',str(out/f'append-{number}.strace')]+cmd
            log=out/f'append-{number}.log';run(cmd,log,env=env)
            samples=[json.loads(line.split('KAN_APPEND_PHASES=',1)[1]) for line in log.read_text().splitlines() if 'KAN_APPEND_PHASES=' in line]
            if len(samples)!=1 or samples[0]['prior_records']!=10239+number: raise ValueError('append identity mismatch')
            state['appends'].append(samples[0]);save()
        modal.Volume.from_name(name).commit()
        state.update(status='complete',phase='two-appends-observed',finished_unix=time.time());save()
    except BaseException as error:
        state.update(status='failed',error=f'{type(error).__name__}: {error}');save();raise
    return state


@app.local_entrypoint()
def main(revision: str):
    run_id=uuid.uuid4().hex;name=identity(revision,run_id)
    print(json.dumps({'revision':revision,'run_id':run_id,'fixture_volume':name,'result_directory':name}),flush=True)
    modal.Volume.objects.create(name,version=2,allow_existing=False)
    volume=modal.Volume.from_name(name)
    seed.with_options(volumes={'/results':results,'/fixture':volume}).remote(revision,run_id)
    print(json.dumps(measure.with_options(volumes={'/results':results,'/fixture':volume}).remote(revision,run_id)),flush=True)
