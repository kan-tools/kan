import hashlib, json, os, shutil, signal, sqlite3, subprocess, sys, tempfile, time, urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BIN = ROOT.parent / 'kan-v2-library-resilience/.local-state/target/debug/kan-v2'
TOKEN = 'synthetic-restart-browser-token-32-plus'
LOG = ROOT / '.local-state/reviews/restart-browser.jsonl'
server = None
url = None

def record(kind, **values):
    value = dict(kind=kind, **values)
    with LOG.open('a') as f: f.write(json.dumps(value) + '\n')
    print(json.dumps(value), flush=True)

def cli(*args):
    return subprocess.run([str(BIN), *map(str, args)], capture_output=True, text=True, check=True)

def stop_server():
    global server
    if server is not None:
        server.send_signal(signal.SIGINT)
        try: server.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server.kill(); server.wait()
        server = None

def start_server(collection, token_file, listen):
    global server, url
    server = subprocess.Popen([str(BIN), 'dashboard', str(collection), '--listen', listen,
                               '--token-file', str(token_file)], stdout=subprocess.DEVNULL,
                              stderr=subprocess.PIPE, text=True)
    line = server.stderr.readline().strip()
    if not line.startswith('dashboard http://'): raise RuntimeError(line)
    url = line.removeprefix('dashboard ')
    return url

def api(path, method='GET'):
    request = urllib.request.Request(url + path, method=method,
        headers={'Authorization': 'Bearer ' + TOKEN})
    with urllib.request.urlopen(request, timeout=5) as response:
        return json.load(response)

def row(db, n):
    h = dict(attempt=f'{n:064x}', observer='collector', observed=n,
             locally_queued=n-1, unconfirmed=1, recording_gap=True,
             remote_acknowledged=False, status=200, outcome='completed')
    with sqlite3.connect(db) as c:
        c.execute('INSERT INTO attempts VALUES(?,?,?,?,?,?)',
                  (h['attempt'], int(time.time()), n, n-1, 1, json.dumps(h)))

try:
    with tempfile.TemporaryDirectory(prefix='restart-browser-', dir=ROOT/'.local-state') as tmp:
        tmp = Path(tmp)
        shutil.copy2(BIN, tmp/'kan-v2')
        BIN = tmp/'kan-v2'
        issuer = json.loads((ROOT/'.design/fixtures/service-attestation-v1.json').read_text())['pinnedIssuer']
        spool, health, collection, token_file = [tmp/x for x in ['spool','health','collection','token']]
        token_file.write_text(TOKEN); token_file.chmod(0o600)
        cli('spool-init', spool, '--scope', '01'*32, '--writer', issuer,
            '--audience', issuer, '--budget', 1048576)
        cli('ops-init', health, '--spool', spool)
        row(health, 1)
        cli('ops-adopt', health, collection)
        start_server(collection, token_file, '127.0.0.1:0')
        with urllib.request.urlopen(url+'/app.js',timeout=5) as response: served=response.read()
        expected=subprocess.check_output(['git','show','7126848:web/operations/app.js'],cwd=ROOT)
        assert served == expected, 'served asset differs from reviewed production fix'
        record('ready', url=url, pid=server.pid, synthetic_root=str(tmp),
               app_sha256=hashlib.sha256(served).hexdigest(),
               binary_sha256=hashlib.sha256(BIN.read_bytes()).hexdigest())
        for line in sys.stdin:
            action=line.strip()
            if action == 'stop': break
            if action == 'sample': record('sample', sample=api('/api/overview')); continue
            if action != 'advance': continue
            old = api('/api/overview')
            assert old['state']=='completed' and old['last_job']==1
            started=time.monotonic(); listen=url.removeprefix('http://')
            stop_server()
            manifest=json.loads((collection/'manifest.json').read_text())
            row(collection/('generation-'+manifest['active']+'.sqlite'),2)
            start_server(collection, token_file, listen)
            api('/api/overview/refresh','POST')
            for _ in range(100):
                fresh=api('/api/overview')
                if fresh['state']=='completed':break
                time.sleep(.02)
            assert fresh['last_job']==old['last_job']==1
            assert fresh['last']['manifest_sha256']==old['last']['manifest_sha256']
            assert fresh['last']['totals']['attempts']=='2'
            record('restarted', seconds=time.monotonic()-started, pid=server.pid,
                   old=old, fresh=fresh)
        stop_server()
    record('cleaned', synthetic_root_removed=not tmp.exists())
finally:
    stop_server()
