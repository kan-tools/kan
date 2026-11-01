#!/usr/bin/env python3
"""Small actual-CLI/MCP capture and backup-recovery qualification; synthetic data.

Run only with the newly built binary. Never uses user keys, agents, or fixtures.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import select
import socket
import subprocess
import sys
import tempfile
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, x25519

os.umask(0o077)
source = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('project', source / 'kan-project.py')
integration = importlib.util.module_from_spec(spec)
spec.loader.exec_module(integration)
binary = Path(sys.argv[1]).resolve(strict=True)


def b58(data):
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    n = int.from_bytes(data, 'big')
    result = ''
    while n:
        n, i = divmod(n, 58)
        result = alphabet[i] + result
    return '1' * (len(data) - len(data.lstrip(b'\0'))) + result


def put(path, value):
    raw = value if isinstance(value, bytes) else json.dumps(value).encode()
    with path.open('xb') as out:
        out.write(raw)
    path.chmod(0o600)
    return str(path)


def key(root, name):
    k = ec.generate_private_key(ec.SECP256R1())
    path = put(root / (name + '.key'), k.private_numbers().private_value.to_bytes(32, 'big'))
    pub = k.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint)
    return path, 'did:key:z' + b58(b'\x80\x24' + pub)


def run(*args, ok=True):
    r = subprocess.run([str(binary), '--no-migration-notice', *map(str, args)], capture_output=True, timeout=120)
    assert (r.returncode == 0) == ok, (list(args)[:1], r.returncode, r.stderr.decode()[:400])
    return r


class Mcp:
    def __init__(self, config, signing):
        self.proc = subprocess.Popen([str(binary), '--no-migration-notice', 'library', '--config', str(config), '--signing-key', signing, '--mcp'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.id = 0
        self.rpc('initialize', {'protocolVersion': '2025-06-18', 'capabilities': {}, 'clientInfo': {'name': 'project-qualification', 'version': '1'}})
        self.proc.stdin.write(b'{"jsonrpc":"2.0","method":"notifications/initialized"}\n')
        self.proc.stdin.flush()

    def rpc(self, method, params):
        self.id += 1
        self.proc.stdin.write((json.dumps({'jsonrpc': '2.0', 'id': self.id, 'method': method, 'params': params}) + '\n').encode())
        self.proc.stdin.flush()
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            ready, _, _ = select.select([self.proc.stdout], [], [], max(0, deadline - time.monotonic()))
            assert ready, 'MCP response deadline'
            line = self.proc.stdout.readline()
            assert line, 'MCP closed early'
            value = json.loads(line)
            if value.get('id') == self.id:
                assert 'error' not in value, value
                return value['result']
        raise AssertionError('MCP response deadline')

    def call(self, name, args, ok=True):
        r = self.rpc('tools/call', {'name': name, 'arguments': args})
        assert bool(r.get('isError')) != ok, r
        assert json.loads(r['content'][0]['text']) == r['structuredContent'], 'text and structured result must agree'
        return r['structuredContent']

    def close(self):
        self.proc.stdin.close()
        self.proc.wait(timeout=10)
        assert self.proc.returncode == 0


def read_decision(client, marker):
    catalog = client.call('kan_v2_catalog', {})
    assert catalog['mcp_authority'] == {'read': True, 'write': False, 'owner': False}
    source_id = catalog['scopes'][0]['id']
    page = client.call('kan_v2_discover', {'source': source_id, 'limit': 20})
    tokens = [r['record']['selection'] for r in page['records']]
    assert tokens
    content = client.call('kan_v2_content', {'source': source_id, 'pin': page['pin'], 'selections': tokens, 'kind': 'attempt'})
    assert marker in json.dumps(content), 'decoded content must contain actual selected decision'
    assert any(g['request']['citation_sets'] for g in content['groups']), 'decoded text must retain source citations'
    assert content['coverage'] and content['occurrences']
    assert not any(k in content for k in ['bytes_hex', 'raw_hex'])
    bad = client.call('kan_v2_discover', {'source': source_id, 'cursor': page['records'][0]['record']['selection']}, False)
    assert bad['field'] == 'arguments.pin'
    wrong = json.loads(json.dumps(page['pin']))
    wrong['request'] = '00'
    denied = client.call('kan_v2_content', {'source': source_id, 'pin': wrong, 'selections': tokens}, False)
    assert denied['error'] in {'invalid-request', 'access-limited', 'corrupt'}
    denied = client.call('kan_v2_read', {'query': {'action': 'annotation-drain', 'destination': 'not-enabled'}}, False)
    assert denied['error'] == 'capability-required'
    record = page['records'][0]['record']
    reference = {'version': 1, 'binding': catalog['scopes'][0]['binding'],
                 'coordinate': {'through': record['sequence'], 'manifest': record['manifest'], 'attestation': record['attestation']}, 'receipt': record['receipt']}
    resolved = client.call('kan_v2_read', {'query': {'action': 'resolve-reference', 'reference': reference}})
    assert page['records'][0]['uri'] == resolved['uri']
    portable = client.call('kan_v2_reference', {'uri': page['records'][0]['uri']})
    assert portable['reference'] == reference and portable['uri'] == resolved['uri']
    return len(page['records'])


with tempfile.TemporaryDirectory(prefix='kan-project-qualification-') as temp:
    root = Path(temp).resolve()
    root.chmod(0o700)
    for name in ['work', 'second-worktree', 'transcripts-actual-name', 'runtime', 'recovered']:
        (root / name).mkdir(mode=0o700)
    issuer_key, issuer = key(root, 'issuer')
    writer_key, writer = key(root, 'writer')
    reader_key, reader = key(root, 'reader')
    recipient_key = x25519.X25519PrivateKey.generate()
    recipient_private = put(root / 'recipient.key', recipient_key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()))
    recipient = recipient_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    archive_id, scope = '15' * 32, '16' * 32
    binding = put(root / 'binding.json', {'archive': archive_id, 'scope': scope, 'issuer': issuer})
    grants = put(root / 'grants.json', [{'principal': writer, 'append': True, 'inventory': False}, {'principal': reader, 'append': False, 'inventory': True}])
    reserved = [socket.socket(), socket.socket()]
    try:
        for sock in reserved:
            sock.bind(('127.0.0.1', 0))
        ports = [sock.getsockname()[1] for sock in reserved]
    finally:
        for sock in reserved:
            sock.close()
    assert ports[0] != ports[1]
    reader_config = root / 'reader.json'
    put(reader_config, [{'archive': archive_id, 'scope': scope, 'issuer': issuer, 'profile': 'admitted', 'protocol': 'kan-proof-reader/1', 'endpoint': f'http://127.0.0.1:{ports[1]}/v2/read', 'private_key_file': recipient_private}])
    archive = root / 'archive'
    proof = ['--proof-archive', archive_id, '--proof-scope', scope, '--proof-issuer', issuer]
    run('init', archive, *proof)
    spool = root / 'spool.sqlite'
    run('spool-init', spool, '--scope', scope, '--writer', writer, '--audience', issuer, '--budget', str(16 * 1024 * 1024))
    services = [{'role': role, 'archive': str(archive), 'binding': binding, 'signing_key': issuer_key, 'grants': grants, 'listen': f'127.0.0.1:{port}'} for role, port in zip(['serve-admitted', 'serve-proof'], ports)]
    config = root / 'project.json'
    c = {'version': 1, 'binary': str(binary), 'project_roots': [str(root / 'work'), str(root / 'second-worktree')], 'transcript_roots': [str(root / 'transcripts-actual-name')], 'runtime': str(root / 'runtime'), 'spool': str(spool), 'writer_key': writer_key, 'recipient': recipient, 'endpoint': f'http://127.0.0.1:{ports[0]}/v1/rpc', 'reader_config': str(reader_config), 'reader_key': reader_key, 'services': services, 'startup_seconds': 30}
    put(config, c)
    p = integration.Project(str(config))
    initial_cwd = Path.cwd()
    client = None
    marker = 'Synthetic accepted decision: retain the existing Day handoff; source revision qualification-1.'
    try:
        os.chdir(root / 'work')
        p.start()
        transcript = root / 'transcripts-actual-name' / 'session.jsonl'
        put(transcript, (json.dumps({'type': 'assistant', 'message': {'role': 'assistant', 'content': [{'type': 'text', 'text': marker}]}}) + '\n').encode())
        observed = p.capture(json.dumps({'hook_event_name': 'KanFinalSnapshot', 'origin': 'explicit-operator-backfill', 'cwd': str(root / 'work'), 'session_id': 'synthetic-session', 'transcript_path': str(transcript)}).encode(), True)
        assert observed['status'] == 'acknowledged', observed
        health = p.health()
        assert health['delivery']['pending'] == 0 and health['capture_completeness'] == 'not-verified'
        client = Mcp(reader_config, reader_key)
        tools = client.rpc('tools/list', {})['tools']
        names = {t['name'] for t in tools}
        assert {'kan_v2_catalog', 'kan_v2_help', 'kan_v2_discover', 'kan_v2_content', 'kan_v2_session', 'kan_v2_reference'} <= names
        assert 'kan_v2_owner' not in names and 'kan_v2_write' not in names
        schemas = {t['name']: t['inputSchema'] for t in tools}
        assert all(s.get('type') == 'object' for s in schemas.values()), 'every advertised MCP root must be an object'
        assert schemas['kan_v2_discover']['properties']['source']['type'] == 'string'
        assert 'query' not in schemas['kan_v2_discover']['properties']
        bad = client.call('kan_v2_content', {'source': 'selected', 'selections': []}, False)
        assert bad['field'] == 'arguments.pin'
        bad = client.call('kan_v2_discover', {'source': 42, 'private-secret-field': 'private-secret-value'}, False)
        assert 'private-secret' not in json.dumps(bad)
        count = read_decision(client, marker)
        client.close()
        client = None
        p.stop()
        database = archive / 'archive.sqlite'
        before = hashlib.sha256(database.read_bytes()).hexdigest()
        mismatch = run('backup', database, root / 'wrong.sqlite', *proof, ok=False)
        assert b'archive DIRECTORY' in mismatch.stderr
        mismatch = run('read-record', database, '1', ok=False)
        assert b'unsigned profile 1 only' in mismatch.stderr
        backup = root / 'backup.sqlite'
        run('backup', archive, backup, *proof)
        verified = json.loads(run('verify', backup, *proof).stdout)
        recovered = root / 'recovered' / 'archive.sqlite'
        run('recover', backup, recovered, *proof)
        restored = json.loads(run('verify', recovered, *proof).stdout)
        for field in ['objects', 'commits', 'bytes', 'tip', 'through']:
            assert restored[field] == verified[field], field
        assert hashlib.sha256(database.read_bytes()).hexdigest() == before
        # Fresh process reads only the recovered archive, with the original
        # source moved out of its configured location and no admitted service.
        archive.rename(root / 'unavailable-original')
        c['services'] = [{**services[1], 'archive': str(recovered.parent)}]
        config.write_text(json.dumps(c))
        p = integration.Project(str(config))
        os.chdir(root / 'second-worktree')
        p.start()
        client = Mcp(reader_config, reader_key)
        assert read_decision(client, marker) == count
        client.close()
        client = None
        print(json.dumps({'qualification': 'project-capture-and-typed-mcp', 'status': 'passed', 'captured_records': count, 'decoded_decision_and_citations': True, 'fresh_client_recovery_readback': True, 'backup_verification': verified['verification'], 'fixture': 'synthetic, same-host, no production key-custody claim'}))
    finally:
        if client is not None:
            client.proc.terminate()
            client.proc.wait(timeout=10)
        p.stop()
        os.chdir(initial_cwd)
