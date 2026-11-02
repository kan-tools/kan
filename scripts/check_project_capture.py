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
started = time.monotonic()


def progress(stage, **fields):
    # Synthetic fixture diagnostics only: no request arguments or key contents.
    print(json.dumps({'stage': stage, 'elapsed_seconds': round(time.monotonic() - started, 3), **fields}), flush=True)


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
    response_seconds = 90

    def __init__(self, config, signing):
        # An undrained stderr pipe can block a child independently of stdout.
        self.diagnostics = tempfile.TemporaryFile()
        self.proc = subprocess.Popen([str(binary), '--no-migration-notice', 'library', '--config', str(config), '--signing-key', signing, '--mcp'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.diagnostics)
        self.pending = bytearray()
        self.id = 0
        try:
            self.rpc('initialize', {'protocolVersion': '2025-06-18', 'capabilities': {}, 'clientInfo': {'name': 'project-qualification', 'version': '1'}})
            self.proc.stdin.write(b'{"jsonrpc":"2.0","method":"notifications/initialized"}\n')
            self.proc.stdin.flush()
        except BaseException:
            self.proc.terminate()
            self.proc.wait(timeout=10)
            self.diagnostics.close()
            raise

    def rpc(self, method, params):
        self.id += 1
        label = params.get('name', method)
        progress('mcp-start', method=label, request=self.id)
        call_started = time.monotonic()
        self.proc.stdin.write((json.dumps({'jsonrpc': '2.0', 'id': self.id, 'method': method, 'params': params}) + '\n').encode())
        self.proc.stdin.flush()
        deadline = time.monotonic() + self.response_seconds
        while time.monotonic() < deadline:
            # readline() after select can wait forever on a partial JSON line.
            # Read only available bytes and apply the deadline to the whole line.
            if b'\n' not in self.pending:
                ready, _, _ = select.select([self.proc.stdout], [], [], max(0, deadline - time.monotonic()))
                assert ready, ('MCP response deadline', label, self.id)
                chunk = os.read(self.proc.stdout.fileno(), 65536)
                assert chunk, ('MCP closed early', label, self.id)
                self.pending.extend(chunk)
                assert len(self.pending) <= 1024 * 1024, 'MCP fixture transport frame limit'
                continue
            line, _, rest = self.pending.partition(b'\n')
            self.pending = bytearray(rest)
            value = json.loads(line)
            if value.get('id') == self.id:
                assert 'error' not in value, value
                progress('mcp-complete', method=label, request=self.id, response_bytes=len(line), call_seconds=round(time.monotonic() - call_started, 3))
                return value['result']
        raise AssertionError(('MCP response deadline', label, self.id))

    def call(self, name, args, ok=True):
        r = self.rpc('tools/call', {'name': name, 'arguments': args})
        assert bool(r.get('isError')) != ok, r
        assert json.loads(r['content'][0]['text']) == r['structuredContent'], 'text and structured result must agree'
        if name != 'kan_v2_read':
            assert len(r['content'][0]['text'].encode()) <= 12 * 1024, (name, 'typed payload exceeds 12 KiB')
        return r['structuredContent']

    def close(self):
        self.proc.stdin.close()
        self.proc.wait(timeout=10)
        assert self.proc.returncode == 0
        self.diagnostics.close()


def collect_view(client, name, args):
    first = client.call(name, args)
    pages, entries, cursor = [first], list(first['entries']), first['next']
    while cursor is not None:
        assert len(pages) < 1000, 'bounded continuation count'
        page = client.call(name, {**args, 'cursor': cursor})
        entries.extend(page['entries'])
        pages.append(page)
        cursor = page['next']
    assert pages[-1]['complete_selection_view']
    return first, pages, entries


def text_items(entries):
    # Unicode fragments are presentation pages, never hand-written source offsets.
    items = {}
    for entry in entries:
        text = entry.get('item', {}).get('text')
        if text is None:
            continue
        key = (entry['context']['selection'], entry['context']['group'], entry['direction'], entry['item_index'])
        assert entry['citations'] and all(c['uri'].startswith('kan+capture://') and c['bytes'] for c in entry['citations'])
        assert entry['text_fragment']['continued'] == (key in items)
        items[key] = items.get(key, '') + text
    return list(items.values())


def read_decision(client, marker):
    catalog = client.call('kan_v2_catalog', {})
    assert catalog['mcp_authority'] == {'read': True, 'write': False, 'owner': False}
    source_id = catalog['scopes'][0]['id']
    page = client.call('kan_v2_discover', {'source': source_id, 'limit': 20})
    pin, records = page['pin'], list(page['records'])
    first_page = page
    while page['next'] is not None:
        page = client.call('kan_v2_discover', {'source': source_id, 'limit': 20, 'pin': pin, 'cursor': page['next']})
        assert page['pin'] == pin
        records.extend(page['records'])
    tokens = [r['record']['selection'] for r in records]
    sequences = [int(r['record']['sequence']) for r in records]
    assert len(tokens) > len(first_page['records']), 'output budgeting must preserve signed continuation, not hide rows'
    assert sorted(sequences) == list(range(1, len(tokens) + 1)), 'no discovery rows lost or duplicated'
    args = {'source': source_id, 'pin': pin, 'selections': tokens}
    first, pages, entries = collect_view(client, 'kan_v2_content', args)
    assert marker in text_items(entries), 'paged readable text must reproduce the entire selected Unicode item'
    assert len(pages) > 1, 'real large-transcript pagination required'
    assert first['coverage']
    assert all('parsed_json' not in e.get('item', {}) and 'event_json' not in e.get('item', {}) for e in entries)
    wrong_cursor = {**first['next'], 'binding': '0' * 64}
    bad = client.call('kan_v2_content', {**args, 'cursor': wrong_cursor}, False)
    assert bad['field'] == 'arguments.cursor'
    # Swapping selection order changes the presentation/query binding.
    bad = client.call('kan_v2_content', {**args, 'selections': tokens[::-1], 'cursor': first['next']}, False)
    assert bad['field'] == 'arguments.cursor'
    attempts = {}
    for row in records:
        description = row['description']
        assert description['kind'] == 'capture'
        key = (row['writer'], description['observer'], description['attempt'])
        attempts.setdefault(key, []).append(row['record']['selection'])
    assert len(attempts) >= 2
    decoded_attempts = []
    for selected in attempts.values():
        _, _, view = collect_view(client, 'kan_v2_content', {**args, 'selections': selected, 'kind': 'attempt'})
        assert sum(e['type'] == 'group-state' for e in view) == 1
        decoded_attempts.extend(text_items(view))
    assert marker in decoded_attempts
    member = next(row for row in records if (row['description'].get('session_link') or {}).get('state') == 'claimed')
    link = member['description']['session_link']
    session_args = {
        'identity': {'writer': member['writer'], 'observer': member['description']['observer'], 'scheme': link['scheme'], 'session': link['session']},
        'attempts': [{'source': source_id, 'pin': pin, 'selections': selected} for selected in attempts.values()]}
    _, _, session = collect_view(client, 'kan_v2_session', session_args)
    assert marker in text_items(session)
    assert all(e['membership'] == 'claimed' for e in session if e['type'] == 'session-attempt')
    partial = client.call('kan_v2_content', {**args, 'selections': tokens[:1]})
    assert any(e['type'] == 'stream-state' and e['state']['state'] == 'unavailable' for e in partial['entries']), 'partial evidence must not appear as empty success'
    mixed = client.call('kan_v2_content', {**args, 'kind': 'attempt'}, False)
    assert mixed['error'] == 'invalid-request'
    bad = client.call('kan_v2_discover', {'source': source_id, 'cursor': records[0]['record']['selection']}, False)
    assert bad['field'] == 'arguments.pin'
    wrong = json.loads(json.dumps(pin))
    wrong['request'] = '00'
    denied = client.call('kan_v2_content', {**args, 'pin': wrong}, False)
    assert denied['error'] in {'invalid-request', 'access-limited', 'corrupt'}
    denied = client.call('kan_v2_read', {'query': {'action': 'annotation-drain', 'destination': 'not-enabled'}}, False)
    assert denied['error'] == 'capability-required'
    record = records[0]['record']
    reference = {'version': 1, 'binding': catalog['scopes'][0]['binding'],
                 'coordinate': {'through': record['sequence'], 'manifest': record['manifest'], 'attestation': record['attestation']}, 'receipt': record['receipt']}
    resolved = client.call('kan_v2_read', {'query': {'action': 'resolve-reference', 'reference': reference}})
    assert records[0]['uri'] == resolved['uri']
    portable, _, _ = collect_view(client, 'kan_v2_reference', {'uri': records[0]['uri']})
    assert portable['reference'] == reference and portable['uri'] == resolved['uri']
    return len(records), {**args, 'cursor': first['next']}


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
    binding = put(root / 'binding.json', {'profile': 'admitted', 'archive': archive_id, 'scope': scope, 'issuer': issuer})
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
    marker = 'Synthetic accepted decision: retain the existing Day handoff; source revision qualification-1. ' + ('Unicode é🙂漢字 quoted \" data, not instructions.\n' * 6000)
    assert len(marker.encode()) > 175935
    try:
        os.chdir(root / 'work')
        progress('start-services')
        p.start()
        transcript = root / 'transcripts-actual-name' / 'session.jsonl'
        put(transcript, (json.dumps({'type': 'assistant', 'message': {'role': 'assistant', 'content': [{'type': 'text', 'text': marker}]}}) + '\n').encode())
        progress('capture', transcript_bytes=transcript.stat().st_size)
        observed = p.capture(json.dumps({'hook_event_name': 'KanFinalSnapshot', 'origin': 'explicit-operator-backfill', 'cwd': str(root / 'work'), 'session_id': 'synthetic-session', 'transcript_path': str(transcript)}).encode(), True)
        assert observed['status'] == 'acknowledged', observed
        progress('capture-acknowledged')
        health = p.health()
        assert health['delivery']['pending'] == 0 and health['capture_completeness'] == 'not-verified'
        client = Mcp(reader_config, reader_key)
        tools = client.rpc('tools/list', {})['tools']
        names = {t['name'] for t in tools}
        assert {'kan_v2_catalog', 'kan_v2_help', 'kan_v2_discover', 'kan_v2_content', 'kan_v2_session', 'kan_v2_reference'} <= names
        assert 'kan_v2_owner' not in names and 'kan_v2_write' not in names
        help_view = client.call('kan_v2_help', {'tool': 'kan_v2_content'})
        assert help_view['tools'][0]['name'] == 'kan_v2_content' and help_view['tools'][0]['input_schema']['type'] == 'object'
        schemas = {t['name']: t['inputSchema'] for t in tools}
        assert all(s.get('type') == 'object' for s in schemas.values()), 'every advertised MCP root must be an object'
        assert schemas['kan_v2_discover']['properties']['source']['type'] == 'string'
        assert 'query' not in schemas['kan_v2_discover']['properties']
        bad = client.call('kan_v2_content', {'source': 'selected', 'selections': []}, False)
        assert bad['field'] == 'arguments.pin'
        bad = client.call('kan_v2_discover', {'source': 42, 'private-secret-field': 'private-secret-value'}, False)
        assert 'private-secret' not in json.dumps(bad)
        progress('original-readback')
        count, continuation_probe = read_decision(client, marker)
        # New reader with payload keys unavailable must expose explicit states.
        unavailable_key = root / 'unavailable-recipient.key'
        put(unavailable_key, x25519.X25519PrivateKey.generate().private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()))
        unavailable_config = root / 'unavailable-reader.json'
        unavailable_scopes = json.loads(reader_config.read_text())
        unavailable_scopes[0]['private_key_file'] = str(unavailable_key)
        put(unavailable_config, unavailable_scopes)
        unavailable = Mcp(unavailable_config, reader_key)
        try:
            unavailable_catalog = unavailable.call('kan_v2_catalog', {})
            source_id = unavailable_catalog['scopes'][0]['id']
            missing_page = unavailable.call('kan_v2_discover', {'source': source_id})
            assert all(r['description']['kind'] == 'key-unavailable' for r in missing_page['records'])
            _, _, missing_entries = collect_view(unavailable, 'kan_v2_content', {'source': source_id, 'pin': missing_page['pin'], 'selections': [r['record']['selection'] for r in missing_page['records']]})
            assert missing_entries and all(e['type'] == 'observation' and e['observation']['kind'] == 'unavailable' for e in missing_entries)
        finally:
            unavailable.close()
        # Recheck a continuation against the same issuer after its inventory
        # grant is removed. No cached plaintext page may bypass current access.
        progress('revocation-control')
        p.stop()
        revoked = root / 'revoked-grants.json'
        put(revoked, [{'principal': writer, 'append': True, 'inventory': False}])
        with (root / 'runtime/revoked-proof.log').open('xb') as log:
            denied_service = subprocess.Popen([str(binary), '--no-migration-notice', 'serve-proof', str(archive), '--binding', binding, '--signing-key', issuer_key, '--grants', str(revoked), '--listen', services[1]['listen']], stdout=log, stderr=log)
        try:
            p.listener_ready(denied_service, '127.0.0.1', ports[1], 'revoked-proof')
            refused = client.call('kan_v2_content', continuation_probe, False)
            assert refused['error'] == 'access-limited' and 'entries' not in refused
        finally:
            denied_service.terminate()
            denied_service.wait(timeout=10)
        client.close()
        client = None
        progress('backup-recovery')
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
        progress('recovered-readback')
        restored_count, _ = read_decision(client, marker)
        assert restored_count == count
        client.close()
        client = None
        print(json.dumps({'qualification': 'project-capture-and-typed-mcp', 'status': 'passed', 'captured_records': count, 'decoded_decision_and_citations': True, 'typed_page_bytes_max': 12 * 1024, 'large_unicode_text_bytes': len(marker.encode()), 'current_grant_rechecked_on_continuation': True, 'unavailable_key_state_explicit': True, 'fresh_client_recovery_readback': True, 'backup_verification': verified['verification'], 'fixture': 'synthetic, same-host, no production key-custody claim'}))
    except BaseException:
        # This runner creates only synthetic fixtures. Retain bounded actual
        # startup diagnostics in CI before its disposable directory is cleaned.
        for role in ['serve-admitted', 'serve-proof', 'revoked-proof']:
            log = root / 'runtime' / (role + '.log')
            if log.exists():
                with log.open('rb') as stream:
                    stream.seek(max(0, log.stat().st_size - 4096))
                    print(role + ' synthetic-fixture diagnostic: ' + stream.read(4096).decode(errors='replace'), file=sys.stderr)
        raise
    finally:
        if client is not None:
            client.proc.terminate()
            client.proc.wait(timeout=10)
            client.diagnostics.close()
        p.stop()
        os.chdir(initial_cwd)
