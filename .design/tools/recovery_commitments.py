#!/usr/bin/env python3
"""Independent, stdlib-only draft M1/R1/O1 byte-framing oracle.

Never invokes Rust or SQLite. These vectors qualify framing, not proof validity
or a publishable member. Record blobs in the framing cases are intentionally
small synthetic CBOR; full valid-member fixtures belong to the later verifier.
--write explicitly regenerates the proposal; --check never rewrites it.
"""
import argparse
import base64
import copy
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PATH = ROOT / '.design/fixtures/recovery-commitments-v1.json'
MAX_OBJECT = 4194304


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def number(n):
    require(type(n) is int and 0 <= n < 2**64, 'uint64')
    return n.to_bytes(8, 'big')


def frame(raw):
    require(type(raw) is bytes, 'byte-storage-class')
    return number(len(raw)) + raw


def raw_cid(raw):
    return 'b' + base64.b32encode(b'\x01\x55\x12\x20' + hashlib.sha256(raw).digest()).decode().lower().rstrip('=')


def cid_bytes(text):
    require(isinstance(text, str) and text.startswith('b') and len(text) <= 128, 'object-cid')
    try:
        raw = base64.b32decode(text[1:].upper() + '=' * (-len(text[1:]) % 8))
    except (ValueError, base64.binascii.Error):
        raise ValueError('object-cid')
    require(len(raw) == 36 and raw[:4] == b'\x01\x55\x12\x20', 'object-cid')
    require(text == 'b' + base64.b32encode(raw).decode().lower().rstrip('='), 'object-cid')
    return raw


def ordered(items):
    names = [item[0] for item in items]
    require(len(names) == len(set(names)), 'duplicate-key')
    for name in names:
        cid_bytes(name)
    return sorted(items, key=lambda item: item[0])


def member_digest(member, output=False):
    require(set(member) == {'profile','archive','scope','issuer','plan','membership','records','objects'}, 'member-fields')
    profile = member['profile']
    require(type(profile) is int and profile in (2,3), 'member-profile')
    for field in ('archive','scope'):
        require(type(member[field]) is bytes and len(member[field]) == 32, 'context-width')
    require(isinstance(member['issuer'],str), 'issuer-text')
    plan = member['plan']
    if profile == 2:
        require(plan is None and not member['membership'], 'profile2-plan')
    else:
        require(type(plan) is bytes and 1 <= len(plan) <= 4096, 'profile3-plan')
    # CID/DID, record and plan signature semantics are deliberately a different
    # verifier layer. The framing itself never authorizes or authenticates inputs.
    h = hashlib.sha256()
    h.update(b'tools.kan.recovery.output.v1\0' if output else b'tools.kan.recovery.member.v1\0')
    h.update(number(profile));h.update(frame(member['archive']));h.update(frame(member['scope']));h.update(frame(member['issuer'].encode()))
    h.update(frame(b'plan'));h.update(number(0 if plan is None else 1))
    if plan is not None:h.update(frame(plan))
    membership = ordered(member['membership'])
    h.update(frame(b'original-membership'));h.update(number(len(membership)))
    for cid,length in membership:
        require(type(length) is int and 1 <= length <= MAX_OBJECT, 'expected-length')
        h.update(frame(cid_bytes(cid)));h.update(number(length))
    records=member['records'];h.update(frame(b'records'));h.update(number(len(records)))
    for expected,(sequence,manifest,receipt,proof) in enumerate(records,1):
        require(sequence == expected and type(sequence) is int, 'record-sequence')
        for value,limit in [(manifest,65536),(receipt,65536),(proof,16384)]:
            require(type(value) is bytes and 1 <= len(value) <= limit, 'record-blob')
        h.update(number(sequence));h.update(frame(manifest));h.update(frame(receipt));h.update(frame(proof))
    objects=ordered(member['objects']);h.update(frame(b'original-objects'));h.update(number(len(objects)))
    for cid,value in objects:
        require(type(value) is bytes, 'byte-storage-class')
        require(len(value) <= MAX_OBJECT, 'object-bound')
        h.update(frame(cid_bytes(cid)));h.update(number(len(value)));h.update(frame(value))
    return h.digest()


def restoration_digest(candidates):
    candidates=ordered(candidates)
    h=hashlib.sha256(b'tools.kan.recovery.restorations.v1\0');h.update(number(len(candidates)))
    for cid,value in candidates:
        require(type(value) is bytes and 1 <= len(value) <= MAX_OBJECT, 'candidate-bytes')
        require(raw_cid(value) == cid, 'candidate-hash')
        h.update(frame(cid_bytes(cid)));h.update(number(len(value)));h.update(frame(value))
    return h.digest()


def notation(value):
    if type(value) is bytes:return {'$bytes':value.hex()}
    if isinstance(value,dict):return {k:notation(v) for k,v in value.items()}
    if isinstance(value,(list,tuple)):return [notation(v) for v in value]
    return value


def decode_notation(value):
    if isinstance(value,dict):
        if set(value)=={'$bytes'}:return bytes.fromhex(value['$bytes'])
        return {k:decode_notation(v) for k,v in value.items()}
    if isinstance(value,list):return [decode_notation(v) for v in value]
    return value


def vectors():
    issuer=json.loads((ROOT/'.design/fixtures/service-attestation-v1.json').read_text())['pinnedIssuer']
    base={'profile':2,'archive':bytes([1])*32,'scope':bytes([2])*32,'issuer':issuer,'plan':None,'membership':[],'records':[],'objects':[]}
    good=b'public synthetic ciphertext';key=raw_cid(good)
    other=b'second synthetic object';other_key=raw_cid(other)
    rows=[]
    def add(name,m):rows.append({'name':name,'member':notation(m),'M1':member_digest(m).hex(),'O1':member_digest(m,True).hex()})
    add('empty',base)
    m=copy.deepcopy(base);m['objects']=[(key,good),(other_key,other)];add('staged',m)
    m=copy.deepcopy(base);m['records']=[(1,b'\xa0',b'\xa1\x01\x01',b'\xa1\x02\x02')];add('missing-payload-framing',m)
    m=copy.deepcopy(base);m['objects']=[(key,b'corrupt original bytes')];add('corrupt',m)
    m=copy.deepcopy(base);m['objects']=[(key,b'')];add('zero-length-corrupt',m)
    m=copy.deepcopy(base);m['objects']=[(key,good)];add('restored-output-framing',m)
    plan=json.loads((ROOT/'.design/fixtures/copy-plan-v1.json').read_text())['positive'][0]
    m=copy.deepcopy(base);m.update(profile=3,archive=bytes.fromhex(plan['archiveHex']),scope=bytes.fromhex(plan['plan']['scopeToken']['$bytes']),issuer=plan['plan']['issuer'],plan=bytes.fromhex(plan['hex']),membership=[(key,len(good)),(other_key,len(other))],objects=[(key,good)])
    add('partial-copy-framing',m)
    candidates=[[],[(key,good)],[(key,good),(other_key,other)]]
    return {'status':'proposal-framing-only-not-logical-member-validation','member':rows,'restorations':[{'candidates':notation(c),'R1':restoration_digest(c).hex()} for c in candidates]}


def checks(value):
    for row in value['member']:
        m=decode_notation(row['member'])
        require(member_digest(m).hex()==row['M1'],'M1 fixture')
        require(member_digest(m,True).hex()==row['O1'],'O1 fixture')
        require(row['M1']!=row['O1'],'domain separation')
        reversed_member=copy.deepcopy(m)
        for field in ('membership','objects'):reversed_member[field].reverse()
        require(member_digest(reversed_member).hex()==row['M1'],'canonical order')
    for row in value['restorations']:
        candidates=decode_notation(row['candidates']);require(restoration_digest(candidates).hex()==row['R1'],'R1 fixture')
        require(restoration_digest(list(reversed(candidates))).hex()==row['R1'],'R1 canonical order')
    base=decode_notation(value['member'][0]['member']);key=raw_cid(b'candidate')
    for objects,reason in [([(key,'text')],'byte-storage-class'),([(key,b''),(key,b'')],'duplicate-key'),([(key.upper(),b'')],'object-cid'),([(key,bytes(MAX_OBJECT+1))],'object-bound')]:
        changed=copy.deepcopy(base);changed['objects']=objects
        try:member_digest(changed)
        except ValueError as e:require(str(e)==reason,'wrong rejection reason')
        else:raise AssertionError('accepted '+reason)
    try:restoration_digest([(key,b'wrong')])
    except ValueError as e:require(str(e)=='candidate-hash','wrong candidate rejection')
    else:raise AssertionError('accepted bad candidate')
    require(len({row['M1'] for row in value['member']})==len(value['member']),'distinct histories collapsed')


def main():
    p=argparse.ArgumentParser();g=p.add_mutually_exclusive_group(required=True);g.add_argument('--write',action='store_true');g.add_argument('--check',action='store_true');args=p.parse_args()
    generated=vectors();checks(generated)
    if args.write:PATH.write_text(json.dumps(generated,indent=2)+'\n')
    else:
        stored=json.loads(PATH.read_text());checks(stored);require(stored==generated,'proposal changed; explicit review/regeneration required')
    print('7 member/output and 3 restoration framing vectors; local negative checks pass. No logical-member acceptance claimed.')


if __name__=='__main__':main()
