#!/usr/bin/env python3
"""Reviewer mutants beyond the author's 27: excluded labels, boundary weakening,
signature-verification removal and semantic narrowings. In-memory only.
Usage: python -I mutate_extended.py <export-root>"""
import contextlib, io, json, sys, types
from pathlib import Path
ROOT = Path(sys.argv[1]).resolve()
PATH = ROOT/'.design/tools/attestation_vectors.py'
SRC = PATH.read_text()
DATA = json.loads((ROOT/'.design/fixtures/service-attestation-v1.json').read_text())

def run(source):
    m = types.ModuleType('oracle_mutant'); m.__file__ = str(PATH)
    exec(compile(source, str(PATH), 'exec'), m.__dict__)
    with contextlib.redirect_stdout(io.StringIO()): m.check(DATA)

run(SRC)
MUTANTS = [
  # (name, old, new) exact text substitutions; each must occur exactly once
  ('drop manifest-profile', "require(isinstance(manifest,dict) and manifest.get('kind')=='manifest' and manifest.get('v')==1,'manifest-profile')", "pass"),
  ('drop receipt-profile', "require(isinstance(receipt,dict) and receipt.get('kind')=='receipt' and receipt.get('v')==1,'receipt-profile')", "pass"),
  ('drop statement-bound', "require(len(env['statement'])<=16384,'statement-bound')", "pass"),
  ('drop canonical re-encode of did', "require('did:key:z'+b58(b'\\x80\\x24'+key.public_bytes(serialization.Encoding.X962,serialization.PublicFormat.CompressedPoint))==did,'issuer-encoding')", "pass"),
  ('drop did length/prefix', "require(isinstance(did,str) and 56<=len(did)<=80 and did.startswith('did:key:z'),'issuer-encoding')", "pass"),
  ('drop signature verification', "try:key.verify(utils.encode_dss_signature(r,s),preimage(env['statement']),ec.ECDSA(hashes.SHA256()))\n    except InvalidSignature:raise Rejected('signature-invalid')", "pass"),
  ('s<=n/2 -> s<n/2', "0<s<=ORDER//2", "0<s<ORDER//2"),
  ('drop r<n', "0<r<ORDER and", "0<r and"),
  ('receipt-binding: drop manifest equality', "r['manifest']==b['manifest'] and ", ""),
  ('receipt-binding: drop operation', "for f in ['scopeToken','operation','position']", "for f in ['scopeToken','position']"),
  ('receipt-binding: drop position', "for f in ['scopeToken','operation','position']", "for f in ['scopeToken','operation']"),
  ('receipt-binding: drop manifest scope==configured', " and m['scopeToken']==scope,'receipt-binding'", ",'receipt-binding'"),
  ('record-binding: drop receipt CID', " and b['receipt'].raw==codec.cid_bytes(codec.cid(receipt_raw)),'record-binding'", ",'record-binding'"),
  ('record-binding: drop manifest CID', "b['manifest'].raw==codec.cid_bytes(codec.cid(manifest_raw)) and ", ""),
  ('chain-position: drop scope continuity', " and b['scopeToken']==previous['scopeToken']", ""),
  ('chain-position: drop archive continuity', " and b['archiveId']==previous['archiveId']", ""),
  ('chain-commitments: drop previousManifest', "b['previousManifest']==previous['manifest'] and ", ""),
  ('chain-commitments: drop previousAttestation', " and b['previousAttestation']==previous['statementCid']", ""),
  ('genesis: drop sequence==1', "b['sequence']==1 and b['previousManifest'] is None", "b['previousManifest'] is None"),
  ('admitted-issuer: compare principal only', "r['issuer']==b['issuer'],'admitted-issuer'", "r['issuer']['principal']==b['issuer']['principal'],'admitted-issuer'"),
  ('purpose: accept any string', "b['purpose'] in ['admitted','retained-verified']", "isinstance(b['purpose'],str)"),
  ('safe-integer: allow bool', "type(v)is int and", "isinstance(v,int) and"),
  ('sequence: drop >0', "b['sequence']>0 and ", ""),
  ('statementCid from envelope instead of statement', "codec.cid(env['statement'])))}", "codec.cid(raw)))}"),
  ('preimage domain changed', "DOMAIN = 'tools.kan.service.attestation.v1'", "DOMAIN = 'tools.kan.service.attestation.v2'"),
]
survivors = []
for name, old, new in MUTANTS:
    n = SRC.count(old)
    if n != 1:
        print(f'{name}: SKIP (pattern count {n})'); continue
    try:
        run(SRC.replace(old, new))
    except AssertionError as e:
        msg = str(e).splitlines()[0][:110]
        print(f'{name}: killed -> {msg}')
    except Exception as e:
        print(f'{name}: killed (non-assert {type(e).__name__}: {str(e)[:80]})')
    else:
        print(f'{name}: SURVIVED'); survivors.append(name)
print(f'\n{len(MUTANTS)-len(survivors)}/{len(MUTANTS)} killed; survivors: {survivors}')
