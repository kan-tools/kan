#!/usr/bin/env python3
"""Independent proposed copy-plan bytes/commitments; no Rust or archive writes."""
import argparse, copy, hashlib, importlib.util, json, sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('copy_plan_reference',ROOT/'scripts/evidence_reference.py')
codec=importlib.util.module_from_spec(spec);sys.modules[spec.name]=codec;spec.loader.exec_module(codec)
PATH=ROOT/'.design/fixtures/copy-plan-v1.json'
DOMAIN=b'tools.kan.archive.copy-plan.v1\0'

def vectors():
    proofs=json.loads((ROOT/'.design/fixtures/service-attestation-v1.json').read_text())
    c=proofs['pinnedIssuer']; h=proofs['positive'][0]['manifest']['body']['writer']['principal']
    tip=codec.cid(codec.encode(proofs['positive'][0]['manifest']))
    base={'recipe':1,'sourceProfile':1,'targetProfile':3,'sourceThrough':1,'sourceTip':codec.link(tip),'sourceDigest':codec.blob(bytes(range(32))),'historicalIssuer':h,'scopeToken':codec.blob(b'\x03'*32),'issuer':c,'nonce':codec.blob(b'\x07'*32)}
    positive=[]
    for name,changes in [('one-retained',{}),('empty',{'sourceThrough':0,'sourceTip':None}),('safe-integer-limit',{'sourceThrough':2**53-1}),('same-issuer',{'historicalIssuer':c}),('historical-k256',{'historicalIssuer':'did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme'})]:
        value=copy.deepcopy(base);value.update(changes);raw=codec.encode(value)
        assert codec.encode_value(codec.decode(raw))==raw
        positive.append({'name':name,'plan':value,'hex':raw.hex(),'archiveHex':hashlib.sha256(DOMAIN+raw).hexdigest()})
    negative=[]
    def add(name,value):negative.append({'name':name,'hex':codec.encode(value).hex()})
    for field in base:
        value=copy.deepcopy(base);del value[field];add('missing-'+field,value)
    for name,changes in [('unknown-field',{'unexpected':True}),('recipe',{'recipe':2}),('source-profile',{'sourceProfile':2}),('target-profile',{'targetProfile':2}),('negative-through',{'sourceThrough':-1}),('unsafe-through',{'sourceThrough':2**53}),('boolean-through',{'sourceThrough':True}),('empty-with-tip',{'sourceThrough':0}),('nonempty-no-tip',{'sourceTip':None}),('tip-as-bytes',{'sourceTip':codec.blob(codec.cid_bytes(tip))}),('tip-as-string',{'sourceTip':tip}),('wrong-tip-codec',{'sourceTip':codec.link(codec.cid(b'test',0x55))}),('short-digest',{'sourceDigest':codec.blob(b'\0'*31)}),('long-scope',{'scopeToken':codec.blob(b'\0'*33)}),('nonce-string',{'nonce':'07'*32}),('short-current-key',{'issuer':'did:key:z'}),('short-historical-key',{'historicalIssuer':'did:key:z'}),('dynamic-issuer',{'issuer':'did:web:example.com'}),('issuer-as-map',{'issuer':{'principal':c}}),('current-k256',{'issuer':'did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme'})]:
        value=copy.deepcopy(base);value.update(changes);add(name,value)
    raw=bytes.fromhex(positive[0]['hex'])
    negative.extend([{'name':'trailing-byte','hex':(raw+b'\0').hex()},{'name':'truncated','hex':raw[:-1].hex()},{'name':'over-bound','hex':(raw+b'\0'*4096).hex()}])
    return {'status':'proposal only; structural recipe and commitment, not verified source or migration','domainHex':DOMAIN.hex(),'positive':positive,'negative':negative}

def main():
    parser=argparse.ArgumentParser();g=parser.add_mutually_exclusive_group(required=True);g.add_argument('--write',action='store_true');g.add_argument('--check',action='store_true');args=parser.parse_args()
    result=vectors();text=json.dumps(result,indent=2)+'\n'
    if args.write:PATH.write_text(text)
    elif PATH.read_text()!=text:raise SystemExit('copy-plan vectors differ')
    print(f"copy-plan vectors: {len(result['positive'])} exact positives, {len(result['negative'])} labelled negatives")
if __name__=='__main__':main()
