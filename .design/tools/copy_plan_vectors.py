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
    # Encode these deliberately outside the reference encoder's canonical path.
    pairs=sorted([(codec.encode(k),codec.encode(v)) for k,v in base.items()],key=lambda p:(len(p[0]),p[0]))
    noncanonical=[
        ('reversed-map-keys',codec.head(5,len(pairs))+b''.join(k+v for k,v in reversed(pairs)),'duplicate or unordered map key'),
        ('nonminimal-map-length',b'\xb8'+bytes([len(pairs)])+raw[1:],'nonminimal header'),
        ('nonminimal-recipe',codec.head(5,len(pairs))+b''.join(k+(b'\x18\x01' if k==codec.encode('recipe') else v) for k,v in pairs),'nonminimal header'),
        ('duplicate-map-key',codec.head(5,len(pairs)+1)+pairs[0][0]+pairs[0][1]+b''.join(k+v for k,v in pairs),'duplicate or unordered map key'),
    ]
    reasons={
        'unknown-field':'missing or unknown field',
        'recipe':'unsupported copy-plan profile or recipe',
        'source-profile':'unsupported copy-plan profile or recipe',
        'target-profile':'unsupported copy-plan profile or recipe',
        'negative-through':'unsupported scalar or tag',
        'unsafe-through':'integer outside safe unsigned range',
        'boolean-through':'expected unsigned safe integer',
        'empty-with-tip':'copy-plan empty source frontier',
        'nonempty-no-tip':'wrong CID profile',
        'tip-as-bytes':'wrong CID profile','tip-as-string':'wrong CID profile',
        'wrong-tip-codec':'wrong CID profile','short-digest':'wrong byte string length',
        'long-scope':'wrong byte string length','nonce-string':'wrong byte string length',
        'short-current-key':'copy-plan issuer encoding','short-historical-key':'copy-plan issuer encoding',
        'dynamic-issuer':'copy-plan issuer encoding','issuer-as-map':'wrong string length or type',
        'current-k256':'copy-plan current issuer must use P-256',
        'trailing-byte':'trailing bytes','truncated':'declared length exceeds remaining input',
        'over-bound':'value exceeds byte limit',
    }
    canonical={'negative-through','unsafe-through','trailing-byte','truncated','over-bound'}
    for vector in negative:
        name=vector['name']
        vector['expectedClass']='canonical' if name in canonical else 'schema'
        vector['expectedReason']='missing or unknown field' if name.startswith('missing-') else reasons[name]
    for name,data,reason in noncanonical:
        negative.append({'name':name,'hex':data.hex(),'expectedClass':'canonical','expectedReason':reason})
    return {'status':'proposal only; structural recipe and commitment, not verified source or migration','domainHex':DOMAIN.hex(),'positive':positive,'negative':negative}

def main():
    parser=argparse.ArgumentParser();g=parser.add_mutually_exclusive_group(required=True);g.add_argument('--write',action='store_true');g.add_argument('--check',action='store_true');args=parser.parse_args()
    result=vectors();text=json.dumps(result,indent=2)+'\n'
    if args.write:PATH.write_text(text)
    elif PATH.read_text()!=text:raise SystemExit('copy-plan vectors differ')
    print(f"copy-plan vectors: {len(result['positive'])} exact positives, {len(result['negative'])} labelled negatives")
if __name__=='__main__':main()
