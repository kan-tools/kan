#!/usr/bin/env python3
"""Independent proposal oracle: exact bytes plus labelled, re-signed negatives.

Public test scalars only. No Rust, archive, network or admission proof.
--check never rewrites; --write explicitly regenerates the proposed wire fixtures.
"""
import argparse
import copy
import importlib.util
import json
import sys
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.exceptions import InvalidSignature
if not __debug__:
    raise RuntimeError('protocol oracle requires assertions enabled')
ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('evidence_oracle', ROOT/'scripts/evidence_reference.py')
codec = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = codec
spec.loader.exec_module(codec)
PATH = ROOT/'.design/fixtures/service-attestation-v1.json'
ORDER = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
DOMAIN = 'tools.kan.service.attestation.v1'
SAFE = 2**53-1
ARCHIVE = b'\x09'*32
SCOPE = b'\x03'*32
ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
class Rejected(ValueError):
    pass

def require(ok, label):
    if not ok:
        raise Rejected(label)

def b58(raw):
    n, result = int.from_bytes(raw, 'big'), ''
    while n:
        n, r = divmod(n,58); result=ALPHABET[r]+result
    return '1'*(len(raw)-len(raw.lstrip(b'\0')))+result

def author(did):
    return {'principal':did,'verificationMethod':did+'#'+did[8:],'identityVersion':{'kind':'static','value':None}}

def identity(scalar=1):
    key=ec.derive_private_key(scalar,ec.SECP256R1())
    public=key.public_key().public_bytes(serialization.Encoding.X962,serialization.PublicFormat.CompressedPoint)
    return key,author('did:key:z'+b58(b'\x80\x24'+public))

def issuer_key(value):
    closed(value,['principal','verificationMethod','identityVersion'],'issuer-fields')
    did=value['principal']
    require(isinstance(did,str) and 56<=len(did)<=80 and did.startswith('did:key:z'),'issuer-encoding')
    encoded=did[9:]
    try:
        n=0
        for c in encoded:n=n*58+ALPHABET.index(c)
        raw=b'\0'*(len(encoded)-len(encoded.lstrip('1')))+n.to_bytes((n.bit_length()+7)//8,'big')
    except ValueError:raise Rejected('issuer-encoding')
    require(len(raw)==35 and raw[:2]==b'\x80\x24','issuer-algorithm')
    try:key=ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(),raw[2:])
    except ValueError:raise Rejected('issuer-point')
    require('did:key:z'+b58(b'\x80\x24'+key.public_bytes(serialization.Encoding.X962,serialization.PublicFormat.CompressedPoint))==did,'issuer-encoding')
    require(value['verificationMethod']==did+'#'+did[8:],'issuer-method')
    require(value['identityVersion']=={'kind':'static','value':None},'issuer-version')
    return key

def closed(value,names,label):
    require(isinstance(value,dict) and set(value)==set(names),label)

def uint(v):
    require(type(v)is int and 0<=v<=SAFE,'safe-integer')

def record_link(v):
    require(isinstance(v,codec.Link) and len(v.raw)==36 and v.raw[:4]==b'\x01\x71\x12\x20','record-cid')

def decode(raw,label):
    try:return codec.decode(raw)
    except ValueError:raise Rejected(label)

def preimage(statement):
    return codec.encode({'domain':DOMAIN,'statement':codec.link(codec.cid(statement))})

def sign(statement,key=None):
    if key is None:key=identity()[0]
    raw=codec.encode(statement)
    r,s=utils.decode_dss_signature(key.sign(preimage(raw),ec.ECDSA(hashes.SHA256(),deterministic_signing=True)))
    sig=r.to_bytes(32,'big')+min(s,ORDER-s).to_bytes(32,'big')
    return codec.encode({'statement':codec.blob(raw),'signature':codec.blob(sig)})

def verify(raw,pinned,archive,scope,previous,manifest_raw,receipt_raw):
    require(len(raw)<=16384,'envelope-bound')
    env=decode(raw,'envelope-canonical')
    closed(env,['statement','signature'],'envelope-fields')
    require(isinstance(env['statement'],bytes),'statement-bytes')
    require(len(env['statement'])<=16384,'statement-bound')
    statement=decode(env['statement'],'statement-canonical')
    closed(statement,['v','kind','body'],'statement-fields')
    require(type(statement['v'])is int and statement['v']==1 and statement['kind']=='service-attestation','profile')
    b=statement['body']
    closed(b,['issuer','archiveId','scopeToken','sequence','manifest','receipt','previousSequence','previousManifest','previousAttestation','purpose','issuedAt'],'body-fields')
    key=issuer_key(b['issuer'])
    require(b['issuer']['principal']==pinned,'pinned-issuer')
    require(isinstance(b['archiveId'],bytes) and len(b['archiveId'])==32,'archive-length')
    require(isinstance(b['scopeToken'],bytes) and len(b['scopeToken'])==32,'scope-length')
    require(b['archiveId']==archive,'configured-archive')
    require(b['scopeToken']==scope,'configured-scope')
    for field in ['sequence','previousSequence','issuedAt']:uint(b[field])
    require(b['sequence']>0 and b['previousSequence']==b['sequence']-1,'sequence')
    for field in ['manifest','receipt']:record_link(b[field])
    require(b['purpose'] in ['admitted','retained-verified'],'purpose')
    if previous is None:
        require(b['sequence']==1 and b['previousManifest'] is None and b['previousAttestation'] is None,'genesis')
    else:
        record_link(b['previousManifest']);record_link(b['previousAttestation'])
        require(b['previousSequence']==previous['sequence'] and b['scopeToken']==previous['scopeToken'] and b['archiveId']==previous['archiveId'],'chain-position')
        require(b['previousManifest']==previous['manifest'] and b['previousAttestation']==previous['statementCid'],'chain-commitments')
    manifest=decode(manifest_raw,'manifest-canonical');receipt=decode(receipt_raw,'receipt-canonical')
    require(isinstance(manifest,dict) and manifest.get('kind')=='manifest' and manifest.get('v')==1,'manifest-profile')
    require(isinstance(receipt,dict) and receipt.get('kind')=='receipt' and receipt.get('v')==1,'receipt-profile')
    require(b['manifest'].raw==codec.cid_bytes(codec.cid(manifest_raw)) and b['receipt'].raw==codec.cid_bytes(codec.cid(receipt_raw)),'record-binding')
    m,r=manifest['body'],receipt['body']
    require(r['manifest']==b['manifest'] and all(r[f]==m[f] for f in ['scopeToken','operation','position']) and m['scopeToken']==scope,'receipt-binding')
    require(b['purpose']!='admitted' or r['issuer']==b['issuer'],'admitted-issuer')
    sig=env['signature']
    require(isinstance(sig,bytes) and len(sig)==64,'signature-encoding')
    r,s=int.from_bytes(sig[:32],'big'),int.from_bytes(sig[32:],'big')
    require(0<r<ORDER and 0<s<=ORDER//2,'signature-range')
    try:key.verify(utils.encode_dss_signature(r,s),preimage(env['statement']),ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:raise Rejected('signature-invalid')
    return {**b,'statementCid':codec.Link(codec.cid_bytes(codec.cid(env['statement'])))}

def vectors():
    source=json.loads((ROOT/'tests/fixtures/evidence-v1/vectors.json').read_text())
    values={v['name']:v['value'] for v in source['positive']}
    key,current=identity();_,historical=identity(2)
    previous_manifest=previous_statement=None
    rows=[]
    for seq,(name,purpose) in enumerate([('manifest','admitted'),('second-batch','retained-verified')],1):
        manifest=copy.deepcopy(values[name]);mc=codec.cid(codec.encode(manifest))
        receipt=copy.deepcopy(values['receipt'])
        receipt['body'].update(issuer=current if seq==1 else historical,manifest=codec.link(mc),position=manifest['body']['position'],operation=manifest['body']['operation'])
        st={'v':1,'kind':'service-attestation','body':{'issuer':current,'archiveId':codec.blob(ARCHIVE),'scopeToken':manifest['body']['scopeToken'],'sequence':seq,'manifest':codec.link(mc),'receipt':codec.link(codec.cid(codec.encode(receipt))),'previousSequence':seq-1,'previousManifest':previous_manifest,'previousAttestation':previous_statement,'purpose':purpose,'issuedAt':1792108800100+seq}}
        raw=codec.encode(st);env=sign(st);decoded=codec.decode(env)
        rows.append({'name':purpose,'manifest':manifest,'receipt':receipt,'manifestHex':codec.encode(manifest).hex(),'receiptHex':codec.encode(receipt).hex(),'statement':st,'statementHex':raw.hex(),'statementCid':codec.cid(raw),'signingHex':preimage(raw).hex(),'signatureHex':decoded['signature'].hex(),'envelopeHex':env.hex(),'envelopeCid':codec.cid(env)})
        previous_manifest,previous_statement=codec.link(mc),codec.link(codec.cid(raw))
    negatives=[]
    def add(name,expected,index=0,st=None,env=None,**overrides):
        base=rows[index]
        if env is None:env=sign(st if st is not None else base['statement'])
        negatives.append(dict(name=name,expected=expected,base=index,envelopeHex=env.hex(),**overrides))
    def change(name,expected,field,value,index=0,**kw):
        st=copy.deepcopy(rows[index]['statement']);st['body'][field]=value
        add(name,expected,index,st=st,**kw)
    wrong_link=codec.link(codec.cid(b'wrong-record'))
    for field in ['previousManifest','previousAttestation']:
        change('wrong-'+field,'chain-commitments',field,wrong_link,1)
        change('genesis-'+field,'genesis',field,wrong_link)
        change('null-'+field,'record-cid',field,None,1)
    st=copy.deepcopy(rows[1]['statement']);st['body'].update(sequence=3,previousSequence=2)
    add('skipped-sequence','chain-position',1,st=st)
    change('bad-previous-sequence','sequence','previousSequence',7,1)
    change('zero-sequence','sequence','sequence',0)
    change('boolean-sequence','safe-integer','sequence',True)
    change('unsafe-time','statement-canonical','issuedAt',SAFE+1)
    for field,label in [('scopeToken','scope'),('archiveId','archive')]:
        change('short-'+label,label+'-length',field,codec.blob(b'\x07'*31))
        change('configured-'+label,'configured-'+label,field,codec.blob(b'\x07'*32))
        kw={label+'Hex':(b'\x07'*32).hex()}
        change('mid-chain-'+label,'chain-position',field,codec.blob(b'\x07'*32),1,**kw)
    change('unknown-body','body-fields','extra',None)
    change('unknown-purpose','purpose','purpose','invented')
    for field,v in [('v',2),('kind','future')]:
        st=copy.deepcopy(rows[0]['statement']);st[field]=v;add('unsupported-'+field,'profile',st=st)
    st=copy.deepcopy(rows[0]['statement']);st['extra']=None;add('unknown-statement','statement-fields',st=st)
    change('cid-shaped-bytes','record-cid','manifest',codec.blob(codec.cid_bytes(rows[0]['statement']['body']['manifest']['$link'])))
    for field in ['manifest','receipt']:change('wrong-'+field,'record-binding',field,wrong_link)
    for field,value in [('verificationMethod',current['principal']+'#different'),('identityVersion',{'kind':'versionId','value':'v1'})]:
        a=copy.deepcopy(current);a[field]=value;change('bad-'+field,'issuer-method' if field=='verificationMethod' else 'issuer-version','issuer',a)
    add('wrong-configured-issuer','pinned-issuer',pinnedIssuer=historical['principal'])
    a=copy.deepcopy(current);a['extra']=None;change('unknown-author','issuer-fields','issuer',a)
    a=author('did:key:u'+current['principal'][9:]);change('noncanonical-did','issuer-encoding','issuer',a,pinnedIssuer=a['principal'])
    secp=ec.derive_private_key(1,ec.SECP256K1());public=secp.public_key().public_bytes(serialization.Encoding.X962,serialization.PublicFormat.CompressedPoint)
    a=author('did:key:z'+b58(b'\xe7\x01'+public));st=copy.deepcopy(rows[0]['statement']);st['body']['issuer']=a
    add('other-algorithm','issuer-algorithm',env=sign(st,secp),pinnedIssuer=a['principal'])
    for name,modify,label in [('foreign-admitted-issuer',lambda r:r['body'].update(issuer=historical),'admitted-issuer'),('receipt-for-other-manifest',lambda r:r['body'].update(manifest=wrong_link),'receipt-binding')]:
        receipt=copy.deepcopy(rows[0]['receipt']);modify(receipt);rb=codec.encode(receipt)
        st=copy.deepcopy(rows[0]['statement']);st['body']['receipt']=codec.link(codec.cid(rb))
        add(name,label,st=st,receiptHex=rb.hex())
    env=bytes.fromhex(rows[0]['envelopeHex']);decoded=codec.decode(env);sig=decoded['signature']
    def signature(name,value,label):
        e=copy.deepcopy(decoded);e['signature']=value;add(name,label,env=codec.encode_value(e))
    signature('DER',utils.encode_dss_signature(int.from_bytes(sig[:32],'big'),int.from_bytes(sig[32:],'big')),'signature-encoding')
    signature('zero-r',bytes(32)+sig[32:],'signature-range');signature('zero-s',sig[:32]+bytes(32),'signature-range')
    signature('high-s',sig[:32]+(ORDER-int.from_bytes(sig[32:],'big')).to_bytes(32,'big'),'signature-range')
    signature('half-order-plus-one',sig[:32]+(ORDER//2+1).to_bytes(32,'big'),'signature-range')
    signature('wrong-valid-range-signature',(1).to_bytes(32,'big')*2,'signature-invalid')
    add('outer-trailing','envelope-canonical',env=env+b'\0')
    e=copy.deepcopy(decoded);e['statement']+=b'\0';add('inner-trailing','statement-canonical',env=codec.encode_value(e))
    e=copy.deepcopy(decoded);e['extra']=None;add('unknown-envelope','envelope-fields',env=codec.encode_value(e))
    e=copy.deepcopy(decoded);e['statement']='text';add('statement-text','statement-bytes',env=codec.encode_value(e))
    # This is ONE well-framed envelope, not trailing bytes: removing the bound
    # must change the exact label rather than passing via the framing error.
    e=copy.deepcopy(decoded);e['statement']=b'\0'*16385;add('oversized-nested-statement','envelope-bound',env=codec.encode_value(e))
    # duplicate signature entry after the complete two-field map
    add('duplicate-envelope','envelope-canonical',env=b'\xa3'+env[1:]+codec.encode_value('signature')+codec.encode_value(sig))
    add('nonminimal-envelope','envelope-canonical',env=b'\xb8\x02'+env[1:])
    return {'status':'proposal; independent codec oracle, not admission/availability proof','testPrivateScalars':[1,2],'pinnedIssuer':current['principal'],'archiveHex':ARCHIVE.hex(),'scopeHex':SCOPE.hex(),'positive':rows,'negative':negatives}

def check(data):
    assert data==vectors(),'exact fixture mismatch; no automatic rewrite'
    previous=None;states=[]
    for row in data['positive']:
        env=bytes.fromhex(row['envelopeHex']);raw=bytes.fromhex(row['statementHex'])
        assert codec.encode(row['statement'])==raw and codec.cid(raw)==row['statementCid']
        assert preimage(raw).hex()==row['signingHex'] and codec.cid(env)==row['envelopeCid']
        previous=verify(env,data['pinnedIssuer'],bytes.fromhex(data['archiveHex']),bytes.fromhex(data['scopeHex']),previous,bytes.fromhex(row['manifestHex']),bytes.fromhex(row['receiptHex']))
        states.append(previous)
    for negative in data['negative']:
        i=negative['base'];row=data['positive'][i]
        try:
            verify(bytes.fromhex(negative['envelopeHex']),negative.get('pinnedIssuer',data['pinnedIssuer']),bytes.fromhex(negative.get('archiveHex',data['archiveHex'])),bytes.fromhex(negative.get('scopeHex',data['scopeHex'])),states[i-1] if i else None,bytes.fromhex(negative.get('manifestHex',row['manifestHex'])),bytes.fromhex(negative.get('receiptHex',row['receiptHex'])))
        except Rejected as e:
            assert str(e)==negative['expected'],f"{negative['name']}: expected {negative['expected']}, got {e}"
        except Exception as e:
            raise AssertionError(f"{negative['name']}: expected {negative['expected']}, got unexpected {type(e).__name__}") from e
        else:raise AssertionError('accepted negative '+negative['name'])
    print(f"{len(states)} exact signed vectors; {len(data['negative'])} labelled negatives; independent byte/signature/chain/metadata checks passed. No admission/availability claim.")

if __name__=='__main__':
    p=argparse.ArgumentParser();m=p.add_mutually_exclusive_group(required=True);m.add_argument('--write',action='store_true');m.add_argument('--check',action='store_true');args=p.parse_args()
    if args.write:PATH.write_text(json.dumps(vectors(),indent=2)+'\n')
    check(json.loads(PATH.read_text()))
