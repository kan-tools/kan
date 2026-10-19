#!/usr/bin/env python3
"""Independent Python construction of real signed recovery-member fixtures.
No Rust, SQLite, production keys or network. P-256 scalars 3/4/5/6 are public.
This is a fixture generator and commitment/loss oracle, not a complete second
member verifier. Prior attestation oracle independently checks every proof.
"""
import argparse,copy,hashlib,json
from pathlib import Path
import attestation_vectors as att
import recovery_commitments as framing
codec=att.codec
ROOT=Path(__file__).resolve().parents[2]
PATH=ROOT/'.design/fixtures/recovery-member-v1.json'

def canonical(v):return json.dumps(v,separators=(',',':'),ensure_ascii=False).encode()
def sign_json(v,key):
    pre=b'tools.kan.service.request.v1\0'+hashlib.sha256(canonical(v)).digest()
    r,s=att.utils.decode_dss_signature(key.sign(pre,att.ec.ECDSA(att.hashes.SHA256(),deterministic_signing=True)))
    return (r.to_bytes(32,'big')+min(s,att.ORDER-s).to_bytes(32,'big')).hex()
def cbor(v):return codec.encode(v)
def framed(b):return len(b).to_bytes(8,'big')+b

def build(profile,count):
    ik,issuer=att.identity(3);_,historical=att.identity(4);wk,writer=att.identity(5);_,observer=att.identity(6)
    scope=b'\x03'*32;audience=historical if profile==3 else issuer
    rows=[];objects=[];previous=None
    for i in range(count):
        op=bytes([i+1])*16
        req={'version':1,'scope':scope.hex(),'audience':audience['principal'],'principal':writer['principal'],'expires':None,'command':{'operation':'append','id':op.hex(),'position':i,'previous':previous,'ciphertext':b'synthetic ciphertext'.hex()}}
        raw=canonical({'request':req,'signature':sign_json(req,wk)})
        m={'v':1,'kind':'manifest','body':{'writer':writer,'scopeToken':codec.blob(scope),'operation':codec.blob(op),'position':i,'previous':None if previous is None else codec.link(previous),'entries':[{'slot':codec.blob(hashlib.sha256(op).digest()),'ciphertext':codec.link(framing.raw_cid(raw)),'length':len(raw)}]}}
        mc=codec.cid(cbor(m));r={'v':1,'kind':'receipt','body':{'issuer':audience,'manifest':codec.link(mc),'scopeToken':codec.blob(scope),'operation':codec.blob(op),'position':i,'durability':'remote-durable','issuedAt':1}}
        rows.append([i+1,cbor(m),cbor(r),b'']);objects.append([framing.raw_cid(raw),raw]);previous=mc
    objects.sort();member={'profile':profile,'archive':b'\x02'*32,'scope':scope,'issuer':issuer['principal'],'plan':None,'membership':[[c,len(b)] for c,b in objects] if profile==3 else [],'records':rows,'objects':objects}
    if profile==3:
        h=hashlib.sha256(b'tools.kan.archive.copy-source.v1\0');h.update(framed(b'commits'));h.update(count.to_bytes(8,'big'))
        for seq,m,r,_ in rows:
            e=codec.decode(m)['body']['entries'][0];h.update(seq.to_bytes(8,'big'));h.update(framed(m));h.update(framed(r));h.update(framed(e['ciphertext'].raw))
        h.update(framed(b'objects'));h.update(len(objects).to_bytes(8,'big'))
        for cid,b in objects:h.update(framed(framing.cid_bytes(cid)));h.update(len(b).to_bytes(8,'big'))
        plan={'recipe':1,'sourceProfile':1,'targetProfile':3,'sourceThrough':count,'sourceTip':None if previous is None else codec.link(previous),'sourceDigest':codec.blob(h.digest()),'historicalIssuer':historical['principal'],'scopeToken':codec.blob(scope),'issuer':issuer['principal'],'nonce':codec.blob(b'\x08'*32)}
        member['plan']=cbor(plan);member['archive']=hashlib.sha256(b'tools.kan.archive.copy-plan.v1\0'+member['plan']).digest()
    return resign(member),observer['principal']

def resign(m,purpose=None):
    key,issuer=att.identity(3);previous=None;proof_state=None
    for row in m['records']:
        seq,manifest,receipt,_=row
        st={'v':1,'kind':'service-attestation','body':{'issuer':issuer,'archiveId':codec.blob(m['archive']),'scopeToken':codec.blob(m['scope']),'sequence':seq,'manifest':codec.link(codec.cid(manifest)),'receipt':codec.link(codec.cid(receipt)),'previousSequence':seq-1,'previousManifest':None if previous is None else codec.link(codec.cid(previous[1])),'previousAttestation':None if proof_state is None else {'$link':codec.cid(codec.decode(previous[3])['statement'])},'purpose':purpose or ('retained-verified' if m['profile']==3 else 'admitted'),'issuedAt':seq-1}}
        row[3]=att.sign(st,key)
        proof_state=att.verify(row[3],m['issuer'],m['archive'],m['scope'],proof_state,manifest,receipt)
        previous=row
    return m

def losses(m):
    objects=dict(m['objects']);membership=dict(m['membership']);coords=[];referenced=set()
    complete=m['profile']==2 or len(m['records'])>=codec.decode(m['plan'])['sourceThrough']
    for seq,raw,_,_ in m['records']:
        e=codec.decode(raw)['body']['entries'][0];cid='b'+framing.base64.b32encode(e['ciphertext'].raw).decode().lower().rstrip('=');length=e['length']
        if length>2*1024*1024+4096:raise ValueError('service request length')
        if cid in referenced:raise ValueError('reused service request CID')
        coords.append((seq,cid,length,'IssuerMetadata'));referenced.add(cid)
    for cid in sorted(set(objects)|set(membership)):
        if cid in referenced:continue
        basis='VerifiedCopyRecipe' if complete else 'UnverifiedMembership'
        coords.append((None,cid,membership[cid] if cid in membership and complete else None,basis if cid in membership else 'OriginalObject'))
    result=[];available=0
    for seq,c,n,basis in coords:
        data=objects.get(c)
        if data is not None and framing.raw_cid(data)==c and n is not None and n!=len(data):
            raise ValueError('hash-valid bytes contradict authenticated length')
        state='missing' if data is None else ('available' if data and framing.raw_cid(data)==c else 'corrupt')
        if state!='available':result.append({'occurrence':seq,'cid':c,'expectedLength':n,'state':state,'basis':basis})
        elif seq is not None:available+=1
    return result,available

def pack(name,m,observer,error=None,complete=True):
    out={'name':name,'context':{'bundle':'01'*32,'profile':m['profile'],'archive':m['archive'].hex(),'scope':m['scope'].hex(),'issuer':m['issuer'],'observer':observer},'plan':None if m['plan'] is None else m['plan'].hex(),'membership':m['membership'],'records':[[seq,a.hex(),b.hex(),c.hex()] for seq,a,b,c in m['records']],'objects':[[c,b.hex()] for c,b in m['objects']]}
    if error:out['error']=error
    else:
        loss,available=losses(m);out['expected']={'member':framing.member_digest(m).hex(),'losses':loss,'verifiedRequests':available,'recipeMetadataComplete':complete,'through':len(m['records'])}
    return out

def vectors():
    cases=[]
    for p in [2,3]:
        for n in [0,3]:
            m,o=build(p,n);cases.append(pack(f'profile{p}-{n}-intact',m,o))
        m,o=build(p,3);m['objects'].pop(0);m['objects'][0][1]=b'';m['objects'].append([framing.raw_cid(b'orphan'),b'broken']);m['objects'].sort();cases.append(pack(f'profile{p}-loss',m,o))
    m,o=build(3,3);m['records']=m['records'][:1];cases.append(pack('partial-profile3',m,o,complete=False))
    def negative(name,profile,edit,reason):
        m,o=build(profile,2);edit(m);cases.append(pack(name,m,o,reason))
    negative('wrong-owner-archive',2,lambda m:m.update(archive=b'\x09'*32),'issuer proof')
    negative('absent-original-membership',3,lambda m:m.update(membership=[]),'retained reference absent from membership')
    negative('conflicting-membership-length',3,lambda m:m['membership'][0].__setitem__(1,m['membership'][0][1]+1),'conflicting expected lengths')
    negative('binary-or-reversed-object-order',2,lambda m:m['objects'].reverse(),'CID order or duplicate')
    negative('duplicate-original-object',2,lambda m:m['objects'].insert(0,m['objects'][0]),'CID order or duplicate')
    negative('reordered-record',2,lambda m:m['records'].reverse(),'record position')
    negative('wrong-plan-binding',3,lambda m:m.update(archive=b'\x09'*32),'plan binding')
    negative('retained-purpose-profile2',2,lambda m:resign(m,'retained-verified'),'proof purpose')
    def bad_digest(m):
        p=codec.decode(m['plan']);p['sourceDigest']=b'\xff'*32;m['plan']=cbor(p);m['archive']=hashlib.sha256(b'tools.kan.archive.copy-plan.v1\0'+m['plan']).digest();resign(m)
    negative('resigned-false-copy-source',3,bad_digest,'source metadata digest')
    # Independently pin the corrected projection rules; these are not merely
    # hand-labelled hostile inputs. The loss oracle must refuse each contradiction.
    def contradiction(name,m,o,reason):
        try:losses(m)
        except ValueError as e:assert str(e)==reason
        else:raise AssertionError(name+' accepted by projection oracle')
        cases.append(pack(name,m,o,reason))
    def edit_manifest(m,index,edit):
        rec=codec.decode(m['records'][index][1]);edit(rec['body']);raw=cbor(rec)
        receipt=codec.decode(m['records'][index][2]);receipt['body']['manifest']=codec.Link(codec.cid_bytes(codec.cid(raw)))
        m['records'][index][1]=raw;m['records'][index][2]=cbor(receipt);resign(m)
    m,o=build(2,1)
    edit_manifest(m,0,lambda b:b['entries'][0].update(length=b['entries'][0]['length']+1))
    contradiction('hash-valid-false-authenticated-length',m,o,'hash-valid bytes contradict authenticated length')
    m,o=build(2,1);empty=framing.raw_cid(b'')
    edit_manifest(m,0,lambda b:b['entries'][0].update(ciphertext=codec.Link(codec.cid_bytes(empty)),length=1));m['objects']=[[empty,b'']]
    contradiction('empty-cid-false-authenticated-length',m,o,'hash-valid bytes contradict authenticated length')
    m,o=build(2,1);edit_manifest(m,0,lambda b:b['entries'][0].update(length=2*1024*1024+4097));m['objects']=[]
    contradiction('unrepresentable-service-request-length',m,o,'service request length')
    m,o=build(2,2);e=codec.decode(m['records'][0][1])['body']['entries'][0]
    edit_manifest(m,1,lambda b:b['entries'][0].update(ciphertext=e['ciphertext'],length=e['length']));m['objects']=[]
    contradiction('reused-missing-service-request',m,o,'reused service request CID')
    m,o=build(3,3);m['records']=m['records'][:1]
    fabricated=framing.raw_cid(b'not authenticated source membership');m['membership'].append([fabricated,77]);m['membership'].sort()
    cases.append(pack('partial-membership-fabrication-remains-unverified',m,o,complete=False))
    m,o=build(3,3);m['records']=m['records'][:1]
    referenced=codec.decode(m['records'][0][1])['body']['entries'][0]['ciphertext'].raw
    for cidlength in m['membership']:
        if codec.cid_bytes(cidlength[0])!=referenced:cidlength[1]+=1
    cases.append(pack('partial-membership-length-does-not-corrupt-valid-bytes',m,o,complete=False))
    return {'status':'independent signed construction and M1/loss oracle; no complete second member validator','publicPrivateScalars':[3,4,5,6],'cases':cases}

def main():
    p=argparse.ArgumentParser();p.add_argument('--write',action='store_true');p.add_argument('--check',action='store_true');a=p.parse_args();v=vectors()
    if a.write:PATH.write_text(json.dumps(v,indent=2)+'\n')
    if a.check:assert json.loads(PATH.read_text())==v
    print(f"{len(v['cases'])} independently constructed member cases; all constructed issuer chains independently verified; no full verifier claim")
if __name__=='__main__':main()
