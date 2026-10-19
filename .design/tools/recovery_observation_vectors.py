#!/usr/bin/env python3
"""Independent draft recovery-observation wire/signature oracle.

Public test keys only. No Rust, SQLite, network or production keys. This layer
checks canonical shape, signature, pinned context and predecessor, not whether
member/candidate/output claims are true. The complete bundle verifier must do
those checks before storage or publication acceptance.
"""
import argparse
import copy
import importlib.util
import json
import sys
from pathlib import Path
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.exceptions import InvalidSignature

ROOT=Path(__file__).resolve().parents[2]
PATH=ROOT/'.design/fixtures/recovery-observation-v1.json'
spec=importlib.util.spec_from_file_location('recovery_crypto_reference',ROOT/'.design/tools/attestation_vectors.py')
crypto=importlib.util.module_from_spec(spec);spec.loader.exec_module(crypto)
codec=crypto.codec
DOMAIN='tools.kan.recovery.observation.v1'
SAFE=2**53-1
COMMON=['version','domain','bundle','profile','archive','scope','issuer','observer','sequence','previous','sampledAt','event','body']
BODY={
 'created':['recipe','member','frontier'],
 'unavailable':['member','entries'],
 'restored':['member','cid','length','candidate'],
 'publication-intent':['attempt','member','restorations','output','frontier'],
 'publication-observed':['attempt','intent','output','frontier'],
 'publication-failed':['attempt','intent','reason'],
}
CONTEXT=['bundle','profile','archive','scope','issuer','observer']


class Rejected(ValueError):pass


def require(ok,reason):
    if not ok:raise Rejected(reason)


def closed(value,fields,reason):
    require(isinstance(value,dict) and set(value)==set(fields),reason)


def uint(value,maximum=SAFE,positive=False):
    require(type(value) is int and (1 if positive else 0)<=value<=maximum,'integer')


def blob(value,length):require(type(value) is bytes and len(value)==length,'byte-width')


def link(value,kind):
    require(isinstance(value,codec.Link) and len(value.raw)==36 and value.raw[:4]==bytes([1,kind,0x12,0x20]),'link-profile')


def frontier(value):
    closed(value,['through','manifest','attestation'],'frontier-fields');uint(value['through'])
    if value['through']==0:require(value['manifest'] is None and value['attestation'] is None,'frontier-empty')
    else:
        link(value['manifest'],0x71);link(value['attestation'],0x71)


def context(ctx):
    closed(ctx,CONTEXT,'context-fields')
    for name in ['bundle','archive','scope']:blob(ctx[name],32)
    require(type(ctx['profile']) is int and ctx['profile'] in (2,3),'profile')
    keys={}
    for name in ['issuer','observer']:
        require(isinstance(ctx[name],str),'did-key')
        try:keys[name]=crypto.issuer_key(crypto.author(ctx[name]))
        except (ValueError,TypeError,IndexError):raise Rejected('did-key')
    return keys['observer']


def preimage(raw,domain=DOMAIN):
    return codec.encode({'domain':domain,'statement':codec.link(codec.cid(raw))})


def sign(statement,key=None,domain=DOMAIN):
    key=crypto.identity(3)[0] if key is None else key
    raw=codec.encode(statement)
    r,s=utils.decode_dss_signature(key.sign(preimage(raw,domain),ec.ECDSA(hashes.SHA256(),deterministic_signing=True)))
    signature=r.to_bytes(32,'big')+min(s,crypto.ORDER-s).to_bytes(32,'big')
    return codec.encode({'statement':codec.blob(raw),'signature':codec.blob(signature)})


def verify(raw,ctx,previous=None):
    key=context(ctx)
    require(type(raw) is bytes and len(raw)<=16384,'envelope-bound')
    try:env=codec.decode(raw)
    except ValueError:raise Rejected('envelope-canonical')
    closed(env,['statement','signature'],'envelope-fields')
    require(type(env['statement']) is bytes,'statement-bytes')
    try:statement=codec.decode(env['statement'])
    except ValueError:raise Rejected('statement-canonical')
    closed(statement,COMMON,'statement-fields')
    require(type(statement['version']) is int and statement['version']==1 and statement['domain']==DOMAIN,'protocol')
    observed={name:statement[name] for name in CONTEXT};context(observed)
    require(observed==ctx,'context-binding')
    uint(statement['sequence'],positive=True);uint(statement['sampledAt'])
    if previous is None:
        require(statement['sequence']==1 and statement['previous'] is None,'genesis')
    else:
        require(all(previous[name]==ctx[name] for name in CONTEXT),'previous-context')
        require(statement['sequence']==previous['sequence']+1,'sequence')
        link(statement['previous'],0x71)
        require(statement['previous']==previous['statementCid'],'predecessor')
    event=statement['event'];require(isinstance(event,str) and event in BODY,'event')
    body=statement['body'];closed(body,BODY[event],'body-fields')
    require((event=='created')==(statement['sequence']==1),'created-position')
    if 'member' in body:blob(body['member'],32)
    if 'frontier' in body:frontier(body['frontier'])
    if event=='created':require(type(body['recipe']) is int and body['recipe']==1,'recipe')
    if event=='unavailable':
        entries=body['entries'];require(isinstance(entries,list) and 1<=len(entries)<=32,'entries-bound')
        positions=[]
        for entry in entries:
            closed(entry,['occurrence','cid','expectedLength','state'],'entry-fields')
            occurrence=entry['occurrence']
            if occurrence is not None:uint(occurrence,positive=True)
            link(entry['cid'],0x55)
            length=entry['expectedLength']
            if length is not None:uint(length,4194304,True)
            require(occurrence is None or length is not None,'occurrence-length')
            require(entry['state'] in ('missing','corrupt'),'availability')
            # CID text is canonical lower-case base32; binary order is NOT the
            # specified lexical text order. Convert deliberately before sorting.
            import base64
            text='b'+base64.b32encode(entry['cid'].raw).decode().lower().rstrip('=')
            positions.append((occurrence is None,occurrence or 0,text))
        require(positions==sorted(set(positions)),'entry-order-unique')
    if event=='restored':
        link(body['cid'],0x55);link(body['candidate'],0x55);uint(body['length'],4194304,True)
        require(body['cid']==body['candidate'],'candidate-cid')
    if event.startswith('publication-'):blob(body['attempt'],16)
    if event=='publication-intent':
        blob(body['restorations'],32);blob(body['output'],32)
    if event in ('publication-observed','publication-failed'):link(body['intent'],0x71)
    if event=='publication-observed':blob(body['output'],32)
    if event=='publication-failed':require(body['reason'] in ('source-changed','invalid-candidate','destination-conflict','budget','io','verification'),'failure-reason')
    signature=env['signature'];blob(signature,64)
    r,s=int.from_bytes(signature[:32],'big'),int.from_bytes(signature[32:],'big')
    require(0<r<crypto.ORDER and 0<s<=crypto.ORDER//2,'signature-range')
    try:key.verify(utils.encode_dss_signature(r,s),preimage(env['statement']),ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:raise Rejected('signature-invalid')
    return {**statement,'statementCid':codec.Link(codec.cid_bytes(codec.cid(env['statement'])))}


def vectors():
    _,issuer=crypto.identity(2);_,observer=crypto.identity(3)
    ctx={'bundle':codec.blob(bytes([4])*32),'profile':2,'archive':codec.blob(bytes([1])*32),'scope':codec.blob(bytes([2])*32),'issuer':issuer['principal'],'observer':observer['principal']}
    empty={'through':0,'manifest':None,'attestation':None}
    member=codec.blob(bytes([5])*32);output=codec.blob(bytes([6])*32);restorations=codec.blob(bytes([7])*32)
    obj=codec.link(codec.cid(b'public fixture',0x55));attempt=codec.blob(bytes([8])*16)
    bodies=[
      ('created',{'recipe':1,'member':member,'frontier':empty}),
      ('unavailable',{'member':member,'entries':[{'occurrence':None,'cid':obj,'expectedLength':None,'state':'corrupt'}]}),
      ('restored',{'member':member,'cid':obj,'length':14,'candidate':obj}),
      ('publication-intent',{'attempt':attempt,'member':member,'restorations':restorations,'output':output,'frontier':empty}),
      ('publication-failed',{'attempt':attempt,'intent':None,'reason':'io'}),
      ('publication-observed',{'attempt':attempt,'intent':None,'output':output,'frontier':empty}),
    ]
    rows=[];previous=None
    for index,(event,body) in enumerate(bodies,1):
        body=copy.deepcopy(body)
        if 'intent' in body:body['intent']=codec.link(rows[3]['statementCid'])
        st={'version':1,'domain':DOMAIN,**ctx,'sequence':index,'previous':previous,'sampledAt':1792400000000+index,'event':event,'body':body}
        raw=codec.encode(st);env=sign(st)
        rows.append({'name':event,'statement':st,'statementHex':raw.hex(),'statementCid':codec.cid(raw),'signingHex':preimage(raw).hex(),'envelopeHex':env.hex()});previous=codec.link(codec.cid(raw))
    negative=[]
    def add(name,reason,index=0,statement=None,envelope=None,**overrides):
        raw=envelope if envelope is not None else sign(statement if statement is not None else rows[index]['statement'])
        negative.append({'name':name,'expected':reason,'base':index,'envelopeHex':raw.hex(),**overrides})
    def change(name,reason,path,value,index=0):
        st=copy.deepcopy(rows[index]['statement']);target=st
        for part in path[:-1]:target=target[part]
        target[path[-1]]=value;add(name,reason,index,st)
    for field,value in [('version',2),('domain','tools.kan.service.attestation.v1')]:change('wrong-'+field,'protocol',[field],value)
    change('unknown-common-field','statement-fields',['extra'],None)
    change('unknown-body-field','body-fields',['body','extra'],None)
    change('wrong-bundle','context-binding',['bundle'],codec.blob(bytes(32)))
    change('wrong-scope','context-binding',['scope'],codec.blob(bytes(32)))
    change('wrong-archive','context-binding',['archive'],codec.blob(bytes(32)))
    change('wrong-profile','context-binding',['profile'],3)
    change('wrong-observer','context-binding',['observer'],issuer['principal'])
    change('short-bundle','byte-width',['bundle'],codec.blob(bytes(31)))
    change('zero-sequence','integer',['sequence'],0)
    change('boolean-sequence','integer',['sequence'],True)
    change('skipped-sequence','sequence',['sequence'],4,1)
    change('wrong-previous','predecessor',['previous'],codec.link(codec.cid(b'other')),1)
    change('genesis-previous','genesis',['previous'],codec.link(codec.cid(b'other')))
    change('unknown-event','event',['event'],'future')
    change('unknown-recipe','recipe',['body','recipe'],2)
    change('empty-loss-entries','entries-bound',['body','entries'],[],1)
    change('duplicate-loss-entry','entry-order-unique',['body','entries'],rows[1]['statement']['body']['entries']*2,1)
    change('wrong-restoration-cid','candidate-cid',['body','candidate'],codec.link(codec.cid(b'other',0x55)),2)
    change('wrong-intent-codec','link-profile',['body','intent'],obj,4)
    change('unknown-failure-reason','failure-reason',['body','reason'],'invented',4)
    add('cross-domain-signature','signature-invalid',envelope=sign(rows[0]['statement'],domain='tools.kan.service.attestation.v1'))
    add('other-observer-signature','signature-invalid',envelope=sign(rows[0]['statement'],crypto.identity(4)[0]))
    env=codec.decode(bytes.fromhex(rows[0]['envelopeHex']));sig=env['signature']
    env['signature']=sig[:32]+(crypto.ORDER-int.from_bytes(sig[32:],'big')).to_bytes(32,'big')
    add('high-s-signature','signature-range',envelope=codec.encode_value(env))
    add('trailing-envelope','envelope-canonical',envelope=bytes.fromhex(rows[0]['envelopeHex'])+b'\0')
    change('wrong-issuer','context-binding',['issuer'],observer['principal'])
    change('unsupported-profile','profile',['profile'],4)
    change('missing-did-key','did-key',['observer'],'did:key:z')
    change('timestamp-negative','statement-canonical',['sampledAt'],-1)
    change('timestamp-boolean','integer',['sampledAt'],True)
    change('sequence-too-large','statement-canonical',['sequence'],SAFE+1)
    st=copy.deepcopy(rows[1]['statement']);st['event']='created';st['body']=copy.deepcopy(rows[0]['statement']['body']);add('creation-later','created-position',1,st)
    st=copy.deepcopy(rows[0]['statement']);st['event']='unavailable';st['body']=copy.deepcopy(rows[1]['statement']['body']);add('noncreation-first','created-position',0,st)
    change('zero-loss-occurrence','integer',['body','entries'],[{'occurrence':0,'cid':obj,'expectedLength':1,'state':'missing'}],1)
    change('occurrence-without-length','occurrence-length',['body','entries'],[{'occurrence':1,'cid':obj,'expectedLength':None,'state':'missing'}],1)
    change('empty-expected-length','integer',['body','entries'],[{'occurrence':1,'cid':obj,'expectedLength':0,'state':'missing'}],1)
    change('unknown-loss-state','availability',['body','entries'],[{'occurrence':1,'cid':obj,'expectedLength':1,'state':'available'}],1)
    change('too-many-loss-entries','entries-bound',['body','entries'],[{'occurrence':n,'cid':obj,'expectedLength':1,'state':'missing'} for n in range(1,34)],1)
    change('unordered-loss-entries','entry-order-unique',['body','entries'],[{'occurrence':n,'cid':obj,'expectedLength':1,'state':'missing'} for n in [2,1]],1)
    change('empty-restoration','integer',['body','length'],0,2)
    change('oversize-restoration','integer',['body','length'],4194305,2)
    change('short-attempt','byte-width',['body','attempt'],codec.blob(bytes(15)),3)
    change('short-member','byte-width',['body','member'],codec.blob(bytes(31)))
    change('short-restorations','byte-width',['body','restorations'],codec.blob(bytes(31)),3)
    change('short-output','byte-width',['body','output'],codec.blob(bytes(31)),3)
    change('zero-frontier-with-links','frontier-empty',['body','frontier'],{'through':0,'manifest':codec.link(codec.cid(b'm')),'attestation':codec.link(codec.cid(b'p'))})
    change('positive-frontier-without-links','link-profile',['body','frontier'],{'through':1,'manifest':None,'attestation':None})
    change('raw-frontier-link','link-profile',['body','frontier'],{'through':1,'manifest':obj,'attestation':codec.link(codec.cid(b'p'))})
    for event_index,(event,_) in enumerate(bodies):
        change('extra-'+event+'-field','body-fields',['body','extra'],None,event_index)
    env=codec.decode(bytes.fromhex(rows[0]['envelopeHex']));env['signature']=bytes(64)
    add('zero-signature','signature-range',envelope=codec.encode_value(env))
    shapes=[]
    def shape(name,index,changes):
        st=copy.deepcopy(rows[index]['statement'])
        for path,value in changes:
            target=st
            for part in path[:-1]:target=target[part]
            target[path[-1]]=value
        raw=codec.encode(st)
        shapes.append({'name':name,'base':index,'statement':st,'statementHex':raw.hex(),'statementCid':codec.cid(raw),'signingHex':preimage(raw).hex(),'envelopeHex':sign(st).hex()})
    shape('maximum-loss-count-and-lengths',1,[(['body','entries'],[{'occurrence':n,'cid':obj,'expectedLength':4194304,'state':'missing'} for n in range(1,32)]+[{'occurrence':None,'cid':obj,'expectedLength':None,'state':'corrupt'}])])
    shape('nonempty-metadata-frontier',0,[(['body','frontier'],{'through':SAFE,'manifest':codec.link(codec.cid(b'm')),'attestation':codec.link(codec.cid(b'p'))}),(['sampledAt'],SAFE)])
    shape('maximum-restoration-length',2,[(['body','length'],4194304)])
    return {'status':'proposal-wire-layer-only-not-complete-bundle-validation','publicObserverScalar':3,'context':ctx,'positive':rows,'shapePositive':shapes,'negative':negative}


def checks(value):
    ctx=codec.from_fixture(value['context']);previous=None;verified=[]
    for row in value['positive']:
        raw=bytes.fromhex(row['envelopeHex']);result=verify(raw,ctx,previous)
        statement=bytes.fromhex(row['statementHex'])
        require(codec.encode(row['statement'])==statement,'statement vector')
        require(codec.cid(statement)==row['statementCid'] and preimage(statement).hex()==row['signingHex'],'preimage vector')
        require(sign(row['statement'])==raw,'signature vector')
        previous=result;verified.append(result)
    for row in value['shapePositive']:
        index=row['base']; raw=bytes.fromhex(row['envelopeHex'])
        result=verify(raw,ctx,None if index==0 else verified[index-1])
        require(sign(row['statement'])==raw and result['statementCid']==codec.Link(codec.cid_bytes(row['statementCid'])),'shape vector')
    for row in value['negative']:
        index=row['base']
        try:verify(bytes.fromhex(row['envelopeHex']),ctx,None if index==0 else verified[index-1])
        except Rejected as e:require(str(e)==row['expected'],row['name']+': '+str(e)+' != '+row['expected'])
        else:raise AssertionError('accepted negative '+row['name'])


def main():
    p=argparse.ArgumentParser();g=p.add_mutually_exclusive_group(required=True);g.add_argument('--write',action='store_true');g.add_argument('--check',action='store_true');args=p.parse_args()
    generated=vectors();checks(generated)
    if args.write:PATH.write_text(json.dumps(generated,indent=2)+'\n')
    else:
        stored=json.loads(PATH.read_text());checks(stored);require(stored==generated,'proposal changed')
    print(f"{len(generated['positive'])} chain positives, {len(generated['shapePositive'])} shape positives and {len(generated['negative'])} re-signed/malformed wire vectors pass; full member/state validation remains separate.")


if __name__=='__main__':main()
