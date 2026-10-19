#!/usr/bin/env python3
"""Independent signed history construction and state replay oracle.
Uses valid members constructed by the independent member fixture generator.
This state oracle is not a general second metadata/schema validator; source
metadata construction and the attestation oracle establish these fixture inputs.
No Rust, SQLite, production keys or network is used.
"""
import argparse,copy,hashlib,json
from pathlib import Path
import recovery_member_vectors as members
import recovery_observation_vectors as wire
import recovery_commitments as frame
codec=wire.codec
PATH=Path(__file__).resolve().parents[2]/'.design/fixtures/recovery-replay-v1.json'

def need(ok,label):
 if not ok:raise ValueError(label)
def text(link):return 'b'+frame.base64.b32encode(link.raw).decode().lower().rstrip('=')
def link(cid):return codec.Link(codec.cid_bytes(cid))
def ctx(m,observer):return {'bundle':b'\x01'*32,'profile':m['profile'],'archive':m['archive'],'scope':m['scope'],'issuer':m['issuer'],'observer':observer}
def frontier(m):
 if not m['records']:return {'through':0,'manifest':None,'attestation':None}
 _,mb,_,pb=m['records'][-1]
 return {'through':len(m['records']),'manifest':link(codec.cid(mb)),'attestation':link(codec.cid(codec.decode(pb)['statement']))}
def losses(m):return [{**{k:v for k,v in l.items() if k!='basis'},'cid':link(l['cid'])} for l in members.losses(m)[0]]
def complete(m):return m['profile']==2 or len(m['records'])>=codec.decode(m['plan'])['sourceThrough']
def keys(m):
 result={c:n if complete(m) else None for c,n in m['membership']}
 for _,mb,_,_ in m['records']:
  for e in codec.decode(mb)['body']['entries']:result[text(e['ciphertext'])]=e['length']
 for c,_ in m['objects']:result.setdefault(c,None)
 return result

def basis(m,cid):
 for _,mb,_,_ in m['records']:
  if any(text(e['ciphertext'])==cid for e in codec.decode(mb)['body']['entries']):return 'IssuerMetadata'
 if cid in dict(m['membership']):return 'VerifiedCopyRecipe' if complete(m) else 'UnverifiedMembership'
 return 'OriginalObject'

def check_writer(m,objects,selected_only=False):
 for _,mb,rb,_ in m['records']:
  manifest=codec.decode(mb);receipt=codec.decode(rb);entry=manifest['body']['entries'][0]
  if selected_only and text(entry['ciphertext']) not in objects:continue
  raw=objects[text(entry['ciphertext'])]
  value=json.loads(raw);need(list(value)==['request','signature'] and members.canonical(value)==raw,'writer-json');request=value['request']
  need(list(request)==['version','scope','audience','principal','expires','command'],'writer-json')
  command=request['command'];need(list(command)==['operation','id','position','previous','ciphertext'] and command['operation']=='append','writer-command')
  sig=bytes.fromhex(value['signature']);need(len(sig)==64,'writer-signature');r,s=int.from_bytes(sig[:32],'big'),int.from_bytes(sig[32:],'big');need(0<r<wire.crypto.ORDER and 0<s<=wire.crypto.ORDER//2,'writer-signature')
  key=wire.crypto.issuer_key(wire.crypto.author(request['principal']))
  key.verify(wire.crypto.utils.encode_dss_signature(r,s),b'tools.kan.service.request.v1\0'+hashlib.sha256(members.canonical(request)).digest(),wire.crypto.ec.ECDSA(wire.crypto.hashes.SHA256()))
  op=bytes.fromhex(command['id']);need(len(op)==16 and request['version']==1,'writer-request')
  expected={'v':1,'kind':'manifest','body':{'writer':wire.crypto.author(request['principal']),'scopeToken':bytes.fromhex(request['scope']),'operation':op,'position':command['position'],'previous':None if command['previous'] is None else link(command['previous']),'entries':[{'slot':hashlib.sha256(op).digest(),'ciphertext':link(frame.raw_cid(raw)),'length':len(raw)}]}}
  need(codec.encode(expected)==mb and receipt['body']['issuer']==wire.crypto.author(request['audience']),'writer-binding')

def output(m,selected):
 need(complete(m),'partial copy publication');original=dict(m['objects']);selected=dict(selected);known=keys(m);objects=[]
 for cid,length in sorted(known.items()):
  data=selected.get(cid,original.get(cid));need(data is not None and data and frame.raw_cid(data)==cid and (length is None or length==len(data)),'publication-blocked-unavailable-object');objects.append([cid,data])
 try:check_writer(m,dict(objects))
 except (ValueError,wire.crypto.InvalidSignature,KeyError,TypeError):raise ValueError('output member validation')
 virtual={**m,'objects':objects}
 return frame.restoration_digest(list(selected.items())),frame.member_digest(virtual,True)

class History:
 def __init__(self,m,observer):
  self.m=m;self.observer=observer;self.context=ctx(m,observer);self.events=[];self.candidates=[];self.checkpoint=None
 def add(self,event,body):self.events.append([event,body]);return len(self.events)-1
 def initial(self):
  digest=frame.member_digest(self.m);self.add('created',{'recipe':1,'member':digest,'frontier':frontier(self.m)})
  lost=losses(self.m)
  for start in range(0,len(lost),32):self.add('unavailable',{'member':digest,'entries':lost[start:start+32]})
 def restore(self,cid,data):
  self.candidates.append([cid,data]);self.candidates.sort();self.add('restored',{'member':frame.member_digest(self.m),'cid':link(cid),'length':len(data),'candidate':link(cid)})
 def intent(self,id_byte=9):
  r,o=output(self.m,self.candidates);return self.add('publication-intent',{'attempt':bytes([id_byte])*16,'member':frame.member_digest(self.m),'restorations':r,'output':o,'frontier':frontier(self.m)})
 def outcome(self,intent,event='publication-observed'):
  b=self.events[intent][1];body={'attempt':b['attempt'],'intentIndex':intent}
  if event=='publication-observed':body.update(output=b['output'],frontier=frontier(self.m))
  else:body['reason']='io'
  self.add(event,body)
 def encoded(self):
  result=[];prior=None
  for seq,(event,body) in enumerate(self.events,1):
   body=copy.deepcopy(body)
   if 'intentIndex' in body:body['intent']=link(codec.cid(codec.decode(result[body.pop('intentIndex')])['statement']))
   st={'version':1,'domain':wire.DOMAIN,**self.context,'sequence':seq,'previous':prior,'sampledAt':1000+seq,'event':event,'body':body}
   raw=wire.sign(st,wire.crypto.identity(6)[0]);result.append(raw);prior=link(codec.cid(codec.decode(raw)['statement']))
  return result

def replay(h,envelopes):
 need(envelopes,'missing observation history');m=h.m;known=keys(m);original=frame.member_digest(m);expected_frontier=frontier(m);lost=losses(m)
 physical={};prior_name=None
 for cid,b in h.candidates:
  need(prior_name is None or prior_name<cid,'candidate order or duplicate');prior_name=cid
  need(cid in known,'candidate outside member');need(1<=len(b)<=4194304,'candidate bounds');need(known[cid] is None or known[cid]==len(b),'candidate expected length');need(frame.raw_cid(b)==cid,'candidate hash');physical[cid]=b
 try:check_writer(m,physical,True)
 except (ValueError,wire.crypto.InvalidSignature,KeyError,TypeError):raise ValueError('candidate writer request')
 previous=None;offset=0;selected={};attempts={};seen=h.checkpoint is None
 for raw in envelopes:
  try:st=wire.verify(raw,h.context,previous)
  except ValueError:raise ValueError('observation authentication')
  b=st['body'];event=st['event'];seq=st['sequence']
  if 'member' in b:need(b['member']==original,'member commitment')
  if 'frontier' in b:need(b['frontier']==expected_frontier,'metadata frontier')
  if seq==1:need(event=='created','created position')
  elif offset<len(lost):
   need(event=='unavailable','initial loss incomplete');expected=lost[offset:offset+32];need(b['entries']==expected,'initial loss partition');offset+=len(expected)
  elif event=='unavailable':raise ValueError('late unavailable')
  elif event=='restored':
   cid=text(b['cid']);need(cid in physical,'restoration without candidate');need(b['length']==len(physical[cid]),'restoration length');need(cid not in selected,'duplicate restoration');selected[cid]=physical[cid]
  elif event=='publication-intent':
   ident=b['attempt'];need(ident not in attempts,'duplicate intent');r,o=output(m,list(selected.items()));need(b['restorations']==r,'historical restorations');need(b['output']==o,'intent output');attempts[ident]={'intent':st['statementCid'],'output':o,'restorations':r,'failureCount':0,'observedAt':None}
  elif event in ['publication-failed','publication-observed']:
   need(b['attempt'] in attempts,'unknown attempt');a=attempts[b['attempt']];need(b['intent']==a['intent'],'intent citation');need(a['observedAt'] is None,'event after observed')
   if event=='publication-observed':need(b['output']==a['output'],'observed output');a['observedAt']=seq
   else:a['failureCount']+=1
  else:raise ValueError('event position')
  if h.checkpoint and h.checkpoint[0]==seq:need(h.checkpoint[1]==text(st['statementCid']),'external checkpoint statement');seen=True
  previous=st
 need(offset==len(lost),'initial loss incomplete');need(len(selected)==len(physical),'candidate without restoration');need(seen,'external checkpoint absent')
 return {'latestSequence':previous['sequence'],'latestCid':text(previous['statementCid']),'restored':len(selected),'restoredObjects':[{'cid':c,'length':len(b),'basis':basis(m,c)} for c,b in sorted(selected.items())],'attempts':[{'id':i.hex(),'intent':text(a['intent']),'output':a['output'].hex(),'restorations':a['restorations'].hex(),'failureCount':a['failureCount'],'observedAt':a['observedAt']} for i,a in sorted(attempts.items())]}

def base(profile=2,damaged=True,n=2):
 m,o=members.build(profile,n);saved=copy.deepcopy(m['objects']);m['objects']=[] if damaged else m['objects'];h=History(m,o);h.initial();return h,saved

def vectors():
 cases=[]
 def add(name,h,error=None,mutate_env=None):
  env=h.encoded()
  if mutate_env:mutate_env(env)
  try:result=replay(h,env)
  except ValueError as e:need(error==str(e),(name,error,str(e)));result=None
  else:need(error is None,(name,'accepted hostile'))
  packed=members.pack(name,h.m,h.observer,complete=complete(h.m))
  c={'name':name,'member':packed,'candidates':[[cid,b.hex()] for cid,b in h.candidates],'observations':[b.hex() for b in env],'checkpoint':h.checkpoint}
  if error:c['error']=error
  else:c['expected']=result
  cases.append(c)
 for p in [2,3]:
  h,saved=base(p);add(f'profile{p}-initial-loss',h)
  for cid,b in saved:h.restore(cid,b)
  i=h.intent();h.outcome(i,'publication-failed');h.outcome(i);add(f'profile{p}-restored-failure-observed',h)
  h.checkpoint=[2,codec.cid(codec.decode(h.encoded()[1])['statement'])]
  add(f'profile{p}-external-prefix-and-extension',h)
 h,_=base(2,True,34);add('greedy-32-plus-2-loss-partition',h)
 h,saved=base(2,False);i=h.intent();h.restore(*saved[0]);h.outcome(i);j=h.intent(10);h.outcome(j);add('later-candidate-keeps-earlier-intent-history',h)
 h,_=base(3,False,3);h.m['records']=h.m['records'][:1];h.events=[];h.initial();add('partial-copy-retained-no-publication',h)
 h,_=base(2,False,0);i=h.intent();h.outcome(i,'publication-failed');add('failed-intent-remains-unobserved',h)
 h,_=base(3,False,3);h.m['records']=h.m['records'][:1];data=b'unverified retained key';cid=frame.raw_cid(data)
 h.m['membership'].append([cid,77]);h.m['membership'].sort();h.events=[];h.initial();h.restore(cid,data)
 referenced=text(codec.decode(h.m['records'][0][1])['body']['entries'][0]['ciphertext'])
 h.restore(*next(o for o in h.m['objects'] if o[0]!=referenced))
 add('partial-membership-restoration-does-not-promote-source-authority',h)
 # Complete-copy staged membership and raw original-only keys exercise the
 # other restoration bases independently of any unavailable-request inference.
 m,o=members.build(3,0);data=b'complete copy staged object';cid=frame.raw_cid(data);m['membership']=[[cid,len(data)]]
 source=hashlib.sha256(b'tools.kan.archive.copy-source.v1\0'+members.framed(b'commits')+(0).to_bytes(8,'big')+members.framed(b'objects')+(1).to_bytes(8,'big')+members.framed(codec.cid_bytes(cid))+len(data).to_bytes(8,'big')).digest()
 plan=codec.decode(m['plan']);plan['sourceDigest']=source;m['plan']=codec.encode(plan);m['archive']=hashlib.sha256(b'tools.kan.archive.copy-plan.v1\0'+m['plan']).digest()
 h=History(m,o);h.initial();h.restore(cid,data);i=h.intent();h.outcome(i);add('verified-copy-recipe-staged-restoration',h)
 m,o=members.build(2,0);data=b'raw original-only object';cid=frame.raw_cid(data);m['objects']=[[cid,b'wrong bytes']]
 h=History(m,o);h.initial();h.restore(cid,data);i=h.intent();h.outcome(i);add('original-object-basis-survives-restoration',h)

 def ready():
  h,saved=base()
  for cid,b in saved:h.restore(cid,b)
  i=h.intent();return h,i
 def bad(name,edit,error):
  h,i=ready();edit(h,i);add(name,h,error)
 bad('wrong-created-member',lambda h,i:h.events[0][1].update(member=b'\xff'*32),'member commitment')
 bad('wrong-created-frontier',lambda h,i:h.events[0][1].update(frontier={'through':0,'manifest':None,'attestation':None}),'metadata frontier')
 bad('omitted-loss-coordinate',lambda h,i:h.events[1][1]['entries'].pop(),'initial loss partition')
 bad('late-unavailable',lambda h,i:h.events.append(copy.deepcopy(h.events[1])),'late unavailable')
 bad('restored-wrong-member',lambda h,i:h.events[2][1].update(member=b'\xff'*32),'member commitment')
 bad('missing-candidate',lambda h,i:h.candidates.pop(),'restoration without candidate')
 bad('duplicate-restored-observation',lambda h,i:h.events.insert(i,copy.deepcopy(h.events[2])),'duplicate restoration')
 bad('false-intent-r1',lambda h,i:h.events[i][1].update(restorations=b'\xff'*32),'historical restorations')
 bad('false-intent-o1',lambda h,i:h.events[i][1].update(output=b'\xff'*32),'intent output')
 bad('duplicate-attempt-intent',lambda h,i:h.events.append(copy.deepcopy(h.events[i])),'duplicate intent')
 def observed_edit(h,i,field,value):h.outcome(i);h.events[-1][1][field]=value
 bad('observed-cites-created',lambda h,i:observed_edit(h,i,'intentIndex',0),'intent citation')
 bad('observed-other-attempt',lambda h,i:observed_edit(h,i,'attempt',b'\x77'*16),'unknown attempt')
 bad('observed-wrong-output',lambda h,i:observed_edit(h,i,'output',b'\xff'*32),'observed output')
 def after(h,i):h.outcome(i);h.outcome(i,'publication-failed')
 bad('failure-after-observed',after,'event after observed')
 def twice(h,i):h.outcome(i);h.outcome(i)
 bad('second-observed',twice,'event after observed')
 bad('checkpoint-future',lambda h,i:setattr(h,'checkpoint',[100,codec.cid(b'future checkpoint')]),'external checkpoint absent')
 bad('checkpoint-wrong-statement',lambda h,i:setattr(h,'checkpoint',[1,codec.cid(b'wrong')]),'external checkpoint statement')
 bad('truncated-after-creation',lambda h,i:(h.events.__delitem__(slice(1,None)),h.candidates.clear()),'initial loss incomplete')
 h,saved=base(2,False);i=h.intent();h.candidates=[saved[0]];add('unsigned-physical-candidate',h,'candidate without restoration')
 h,saved=base(2,False);i=h.intent();h.restore(*saved[0]);h.events[i][1]['restorations']=frame.restoration_digest(h.candidates);add('intent-uses-future-candidate',h,'historical restorations')
 h,saved=base();h.candidates=[[frame.raw_cid(b'extra'),b'extra']];add('new-candidate-outside-member',h,'candidate outside member')
 h,saved=base();h.candidates=[saved[0]];h.candidates[0][1]=b'x'*len(h.candidates[0][1]);add('candidate-hash-mismatch',h,'candidate hash')
 h,_=base(2,False);h.events=[];add('absent-observer-ledger',h,'missing observation history')
 h,_=base(2,True,34);last=h.events[1][1]['entries'].pop();h.events[2][1]['entries'].insert(0,last);add('complete-but-nongreedy-loss-partition',h,'initial loss partition')
 h,saved=base();h.restore(*saved[0]);h.events.insert(1,h.events.pop());add('restoration-before-loss-coverage',h,'initial loss incomplete')
 bad('wrong-loss-length',lambda h,i:h.events[1][1]['entries'][0].update(expectedLength=h.events[1][1]['entries'][0]['expectedLength']+1),'initial loss partition')
 bad('wrong-restoration-length',lambda h,i:h.events[2][1].update(length=h.events[2][1]['length']+1),'restoration length')
 h,_=base(3,False,3);h.m['records']=h.m['records'][:1];h.events=[];h.initial();h.add('publication-intent',{'attempt':b'\x09'*16,'member':frame.member_digest(h.m),'restorations':frame.restoration_digest([]),'output':b'\x00'*32,'frontier':frontier(h.m)});add('partial-copy-publication-refused',h,'partial copy publication')
 h,_=base(2,False);h.m['objects'].append([frame.raw_cid(b'orphan'),b'corrupt']);h.m['objects'].sort();h.events=[];h.initial();h.add('publication-intent',{'attempt':b'\x09'*16,'member':frame.member_digest(h.m),'restorations':frame.restoration_digest([]),'output':b'\x00'*32,'frontier':frontier(h.m)});add('corrupt-orphan-cannot-be-omitted-for-publication',h,'publication-blocked-unavailable-object')
 h,_=base(2,False);h.m['objects'][0][1]=b'x'*len(h.m['objects'][0][1]);add('changed-original-after-created',h,'member commitment')
 h,_=ready();add('replayed-observation-row',h,'observation authentication',lambda env:env.__setitem__(2,env[1]))
 m,o=members.build(2,1);request=json.loads(m['objects'][0][1]);sig=bytearray.fromhex(request['signature']);sig[7]^=1;request['signature']=sig.hex();bad=members.canonical(request);cid=frame.raw_cid(bad)
 manifest=members.codec.decode(m['records'][0][1]);entry=manifest['body']['entries'][0];entry['ciphertext']=members.codec.Link(members.codec.cid_bytes(cid));entry['length']=len(bad);mb=members.codec.encode(manifest)
 receipt=members.codec.decode(m['records'][0][2]);receipt['body']['manifest']=members.codec.Link(members.codec.cid_bytes(members.codec.cid(mb)));m['records'][0][1]=mb;m['records'][0][2]=members.codec.encode(receipt);m['objects']=[];members.resign(m)
 h=History(m,o);h.initial();h.restore(cid,bad);h.add('publication-intent',{'attempt':b'\x09'*16,'member':frame.member_digest(m),'restorations':frame.restoration_digest(h.candidates),'output':frame.member_digest({**m,'objects':[[cid,bad]]},True),'frontier':frontier(m)});add('restored-content-address-does-not-certify-writer',h,'candidate writer request')
 return {'status':'pure state replay vectors over independently constructed valid members; no physical format/durability claim','cases':cases}

def main():
 p=argparse.ArgumentParser();p.add_argument('--write',action='store_true');p.add_argument('--check',action='store_true');a=p.parse_args();v=vectors()
 if a.write:PATH.write_text(json.dumps(v,indent=2)+'\n')
 if a.check:need(json.loads(PATH.read_text())==v,'fixture drift')
 print(f"{len(v['cases'])} independent state cases; {sum('expected' in c for c in v['cases'])} positive; no storage or durability acceptance")
if __name__=='__main__':main()
