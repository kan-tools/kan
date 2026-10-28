#!/usr/bin/env python3
"""Reproduce three independent review probes and add partial-profile-3 coverage.

The raw reviewer generator is retained separately. This promoted generator uses
its same signed history construction and compares the exact fixture bytes.
Physical files are produced by recovery_bundle_files.py; no Rust or live data.
"""
import argparse,json
from pathlib import Path
import recovery_replay_vectors as rv
ROOT=Path(__file__).resolve().parents[2]
TARGET=ROOT/'.design/fixtures/recovery-bundle-review-v1.json'

def generate():
    cases=[]
    for name,original,restore in [
        ('E1-empty-original-initial-loss',b'',False),
        ('E2-empty-original-restored',b'',True),
        ('E3-nonempty-corrupt-original-restored-control',b'x',True),
    ]:
        member,observer=rv.members.build(2,0)
        cid=rv.frame.raw_cid(b'correct');member['objects']=[[cid,original]]
        history=rv.History(member,observer);history.initial()
        if restore:history.restore(cid,b'correct')
        encoded=history.encoded()
        packed=rv.members.pack(name,member,observer,complete=rv.complete(member))
        rv.replay(history,encoded)
        cases.append({'name':name,'member':packed,'candidates':[[cid,b.hex()] for cid,b in history.candidates],
            'observations':[b.hex() for b in encoded],'checkpoint':history.checkpoint,
            'designExpect':'accept','pythonOracle':'accept'})
    for restore in [False,True]:
        name='E5-partial-profile3-empty-original-restored' if restore else 'E4-partial-profile3-empty-original-initial-loss'
        member,observer=rv.members.build(3,3);member['records']=member['records'][:1]
        cid,correct=member['objects'][0];member['objects'][0]=[cid,b'']
        history=rv.History(member,observer);history.initial()
        if restore:history.restore(cid,correct)
        encoded=history.encoded();rv.replay(history,encoded)
        packed=rv.members.pack(name,member,observer,complete=False)
        cases.append({'name':name,'member':packed,'candidates':[[cid,b.hex()] for cid,b in history.candidates],
            'observations':[b.hex() for b in encoded],'checkpoint':history.checkpoint,
            'designExpect':'accept','pythonOracle':'accept'})
    return json.dumps({'cases':cases},indent=1)

def main():
    p=argparse.ArgumentParser();p.add_argument('--check',action='store_true');a=p.parse_args();text=generate()
    if a.check:
        if TARGET.read_text()!=text:raise SystemExit('promoted recovery-bundle vectors differ')
        print('Five empty/corrupt-original vectors reproduce; original three reviewer cases retained unchanged')
    else:TARGET.write_text(text)
if __name__=='__main__':main()
