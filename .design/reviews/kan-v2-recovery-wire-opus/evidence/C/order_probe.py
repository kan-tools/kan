"""Does any committed fixture discriminate canonical CID *text* order from binary order?"""
import base64, hashlib, json, sys
def raw(b): return b'\x01\x55\x12\x20'+hashlib.sha256(b).digest()
def text(r): return 'b'+base64.b32encode(r).decode().lower().rstrip('=')
root=sys.argv[1]
good=b'public synthetic ciphertext'; other=b'second synthetic object'
for a,b in [(good,other)]:
    ta,tb=text(raw(a)),text(raw(b))
    print('commitments pair: text_order', ta<tb, 'binary_order', raw(a)<raw(b), 'discriminates', (ta<tb)!=(raw(a)<raw(b)))
f=json.load(open(root+'/.design/fixtures/recovery-observation-v1.json'))
def cids(v,acc):
    if isinstance(v,dict):
        if set(v)=={'$link'}: acc.add(v['$link'])
        else: [cids(x,acc) for x in v.values()]
    elif isinstance(v,list): [cids(x,acc) for x in v]
    return acc
for row in f['positive']+f['shapePositive']:
    if row['statement']['event']=='unavailable':
        ents=row['statement']['body']['entries']; s={e['cid']['$link'] for e in ents}
        print('observation', row['name'], 'entries', len(ents), 'distinct cids', len(s))
# find a pair of raw CIDs whose text and binary orders disagree
i=0
while True:
    a,b=raw(b'probe-%d'%i),raw(b'probe-%d'%(i+1))
    if (text(a)<text(b))!=(a<b): print('disagreeing pair found at', i, text(a), text(b)); break
    i+=1
