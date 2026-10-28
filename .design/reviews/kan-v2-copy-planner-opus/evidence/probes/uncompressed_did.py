#!/usr/bin/env python3
"""Reviewer-only: derive an uncompressed-point did:key for the fixture's P-256 issuer and
append plan vectors using it (noncanonical spelling of the same key)."""
import json, sys
sys.path.insert(0, sys.argv[3])
import noncanonical_plans as nc
B58='123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
def b58d(s):
    n=0
    for c in s: n=n*58+B58.index(c)
    raw=n.to_bytes((n.bit_length()+7)//8,'big'); return b'\0'*(len(s)-len(s.lstrip('1')))+raw
def b58e(b):
    n=int.from_bytes(b,'big'); out=''
    while n: n,r=divmod(n,58); out=B58[r]+out
    return '1'*(len(b)-len(b.lstrip(b'\0')))+out
p=2**256-2**224+2**192+2**96-1; bcoef=0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
fx=json.load(open(sys.argv[1])); base=fx['positive'][0]['plan']
raw=b58d(base['issuer'][len('did:key:z'):]); assert raw[:2]==b'\x80\x24' and len(raw)==35, raw[:3]
x=int.from_bytes(raw[3:],'big'); y=pow((x**3-3*x+bcoef)%p,(p+1)//4,p)
if y%2!=raw[2]%2: y=p-y
unc='did:key:z'+b58e(b'\x80\x24'+b'\x04'+x.to_bytes(32,'big')+y.to_bytes(32,'big'))
vs=json.load(open(sys.argv[2]))
for field in ('issuer','historicalIssuer'):
    v=dict(base); v[field]=unc; vs.append({'name':field+'-uncompressed-p256','hex':nc.enc(v,{}).hex(),'expect':'refuse'})
json.dump(vs,open(sys.argv[2],'w'),indent=1); print(unc, len(unc))
