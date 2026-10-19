const {test}=require('node:test'), assert=require('node:assert/strict'), vm=require('node:vm'), fs=require('node:fs');
const tick=()=>new Promise(setImmediate);
function ui(){
 const nodes=new Map(),pending=[],downloads=[],revoked=[],timers=new Map(),blobs=[];let active;
 class Element{constructor(){this.value='';this.hidden=false;this.disabled=false;this.children=[];this.events={};this.attrs={};this.textContent='';}setAttribute(k,v){this.attrs[k]=v;}addEventListener(k,f){this.events[k]=f;}append(v){this.children.push(v);}replaceChildren(){this.children=[];}remove(){this.removed=true;}focus(){active=this;}click(){downloads.push(this);if(this.events.click)this.events.click();}}
 const node=id=>{if(!nodes.has(id))nodes.set(id,new Element());return nodes.get(id);};const window={events:{},addEventListener(k,f){this.events[k]=f;}};
 const context={document:{getElementById:node,createElement:()=>new Element(),body:node("body")},window,AbortController,Blob,Uint8Array,setTimeout:(fn)=>{const id={};timers.set(id,fn);return id;},clearTimeout:id=>timers.delete(id),URL:{createObjectURL:blob=>{blobs.push(blob);return 'blob:synthetic';},revokeObjectURL:url=>revoked.push(url)},fetch:(url,opts)=>new Promise((resolve,reject)=>pending.push({url,opts,resolve,reject})),console};
 node('library').hidden=true;node('inspection').hidden=true;
 vm.createContext(context);vm.runInContext(fs.readFileSync('web/library/app.js','utf8'),context);
 const respond=async(value,status=200)=>{const request=pending.shift();assert.ok(request,'expected request');request.resolve({ok:status===200,status,json:async()=>value});await tick();await tick();};
 const login=async()=>{node('token').value='synthetic-library-token';node('connect').events.submit({preventDefault(){}});await tick();};
 return{node,pending,respond,login,downloads,revoked,timers,blobs,window,active:()=>active};
}
const pin={request:'synthetic-pin',reply:{}};
const catalog={version:1,coverage:'complete',capabilities:['snapshot-inventory','source-ranges','provenance'],unavailable:['semantic-search','normalized-sessions','annotations','saved-views','analysis','administrative-jobs'],scopes:[{scope:'allowed-A',pin},{scope:'allowed-B',pin}]};
const page={through:2,next:1,records:[{sequence:1,manifest:'<img src=https://untrusted.invalid onerror=alert(1)>',receipt:'receipt-A'}],coverage:'selected scope at snapshot'};
const source={record:{sequence:1,manifest:'manifest-A',receipt:'receipt-A'},scope:'allowed-A',writer:'writer-A',service_issuer:'service-A',signature:'verified',admission:'signed service',content_trust:'untrusted bytes',total_bytes:8,offset:0,next:4,bytes_hex:'3c623e78',utf8:'<b>x'};
async function open(u){await u.login();await u.respond(catalog);await u.respond(page);}
// Reviewer probes (not committed). Boundaries, shapes the committed list omits, retry state.
const many=n=>Array.from({length:n},(_,i)=>({scope:String(i),pin}));
const accepted=async scopes=>{const u=ui();await u.login();await u.respond({...catalog,scopes});return u;};
test('PB1 boundary values are accepted, not falsely rejected',async()=>{
 for(const scopes of [many(16),[{scope:'s'.repeat(256),pin}],[{scope:'a',pin:{request:'r'.repeat(8192),reply:{}}}]]){const u=await accepted(scopes);assert.equal(u.node('library').hidden,false);assert.equal(u.node('scope').children.length,scopes.length);assert.equal(u.pending.length,1);assert.equal(JSON.parse(u.pending[0].opts.body).action,'page');}
});
test('PB2 complete empty catalog still opens without page request',async()=>{const u=await accepted([]);assert.equal(u.node('library').hidden,false);assert.equal(u.pending.length,0);assert.match(u.node('notice').textContent,/No currently authorized/);});
test('PB3 over-limit scope name and pin request are rejected',async()=>{
 for(const scopes of [[{scope:'s'.repeat(257),pin}],[{scope:'a',pin:{request:'r'.repeat(8193),reply:{}}}]]){const u=await accepted(scopes);assert.equal(u.node('library').hidden,true,JSON.stringify(scopes).slice(0,40));assert.equal(u.pending.length,0);}
});
test('PB4 non-string scope/request with a length property are rejected',async()=>{
 for(const scopes of [[{scope:['a'],pin}],[{scope:{length:1},pin}],[{scope:'a',pin:{request:['x'],reply:{}}}],[{scope:'a',pin:{request:7,reply:{}}}],[{scope:'a',pin:[]}]]){const u=await accepted(scopes);assert.equal(u.node('library').hidden,true,JSON.stringify(scopes));assert.equal(u.pending.length,0);assert.equal(u.node('scope').children.length,0);}
});
test('PB5 malformed retry from partial resets capabilities, styling and keeps lock/recovery',async()=>{
 const u=ui();await u.login();await u.respond({...catalog,coverage:'partial'});await u.respond(page);u.node('rows').children[0].click();await tick();await u.respond(source);
 assert.equal(u.node('catalog-status').className,'partial');
 u.node('retry-sources').click();await tick();
 assert.equal(u.node('source').textContent,'','plaintext cleared before recheck reply');assert.equal(u.node('rows').children.length,0);
 await u.respond({...catalog,coverage:'partial',scopes:[{scope:'a',pin},{scope:'a',pin}]});
 assert.equal(u.node('library').hidden,false);assert.equal(u.node('capability-list').children.length,0);assert.equal(u.node('scope').children.length,0);
 assert.equal(u.node('catalog-status').className,'');assert.match(u.node('catalog-status').textContent,/coverage is unknown/);assert.equal(u.node('lock').disabled,false);assert.equal(u.pending.length,0);
 u.node('scope').value='a';u.node('scope').events.change();await tick();assert.equal(u.pending.length,0,'old scopes array must not allow navigation');
 u.node('next').click();await tick();assert.equal(u.pending.length,0,'next must not page with cleared pin');
 u.node('resnapshot').click();await tick();assert.equal(u.pending.length,0,'resnapshot must not run without pin');
});
test('PB6 lock during malformed-catalog reply ignores the late reply',async()=>{const u=ui();await u.login();u.node('lock').click();const r=u.pending.shift();r.resolve({ok:true,status:200,json:async()=>({...catalog,scopes:[null]})});await tick();await tick();assert.equal(u.node('library').hidden,true);assert.equal(u.node('login').hidden,false);});
test('PB7 after malformed retry, old scope names and pins cannot be navigated',async()=>{
 const u=ui();await open(u);u.node('retry-sources').click();await tick();await u.respond({...catalog,scopes:[{scope:'x',pin},7]});
 assert.equal(u.pending.length,0);
 u.node('scope').value='allowed-A';u.node('scope').events.change();await tick();assert.equal(u.pending.length,0,'old scopes array still navigable');
 u.node('resnapshot').click();await tick();assert.equal(u.pending.length,0,'old pin still usable');
});
