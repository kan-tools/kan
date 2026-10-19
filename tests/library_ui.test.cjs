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
test('real endpoint uses header auth and untrusted source stays text',async()=>{const u=ui();await u.login();assert.equal(u.node('token').value,'');assert.equal(u.pending[0].url,'/api/library');assert.equal(u.pending[0].opts.headers.Authorization,'Bearer synthetic-library-token');assert.equal(u.pending[0].opts.credentials,'omit');await u.respond(catalog);await u.respond(page);assert.equal(u.node('rows').children[0].children[1].textContent,page.records[0].manifest);u.node('rows').children[0].click();await tick();assert.equal(JSON.parse(u.pending[0].opts.body).action,'source');await u.respond(source);assert.equal(u.node('source').textContent,'<b>x');assert.equal(u.node('inspection').hidden,false);assert.equal(u.pending.length,0);assert.equal(u.active(),u.node('source-tab'));});
test('lock aborts pending source and clears every private view',async()=>{const u=ui();await open(u);u.node('rows').children[0].click();await tick();const pending=u.pending[0];u.node('lock').click();assert.equal(pending.opts.signal.aborted,true);await u.respond(source);assert.equal(u.node('library').hidden,true);assert.equal(u.node('source').textContent,'');assert.equal(u.node('rows').children.length,0);assert.equal(u.node('provenance').children.length,0);assert.equal(u.node('scope').children.length,0);assert.equal(u.node('count').textContent,'');assert.equal(u.active(),u.node('token'));});
test('page and scope navigation carry only the selected authenticated pin',async()=>{const u=ui();await open(u);u.node('next').click();await tick();assert.equal(JSON.parse(u.pending[0].opts.body).after,1);await u.respond({...page,next:null,records:[{...page.records[0],sequence:2}]});assert.equal(u.node('previous').disabled,false);u.node('previous').click();await tick();assert.equal(JSON.parse(u.pending[0].opts.body).after,0);await u.respond(page);u.node('scope').value='allowed-B';u.node('scope').events.change();await tick();assert.equal(JSON.parse(u.pending[0].opts.body).after,0);await u.respond({...page,through:0,next:null,records:[]});assert.equal(u.node('empty').hidden,false);assert.equal(u.node('previous').disabled,true);});
test('download rechecks authorization and denied export clears prior plaintext',async()=>{const u=ui();await open(u);u.node('rows').children[0].click();await tick();await u.respond(source);u.node('download').click();await tick();assert.equal(JSON.parse(u.pending[0].opts.body).action,'source');await u.respond({},403);assert.equal(u.node('source').textContent,'');assert.equal(u.node('library').hidden,true);assert.equal(u.downloads.filter(x=>x.download).length,0);assert.match(u.node('notice').textContent,/revoked/);});
test('old transport errors cannot lock a newer session',async()=>{const u=ui();await u.login();const old=u.pending.shift();u.node('lock').click();await u.login();await u.respond(catalog);await u.respond(page);old.reject(new Error('old network failure'));await tick();await tick();assert.equal(u.node('library').hidden,false);assert.equal(u.node('rows').children.length,1);});
test('range reads do not accumulate plaintext and inspector close returns focus',async()=>{const u=ui();await open(u);const row=u.node('rows').children[0];row.click();await tick();await u.respond(source);u.node('more').click();await tick();assert.equal(u.node('source').textContent,'');assert.equal(JSON.parse(u.pending[0].opts.body).offset,4);await u.respond({...source,offset:4,next:null,bytes_hex:'00ff0102',utf8:null});assert.equal(u.node('source').textContent,'00ff0102');assert.equal(u.node('more').disabled,true);u.node('close-inspector').click();assert.equal(u.node('source').textContent,'');assert.equal(u.active(),row);});
test('pagehide locks and no reader persistence or HTML execution sinks are present',async()=>{const u=ui();await open(u);u.window.events.pagehide();assert.equal(u.node('library').hidden,true);const code=fs.readFileSync('web/library/app.js','utf8');assert.doesNotMatch(code,/localStorage|sessionStorage|indexedDB|innerHTML|insertAdjacentHTML|eval\(/);});

test('source view can inspect exact bytes even when UTF-8 contains controls',async()=>{const u=ui();await open(u);u.node('rows').children[0].click();await tick();await u.respond({...source,utf8:'x\0y',bytes_hex:'780079',total_bytes:3,next:null});assert.equal(u.node('source').textContent,'780079');assert.match(u.node('range').textContent,/hex/);u.node('encoding').click();assert.equal(u.node('source').textContent,'x\0y');u.node('encoding').click();assert.equal(u.node('source').textContent,'780079');});

test('export keeps exact bytes alive until navigation starts and releases on timeout or lock',async()=>{for(const finish of ['timeout','lock']){const u=ui();await open(u);u.node('rows').children[0].click();await tick();await u.respond(source);u.node('download').click();await tick();await u.respond(source);const a=u.downloads.find(x=>x.download);assert.ok(u.node('body').children.includes(a));assert.equal(a.removed,true);assert.equal(a.download,'kan-occurrence-1-offset-0.bin');assert.deepEqual([...new Uint8Array(await u.blobs[0].arrayBuffer())],[60,98,62,120]);assert.equal(u.revoked.length,0);assert.equal(u.timers.size,1);if(finish==='lock')u.node('lock').click();else [...u.timers.values()][0]();assert.deepEqual(u.revoked,['blob:synthetic']);assert.equal(u.timers.size,0);}});

test('scope changes remove old-scope rows before a new pin is used',async()=>{const u=ui();await open(u);assert.equal(u.node('rows').children.length,1);u.node('scope').value='allowed-B';u.node('scope').events.change();await tick();assert.equal(u.node('rows').children.length,0,'old rows must not remain actionable under a new scope pin');assert.equal(u.node('next').disabled,true);await u.respond({...page,through:0,next:null,records:[]});assert.equal(u.node('empty').hidden,false);});

test('unavailable or unverifiable source clears plaintext but preserves other browsing',async()=>{for(const status of [404,503]){const u=ui();await open(u);u.node('rows').children[0].click();await tick();await u.respond(source);u.node('download').click();await tick();await u.respond({},status);assert.equal(u.node('library').hidden,false);assert.equal(u.node('source').textContent,'');assert.equal(u.node('provenance').children.length,0);assert.equal(u.node('rows').children.length,1);assert.match(u.node('notice').textContent,status===404?/Retained source is unavailable/:/could not be verified/);u.node('rows').children[0].click();await tick();await u.respond(source);assert.equal(u.node('source').textContent,'<b>x');}});
test('unverifiable page removes old rows and leaves scope recovery available',async()=>{const u=ui();await open(u);u.node('scope').value='allowed-B';u.node('scope').events.change();await tick();await u.respond({},503);assert.equal(u.node('library').hidden,false);assert.equal(u.node('rows').children.length,0);assert.equal(u.node('count').textContent,'');assert.equal(u.node('scope').children.length,2);assert.match(u.node('notice').textContent,/could not be verified/);});
test('directional format controls default to exact hex and permit explicit UTF-8',async()=>{const u=ui();await open(u);u.node('rows').children[0].click();await tick();await u.respond({...source,utf8:'abc\u202etxt',bytes_hex:'616263e280ae747874',total_bytes:9,next:null});assert.equal(u.node('source').textContent,'616263e280ae747874');u.node('encoding').click();assert.equal(u.node('source').textContent,'abc\u202etxt');});

test('capability matrix renders actual service capabilities without claiming unknown support',async()=>{const u=ui();await u.login();await u.respond({...catalog,capabilities:[...catalog.capabilities,'future-mode']});await u.respond(page);const rows=u.node('capability-list').children.map(r=>r.children.map(x=>x.textContent));assert.deepEqual(rows.find(r=>r[0]==='Snapshot inventory'),['Snapshot inventory','Available']);assert.deepEqual(rows.find(r=>r[0]==='Sessions'),['Sessions','Upcoming']);assert.deepEqual(rows.find(r=>r[0]==='future-mode'),['future-mode','Client unsupported']);u.node('lock').click();assert.equal(u.node('capability-list').children.length,0);});

test('partial catalog coverage persists while browsing and retry clears old authority',async()=>{const u=ui();await u.login();await u.respond({...catalog,coverage:'partial'});await u.respond(page);assert.match(u.node('catalog-status').textContent,/Partial coverage/);u.node('rows').children[0].click();await tick();await u.respond(source);assert.match(u.node('catalog-status').textContent,/Partial coverage/);u.node('retry-sources').click();await tick();assert.equal(u.node('source').textContent,'');assert.equal(u.node('rows').children.length,0);assert.equal(u.node('scope').children.length,0);assert.equal(u.node('capability-list').children.length,0);assert.equal(u.node('previous').disabled,true);assert.equal(u.node('next').disabled,true);assert.equal(JSON.parse(u.pending[0].opts.body).action,'catalog');await u.respond(catalog);await u.respond(page);assert.match(u.node('catalog-status').textContent,/Source checks complete/);});
test('incomplete empty catalog differs from complete empty and late retry cannot repaint after lock',async()=>{for(const coverage of ['partial','complete']){const u=ui();await u.login();await u.respond({...catalog,coverage,scopes:[]});assert.equal(u.node('library').hidden,false);assert.equal(u.node('rows').children.length,0);assert.match(u.node('notice').textContent,coverage==='partial'?/incomplete check/:/No currently authorized/);u.node('retry-sources').click();await tick();const request=u.pending[0];u.node('lock').click();assert.equal(request.opts.signal.aborted,true);await u.respond(catalog);assert.equal(u.node('library').hidden,true);assert.equal(u.node('catalog-status').textContent,'');assert.equal(u.node('capability-list').children.length,0);assert.equal(u.node('scope').children.length,0);}});
test('both authorization denial statuses lock an already open Library',async()=>{for(const status of [401,403]){const u=ui();await open(u);u.node('rows').children[0].click();await tick();await u.respond(source);u.node('more').click();await tick();await u.respond({},status);assert.equal(u.node('library').hidden,true);assert.equal(u.node('source').textContent,'');assert.equal(u.node('catalog-status').textContent,'');assert.equal(u.node('provenance').children.length,0);assert.equal(u.node('scope').children.length,0);assert.equal(u.active(),u.node('token'));}});
test('Previous is disabled immediately when leaving a later page',async()=>{const u=ui();await open(u);u.node('next').click();await tick();await u.respond({...page,next:null,records:[{...page.records[0],sequence:2}]});assert.equal(u.node('previous').disabled,false);u.node('scope').value='allowed-B';u.node('scope').events.change();await tick();assert.equal(u.node('previous').disabled,true);assert.equal(u.node('next').disabled,true);assert.equal(u.node('rows').children.length,0);assert.equal(u.node('count').textContent,'');await u.respond(page);});
test('malformed duplicate and inconsistent capabilities never open a Library',async()=>{for(const change of [{capabilities:null},{unavailable:{}},{capabilities:['snapshot-inventory',7]},{capabilities:['provenance','provenance']},{unavailable:['provenance']},{coverage:'invented'}]){const u=ui();await u.login();await u.respond({...catalog,...change});assert.equal(u.node('library').hidden,true);assert.equal(u.node('capability-list').children.length,0);assert.equal(u.node('rows').children.length,0);assert.equal(u.node('catalog-status').textContent,'');assert.equal(u.pending.length,0);}});
test('all directional control families default to exact hex with explicit text access',async()=>{for(const point of [0x061c,0x200e,0x200f,0x202a,0x202b,0x202c,0x202d,0x202e,0x2066,0x2067,0x2068,0x2069]){const u=ui();await open(u);u.node('rows').children[0].click();await tick();const utf8='a'+String.fromCodePoint(point)+'z',bytes_hex=Buffer.from(utf8).toString('hex');await u.respond({...source,utf8,bytes_hex,total_bytes:Buffer.byteLength(utf8),next:null});assert.equal(u.node('source').textContent,bytes_hex,'U+'+point.toString(16));u.node('encoding').click();assert.equal(u.node('source').textContent,utf8);}});

test('malformed retry clears partially rendered capabilities and keeps recovery available',async()=>{const u=ui();await u.login();await u.respond({...catalog,coverage:'partial'});await u.respond(page);assert.equal(u.node('catalog-status').className,'partial');u.node('retry-sources').click();await tick();await u.respond({...catalog,capabilities:['provenance','provenance']});assert.equal(u.node('library').hidden,false);assert.equal(u.node('scope').children.length,0);assert.equal(u.node('capability-list').children.length,0);assert.equal(u.node('rows').children.length,0);assert.match(u.node('catalog-status').textContent,/coverage is unknown/);assert.equal(u.node('catalog-status').className,'');u.node('retry-sources').click();await tick();await u.respond(catalog);await u.respond(page);assert.equal(u.node('rows').children.length,1);});

test('malformed scope catalogs are rejected before any option or page request',async()=>{
 for(const scopes of [null,{},[null],[[]],[{scope:'',pin}],[{scope:7,pin}],[{scope:'a',pin:null}],[{scope:'a',pin:{request:'',reply:{}}}],[{scope:'a',pin:{request:'x',reply:[]}}],[{scope:'a',pin},{scope:'a',pin}],Array.from({length:17},(_,i)=>({scope:String(i),pin}))]) {
  const u=ui();await u.login();await u.respond({...catalog,scopes});
  assert.equal(u.node('library').hidden,true);assert.equal(u.node('scope').children.length,0);assert.equal(u.pending.length,0);
 }
});
test('malformed scope retry clears old plaintext and permits recovery',async()=>{
 const u=ui();await open(u);u.node('rows').children[0].click();await tick();await u.respond(source);
 u.node('retry-sources').click();await tick();await u.respond({...catalog,scopes:[{scope:'a',pin},null]});
 assert.equal(u.node('source').textContent,'');assert.equal(u.node('scope').children.length,0);assert.equal(u.node('rows').children.length,0);assert.equal(u.pending.length,0);
 u.node('retry-sources').click();await tick();await u.respond(catalog);await u.respond(page);assert.equal(u.node('rows').children.length,1);
});

// Boundary and state probes retained from the independent Opus review.
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

const exactPin='{"reply":{"through":9007199254740993},"signature":"synthetic-exact"}';
const contentCatalog={...catalog,capabilities:[...catalog.capabilities,'content-inspection'],scopes:catalog.scopes.map(s=>({...s,pin_wire:exactPin}))};
const contentPage={...page,through:'9007199254740993',next:null,records:[{...page.records[0],sequence:'9007199254740993'}]};
const contentResult={version:'kan-content/1',pin_wire:exactPin,coverage:'explicit selection only',occurrences:[{record:{sequence:'9007199254740993'}}],observations:[{input:'0',kind:'capture'}],groups:[{observer:'collector',terminal:'unknown',attempt:'a'.repeat(64),missing_start:false,events_after_terminal:false,unconfirmed_claim:false,ordinal_gaps:[['1','3']],ordinals:[],request:{state:'interpreted',issues:[],coherent_stop_observed:false,parsed_json:'{"unknown":9007199254740993}',items:[{kind:'text',role:'user',index:null,text:'<script>never execute</script>',issues:[],pointer:'/messages/0/content',event_json:null,region:['0','10'],coarse:true,citations:[{input:'0',bytes:['20','30']}]}]},response:{state:'unavailable',issues:[{kind:'gap',bytes:['0','8']}],items:[]}}]};
const walk=e=>[e,...e.children.flatMap(walk)];
async function openContent(u){await u.login();await u.respond(contentCatalog);assert.deepEqual(JSON.parse(u.pending[0].opts.body),{action:'content-page',pin_wire:exactPin,after:'0',limit:20});await u.respond(contentPage);u.node('content-format').value='anthropic-messages-sse';const check=u.node('rows').children[0].children[0];check.checked=true;check.events.change();}
async function interpretContent(u){u.node('interpret').click();await tick();assert.deepEqual(JSON.parse(u.pending[0].opts.body),{action:'content',pin_wire:exactPin,sequences:['9007199254740993'],format:'anthropic-messages-sse'});await u.respond(contentResult);}
test('Content preserves opaque pins and large sequence strings through source return',async()=>{
 const u=ui();await openContent(u);await interpretContent(u);
 assert.equal(u.node('content-panel').hidden,false);assert.equal(u.node('content-tab').disabled,false);
 const all=walk(u.node('content-panel'));assert.ok(all.some(e=>e.textContent==='<script>never execute</script>'));
 assert.ok(all.some(e=>e.textContent==='{"unknown":9007199254740993}'));
 assert.ok(all.some(e=>String(e.textContent).includes('No recognized capture at ordinals 1–3')));
 const cite=all.find(e=>String(e.textContent).startsWith('Source 9007199254740993'));assert.ok(cite);cite.click();await tick();
 assert.deepEqual(JSON.parse(u.pending[0].opts.body),{action:'source-exact',pin_wire:exactPin,sequence:'9007199254740993',offset:'20',length:'65536'});
 await u.respond({...source,record:{...source.record,sequence:'9007199254740993'},offset:'20',total_bytes:'30',next:null});
 assert.equal(u.node('content-panel').hidden,true);assert.match(u.node('range').textContent,/20–24 of 30/);
 u.node('content-tab').click();assert.equal(u.node('content-panel').hidden,false);assert.equal(u.active(),cite);
});
test('Content lock, scope, selection and format changes discard late plaintext',async()=>{
 for(const action of ['lock','scope','selection','format']){
  const u=ui();await openContent(u);u.node('interpret').click();await tick();const pending=u.pending.shift();
  if(action==='lock')u.node('lock').click();
  if(action==='scope'){u.node('scope').value='allowed-B';u.node('scope').events.change();await tick();}
  if(action==='selection'){const check=u.node('rows').children[0].children[0];check.checked=false;check.events.change();}
  if(action==='format'){u.node('content-format').value='anthropic-messages-json';u.node('content-format').events.change();}
  assert.equal(pending.opts.signal.aborted,true,action);pending.resolve({ok:true,status:200,json:async()=>contentResult});await tick();await tick();
  assert.equal(u.node('content-panel').children.length,0,action);assert.equal(u.node('content-tab').disabled,true,action);
 }
});
test('Content unplaced input is visible and denied citations clear all plaintext',async()=>{
 const u=ui();await openContent(u);u.node('interpret').click();await tick();await u.respond({...contentResult,observations:[{input:'0',kind:'unsupported',reason:'Event'}],groups:[]});
 const nodes=walk(u.node('content-panel'));assert.ok(nodes.some(e=>e.textContent==='Other selected evidence'));
 const cite=nodes.find(e=>e.textContent==='Inspect source');cite.click();await tick();await u.respond({},403);
 assert.equal(u.node('content-panel').children.length,0);assert.equal(u.node('content-count').textContent,'0 selected');assert.equal(u.node('source').textContent,'');assert.equal(u.node('library').hidden,true);
});
test('Content refuses wrong snapshot and missing exact pins before exposing items',async()=>{
 const u=ui();await openContent(u);u.node('interpret').click();await tick();await u.respond({...contentResult,pin_wire:'other-snapshot'});
 assert.equal(u.node('content-panel').children.length,0);assert.equal(u.node('content-tab').disabled,true);
 const bad=ui();await bad.login();await bad.respond({...contentCatalog,scopes:catalog.scopes});assert.equal(bad.pending.length,0);assert.equal(bad.node('library').hidden,true);
});

test('Content labels supplied history and derived numbers, with separate tool block citations',async()=>{
 const u=ui();await openContent(u);u.node('interpret').click();await tick();
 const value=JSON.parse(JSON.stringify(contentResult));
 value.groups[0].request.items[0].tool={json:'{"x":1}',region:['0','80'],citations:[{input:'0',bytes:['40','80']}]};
 await u.respond(value);
 const nodes=walk(u.node('content-panel'));
 assert.ok(nodes.some(n=>n.textContent==='Supplied history · user · text'));
 assert.ok(nodes.some(n=>/Parsed body.*numbers may be rounded/.test(n.textContent)));
 assert.ok(nodes.some(n=>n.textContent==='Accumulated tool input (derived)'));
 const tool=nodes.find(n=>n.textContent==='Tool input source 9007199254740993 · 40–80');assert.ok(tool);
 tool.click();await tick();assert.deepEqual(JSON.parse(u.pending[0].opts.body),{action:'source-exact',pin_wire:exactPin,sequence:'9007199254740993',offset:'40',length:'65536'});
});
