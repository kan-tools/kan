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
const contentResult={version:'kan-content/2',pin_wire:exactPin,coverage:'explicit selection only',occurrences:[{record:{sequence:'9007199254740993'}}],observations:[{input:'0',kind:'capture'}],groups:[{writer:'writer-A',unexpected_starts:[],observer:'collector',terminal:'unknown',attempt:'a'.repeat(64),missing_start:false,events_after_terminal:false,unconfirmed_claim:false,ordinal_gaps:[['1','3']],ordinals:[],request:{citation_sets:[[{input:'0',bytes:['20','30']}]],observed_bytes:'10',expected_bytes:'10',extent_claims:[],state:'interpreted',issues:[],coherent_stop_observed:false,parsed_json:'{"unknown":9007199254740993}',items:[{kind:'text',role:'user',index:null,text:'<script>never execute</script>',issues:[],pointer:'/messages/0/content',event_json:null,region:['0','10'],coarse:true,citation_set:'0'}]},response:{citation_sets:[],observed_bytes:null,expected_bytes:null,extent_claims:[],state:'unavailable',issues:[{kind:'gap',bytes:['0','8']}],items:[]}}]};
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
 value.groups[0].request.citation_sets.push([{input:'0',bytes:['40','80']}]);value.groups[0].request.items[0].tool={json:'{"x":1}',region:['0','80'],citation_set:'1'};
 await u.respond(value);
 const nodes=walk(u.node('content-panel'));
 assert.ok(nodes.some(n=>n.textContent==='Supplied history · user · text'));
 assert.ok(nodes.some(n=>/Parsed body.*numbers may be rounded/.test(n.textContent)));
 assert.ok(nodes.some(n=>n.textContent==='Accumulated tool input (derived)'));
 const tool=nodes.find(n=>n.textContent==='Tool input source 9007199254740993 · 40–80');assert.ok(tool);
 tool.click();await tick();assert.deepEqual(JSON.parse(u.pending[0].opts.body),{action:'source-exact',pin_wire:exactPin,sequence:'9007199254740993',offset:'40',length:'65536'});
});

test('Content exposes unexpected starts and every exact observer length claim beside unavailable streams',async()=>{
 const u=ui();await openContent(u);u.node('interpret').click();await tick();
 const v=JSON.parse(JSON.stringify(contentResult));v.groups[0].unexpected_starts=['0'];
 v.groups[0].response.extent_claims=[{input:'0',bytes:'9007199254740993'},{input:'0',bytes:'9007199254740994'}];
 await u.respond(v);const nodes=walk(u.node('content-panel'));
 assert.ok(nodes.some(n=>n.textContent==='Retained request signer: writer-A'));
 assert.ok(nodes.some(n=>n.textContent==='Unexpected start · Source 9007199254740993'));
 assert.ok(nodes.some(n=>n.textContent==='Contiguous selected bytes: unavailable · Consistent observer length claim: none'));
 assert.ok(nodes.some(n=>n.textContent==='Claimed bytes: 9007199254740993 '));
 assert.ok(nodes.some(n=>n.textContent==='Claimed bytes: 9007199254740994 '));
 const claim=nodes.find(n=>n.textContent==='Length claim · Source 9007199254740993');claim.click();await tick();
 assert.equal(JSON.parse(u.pending[0].opts.body).sequence,'9007199254740993');
 await u.respond({...source,record:{...source.record,sequence:'9007199254740993'},offset:'0',total_bytes:'8',next:null});
 u.node('content-tab').click();assert.equal(u.active(),claim);
});

test('Content limits and busy workers have distinct fixed messages without claiming failed verification',async()=>{
 for(const [status,pattern] of [[422,/presentation limit or deadline/],[429,/workers are busy/]]){
  const u=ui();await openContent(u);u.node('interpret').click();await tick();await u.respond({},status);
  assert.match(u.node('notice').textContent,pattern);assert.doesNotMatch(u.node('notice').textContent,/could not be verified/);
  assert.equal(u.node('library').hidden,false);assert.equal(u.node('content-panel').children.length,0);assert.equal(u.node('source').textContent,'');
 }
});
test('Source supersedes pending Content and leaves Interpret available for the current selection',async()=>{
 const u=ui();await openContent(u);u.node('interpret').click();await tick();const contentRequest=u.pending[0];
 u.node('rows').children[0].children[1].click();await tick();
 assert.equal(contentRequest.opts.signal.aborted,true);assert.equal(u.node('interpret').disabled,false);
 await u.respond(contentResult);assert.equal(u.node('content-panel').children.length,0);
 await u.respond({...source,record:{...source.record,sequence:'9007199254740993'},offset:'0',total_bytes:'8',next:null});
 assert.equal(u.node('interpret').disabled,false);u.node('interpret').click();await tick();
 assert.equal(JSON.parse(u.pending[0].opts.body).action,'content');
});

// ===== independent reviewer UI probes (bb1e0ab). pass_* assert; char_* log observed behaviour =====
const clone=v=>JSON.parse(JSON.stringify(v));
const texts=u=>walk(u.node('content-panel')).map(e=>String(e.textContent));
test('pass_u2 late Content reply after resnapshot is suppressed',async()=>{
 const u=ui();await openContent(u);u.node('interpret').click();await tick();const pending=u.pending.shift();
 u.node('resnapshot').click();await tick();assert.equal(pending.opts.signal.aborted,true);
 pending.resolve({ok:true,status:200,json:async()=>contentResult});await tick();await tick();
 assert.equal(u.node('content-panel').children.length,0);assert.equal(u.node('content-tab').disabled,true);
 assert.equal(u.node('content-count').textContent,'0 selected');
});
test('pass_u3 invalid citation index leaves no partial Content',async()=>{
 const u=ui();await openContent(u);u.node('interpret').click();await tick();
 const v=clone(contentResult);v.groups[0].request.citation_sets[0]=[{input:'7',bytes:['0','1']}];await u.respond(v);
 assert.equal(u.node('content-panel').children.length,0);assert.equal(u.node('content-tab').disabled,true);
 assert.equal(u.node('library').hidden,false);
});
test('pass_u4 hostile strings in every rendered field stay text and set no attributes',async()=>{
 const u=ui();await openContent(u);u.node('interpret').click();await tick();
 const h='<img src=x onerror=alert(1)>‮';const v=clone(contentResult);
 Object.assign(v.groups[0],{observer:h,terminal:h,attempt:h});
 v.observations=[{input:'0',kind:h,reason:h}];
 v.groups[0].request.citation_sets.push([{input:'0',bytes:[h,h]}]);
 Object.assign(v.groups[0].request.items[0],{role:h,kind:h,text:h,pointer:h,event_json:h,issues:[h],index:h,tool:{json:h,region:[h,h],citation_set:'1'}});
 v.groups[0].request.parsed_json=h;v.coverage=h;await u.respond(v);
 const all=walk(u.node('content-panel'));assert.ok(all.length>10);
 for(const e of all){for(const k of Object.keys(e.attrs))assert.ok(/^aria-/.test(k),'unexpected attribute '+k);assert.ok(!('innerHTML' in e));}
 assert.ok(texts(u).some(t=>t===h));assert.ok(texts(u).some(t=>t.includes(h)&&t.startsWith('Supplied history')));
});
test('pass_u5 page navigation clears selection and disables Interpret',async()=>{
 const u=ui();await u.login();await u.respond(contentCatalog);await u.respond({...contentPage,next:'9007199254740993'});
 const check=u.node('rows').children[0].children[0];check.checked=true;check.events.change();assert.equal(u.node('content-count').textContent,'1 selected');
 u.node('next').click();await tick();assert.deepEqual(JSON.parse(u.pending[0].opts.body).after,'9007199254740993');
 assert.equal(u.node('content-count').textContent,'0 selected');assert.equal(u.node('interpret').disabled,true);
});
test('pass_u7 duplicate lineage citations navigate to each distinct occurrence',async()=>{
 const u=ui();await openContent(u);u.node('interpret').click();await tick();const v=clone(contentResult);
 v.occurrences=[{record:{sequence:'9007199254740993'}},{record:{sequence:'18446744073709551615'}}];
 v.groups[0].request.citation_sets[0]=[{input:'0',bytes:['20','30']},{input:'1',bytes:['20','30']}];await u.respond(v);
 const second=walk(u.node('content-panel')).find(e=>e.textContent==='Source 18446744073709551615 · 20–30');assert.ok(second);
 second.click();await tick();assert.equal(JSON.parse(u.pending[0].opts.body).sequence,'18446744073709551615');
});
test('pass_u10 more than 40 occurrences or wrong version is refused',async()=>{
 for(const bad of [{occurrences:Array.from({length:41},()=>({record:{sequence:'1'}}))},{version:'kan-content/3'}]){
  const u=ui();await openContent(u);u.node('interpret').click();await tick();await u.respond({...clone(contentResult),...bad});
  assert.equal(u.node('content-panel').children.length,0);
 }
});
test('pass_u11 format change keeps selection but clears Content',async()=>{
 const u=ui();await openContent(u);await interpretContent(u);assert.ok(u.node('content-panel').children.length>0);
 u.node('content-format').value='anthropic-messages-json';u.node('content-format').events.change();
 assert.equal(u.node('content-panel').children.length,0);assert.equal(u.node('content-count').textContent,'1 selected');assert.equal(u.node('interpret').disabled,false);
});
test('pass_u12 v1 reader without content capability keeps numeric v1 page/source and no checkboxes',async()=>{
 const u=ui();await u.login();await u.respond(catalog);const req=JSON.parse(u.pending[0].opts.body);assert.equal(req.action,'page');assert.equal(req.after,0);
 await u.respond(page);assert.equal(u.node('rows').children[0].children.length,2,'button only (title+id), no checkbox wrapper');
 assert.equal(u.node('interpret').disabled,true);
 u.node('rows').children[0].click();await tick();assert.equal(JSON.parse(u.pending[0].opts.body).action,'source');
});
test('pass_u13 refreshed snapshot missing pin_wire is refused; old signed snapshot stays coherent',async()=>{
 const u=ui();await openContent(u);u.node('resnapshot').click();await tick();await u.respond({pin});
 assert.equal(u.node('content-count').textContent,'0 selected');assert.match(u.node('notice').textContent,/Reader unavailable/);
 const check=u.node('rows').children[0].children[0];check.checked=true;check.events.change();u.node('interpret').click();await tick();
 assert.equal(JSON.parse(u.pending[0].opts.body).pin_wire,exactPin,'old exact pin still used, never a half-updated pin');
});


test('retryable Content limits keep selection and retry the exact request',async()=>{
 for(const status of [422,429]){
  const u=ui();await openContent(u);await interpretContent(u);
  u.node('interpret').click();await tick();const first=JSON.parse(u.pending[0].opts.body);await u.respond({},status);
  assert.equal(u.node('content-panel').children.length,0);assert.equal(u.node('source').textContent,'');
  assert.equal(u.node('content-count').textContent,'1 selected');assert.equal(u.node('interpret').disabled,false);assert.equal(u.node('rows').children[0].children[0].checked,true);
  u.node('interpret').click();await tick();assert.deepEqual(JSON.parse(u.pending[0].opts.body),first);await u.respond(contentResult);assert.ok(u.node('content-panel').children.length>0);
 }
});
test('shared citation ranges render once and preserve exact source navigation and focus',async()=>{
 const u=ui();await openContent(u);u.node('interpret').click();await tick();const v=clone(contentResult);
 v.groups[0].request.items=Array.from({length:500},()=>clone(v.groups[0].request.items[0]));await u.respond(v);
 const nodes=walk(u.node('content-panel'));const sources=nodes.filter(n=>String(n.textContent).startsWith('Source 9007199254740993'));
 assert.equal(sources.length,1);const references=nodes.filter(n=>n.textContent==='Sources · shared range 1');assert.equal(references.length,500);
 references[499].click();assert.equal(u.active(),sources[0]);assert.equal(nodes.find(n=>n.className==='content-citation-set').open,true);
 sources[0].click();await tick();assert.equal(JSON.parse(u.pending[0].opts.body).offset,'20');
 await u.respond({...source,record:{...source.record,sequence:'9007199254740993'},offset:'20',total_bytes:'30',next:null});u.node('content-tab').click();assert.equal(u.active(),sources[0]);
});
test('malformed shared citation references fail closed without partial Content',async()=>{
 for(const ref of ['1','-1','01','1e0','9007199254740993',0,null]){
  const u=ui();await openContent(u);u.node('interpret').click();await tick();const v=clone(contentResult);v.groups[0].request.items[0].citation_set=ref;await u.respond(v);
  assert.equal(u.node('content-panel').children.length,0,String(ref));assert.equal(u.node('content-tab').disabled,true,String(ref));
 }
 const u=ui();await openContent(u);u.node('interpret').click();await tick();const v=clone(contentResult);v.groups[0].request.citation_sets=null;await u.respond(v);assert.equal(u.node('content-panel').children.length,0);
});

// Promoted from cold Opus review bf3c44e: A-F1 and cross-stream partial rendering.

test('non-canonical aliases of a VALID citation index fail closed',async()=>{
 for(const ref of ['','00','+0','0x0',' 0','0 ','0.0',' 0']){
  const u=ui();await openContent(u);u.node('interpret').click();await tick();const v=clone(contentResult);v.groups[0].request.items[0].citation_set=ref;await u.respond(v);
  assert.equal(u.node('content-panel').children.length,0,'accepted alias '+JSON.stringify(ref));assert.equal(u.node('content-tab').disabled,true,JSON.stringify(ref));
 }
});
test('malformed ref in the RESPONSE stream after a valid request stream leaves no partial Content',async()=>{
 const u=ui();await openContent(u);u.node('interpret').click();await tick();const v=clone(contentResult);
 v.groups[0].response={...clone(v.groups[0].request),citation_sets:[[{input:'0',bytes:['1','2']}]]};v.groups[0].response.items[0].citation_set='1';await u.respond(v);
 assert.equal(u.node('content-panel').children.length,0);assert.equal(u.node('content-tab').disabled,true);
});
