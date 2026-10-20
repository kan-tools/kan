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

const proofEntry=id=>({id,scope:'shared-scope',protocol:'kan-proof-reader/1',binding:{profile:'copied',archive:id},pin,capabilities:['snapshot-inventory','source-ranges','provenance','payload-availability']});
const proofCatalog={...catalog,version:2,capabilities:['snapshot-inventory','source-ranges','provenance','payload-availability'],scopes:[proofEntry('archive-A'),proofEntry('archive-B')]};
const proofRow={sequence:'3',manifest:'manifest-proof',receipt:'receipt-proof',attestation:'attestation-proof',purpose:'retained-verified',issued_at:'1234',receipt_issuer:'historical-issuer',availability:'available',selection:{signature:'selection-token'}};
const proofPage={through:'3',records:[proofRow],next:{signature:'page-token'},coverage:'Issuer-attested metadata'};
const proofSource={...source,record:proofRow,scope:'shared-scope',archive:'archive-A',profile:'copied',availability:'available',offset:'0',total_bytes:'8',next:'4'};
async function openProof(u){await u.login();await u.respond(proofCatalog);await u.respond(proofPage);}
test('proof sources sharing one scope use distinct configured identities and opaque page tokens',async()=>{
 const u=ui();await openProof(u);assert.deepEqual(u.node('scope').children.map(x=>x.value),['archive-A','archive-B']);
 assert.match(u.node('rows').children[0].children[2].textContent,/available.*retained-verified/);
 u.node('next').click();await tick();let request=JSON.parse(u.pending[0].opts.body);assert.equal(request.action,'proof-page');assert.equal(request.source,'archive-A');assert.deepEqual(request.cursor,proofPage.next);
 await u.respond({...proofPage,next:null,records:[{...proofRow,sequence:'2'}]});u.node('previous').click();await tick();assert.equal(JSON.parse(u.pending[0].opts.body).cursor,null);await u.respond(proofPage);
 u.node('scope').value='archive-B';u.node('scope').events.change();await tick();request=JSON.parse(u.pending[0].opts.body);assert.equal(request.source,'archive-B');assert.equal(request.cursor,null);assert.equal(u.node('rows').children.length,0);await u.respond(proofPage);
});
test('proof source keeps exact selection, proof purpose and historical issuer',async()=>{
 const u=ui();await openProof(u);u.node('rows').children[0].click();await tick();const request=JSON.parse(u.pending[0].opts.body);
 assert.equal(request.action,'proof-source');assert.deepEqual(request.selection,proofRow.selection);assert.equal(request.offset,'0');assert.equal(request.length,'65536');
 await u.respond(proofSource);const text=u.node('provenance').children.map(x=>x.textContent).join(' ');assert.match(text,/retained-verified/);assert.match(text,/historical-issuer/);assert.match(text,/1234/);assert.equal(u.node('download').disabled,false);
});
test('loss or corruption after available sample clears plaintext, preserves provenance and cannot export a Blob',async()=>{
 for(const availability of ['missing','corrupt']){const u=ui();await openProof(u);u.node('rows').children[0].click();await tick();await u.respond(proofSource);
 u.node('download').click();await tick();assert.equal(u.node('source').textContent,'');assert.equal(u.node('download').disabled,true);
 const lost={...proofSource,availability,record:{...proofRow,availability},writer:null};for(const key of ['bytes_hex','utf8','offset','total_bytes','next'])delete lost[key];await u.respond(lost);
 assert.equal(u.blobs.length,0);assert.match(u.node('source').textContent,new RegExp(availability));assert.equal(u.node('source').textContent.includes('<b>x'),false);
 assert.equal(u.node('download').disabled,true);assert.equal(u.node('more').disabled,true);assert.equal(u.node('provenance-tab').disabled,false);assert.equal(u.node('rows').children.length,1);
 assert.match(u.node('provenance').children.map(x=>x.textContent).join(' '),/Writer|Unavailable/);
 }
});
test('proof export reauthorizes; denial clears the Library and emits no Blob',async()=>{
 const u=ui();await openProof(u);u.node('rows').children[0].click();await tick();await u.respond(proofSource);u.node('download').click();await tick();assert.equal(JSON.parse(u.pending[0].opts.body).action,'proof-source');await u.respond({},403);
 assert.equal(u.node('library').hidden,true);assert.equal(u.node('source').textContent,'');assert.equal(u.blobs.length,0);assert.equal(u.node('provenance').children.length,0);
});
test('mixed catalog changes per-source Content capability without legacy fallback',async()=>{
 const u=ui();await u.login();await u.respond({...proofCatalog,scopes:[proofEntry('archive-A'),{id:'legacy',scope:'legacy',protocol:'legacy',pin,pin_wire:'exact-legacy-pin',capabilities:['content-inspection']}]});await u.respond(proofPage);
 assert.match(u.node('content-support').textContent,/not yet available/);assert.equal(u.node('rows').children[0].children.some(c=>c.type==='checkbox'),false);
 u.node('scope').value='legacy';u.node('scope').events.change();await tick();assert.equal(JSON.parse(u.pending[0].opts.body).action,'content-page');await u.respond({...page,through:'2',next:null,records:[{...page.records[0],sequence:'1'}]});assert.match(u.node('content-support').textContent,/Select captures/);
 u.node('scope').value='archive-A';u.node('scope').events.change();await tick();assert.equal(JSON.parse(u.pending[0].opts.body).action,'proof-page');await u.respond({},503);assert.equal(u.pending.length,0);assert.equal(u.node('rows').children.length,0);
});
test('proof refresh and lock preserve no stale source or selection',async()=>{
 const u=ui();await openProof(u);u.node('resnapshot').click();await tick();assert.deepEqual(JSON.parse(u.pending[0].opts.body),{action:'proof-snapshot',source:'archive-A'});await u.respond({pin:{...pin,request:'new-pin'}});assert.equal(JSON.parse(u.pending[0].opts.body).cursor,null);await u.respond(proofPage);
 u.node('rows').children[0].click();await tick();const pending=u.pending[0];u.node('lock').click();assert.equal(pending.opts.signal.aborted,true);await u.respond(proofSource);assert.equal(u.node('source').textContent,'');assert.equal(u.node('rows').children.length,0);assert.equal(u.node('download').disabled,true);
});

async function openProofContent(u){
 await u.login();await u.respond({...proofCatalog,capabilities:[...proofCatalog.capabilities,'content-inspection'],scopes:[{...proofEntry('archive-A'),pin_wire:exactPin,capabilities:[...proofEntry('archive-A').capabilities,'content-inspection']}]});await u.respond(proofPage);
 const check=u.node('rows').children[0].children[0];check.checked=true;check.events.change();
}
test('proof Content sends signed selections and citations return through proof source verification',async()=>{
 const u=ui();await openProofContent(u);u.node('interpret').click();await tick();assert.equal(u.pending[0].url,'/api/library/proof-content');
 const request=JSON.parse(u.pending[0].opts.body);assert.equal(request.action,'proof-content');assert.deepEqual(request.selections,[proofRow.selection]);assert.equal(request.source,'archive-A');
 const value=clone(contentResult);value.occurrences[0].record=proofRow;await u.respond(value);
 const citation=walk(u.node('content-panel')).find(n=>n.textContent.startsWith('Source 3 ·'));assert.ok(citation);citation.click();await tick();assert.equal(JSON.parse(u.pending[0].opts.body).action,'proof-source');assert.deepEqual(JSON.parse(u.pending[0].opts.body).selection,proofRow.selection);await u.respond(proofSource);
 u.node('content-tab').click();assert.equal(u.active(),citation);
});
test('proof Content keeps unavailable inputs visible and presentation limits preserve selection',async()=>{
 const u=ui();await openProofContent(u);u.node('interpret').click();await tick();await u.respond({},422);assert.match(u.node('content-count').textContent,/1 selected/);assert.match(u.node('notice').textContent,/presentation limit/);
 u.node('interpret').click();await tick();await u.respond({version:'kan-content/2',pin_wire:exactPin,occurrences:[{record:{...proofRow,availability:'missing'},writer:null}],observations:[{input:'0',kind:'unavailable',reason:'Missing'}],groups:[],coverage:'explicit selection only'});
 assert.ok(walk(u.node('content-panel')).some(n=>n.textContent.includes('unavailable · Missing')));const inspect=walk(u.node('content-panel')).find(n=>n.textContent==='Inspect source');assert.ok(inspect);inspect.click();await tick();assert.equal(JSON.parse(u.pending[0].opts.body).action,'proof-source');await u.respond({},403);assert.equal(u.node('library').hidden,true);assert.equal(u.node('content-panel').children.length,0);
});

async function openDiscovery(u) {
 await u.login(); await u.respond({...proofCatalog,scopes:[{...proofEntry('archive-A'),pin_wire:exactPin,capabilities:['attempt-discovery','content-inspection']} ]}); await u.respond(proofPage);
}
const discoveredCapture=(sequence,writer='writer-A',ordinal='0')=>({record:{...proofRow,sequence,selection:{signature:'selection-'+sequence}},writer,description:{kind:'capture',attempt:'a'.repeat(64),observer:'collector',ordinal,event:{type:'started',method:'POST',route:'/v1/messages'}}});
test('discovery continues across pages and groups only equal verified writer/observer/attempt identities',async()=>{
 const u=ui();await openDiscovery(u);assert.equal(u.node('discovery').hidden,false);
 u.node('scan-attempts').click();await tick();assert.equal(JSON.parse(u.pending[0].opts.body).action,'proof-discover');
 await u.respond({version:'kan-discovery/1',records:[discoveredCapture('3')],next:{signature:'next-discovery'}});
 assert.match(u.node('discovery-coverage').textContent,/Partial inventory/);
 u.node('scan-attempts').click();await tick();assert.deepEqual(JSON.parse(u.pending[0].opts.body).cursor,{signature:'next-discovery'});
 const second=discoveredCapture('2','writer-A','1'), distinct=discoveredCapture('1','writer-B');
 await u.respond({version:'kan-discovery/1',records:[second,distinct],next:null});
 assert.match(u.node('discovery-coverage').textContent,/3 occurrences inspected.*2 attempt groups/);assert.match(u.node('discovery-coverage').textContent,/traffic completeness remains unknown/);
 const read=walk(u.node('attempts')).find(n=>n.textContent==='Read records 1–2');assert.ok(read);read.click();await tick();await tick();
 const req=JSON.parse(u.pending[0].opts.body);assert.equal(req.action,'proof-content');assert.deepEqual(req.selections,[{signature:'selection-3'},{signature:'selection-2'}]);
 await u.respond({},422);const source=walk(u.node('attempts')).find(n=>n.textContent==='Source 2');source.click();await tick();assert.deepEqual(JSON.parse(u.pending[0].opts.body).selection,second.record.selection);await u.respond(proofSource);
});
test('discovery preserves unassigned loss, treats hostile labels as text, and lock discards late scans',async()=>{
 const u=ui();await openDiscovery(u);u.node('scan-attempts').click();await tick();
 const hostile=discoveredCapture('3');hostile.description.event.route='<img src=x onerror=alert(1)>';
 await u.respond({version:'kan-discovery/1',records:[hostile,{record:{...proofRow,sequence:'2'},writer:null,description:{kind:'missing'}}],next:{signature:'more'}});
 assert.match(u.node('discovery-coverage').textContent,/1 unassigned/);assert.ok(walk(u.node('attempts')).some(n=>n.textContent.includes('<img src=x onerror=alert(1)>')));
 u.node('scan-attempts').click();await tick();const pending=u.pending[0];u.node('lock').click();assert.equal(pending.opts.signal.aborted,true);
 await u.respond({version:'kan-discovery/1',records:[hostile],next:null});assert.equal(u.node('attempts').children.length,0);assert.equal(u.node('discovery').hidden,true);
});
test('discovery revocation clears cached descriptions and refresh resets scan coverage',async()=>{
 const u=ui();await openDiscovery(u);u.node('scan-attempts').click();await tick();await u.respond({version:'kan-discovery/1',records:[discoveredCapture('3')],next:null});
 u.node('resnapshot').click();await tick();assert.equal(u.node('attempts').children.length,0);await u.respond({pin,pin_wire:exactPin});await u.respond(proofPage);
 assert.match(u.node('discovery-coverage').textContent,/No capture discovery/);u.node('scan-attempts').click();await tick();assert.equal(JSON.parse(u.pending[0].opts.body).cursor,null);await u.respond({},403);
 assert.equal(u.node('library').hidden,true);assert.equal(u.node('attempts').children.length,0);
});

async function openSessions(u){await u.login();await u.respond({...proofCatalog,scopes:[{...proofEntry('archive-A'),pin_wire:exactPin,capabilities:['attempt-discovery','content-inspection','attempt-content','session-links']}]});await u.respond(proofPage);}
test('large attempt uses one verified selection beyond forty and long text stays readable in pages',async()=>{
 const u=ui();await openSessions(u);
 for(let batch=0;batch<3;batch++){
  u.node('scan-attempts').click();await tick();
  const records=Array.from({length:batch===2?8:20},(_,i)=>discoveredCapture(String(batch*20+i+1),'writer-A',String(batch*20+i)));
  await u.respond({version:'kan-discovery/1',records,next:batch===2?null:{signature:'next-'+batch}});
 }
 const read=walk(u.node('attempts')).find(n=>n.textContent==='Read attempt · 48 observed records');assert.ok(read);read.click();await tick();await tick();
 const req=JSON.parse(u.pending[0].opts.body);assert.equal(req.action,'proof-attempt');assert.equal(req.selections.length,48);assert.equal(u.pending[0].url,'/api/library/proof-attempt');
 const value=clone(contentResult);value.occurrences=Array.from({length:48},(_,i)=>({record:{sequence:String(i+1)}}));value.groups[0].request.items[0].text='x'.repeat(32768)+'THE END';await u.respond(value);
 assert.ok(walk(u.node('content-panel')).some(n=>n.textContent==='x'.repeat(32768)));
 const next=walk(u.node('content-panel')).find(n=>n.textContent==='Next text page');next.click();assert.ok(walk(u.node('content-panel')).some(n=>n.textContent==='THE END'));
});
test('explicit session view retains branch and compaction claims, cites their source and clears on lock',async()=>{
 const u=ui();await openSessions(u);u.node('scan-attempts').click();await tick();
 const a=discoveredCapture('3'),b=discoveredCapture('2');b.description.attempt='b'.repeat(64);
 a.description.session_link={state:'claimed',scheme:'kan-header',session:'c'.repeat(64),parent_attempt:null,transition:'start'};
 b.description.session_link={state:'claimed',scheme:'kan-header',session:'c'.repeat(64),parent_attempt:a.description.attempt,transition:'branch'};
 const c=clone(b);c.record={...proofRow,sequence:'1'};c.description.session_link.transition='compaction';
 await u.respond({version:'kan-discovery/1',records:[a,b,c],next:null});
 let texts=walk(u.node('sessions')).map(n=>n.textContent).join(' ');assert.match(texts,/branch/);assert.match(texts,/compaction/);assert.match(texts,/Conflicting session claims retained/);
 const cite=walk(u.node('sessions')).find(n=>n.textContent==='Session link source 2');cite.click();await tick();assert.deepEqual(JSON.parse(u.pending[0].opts.body).selection,b.record.selection);await u.respond(proofSource);
 u.node('lock').click();assert.equal(u.node('sessions').children.length,0);
});

test('scan window progresses through batches and stopping ignores late descriptions',async()=>{
 const u=ui();await openSessions(u);u.node('scan-window').click();await tick();
 await u.respond({version:'kan-discovery/1',records:[discoveredCapture('3')],next:{signature:'next'}});
 assert.equal(JSON.parse(u.pending[0].opts.body).cursor.signature,'next');const pending=u.pending[0];u.node('stop-scan').click();assert.equal(pending.opts.signal.aborted,true);
 await u.respond({version:'kan-discovery/1',records:[discoveredCapture('2')],next:null});assert.match(u.node('discovery-coverage').textContent,/1 occurrences inspected/);assert.equal(u.node('scan-window').disabled,false);
});

async function openWorkspaceUI(u){
 await u.login();await u.respond({...proofCatalog,scopes:['archive-A','archive-B'].map(id=>({...proofEntry(id),pin:{request:'pin-'+id,reply:{}},pin_wire:exactPin,capabilities:['attempt-discovery','content-inspection','attempt-content','session-links']}))});await u.respond(proofPage);
}
function linkedRecord(sequence,attempt,parent=null,writer='verified-writer'){
 const item=discoveredCapture(sequence);item.writer=writer;item.description.attempt=attempt;
 item.record.selection={signature:sequence+'-'+attempt};
 item.description.session_link={state:'claimed',scheme:'kan-header',session:'c'.repeat(64),parent_attempt:parent,transition:parent?'branch':'start'};return item;
}
test('cross-archive sessions follow parent and link source with each original pin',async()=>{
 const u=ui();await openWorkspaceUI(u);u.node('scan-archives').click();await tick();
 const parent=linkedRecord('1','a'.repeat(64)),child=linkedRecord('1','b'.repeat(64),parent.description.attempt);
 assert.equal(JSON.parse(u.pending[0].opts.body).source,'archive-A');
 await u.respond({version:'kan-discovery/1',records:[parent],next:null});
 assert.equal(JSON.parse(u.pending[0].opts.body).source,'archive-B');
 await u.respond({version:'kan-discovery/1',records:[child],next:null});
 const texts=walk(u.node('workspace-sessions')).map(n=>n.textContent).join(' ');assert.match(texts,/2 archives/);assert.match(texts,/branch/);
 walk(u.node('workspace-sessions')).find(n=>n.textContent==='Read parent in archive-A').click();await tick();
 let q=JSON.parse(u.pending[0].opts.body);assert.equal(q.action,'proof-attempt');assert.equal(q.source,'archive-A');assert.equal(q.pin.request,'pin-archive-A');assert.deepEqual(q.selections,[parent.record.selection]);
 await u.respond({...contentResult,occurrences:[{record:{sequence:'1'}}]});
 const cites=walk(u.node('workspace-sessions')).filter(n=>n.textContent==='Link source 1');cites[1].click();await tick();
 q=JSON.parse(u.pending[0].opts.body);assert.equal(q.action,'proof-source');assert.equal(q.source,'archive-B');assert.equal(q.pin.request,'pin-archive-B');assert.deepEqual(q.selection,child.record.selection);
 await u.respond({},403);assert.equal(u.node('workspace-sessions').children.length,0);assert.equal(u.node('session-workspace').hidden,true);
});
test('workspace separates writers and archive copies and exposes all parent matches',async()=>{
 const u=ui();await openWorkspaceUI(u);u.node('scan-archives').click();await tick();
 const parent=linkedRecord('3','a'.repeat(64)),child=linkedRecord('2','b'.repeat(64),parent.description.attempt),foreign=linkedRecord('1','b'.repeat(64),parent.description.attempt,'other-writer');
 await u.respond({version:'kan-discovery/1',records:[parent,child],next:null});
 await u.respond({version:'kan-discovery/1',records:[clone(parent),foreign],next:null});
 assert.match(u.node('workspace-coverage').textContent,/2 explicit session groups/);
 const texts=walk(u.node('workspace-sessions')).map(n=>n.textContent).join(' ');assert.match(texts,/2 observed parent archive matches/);assert.match(texts,/Parent not observed/);
 const parentButtons=walk(u.node('workspace-sessions')).filter(n=>n.textContent.startsWith('Read parent in '));assert.equal(parentButtons.length,2);
 u.node('resnapshot').click();await tick();assert.match(u.node('workspace-coverage').textContent,/0 records/);
 await u.respond({pin:{request:'new',reply:{}},pin_wire:exactPin});await u.respond(proofPage);
 u.node('scan-archives').click();await tick();assert.equal(JSON.parse(u.pending[0].opts.body).pin.request,'new');assert.equal(JSON.parse(u.pending[0].opts.body).cursor,null);
 u.node('lock').click();await u.respond({version:'kan-discovery/1',records:[parent],next:null});assert.equal(u.node('workspace-sessions').children.length,0);
});
test('workspace scans round-robin, retains failed coverage, and stops without accepting late replies',async()=>{
 const u=ui();await openWorkspaceUI(u);u.node('scan-archives').click();await tick();
 await u.respond({version:'kan-discovery/1',records:[linkedRecord('3','a'.repeat(64))],next:{signature:'continue-A'}});
 assert.equal(JSON.parse(u.pending[0].opts.body).source,'archive-B');await u.respond({},503);
 assert.equal(JSON.parse(u.pending[0].opts.body).source,'archive-A');assert.deepEqual(JSON.parse(u.pending[0].opts.body).cursor,{signature:'continue-A'});
 u.node('stop-archives').click();await u.respond({version:'kan-discovery/1',records:[linkedRecord('2','b'.repeat(64))],next:null});
 assert.match(u.node('workspace-coverage').textContent,/1 records/);assert.match(walk(u.node('workspace-sources')).map(n=>n.textContent).join(' '),/unavailable; retry scan/);
 u.node('clear-archives').click();assert.match(u.node('workspace-coverage').textContent,/0 records/);
});
test('workspace window bound preserves independent continuation without growing tab storage',async()=>{
 const u=ui();await openWorkspaceUI(u);u.node('scan-archives').click();await tick();
 for(let batch=0;batch<50;batch++){
  assert.equal(JSON.parse(u.pending[0].opts.body).source,batch%2?'archive-B':'archive-A');
  await u.respond({version:'kan-discovery/1',records:Array.from({length:20},(_,i)=>linkedRecord(String(batch*20+i+1),'a'.repeat(64))),next:{signature:'next-'+batch}});
 }
 assert.equal(u.pending.length,0);assert.match(u.node('workspace-coverage').textContent,/1000 records/);assert.equal(u.node('scan-archives').textContent,'Continue in a new window');
 u.node('scan-archives').click();await tick();assert.deepEqual(JSON.parse(u.pending[0].opts.body).cursor,{signature:'next-48'});
 await u.respond({version:'kan-discovery/1',records:[],next:null});assert.deepEqual(JSON.parse(u.pending[0].opts.body).cursor,{signature:'next-49'});
 await u.respond({version:'kan-discovery/1',records:[],next:null});assert.match(u.node('workspace-coverage').textContent,/0 records.*2\/2 archive inventories finished/);
});

test('fragmented links resolve across discovery pages and cite every original fragment',async()=>{
 const u=ui();await openSessions(u);
 const a=discoveredCapture('2'),b=discoveredCapture('1');
 for(const item of [a,b])item.description.event={type:'http-metadata-chunk',direction:'request',offset:item===a?'50':'0',total:'100'};
 u.node('scan-attempts').click();await tick();await u.respond({version:'kan-discovery/1',records:[a],next:{signature:'more'}});
 u.node('scan-attempts').click();await tick();await u.respond({version:'kan-discovery/1',records:[b],next:null});
 walk(u.node('attempts')).find(n=>n.textContent==='Resolve chunked session links').click();await tick();
 const q=JSON.parse(u.pending[0].opts.body);assert.equal(q.action,'proof-attempt');assert.equal(q.selections.length,2);
 const result={...contentResult,occurrences:[{record:{sequence:'2'}},{record:{sequence:'1'}}],groups:[{...contentResult.groups[0],metadata:[{state:'complete',fragmented:true,session_link:{state:'claimed',scheme:'kan-header',session:'c'.repeat(64),transition:'branch',parent_attempt:'b'.repeat(64)},sources:[{input:'1',bytes:['200','250']},{input:'0',bytes:['210','260']}]}]}]};
 await u.respond(result);
 assert.match(walk(u.node('sessions')).map(n=>n.textContent).join(' '),/branch/);
 const links=walk(u.node('sessions')).filter(n=>n.textContent.startsWith('Session link source '));assert.equal(links.length,2);
 links[0].click();await tick();assert.equal(JSON.parse(u.pending[0].opts.body).offset,'200');await u.respond(proofSource);
 u.node('resnapshot').click();await tick();assert.equal(u.node('sessions').children.length,0);
});
test('workspace fragment resolution retains incomplete state without claiming a session',async()=>{
 const u=ui();await openWorkspaceUI(u);u.node('scan-archives').click();await tick();
 const item=discoveredCapture('3');item.description.event={type:'http-metadata-chunk',direction:'request',offset:'0',total:'100'};
 await u.respond({version:'kan-discovery/1',records:[item],next:null});await u.respond({version:'kan-discovery/1',records:[],next:null});
 walk(u.node('workspace-sessions')).find(n=>n.textContent==='Resolve chunked session links').click();await tick();
 assert.equal(JSON.parse(u.pending[0].opts.body).source,'archive-A');
 await u.respond({...contentResult,occurrences:[{record:{sequence:'3'}}],groups:[{metadata:[{state:'incomplete',fragmented:true,session_link:null,sources:[{input:'0',bytes:['210','260']}]}]}]});
 assert.match(walk(u.node('workspace-sessions')).map(n=>n.textContent).join(' '),/Metadata incomplete/);assert.match(u.node('workspace-coverage').textContent,/0 explicit session groups/);
 walk(u.node('workspace-sessions')).find(n=>n.textContent==='Resolve chunked session links').click();await tick();u.node('lock').click();await u.respond(contentResult);assert.equal(u.node('workspace-sessions').children.length,0);
});

const searchCatalog={...proofCatalog,scopes:[proofEntry('archive-A'),proofEntry('archive-B')],capabilities:[...proofCatalog.capabilities,'text-search','saved-views'],unavailable:proofCatalog.unavailable.filter(x=>x!=='saved-views')};
const searchPage={state:'indexed',indexed_occurrences:3,indexed_at:'123',hits:[{record:proofRow,writer:'writer',kind:'opaque',offset:'5',end:'11',snippet:'<script>Needle</script>'}],next:null,unsearchable_bytes:'0',unavailable_matches:0,facets_as_indexed:{kind:{opaque:3},writer:{writer:3}}};
async function openSearch(u){await u.login();await u.respond(searchCatalog);await u.respond(proofPage);u.node('search-text').value='needle';u.node('search-form').events.submit({preventDefault(){}});await tick();}
test('persistent search scans distinct archives, keeps text inert and opens the exact pinned citation',async()=>{
 const u=ui();await openSearch(u);assert.equal(u.node('search-workspace').hidden,false);
 for(const id of ['archive-A','archive-B']){let q=JSON.parse(u.pending[0].opts.body);assert.equal(q.action,'index-page');assert.equal(q.target.source,id);await u.respond(searchPage);q=JSON.parse(u.pending[0].opts.body);assert.equal(q.action,'search-page');assert.equal(q.filter.text,'needle');await u.respond(searchPage);}
 assert.equal(u.node('search-results').children.length,2);assert.match(u.node('search-coverage').textContent,/2 matches/);assert.equal(u.node('resume-search').disabled,true);
 const row=u.node('search-results').children[1];assert.equal(row.children[1].textContent,'<script>Needle</script>');row.children.at(-1).click();await tick();const q=JSON.parse(u.pending[0].opts.body);assert.equal(q.source,'archive-B');assert.equal(q.offset,'5');assert.deepEqual(q.selection,proofRow.selection);assert.equal(u.node('rows').children.length,0);await u.respond({...proofSource,offset:'5'});
 u.node('lock').click();assert.equal(u.node('search-results').children.length,0);assert.equal(u.node('search-text').value,'');assert.equal(u.node('search-workspace').hidden,true);
});
test('search stop and revocation cannot accept late snippets or leave saved views exposed',async()=>{
 const u=ui();await openSearch(u);await u.respond(searchPage);const request=u.pending[0];u.node('stop-search').click();assert.equal(request.opts.signal.aborted,true);await u.respond(searchPage);assert.equal(u.node('search-results').children.length,0);assert.equal(u.node('resume-search').disabled,false);
 u.node('resume-search').click();await tick();assert.equal(JSON.parse(u.pending[0].opts.body).cursor,null);await u.respond(searchPage);await u.respond({},403);assert.equal(u.node('library').hidden,true);assert.equal(u.node('search-results').children.length,0);assert.equal(u.node('saved-views').children.length,0);
});
test('saved views preserve exact snapshots and filters and reload through the shared API',async()=>{
 const u=ui();await openSearch(u);for(let i=0;i<2;i++){await u.respond(searchPage);await u.respond(searchPage);}
 u.node('view-name').value='My view';u.node('save-view').click();await tick();const saved=JSON.parse(u.pending[0].opts.body);assert.equal(saved.action,'save-view');assert.equal(saved.targets.length,2);assert.deepEqual(saved.targets[0].pin,pin);assert.equal(saved.filter.text,'needle');await u.respond({...saved,id:'view-id'});
 u.node('load-views').click();await tick();await u.respond({coverage:'complete',views:[{...saved,id:'view-id',author:'owner'}]});const button=u.node('saved-views').children[0].children.at(-1);button.click();await tick();const request=JSON.parse(u.pending[0].opts.body);assert.equal(request.action,'index-page');assert.deepEqual(request.target,saved.targets[0]);u.node('lock').click();await u.respond(searchPage);assert.equal(u.pending.length,0);assert.equal(u.node('saved-views').children.length,0);
});

const knowledgeCatalog={...searchCatalog,scopes:[proofEntry('archive-A'),proofEntry('archive-B')],capabilities:[...searchCatalog.capabilities,'annotations'],unavailable:searchCatalog.unavailable.filter(x=>x!=='annotations')};
async function openKnowledge(u){await u.login();await u.respond(knowledgeCatalog);await u.respond(proofPage);u.node('rows').children[0].click();await tick();await u.respond(proofSource);u.node('annotate-source').click();u.node('annotation-subject').value='decision/test';u.node('annotation-text').value='<script>A note</script>';u.node('annotation-tags').value='decision, useful';}
test('annotation preview verifies exact citations before append and corrections retain the prior record',async()=>{
 const u=ui();await openKnowledge(u);assert.equal(u.node('knowledge').hidden,false);assert.equal(u.node('annotation-form').hidden,false);
 u.node('annotation-form').events.submit({preventDefault(){}});await tick();const request=JSON.parse(u.pending[0].opts.body);assert.equal(request.action,'annotation-preview');assert.deepEqual(request.draft.cites,[{source:'archive-A',pin,selection:proofRow.selection}]);assert.equal(u.node('save-annotation').disabled,true);
 const preview={id:'digest',declaration:{author:'owner',draft:request.draft},effect:'Append only',evidence:[{source:'archive-A',record:proofRow,availability:'available'}]};await u.respond(preview);assert.match(u.node('annotation-preview').textContent,/<script>A note<\/script>/);assert.equal(u.node('save-annotation').disabled,false);
 u.node('save-annotation').click();await tick();const save=JSON.parse(u.pending[0].opts.body);assert.equal(save.action,'annotation-save');assert.equal(save.preview,'digest');assert.deepEqual(save.draft,request.draft);const note={id:'digest',...preview.declaration};await u.respond(note);assert.equal(JSON.parse(u.pending[0].opts.body).action,'annotations');await u.respond({records:[note],coverage:'complete'});
 assert.equal(u.node('annotation-form').hidden,true);const row=u.node('annotation-list').children[0];assert.equal(row.children[1].textContent,'<script>A note</script>');row.children.at(-1).click();assert.match(u.node('annotation-target').textContent,/correction of digest/);assert.equal(u.node('annotation-subject').value,'decision/test');assert.equal(u.node('annotation-list').children.length,1);
 u.node('lock').click();assert.equal(u.node('annotation-list').children.length,0);assert.equal(u.node('annotation-text').value,'');assert.equal(u.node('knowledge').hidden,true);
});
test('editing or cancelling an annotation invalidates an in-flight preview',async()=>{
 for(const action of ['edit','cancel']){const u=ui();await openKnowledge(u);u.node('annotation-form').events.submit({preventDefault(){}});await tick();const pending=u.pending[0];if(action==='edit'){u.node('annotation-text').value='changed';u.node('annotation-text').events.input();}else u.node('cancel-annotation').click();assert.equal(pending.opts.signal.aborted,true);await u.respond({id:'stale',declaration:{author:'owner',draft:{}},evidence:[],effect:'old'});assert.equal(u.node('save-annotation').disabled,true);assert.equal(u.node('annotation-preview').textContent,'');}
});

test('operations navigation is shown only for a configured capability and cleared on lock',async()=>{
 const u=ui();await u.login();await u.respond({...proofCatalog,scopes:[proofEntry('archive-A')],capabilities:[...proofCatalog.capabilities,'operations-read']});await u.respond(proofPage);assert.equal(u.node('operations-link').hidden,false);u.node('lock').click();assert.equal(u.node('operations-link').hidden,true);
});

test('annotation publication shows the fixed destination and uses exact retry and acknowledgment states',async()=>{
 const u=ui();await openKnowledge(u);u.node('load-annotations').click();await tick();const note={id:'a'.repeat(64),author:'writer',recorded_at:'123',draft:{subject:'note',text:'retained note',tags:[],supersedes:null,cites:[{source:'archive-A',pin,selection:proofRow.selection}]}};await u.respond({records:[note],coverage:'complete'});
 const row=u.node('annotation-list').children[0];row.children.find(x=>x.textContent==='Check ledger publication').click();await tick();assert.equal(JSON.parse(u.pending[0].opts.body).action,'annotation-delivery');
 const status={state:'not-queued',destination:{scope:'target-scope',issuer:'target-issuer',recipient:'public-recipient',endpoint:'http://127.0.0.1:7282/v1/rpc'},destination_digest:'fixed-destination',record:null};await u.respond(status);
 const parent=row.children.find(x=>x.children.some(y=>y.textContent==='Queue encrypted annotation'));assert.match(parent.children[0].textContent,/target-scope.*target-issuer.*public-recipient/);parent.children.find(x=>x.textContent==='Queue encrypted annotation').click();await tick();assert.deepEqual(JSON.parse(u.pending[0].opts.body),{action:'annotation-queue',id:note.id,destination:'fixed-destination'});
 await u.respond({...status,state:'queued',record:{manifest:'manifest',position:0}});parent.children.find(x=>x.textContent==='Deliver one queued record').click();await tick();assert.equal(JSON.parse(u.pending[0].opts.body).action,'annotation-drain');await u.respond({pending:'0'});assert.equal(JSON.parse(u.pending[0].opts.body).action,'annotation-delivery');await u.respond({...status,state:'acknowledged',record:{manifest:'manifest',position:0}});assert.match(parent.children[0].textContent,/acknowledged/);assert.equal(parent.children.filter(x=>x.textContent==='Deliver one queued record').length,0);
});

async function sessionReaderFixture(u){
 await u.login();await u.respond({...proofCatalog,scopes:['archive-A','archive-B'].map(id=>({...proofEntry(id),pin:{request:'pin-'+id,reply:{}},pin_wire:exactPin,capabilities:['attempt-discovery','content-inspection','attempt-content','session-links','session-content']}))});await u.respond(proofPage);
 u.node('content-format').value='anthropic-messages-json';u.node('scan-archives').click();await tick();
 const a=linkedRecord('1','a'.repeat(64)),b=linkedRecord('1','b'.repeat(64),a.description.attempt);
 await u.respond({version:'kan-discovery/1',records:[a],next:null});await u.respond({version:'kan-discovery/1',records:[b],next:null});
 walk(u.node('workspace-sessions')).find(n=>n.textContent==='Read conversation · attempts 1–2').click();await tick();
 const request=JSON.parse(u.pending[0].opts.body);assert.equal(request.action,'proof-session');assert.equal(u.pending[0].url,'/api/library/proof-session');
 assert.deepEqual(request.attempts.map(a=>a.source),['archive-A','archive-B']);
 return {version:'kan-session-content/1',identity:request.identity,coverage:'Explicit attempts; no inferred chronology',attempts:request.attempts.map((attempt,index)=>{
  const content=clone(contentResult);content.occurrences=[{record:{sequence:'1'}}];content.groups[0].writer='verified-writer';content.groups[0].observer=a.description.observer;
  return {source:attempt.source,pin:attempt.pin,membership:index?'conflicting':'claimed',links:[index?b.description.session_link:a.description.session_link],content};
 })};
}
test('conversation presents attempts without replaying request history as new turns and keeps archive citations',async()=>{
 const u=ui(),value=await sessionReaderFixture(u);await u.respond(value);
 assert.equal(u.node('session-reader').hidden,false);
 const nodes=walk(u.node('session-reader-body'));
 assert.ok(nodes.some(n=>n.textContent==='Supplied request history · may repeat earlier messages'));
 assert.ok(nodes.some(n=>String(n.textContent).includes('Session membership conflicting')));
 assert.ok(nodes.some(n=>n.textContent==='<script>never execute</script>'));
 const cites=nodes.filter(n=>String(n.textContent).startsWith('Source 1 ·'));assert.equal(cites.length,2);cites[1].click();await tick();
 const request=JSON.parse(u.pending[0].opts.body);assert.equal(request.source,'archive-B');assert.equal(request.pin.request,'pin-archive-B');assert.equal(request.offset,'20');
 await u.respond({},403);assert.equal(u.node('session-reader-body').children.length,0);assert.equal(u.node('session-reader').hidden,true);
});
test('conversation refuses foreign identity and discards replies after close or lock',async()=>{
 for(const action of ['identity','close','lock']) {
  const u=ui(),value=await sessionReaderFixture(u);
  if(action==='identity')value.identity.writer='other-writer';
  if(action==='close')u.node('close-session-reader').click();
  if(action==='lock')u.node('lock').click();
  await u.respond(value);assert.equal(u.node('session-reader-body').children.length,0,action);assert.equal(u.node('session-reader').hidden,true,action);
 }
});

const analysisConfiguration={recipes:[{id:'day-review',revision:'1',purpose:'day-assessment',instructions:'Assess progress using cited evidence only.'}],model:'synthetic-model',endpoint:'http://127.0.0.1:9999/v1/messages',limits:{jobs:10}};
async function openAnalysisUI(u){
 await u.login();await u.respond({...proofCatalog,capabilities:[...proofCatalog.capabilities,'analysis','annotations'],unavailable:proofCatalog.unavailable.filter(c=>!['analysis','annotations'].includes(c)),scopes:[{...proofEntry('archive-A'),pin,pin_wire:exactPin}]});await u.respond(proofPage);
 u.node('rows').children[0].click();await tick();await u.respond(proofSource);u.node('analyze-source').click();await tick();
 assert.equal(JSON.parse(u.pending[0].opts.body).action,'analysis-jobs');await u.respond({configuration:analysisConfiguration,jobs:[],coverage:'complete'});
 u.node('analysis-form').events.submit({preventDefault(){}});await tick();return JSON.parse(u.pending[0].opts.body);
}
test('analysis requires a destination and recipe preview, submits asynchronously, and treats results as text',async()=>{
 const u=ui(),request=await openAnalysisUI(u);assert.equal(request.action,'analysis-preview');assert.equal(request.draft.cites[0].source,'archive-A');
 const checked={digest:'preview-digest',nonce:'a'.repeat(64),effect:'Send selected evidence',endpoint:analysisConfiguration.endpoint,model:'synthetic-model',recipe:analysisConfiguration.recipes[0],input_bytes:8,max_output_tokens:128};
 await u.respond(checked);assert.match(u.node('analysis-preview').textContent,/127.0.0.1:9999/);assert.match(u.node('analysis-preview').textContent,/day-assessment/);
 u.node('submit-analysis').click();await tick();assert.deepEqual(JSON.parse(u.pending[0].opts.body),{action:'analysis-submit',draft:request.draft,preview:checked.digest,nonce:checked.nonce,wait:false});
 const job={id:'job-id',draft:request.draft};await u.respond({state:'running',job});await u.respond({configuration:analysisConfiguration,jobs:[{state:'running',job}],coverage:'complete'});
 walk(u.node('analysis-jobs')).find(n=>n.textContent==='Inspect job and lineage').click();await tick();
 await u.respond({state:'succeeded',job,input:{request_hex:'00'},result:{parsed:{content:[{type:'text',text:'<script>derived, never executed</script>'}]}}});
 assert.ok(walk(u.node('analysis-detail')).some(n=>n.textContent==='<script>derived, never executed</script>'));
 u.node('lock').click();assert.equal(u.node('analysis-detail').children.length,0);assert.equal(u.node('analysis-jobs').children.length,0);assert.equal(u.node('analysis').hidden,true);
});
test('analysis recipe changes and cancellation invalidate stale previews',async()=>{
 for(const action of ['recipe','cancel']){
  const u=ui();await openAnalysisUI(u);const pending=u.pending[0];
  if(action==='recipe')u.node('analysis-recipe').events.change();else u.node('cancel-analysis-draft').click();
  assert.equal(pending.opts.signal.aborted,true);await u.respond({digest:'stale',nonce:'stale'});assert.equal(u.node('submit-analysis').disabled,true);assert.equal(u.node('analysis-preview').textContent,'');
 }
});

test('tag trigger plans are visible before append and scheduling failures remain retryable',async()=>{
 const u=ui();await openKnowledge(u);u.node('load-annotations').click();await tick();
 const note={id:'tag-note',author:'reader',analysis_trigger_plan:[{tag:'assess',recipe:{id:'day-review'},endpoint:'http://127.0.0.1:9999/v1/messages'}],draft:{subject:'day/subject',text:'Evidence for assessment',tags:['assess'],cites:[]}};
 await u.respond({records:[note],coverage:'complete'});
 walk(u.node('annotation-list')).find(n=>n.textContent==='Inspect tag-triggered jobs').click();await tick();assert.deepEqual(JSON.parse(u.pending[0].opts.body),{action:'annotation-triggers',id:note.id,retry:false});
 await u.respond({plan:note.analysis_trigger_plan,attempts:[{outcomes:[{recipe:'day-review',state:'not-scheduled',reason:'Quota unavailable'}]}]});
 walk(u.node('annotation-list')).find(n=>n.textContent==='Retry failed scheduling').click();await tick();assert.equal(JSON.parse(u.pending[0].opts.body).retry,true);
 u.node('lock').click();await u.respond({plan:[],attempts:[]});assert.equal(u.node('annotation-list').children.length,0);
});

test('promoting model output drafts an editable annotation with job provenance and original citations',async()=>{
 const u=ui(),request=await openAnalysisUI(u);u.node('cancel-analysis-draft').click();await u.respond({});
 u.node('load-analysis').click();await tick();const job={id:'derived-job',draft:request.draft};
 await u.respond({configuration:analysisConfiguration,jobs:[{state:'succeeded',job}],coverage:'complete'});
 walk(u.node('analysis-jobs')).find(n=>n.textContent==='Inspect job and lineage').click();await tick();await u.respond({state:'succeeded',job,input:{},result:{parsed:{content:[{type:'text',text:'Review this generated assessment'}]}}});
 walk(u.node('analysis-detail')).find(n=>n.textContent==='Draft annotation from this result').click();assert.equal(u.node('annotation-text').value,'Review this generated assessment');
 u.node('annotation-form').events.submit({preventDefault(){}});await tick();const preview=JSON.parse(u.pending[0].opts.body);assert.equal(preview.action,'annotation-preview');assert.deepEqual(preview.draft.derived_from,['derived-job']);assert.deepEqual(preview.draft.cites,request.draft.cites);
});

test('subject relations are previewed as attributed assertions and day browsing retains correction history',async()=>{
 const u=ui();await openKnowledge(u);u.node('relation-kind').value='InTensionWith';u.node('relation-target').value='telos/speed';u.node('add-relation').click();
 u.node('annotation-form').events.submit({preventDefault(){}});await tick();assert.deepEqual(JSON.parse(u.pending[0].opts.body).draft.relations,[{kind:'InTensionWith',target:'telos/speed'}]);
 u.node('cancel-annotation').click();await u.respond({});u.node('knowledge-mode').value='day';u.node('load-subjects').click();await tick();assert.deepEqual(JSON.parse(u.pending[0].opts.body),{action:'knowledge-graph',subject:null,day:true});
 await u.respond({coverage:'complete',authority:'Attributed declarations only',subjects:[{subject:'atom/storage',kind:'atom',declarations:2}],relations:[],records:[]});
 u.node('knowledge-subjects').children[0].click();await tick();assert.equal(JSON.parse(u.pending[0].opts.body).subject,'atom/storage');
 const declaration={id:'old-note',author:'reader',draft:{subject:'atom/storage',text:'```day-atom\n{"inputs":["raw"],"outputs":["durable"]}\n```',cites:[]}};
 await u.respond({coverage:'complete',authority:'History retained',subjects:[],records:[{declaration,corrected_by:['new-note']}],relations:[{from:'atom/storage',to:'telos/durability',kind:'About',author:'reader',annotation:'old-note',corrected_by:['new-note']}]});
 const nodes=walk(u.node('knowledge-detail'));assert.ok(nodes.some(n=>n.textContent==='Declared day-atom structure'));assert.ok(nodes.some(n=>String(n.textContent).includes('corrected by new-note')));
 nodes.find(n=>n.textContent==='telos/durability').click();await tick();assert.equal(JSON.parse(u.pending[0].opts.body).subject,'telos/durability');u.node('lock').click();await u.respond({});assert.equal(u.node('knowledge-detail').children.length,0);assert.equal(u.node('knowledge-subjects').children.length,0);
});

async function ownerUI(u){
 await u.login();await u.respond({...proofCatalog,capabilities:['snapshot-inventory','source-ranges','provenance','payload-availability','owner-maintenance'],scopes:['archive-A','archive-B'].map(proofEntry)});await u.respond(proofPage);
 u.node('owner-token').value='owner-only-credential';u.node('owner-connect').events.submit({preventDefault(){}});await tick();assert.equal(u.node('owner-token').value,'');assert.equal(u.pending[0].url,'/api/owner');assert.equal(u.pending[0].opts.headers.Authorization,'Bearer owner-only-credential');
 await u.respond({owner:'owner-did',targets:[{id:'evidence',kind:'archive'}],jobs:[],limits:{jobs:10}});
}
test('owner maintenance uses separate credentials and exact preview-bound requests without browser paths',async()=>{
 const u=ui();await ownerUI(u);u.node('owner-job-form').events.submit({preventDefault(){}});await tick();assert.deepEqual(JSON.parse(u.pending[0].opts.body),{action:'preview',target:'evidence',operation:'backup',retry_of:null});
 const contract={target:{id:'evidence',kind:'archive',root:'/configured/archive'},operation:'backup',destination:'/configured/output/nonce.sqlite',effect:'New verified backup; no activation',cancellation:'Runs to a safe boundary'};
 await u.respond({digest:'owner-preview',nonce:'a'.repeat(64),contract});assert.match(u.node('owner-preview').textContent,/no activation/);assert.match(u.node('owner-preview').textContent,/configured\/output/);
 u.node('owner-submit').click();await tick();assert.deepEqual(JSON.parse(u.pending[0].opts.body),{action:'submit',target:'evidence',operation:'backup',retry_of:null,nonce:'a'.repeat(64),preview:'owner-preview',wait:false});
 await u.respond({state:'running'});await u.respond({owner:'owner-did',targets:[{id:'evidence',kind:'archive'}],jobs:[{state:'running',job:{id:'job',contract}}],limits:{jobs:10}});
 walk(u.node('owner-jobs')).find(n=>n.textContent==='Inspect maintenance job').click();await tick();u.node('owner-lock').click();await u.respond({state:'succeeded',secret:'late-result'});assert.equal(u.node('owner-detail').children.length,0);assert.equal(u.node('owner-jobs').children.length,0);assert.equal(u.node('library').hidden,false);
});
test('owner target changes invalidate late previews and reader lock clears owner authority',async()=>{
 const u=ui();await ownerUI(u);u.node('owner-job-form').events.submit({preventDefault(){}});await tick();const pending=u.pending[0];u.node('owner-operation').events.change();assert.equal(pending.opts.signal.aborted,true);await u.respond({digest:'late',nonce:'late',contract:{}});assert.equal(u.node('owner-submit').disabled,true);
 u.node('owner-refresh').click();await tick();u.node('lock').click();await u.respond({owner:'late',targets:[],jobs:[],limits:{jobs:10}});assert.equal(u.node('owner-controls').hidden,true);assert.equal(u.node('owner-jobs').children.length,0);assert.equal(u.node('owner-preview').textContent,'');
});

const importedItem={record:proofRow,writer:'writer-A',description:{kind:'import',plan:'a'.repeat(64),ordinal:'0',frame_kind:'inventory',part:0,parts:1,file:null}};
const importView={version:'kan-import-content/1',plan:'a'.repeat(64),source:'archive-A',pin,state:'inventory-verified',coverage:'Selected file hashes and individual signatures; no repository membership.',files:[{index:0,path:'repo.car',length:'400',present_parts:1,parts:1}],inventory_cites:[{record:proofRow,bytes:['9','40']}],unavailable:[],file:null};
async function openImported(u){await openDiscovery(u);u.node('scan-attempts').click();await tick();await u.respond({version:'kan-discovery/1',records:[importedItem],next:null});walk(u.node('attempts')).find(n=>n.textContent==='Browse imported files and claims').click();await tick();}
test('import browser opens files, preserves claim text and exact source coordinates, then clears on revocation',async()=>{
 const u=ui();await openImported(u);assert.equal(u.pending[0].url,'/api/library/proof-import');assert.equal(JSON.parse(u.pending[0].opts.body).plan,importView.plan);await u.respond(importView);
 walk(u.node('content-panel')).find(n=>n.textContent==='Read repo.car').click();await tick();assert.equal(JSON.parse(u.pending[0].opts.body).file,0);
 const value={...importView,file:{index:0,path:'repo.car',state:'verified',sources:importView.inventory_cites,car:{membership:'Not evaluated',scan:{error:null},next:null,records:[{state:'verified-claim',id:'claim-cid',claim:{text:'<script>retained claim</script>',cites:['original-cite']},sources:[{record:proofRow,bytes:['23','39']}]}]}}};
 await u.respond(value);assert.ok(walk(u.node('content-panel')).some(n=>n.textContent.includes('<script>retained claim</script>')));
 walk(u.node('content-panel')).find(n=>n.textContent==='Source 3 · 23–39').click();await tick();const request=JSON.parse(u.pending[0].opts.body);assert.equal(request.offset,'23');assert.deepEqual(request.selection,proofRow.selection);await u.respond({},403);assert.equal(u.node('library').hidden,true);assert.equal(u.node('content-panel').children.length,0);
});
test('import browser exposes incomplete inventories and rejects a source citation outside the selected frames',async()=>{
 const u=ui();await openImported(u);await u.respond({...importView,state:'inventory-incomplete',files:[],inventory_cites:[]});assert.ok(walk(u.node('content-panel')).some(n=>n.textContent.includes('complete inventory is not selected')));
 walk(u.node('attempts')).find(n=>n.textContent==='Browse imported files and claims').click();await tick();await u.respond({...importView,inventory_cites:[{record:{...proofRow,sequence:'99'},bytes:['1','2']}]});assert.equal(u.node('content-panel').children.length,0);assert.equal(u.node('inspection').hidden,true);
});
test('owner migration exposes only configured import action and shows pinned snapshot before queueing',async()=>{
 const u=ui();await ownerUI(u);u.node('owner-refresh').click();await tick();await u.respond({owner:'owner-did',targets:[{id:'legacy',kind:'migration'}],jobs:[],limits:{jobs:10}});
 assert.equal(u.node('owner-operation').value,'import');assert.equal(u.node('owner-operation').children.length,1);u.node('owner-job-form').events.submit({preventDefault(){}});await tick();assert.equal(JSON.parse(u.pending[0].opts.body).operation,'import');
 await u.respond({digest:'pinned',nonce:'a'.repeat(64),contract:{import:{plan:'commitment',files:2},effect:'Queue encrypted batch; retain originals',cancellation:'Safe boundary'}});assert.match(u.node('owner-preview').textContent,/commitment/);assert.match(u.node('owner-preview').textContent,/retain originals/);
});
test('owner import recovery offers its explicit plaintext restoration operation',async()=>{
 const u=ui();await ownerUI(u);u.node('owner-refresh').click();await tick();await u.respond({owner:'owner-did',targets:[{id:'snapshot',kind:'import-recovery'}],jobs:[],limits:{jobs:10}});assert.equal(u.node('owner-operation').value,'restore-import');assert.equal(u.node('owner-operation').children.length,1);
});
test('application navigation exposes available areas and clears them on lock',async()=>{
 const u=ui();await openSearch(u);assert.equal(u.node('nav-search').hidden,false);assert.equal(u.node('nav-evidence').hidden,false);assert.equal(u.node('nav-knowledge').hidden,true);u.node('lock').click();for(const id of ['search','evidence','sessions','imports','knowledge','views','analysis','owner'])assert.equal(u.node('nav-'+id).hidden,true);
});
test('search includes observer, attempt and attestation time in the reproducible filter',async()=>{
 const u=ui();await u.login();await u.respond(searchCatalog);await u.respond(proofPage);u.node('search-text').value='needle';u.node('search-observer').value='gateway';u.node('search-attempt').value='a'.repeat(64);u.node('search-from').value='2026-10-20T00:00';u.node('search-to').value='2026-10-21T00:00';u.node('search-form').events.submit({preventDefault(){}});await tick();await u.respond({indexed_occurrences:1,next:null});const request=JSON.parse(u.pending[0].opts.body);assert.equal(request.filter.observer,'gateway');assert.equal(request.filter.attempt,'a'.repeat(64));assert.equal(request.filter.attested_from,String(new Date('2026-10-20T00:00').getTime()));assert.ok(BigInt(request.filter.attested_to)>BigInt(request.filter.attested_from));
});
test('import source inspection retains its selection for following bytes and fresh-authority export',async()=>{
 const u=ui();await openImported(u);await u.respond(importView);walk(u.node('content-panel')).find(n=>n.textContent==='Source 3 · 9–40').click();await tick();await u.respond({...proofSource,offset:'9',next:'13',total_bytes:'17'});
 u.node('more').click();await tick();let request=JSON.parse(u.pending[0].opts.body);assert.deepEqual(request.selection,proofRow.selection);assert.equal(request.offset,'13');await u.respond({...proofSource,offset:'13',next:null,total_bytes:'17'});
 u.node('download').click();await tick();request=JSON.parse(u.pending[0].opts.body);assert.deepEqual(request.selection,proofRow.selection);assert.equal(request.offset,'13');await u.respond({},403);assert.equal(u.node('library').hidden,true);
});
test('owner offers reconciliation only when a fixed recovery directory is configured',async()=>{
 const u=ui();await ownerUI(u);u.node('owner-refresh').click();await tick();await u.respond({owner:'owner-did',targets:[{id:'legacy',kind:'migration',recovered:'/configured/recovery'}],jobs:[],limits:{jobs:10}});assert.deepEqual(u.node('owner-operation').children.map(n=>n.value),['import','reconcile-import']);
});

test('owner workspace recovery offers only the configured recovery operation',async()=>{
 const u=ui();await ownerUI(u);u.node('owner-refresh').click();await tick();await u.respond({owner:'owner-did',targets:[{id:'reader-history',kind:'workspace-recovery'}],jobs:[],limits:{jobs:10}});assert.deepEqual(u.node('owner-operation').children.map(n=>n.value),['recover']);
});

test('search reconstructs selected attempts after inventory and opens every contributing range',async()=>{
 const u=ui();await openSearch(u);
 const member={record:proofRow,writer:'writer',observer:'collector',attempt:'a'.repeat(64)};
 const page={...searchPage,hits:[],attempt_members:[member]};
 await u.respond(page);await u.respond(page);
 await u.respond(searchPage);await u.respond({...searchPage,hits:[],attempt_members:[]});
 let q=JSON.parse(u.pending[0].opts.body);assert.equal(q.action,'search-attempt');assert.equal(q.target.source,'archive-A');assert.deepEqual(q.selections,[proofRow.selection]);
 const second={...proofRow,sequence:'2',selection:{...proofRow.selection,body:'second-selection'}};
 const hit={...searchPage.hits[0],kind:'capture',interpretation:'reconstructed-message',coarse:true,direction:'request',item:1,cites:[{record:proofRow,offset:'200',end:'210'},{record:second,offset:'300',end:'320'}]};
 await u.respond({version:'normalized-attempt-search/1',hits:[hit],streams:[{attempt:member.attempt,direction:'response',state:'unavailable',issues:[]}]});
 assert.equal(u.node('search-results').children.length,1);assert.match(u.node('search-facets').children.map(n=>n.textContent).join(' '),/response: unavailable/);assert.equal(u.node('resume-search').disabled,true);
 const links=walk(u.node('search-results')).filter(n=>n.textContent.startsWith('Source '));assert.equal(links.length,2);links[1].click();await tick();q=JSON.parse(u.pending[0].opts.body);assert.equal(q.source,'archive-A');assert.equal(q.offset,'300');assert.deepEqual(q.selection,second.selection);await u.respond(proofSource);
});

test('portable reference resolution installs fresh reader selections and clears exports on lock',async()=>{
 const fresh={...proofCatalog,scopes:[proofEntry('archive-A')]};const u=ui();await u.login();await u.respond(fresh);await u.respond(proofPage);
 const reference={version:1,binding:{archive:'archive-A'},coordinate:{through:'1',manifest:'m',attestation:'a'},receipt:'r'};
 u.node('reference-input').value=JSON.stringify({reference,offset:'9'});u.node('reference-form').events.submit({preventDefault(){}});await tick();assert.deepEqual(JSON.parse(u.pending[0].opts.body),{action:'resolve-reference',reference});
 const entry=fresh.scopes[0],record={...proofRow,selection:{...proofRow.selection,body:'new-reader-selection'}};
 await u.respond({source:entry.id,pin:entry.pin,pin_wire:entry.pin_wire,record,reference});
 const query=JSON.parse(u.pending[0].opts.body);assert.equal(query.action,'proof-source');assert.equal(query.offset,'9');assert.deepEqual(query.selection,record.selection);
 await u.respond({...proofSource,record,reference,offset:'9'});assert.deepEqual(JSON.parse(u.node('reference-value').value),{reference,offset:'9'});assert.equal(u.node('reference-export').hidden,false);
 u.node('lock').click();assert.equal(u.node('reference-input').value,'');assert.equal(u.node('reference-value').value,'');assert.equal(u.node('reference-export').hidden,true);
});

test('published annotation restoration requires preview and keeps provenance and lock state',async()=>{
 const u=ui();await u.login();await u.respond(knowledgeCatalog);await u.respond(proofPage);
 u.node('rows').children[0].click();await tick();
 const reference={version:1,binding:{archive:'archive-A'},coordinate:{through:'3'},receipt:'r'};
 await u.respond({...proofSource,reference,utf8:'{"format":"kan-annotation/1","declaration":{}}',offset:'0'});
 assert.equal(u.node('restore-annotation').hidden,false);u.node('restore-annotation').click();await tick();assert.equal(JSON.parse(u.pending[0].opts.body).action,'restore-annotation');
 await u.respond({state:'preview',digest:'checked',contract:{declaration:{author:'original',id:'retained'}}});assert.equal(u.node('annotation-recovery-save').disabled,false);
 u.node('annotation-recovery-save').click();await tick();assert.deepEqual(JSON.parse(u.pending[0].opts.body),{action:'restore-annotation',reference,preview:'checked'});
 await u.respond({state:'restored',annotation:{id:'retained',author:'original'}});assert.match(u.node('annotation-recovery-preview').textContent,/original author original/);
 u.node('lock').click();assert.equal(u.node('annotation-recovery').hidden,true);assert.equal(u.node('annotation-recovery-preview').textContent,'');
});
test('import repository view separates reachability from trust and follows fold sources',async()=>{
 const u=ui();await openImported(u);await u.respond(importView);walk(u.node('content-panel')).find(n=>n.textContent==='Read repo.car').click();await tick();
 const author={did:'did:key:synthetic',agent:null},repo={state:'membership-verified',head:'head-cid',head_sources:importView.inventory_cites,records:2,commit:{signature:'valid-static-did-key',after:5},authors:[author],fold:{coverage:'Verified reachable v1 claims; explicit trust is interpretation.',verified_claims:2,uninterpreted_members:0,total_classes:0,classes:[],excluded_by_trust:[{subject:{Local:'telos/memory'},claims:2}],next:null}};
 const value={...importView,file:{index:0,path:'repo.car',state:'verified',sources:importView.inventory_cites,car:{membership:'Exact imported HEAD only',repository:repo,scan:{error:null},records:[{state:'verified-claim',id:'claim-1',block:'block-1',membership:{state:'not-a-current-record'},claim:{text:'historical'},sources:importView.inventory_cites}],next:null}}};
 await u.respond(value);assert.ok(walk(u.node('content-panel')).some(n=>n.textContent.includes('not-a-current-record')));
 const checkbox=walk(u.node('content-panel')).find(n=>n.type==='checkbox');assert.equal(checkbox.checked,false);checkbox.checked=true;
 walk(u.node('content-panel')).find(n=>n.textContent==='Apply repository trust view').click();await tick();assert.deepEqual(JSON.parse(u.pending[0].opts.body).view,{trust:[author],subjects_after:0});
 const folded={...value,file:{...value.file,car:{...value.file.car,repository:{...repo,fold:{...repo.fold,total_classes:1,classes:[{subjects:[{Local:'telos/memory'}],status:{kind:'contested'},live_status_claims:['a','b'],witnesses:[],claims:[{id:'claim-1',author,body:{Observation:{text:'<b>raw</b>'}},cites:['original'],source:{after:2}}]}]}}}}};
 await u.respond(folded);assert.ok(walk(u.node('content-panel')).some(n=>n.textContent==='contested'));assert.ok(walk(u.node('content-panel')).some(n=>n.textContent.includes('<b>raw</b>')));
 walk(u.node('content-panel')).find(n=>n.textContent==='Inspect claim claim-1').click();await tick();const request=JSON.parse(u.pending[0].opts.body);assert.equal(request.after,2);assert.deepEqual(request.view.trust,[author]);u.node('lock').click();await u.respond(folded);assert.equal(u.node('content-panel').children.length,0);
});
