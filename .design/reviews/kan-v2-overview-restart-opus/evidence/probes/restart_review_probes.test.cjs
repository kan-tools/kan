// Independent review probes (Opus 5.5, fresh) for the 7126848 restart correction.
// Runs the real web/operations/app.js (path from APP env or cwd). Node DOM stub only:
// this is NOT browser qualification. Harness differences from the imported one:
//  - fetch honours AbortSignal (as there) AND the body json() honours it too;
//  - setTimeout is controllable so the 8 s request timeout can be fired on demand.
const {test}=require('node:test');const assert=require('node:assert/strict');const vm=require('node:vm');const fs=require('node:fs');const path=require('node:path');
const APP=process.env.APP||path.resolve('web/operations/app.js');
function ui(){const nodes=new Map();class Element{constructor(){this.value='';this.hidden=false;this.events={};this.children=[];this.checked=false;this.open=false;this.isConnected=true;this.textWrites=0;}set textContent(v){this._text=v;this.textWrites++;}get textContent(){return this._text;}getAttribute(k){return this[k]??null;}setAttribute(k,v){this[k]=v;}showModal(){this.open=true;}close(){this.open=false;}focus(){this.focused=true;document.activeElement=this;}select(){this.selected=true;}addEventListener(k,f){this.events[k]=f;}replaceChildren(){const d=n=>{n.isConnected=false;for(const c of n.children)d(c);};for(const c of this.children)d(c);this.children=[];}append(x){this.children.push(x);}}
 const node=id=>{if(!nodes.has(id))nodes.set(id,new Element());return nodes.get(id);};const pending=[];const log=[];const document={getElementById:node,createElement:()=>new Element(),activeElement:null};
 const abortErr=()=>{const e=new Error('aborted');e.name='AbortError';return e;};
 const fetch=(url,opts)=>new Promise((resolve,reject)=>{const p={url,opts,resolve,reject};log.push(url);opts.signal?.addEventListener('abort',()=>{const i=pending.indexOf(p);if(i>=0)pending.splice(i,1);reject(abortErr());});pending.push(p);});
 const timers=new Map();let tid=0;
 const setTimeoutC=(f,ms)=>{const id=++tid;timers.set(id,{f,ms});return id;};const clearTimeoutC=id=>{timers.delete(id);};
 const fireTimeouts=()=>{const all=[...timers];timers.clear();for(const [,t] of all)t.f();};
 const context={document,fetch,setInterval:()=>{},setTimeout:setTimeoutC,clearTimeout:clearTimeoutC,AbortController,Date,Number};vm.createContext(context);vm.runInContext(fs.readFileSync(APP,'utf8'),context);
 const settle=async()=>{for(let i=0;i<4;i++)await new Promise(setImmediate);};
 const login=()=>{node('token').value='synthetic-operator-token';node('connect').events.submit({preventDefault(){}});};
 const respondTo=async(pred,s,status=200)=>{const i=pending.findIndex(pred);assert.ok(i>=0,'no pending request matches');const [p]=pending.splice(i,1);p.resolve({ok:status===200,status,json:async()=>s});await settle();};
 // Headers arrive now; body is delivered later and rejects with AbortError if the signal aborts first (browser semantics).
 const respondHeaders=async(pred)=>{const i=pending.findIndex(pred);assert.ok(i>=0,'no pending request matches');const [p]=pending.splice(i,1);let deliver;const body=new Promise((res,rej)=>{deliver=res;p.opts.signal?.addEventListener('abort',()=>rej(abortErr()));});p.resolve({ok:true,status:200,json:()=>body});await settle();return s=>{deliver(s);return settle();};};
 return{node,pending,log,login,respondTo,respondHeaders,settle,fireTimeouts,timers};}
const snapshot=(active='a'.repeat(32))=>({version:2,active_generation:active,journal:{schema:2,pages_used:80,pages_limit:8192,free_pages:0,page_size:4096,attempts_used:1,attempts_limit:100000,sessions_used:1,sessions_limit:1024,reserve_bytes:262144,exhausted_observed:false,last_success_at:Date.now()/1000,scope:'active generation'},read_at:Date.now()/1000,worker:{sampled_at:Date.now()/1000,state:'idle',queue:{next:9,pending:2,pending_bytes:64,budget:128}},attempts:1,unconfirmed:1,telemetry_dropped:0,unclosed_sessions:0,reporters:[],recent:[]});
// Server-faithful shape: includes the Rust fields the UI does not render (accounted_bytes, memory_limit, scan window, worker).
const scan=d=>({started_at:1000,finished_at:1001,digest:d,worker:{sampled_at:999,state:'idle',queue:null,nonempty_since:null,last_ack_at:null,last_ack_position:null,consecutive_failures:0,retry_seconds:0,telemetry_failures:0},exhausted_observed:false});
const overview=(o={})=>({version:1,state:'completed',job:1,reason:null,last_job:1,last:{version:1,coverage:'observations-only',capture_completeness:'unknown',built_at:Math.floor(Date.now()/1000)-30,manifest_sha256:'b'.repeat(64),active:'a'.repeat(32),sources:[{generation:'a'.repeat(32),sealed_sha256:null,snapshot:scan('c'.repeat(64))}],totals:{attempts:'1',sessions:'1',observed:'3',locally_queued:'2',unconfirmed:'1',attempts_with_gaps:'1',telemetry_dropped_lower_bound:'8',unclosed_sessions:'0'},accounted_bytes:4096,memory_limit:134217728},...o});
const isOv=p=>p.url.startsWith('/api/overview');
const clone=x=>JSON.parse(JSON.stringify(x));
const body=u=>({summary:u.node('overview-summary').textContent,coverage:u.node('overview-coverage').textContent,sources:u.node('overview-sources').children.map(c=>c.textContent)});
async function loaded(){const u=ui();u.login();await u.respondTo(p=>p.url==='/api/status',snapshot());u.node('overview-load').events.click();const first=overview();await u.respondTo(isOv,first);return{u,first};}

test('RP1: restart, same job/manifest/built_at/totals, only a source row digest differs -> source list repaints',async()=>{
 const {u,first}=await loaded();const fresh=clone(first);fresh.last.sources[0].snapshot.digest='e'.repeat(64);
 u.node('overview-load').events.click();await u.respondTo(isOv,fresh);
 assert.match(u.node('overview-sources').children[0].textContent,/row digest e{64}$/,'source digest from pre-restart sample still shown');
});
test('RP2: restart, same job/manifest/built_at, only totals differ -> totals repaint',async()=>{
 const {u,first}=await loaded();const fresh=clone(first);fresh.last.totals.attempts='5';
 u.node('overview-load').events.click();await u.respondTo(isOv,fresh);
 assert.match(u.node('overview-summary').textContent,/^5 distinct attempts/,'pre-restart totals retained beside new sample');
});
test('RP3: restart, same everything except the sealed source set (generation added) -> coverage + sources repaint',async()=>{
 const {u,first}=await loaded();const fresh=clone(first);fresh.last.sources.unshift({generation:'f'.repeat(32),sealed_sha256:'9'.repeat(64),snapshot:scan('8'.repeat(64))});
 u.node('overview-load').events.click();await u.respondTo(isOv,fresh);
 assert.equal(u.node('overview-sources').children.length,2);assert.match(u.node('overview-coverage').textContent,/Complete for 2 selected/);
});
test('RP4: lock -> relogin -> load returns the SAME cached sample -> body is repainted, not left blank',async()=>{
 const {u,first}=await loaded();const shown=body(u);
 u.node('lock').events.click();assert.equal(u.node('overview-summary').textContent,'');
 u.login();await u.respondTo(p=>p.url==='/api/status',snapshot());
 u.node('overview-load').events.click();await u.respondTo(isOv,first);
 assert.deepEqual(body(u),shown,'label says cached sample but body stayed blank after relogin');
 assert.match(u.node('overview-state').textContent,/Cached sample/);
});
test('RP5: restart observed via last:null in between, then identical-looking sample -> body repainted',async()=>{
 const {u,first}=await loaded();const shown=body(u);
 u.node('overview-load').events.click();await u.respondTo(isOv,{version:1,state:'unavailable',job:0,reason:null,last_job:null,last:null});
 assert.equal(u.node('overview-summary').textContent,'');
 u.node('overview-load').events.click();await u.respondTo(isOv,first);
 assert.deepEqual(body(u),shown,'body left blank after null-last then identical sample');
});
test('RP6: the 8 s timeout labels "timed out", retains prior sample, and releases the request slot',async()=>{
 const {u}=await loaded();const shown=body(u);
 u.node('overview-load').events.click();assert.equal(u.pending.filter(isOv).length,1);
 u.fireTimeouts();await u.settle();
 assert.match(u.node('overview-state').textContent,/^Overview request timed out\. Prior sample retained\./);
 assert.deepEqual(body(u),shown);
 u.node('overview-load').events.click();assert.equal(u.pending.filter(isOv).length,1,'slot not released after timeout');
});
test('RP7: a queued action does not leak across lock/relogin into the next session',async()=>{
 const u=ui();u.login();await u.respondTo(p=>p.url==='/api/status',snapshot());
 u.node('overview-build').events.click();u.node('overview-cancel').events.click();assert.match(u.node('overview-state').textContent,/queued/);
 u.node('lock').events.click();await u.settle();
 u.login();await u.respondTo(p=>p.url==='/api/status',snapshot());
 u.node('overview-load').events.click();await u.respondTo(isOv,overview());
 assert.equal(u.pending.filter(isOv).length,0,'stale queued action from the locked session was dispatched: '+JSON.stringify(u.log));
});
test('RP8: Build preempts a poll whose headers arrived but whose body is still streaming',async()=>{
 const {u}=await loaded();const shown=body(u);
 u.node('overview-load').events.click();const deliver=await u.respondHeaders(isOv);
 u.node('overview-build').events.click();await u.settle();
 assert.doesNotMatch(u.node('overview-state').textContent,/timed out/);
 const stale=overview();stale.last.totals.attempts='77';await deliver(stale); // already rejected by abort: no effect
 assert.deepEqual(body(u),shown);
 await u.respondTo(isOv,overview({state:'building',job:2}));assert.match(u.node('overview-state').textContent,/Overview building/);
});
test('RP9: valid A, invalid reply, then valid B (same job/manifest) -> B repaints',async()=>{
 const {u,first}=await loaded();const bad=clone(first);bad.last.sources=[];
 u.node('overview-load').events.click();await u.respondTo(isOv,bad);assert.match(u.node('overview-state').textContent,/Invalid/);
 const b=clone(first);b.last.totals.observed='42';
 u.node('overview-load').events.click();await u.respondTo(isOv,b);
 assert.match(u.node('overview-summary').textContent,/42 observed/);assert.doesNotMatch(u.node('overview-state').textContent,/Invalid/);
});
test('RP10: identical sample repeated: neither summary, coverage nor sources are rewritten (no announce churn)',async()=>{
 const {u,first}=await loaded();const w={s:u.node('overview-summary').textWrites,c:u.node('overview-coverage').textWrites};const kids=u.node('overview-sources').children;
 for(let i=0;i<3;i++){u.node('overview-load').events.click();await u.respondTo(isOv,clone(first));}
 assert.equal(u.node('overview-summary').textWrites,w.s);assert.equal(u.node('overview-coverage').textWrites,w.c);assert.equal(u.node('overview-sources').children,kids);
});
test('RP11 (informational): same sample re-serialised with different key order re-renders but shows identical content',async()=>{
 const {u,first}=await loaded();const shown=body(u);const w=u.node('overview-summary').textWrites;
 const re=clone(first);const l=re.last;re.last=Object.fromEntries(Object.entries(l).reverse());
 u.node('overview-load').events.click();await u.respondTo(isOv,re);
 assert.deepEqual(body(u),shown);console.log('RP11 summary rewrites after key reorder:',u.node('overview-summary').textWrites-w);
});
test('RP12: bounds - 1024 server-shaped sources render; key work is small; 1025 sources are rejected',async()=>{
 const big=overview();const src=[];for(let i=0;i<1023;i++){const h=i.toString(16).padStart(32,'0');src.push({generation:h,sealed_sha256:'1'.repeat(64),snapshot:scan(h+h)});}
 big.last.sources=[...src,big.last.sources[0]];
 const {u}=await loaded();const t0=process.hrtime.bigint();
 for(let i=0;i<10;i++){const b=clone(big);b.last.built_at-=i;u.node('overview-load').events.click();await u.respondTo(isOv,b);}
 const ms=Number(process.hrtime.bigint()-t0)/1e6;
 assert.equal(u.node('overview-sources').children.length,1024);
 const keyBytes=String(big.last_job).length+1+JSON.stringify(big.last).length;console.log('RP12 key bytes at 1024 sources:',keyBytes,'10 distinct renders ms:',ms.toFixed(1));
 assert.ok(keyBytes<1_000_000,'key exceeds 1 MB');
 const over=clone(big);over.last.sources.unshift({generation:'e'.repeat(32),sealed_sha256:'1'.repeat(64),snapshot:scan('2'.repeat(64))});
 u.node('overview-load').events.click();await u.respondTo(isOv,over);assert.match(u.node('overview-state').textContent,/Invalid overview snapshot/);assert.equal(u.node('overview-sources').children.length,1024);
});
