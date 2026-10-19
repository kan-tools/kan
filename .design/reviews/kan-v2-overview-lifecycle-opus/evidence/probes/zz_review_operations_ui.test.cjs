// Reviewer UI probes for 262cad3 (Scope A). Runs the real web/operations/app.js.
// Difference from the author harness: fetch HONOURS AbortSignal (rejects with an
// AbortError like a browser), so abort/catch/finally paths are actually exercised.
const {test}=require('node:test');const assert=require('node:assert/strict');const vm=require('node:vm');const fs=require('node:fs');
function ui(){const nodes=new Map();class Element{constructor(){this.value='';this.hidden=false;this.events={};this.children=[];this.checked=false;this.open=false;this.isConnected=true;this.textWrites=0;}set textContent(v){this._text=v;this.textWrites++;}get textContent(){return this._text;}getAttribute(k){return this[k]??null;}setAttribute(k,v){this[k]=v;}showModal(){this.open=true;}close(){this.open=false;}focus(){this.focused=true;document.activeElement=this;}select(){this.selected=true;}addEventListener(k,f){this.events[k]=f;}replaceChildren(){const d=n=>{n.isConnected=false;for(const c of n.children)d(c);};for(const c of this.children)d(c);this.children=[];}append(x){this.children.push(x);}}
 const node=id=>{if(!nodes.has(id))nodes.set(id,new Element());return nodes.get(id);};const pending=[];const log=[];const document={getElementById:node,createElement:()=>new Element(),activeElement:null};
 const fetch=(url,opts)=>new Promise((resolve,reject)=>{const p={url,opts,resolve,reject,aborted:false};log.push(url);opts.signal?.addEventListener('abort',()=>{p.aborted=true;const i=pending.indexOf(p);if(i>=0)pending.splice(i,1);const e=new Error('aborted');e.name='AbortError';reject(e);});pending.push(p);});
 const context={document,fetch,setInterval:()=>{},setTimeout,clearTimeout,AbortController,Date,Number};vm.createContext(context);vm.runInContext(fs.readFileSync('web/operations/app.js','utf8'),context);
 const login=()=>{node('token').value='synthetic-operator-token';node('connect').events.submit({preventDefault(){}});};
 const respondTo=async(pred,s,status=200)=>{const i=pending.findIndex(pred);assert.ok(i>=0,'no pending request matches');const [p]=pending.splice(i,1);p.resolve({ok:status===200,status,json:async()=>s});await new Promise(setImmediate);await new Promise(setImmediate);};
 const respond=(s,status)=>respondTo(()=>true,s,status);
 const settle=async()=>{await new Promise(setImmediate);await new Promise(setImmediate);};
 return{node,pending,log,login,respond,respondTo,settle};}
const snapshot=()=>({version:2,active_generation:'a'.repeat(32),journal:{schema:2,pages_used:80,pages_limit:8192,free_pages:0,page_size:4096,attempts_used:1,attempts_limit:100000,sessions_used:1,sessions_limit:1024,reserve_bytes:262144,exhausted_observed:false,last_success_at:Date.now()/1000,scope:"active generation"},read_at:Date.now()/1000,worker:{sampled_at:Date.now()/1000,state:'idle',queue:{next:9,pending:2,pending_bytes:64,budget:128}},attempts:1,unconfirmed:1,telemetry_dropped:0,unclosed_sessions:0,reporters:[],recent:[]});
const overview=(o={})=>({version:1,state:'completed',job:1,reason:null,last_job:1,last:{version:1,coverage:'observations-only',capture_completeness:'unknown',built_at:Math.floor(Date.now()/1000)-30,active:'a'.repeat(32),manifest_sha256:'b'.repeat(64),sources:[{generation:'a'.repeat(32),sealed_sha256:null,snapshot:{digest:'c'.repeat(64)}}],totals:{attempts:'1',sessions:'1',observed:'3',locally_queued:'2',unconfirmed:'1',attempts_with_gaps:'1',telemetry_dropped_lower_bound:'8',unclosed_sessions:'0'}},...o});
const isOv=p=>p.url.startsWith('/api/overview');

test('UPa: a poll aborted by a preempting Build never labels the view as timed out/failed',async()=>{
 const u=ui();u.login();await u.respond(snapshot());
 u.node('overview-load').events.click();
 u.node('overview-build').events.click();await u.settle();
 assert.doesNotMatch(u.node('overview-state').textContent||'',/timed out|unavailable|Token/,'aborted poll leaked into the label');
 assert.equal(u.pending.filter(isOv).length,1);assert.equal(u.pending.find(isOv).url,'/api/overview/refresh');
 await u.respondTo(isOv,overview({state:'building',job:2}));
 assert.match(u.node('overview-state').textContent,/Overview building/);
 assert.doesNotMatch(u.node('overview-state').textContent,/timed out/);
});

test('UPb: after a service restart, a new sample with the same job number and manifest must repaint totals',async()=>{
 const u=ui();u.login();await u.respond(snapshot());
 u.node('overview-load').events.click();await u.respondTo(isOv,overview());
 assert.match(u.node('overview-summary').textContent,/^1 distinct attempts/);
 // Restarted process: job counter restarts at 1, manifest unchanged (no rotation), new active rows.
 const fresh=overview();fresh.last.built_at=Math.floor(Date.now()/1000)-1;fresh.last.totals.attempts='5';fresh.last.totals.observed='9';fresh.last.sources[0].snapshot.digest='e'.repeat(64);
 u.node('overview-load').events.click();await u.respondTo(isOv,fresh);
 assert.match(u.node('overview-state').textContent,/1s old|0s old|2s old/,'label is from the new sample');
 assert.match(u.node('overview-summary').textContent,/^5 distinct attempts/,'summary still shows the pre-restart sample beside the new label');
});

test('UPc: lock with a queued action dispatches nothing and repaints nothing afterwards',async()=>{
 const u=ui();u.login();await u.respond(snapshot());
 u.node('overview-build').events.click();u.node('overview-cancel').events.click();
 assert.match(u.node('overview-state').textContent,/queued/);
 const before=u.log.length;u.node('lock').events.click();await u.settle();
 assert.equal(u.pending.filter(isOv).length,0,'lock aborts the in-flight action');
 assert.equal(u.log.length,before,'queued Cancel must not be dispatched after lock');
 assert.equal(u.node('overview-state').textContent,'No overview loaded.');
});

test('UPd: Build, Cancel, Build while an action is in flight: only the last queued action is sent',async()=>{
 const u=ui();u.login();await u.respond(snapshot());
 u.node('overview-build').events.click();u.node('overview-cancel').events.click();u.node('overview-build').events.click();
 await u.respondTo(isOv,overview({state:'building',job:2,last:null,last_job:null}));
 const sent=u.log.filter(x=>x.startsWith('/api/overview'));
 console.log('UPd dispatched actions:',JSON.stringify(sent));
 assert.deepEqual(sent,['/api/overview/refresh','/api/overview/refresh'],'observed queue semantics');
});

test('UPe: a failing action still dispatches the queued action and keeps the prior-sample label',async()=>{
 const u=ui();u.login();await u.respond(snapshot());
 u.node('overview-load').events.click();await u.respondTo(isOv,overview());
 u.node('overview-build').events.click();u.node('overview-cancel').events.click();
 await u.respondTo(isOv,{},503);
 assert.match(u.node('overview-state').textContent,/Overview unavailable\. Prior sample retained\./);
 assert.equal(u.pending.find(isOv)?.url,'/api/overview/cancel','queued cancel dispatched after failure');
 assert.match(u.node('overview-summary').textContent,/^1 distinct attempts/);
});

test('UPf: superseded label survives later overview polls and a failed status poll',async()=>{
 const u=ui();u.login();const st=snapshot();await u.respond(st);
 u.node('overview-load').events.click();await u.respondTo(isOv,overview());
 st.active_generation='d'.repeat(32);u.node('refresh').events.click();await u.respondTo(p=>p.url==='/api/status',st);
 assert.match(u.node('overview-state').textContent,/Superseded by active generation d+/);
 u.node('overview-load').events.click();await u.respondTo(isOv,overview());
 assert.match(u.node('overview-state').textContent,/Superseded/,'an overview poll dropped the superseded label');
 u.node('refresh').events.click();await u.respondTo(p=>p.url==='/api/status',{},503);
 assert.match(u.node('overview-state').textContent,/Superseded/,'status failure dropped the superseded label');
});

test('UPg: future-dated sample says its clock is ahead, not "0s old"',async()=>{
 const u=ui();u.login();await u.respond(snapshot());
 const s=overview();s.last.built_at=Math.floor(Date.now()/1000)+3600;
 u.node('overview-load').events.click();await u.respondTo(isOv,s);
 assert.match(u.node('overview-state').textContent,/sample clock is ahead/);
});

test('UPh: relogin after lock ignores the old session\'s late action reply',async()=>{
 const u=ui();u.login();await u.respond(snapshot());
 u.node('overview-build').events.click();const old=u.pending.find(isOv);
 u.node('lock').events.click();u.login();await u.respondTo(p=>p.url==='/api/status',snapshot());
 // the old request was aborted by lock; a browser could still have delivered bytes - simulate a late resolve
 old.resolve({ok:true,status:200,json:async()=>overview()});await u.settle();
 assert.equal(u.node('overview-summary').textContent||'','');
});

test('UPi: after a Build preempts a poll, a following Cancel is still queued (one action in flight)',async()=>{
 const u=ui();u.login();await u.respond(snapshot());
 u.node('overview-load').events.click();
 u.node('overview-build').events.click();await u.settle(); // aborted poll's catch/finally run here
 u.node('overview-cancel').events.click();
 assert.equal(u.pending.filter(isOv).length,1,'a second action was dispatched concurrently with Build');
 assert.match(u.node('overview-state').textContent,/queued/);
 await u.respondTo(isOv,overview({state:'building',job:2,last:null,last_job:null}));
 assert.equal(u.pending.find(isOv)?.url,'/api/overview/cancel');
});
