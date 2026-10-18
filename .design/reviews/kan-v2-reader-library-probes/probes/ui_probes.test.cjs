// Independent review probes against web/library/app.js using the author's DOM harness shape.
const {test}=require('node:test'), assert=require('node:assert/strict'), vm=require('node:vm'), fs=require('node:fs');
const tick=()=>new Promise(setImmediate);
function ui(){
 const nodes=new Map(),pending=[],downloads=[],revoked=[],timers=new Map(),blobs=[];let active;
 class Element{constructor(){this.value='';this.hidden=false;this.disabled=false;this.children=[];this.events={};this.attrs={};this.textContent='';}setAttribute(k,v){this.attrs[k]=v;}addEventListener(k,f){this.events[k]=f;}append(v){this.children.push(v);}replaceChildren(){this.children=[];}remove(){this.removed=true;}focus(){active=this;}click(){downloads.push(this);if(this.events.click)this.events.click();}}
 const node=id=>{if(!nodes.has(id))nodes.set(id,new Element());return nodes.get(id);};const window={events:{},addEventListener(k,f){this.events[k]=f;}};
 const context={document:{getElementById:node,createElement:()=>new Element(),body:node("body")},window,AbortController,Blob,Uint8Array,setTimeout:(fn)=>{const id={};timers.set(id,fn);return id;},clearTimeout:id=>timers.delete(id),URL:{createObjectURL:blob=>{blobs.push(blob);return 'blob:synthetic';},revokeObjectURL:url=>revoked.push(url)},fetch:(url,opts)=>new Promise((resolve,reject)=>pending.push({url,opts,resolve,reject})),console};
 vm.createContext(context);vm.runInContext(fs.readFileSync('web/library/app.js','utf8'),context);
 const respond=async(value,status=200)=>{const request=pending.shift();assert.ok(request,'expected request');request.resolve({ok:status===200,status,json:async()=>value});await tick();await tick();};
 const login=async()=>{node('token').value='synthetic-library-token';node('connect').events.submit({preventDefault(){}});await tick();};
 return{node,pending,respond,login,downloads,revoked,timers,blobs,window};
}
const pinA={request:'pin-A',reply:{}}, pinB={request:'pin-B',reply:{}};
const catalog={version:1,scopes:[{scope:'A',pin:pinA},{scope:'B',pin:pinB}]};
const pageA={through:5,next:3,records:[{sequence:3,manifest:'A-manifest-3',receipt:'r'}],coverage:'c'};
test('PROBE stale row click during scope switch reads the clicked sequence under the other scope pin',async()=>{
 const u=ui();await u.login();await u.respond(catalog);await u.respond(pageA);
 const rowA3=u.node('rows').children[0];
 u.node('scope').value='B';u.node('scope').events.change();await tick();
 assert.equal(JSON.parse(u.pending[0].opts.body).pin.request,'pin-B');
 assert.equal(u.node('rows').children[0],rowA3,'scope A rows remain clickable while B page is in flight');
 rowA3.click();await tick();
 const body=JSON.parse(u.pending.at(-1).opts.body);
 console.log('PROBE stale-click request',JSON.stringify({action:body.action,pin:body.pin.request,sequence:body.sequence}));
 assert.equal(body.pin.request,'pin-B'); // the row belongs to A
});
test('PROBE stale Next during scope switch sends scope A continuation under scope B pin',async()=>{
 const u=ui();await u.login();await u.respond(catalog);await u.respond(pageA);
 u.node('scope').value='B';u.node('scope').events.change();await tick();
 u.node('next').click();await tick();
 const body=JSON.parse(u.pending.at(-1).opts.body);
 console.log('PROBE stale-next request',JSON.stringify({pin:body.pin.request,after:body.after}),'next.disabled=',u.node('next').disabled);
});
test('PROBE a 503 (e.g. one missing/corrupt object in page) locks the whole session',async()=>{
 const u=ui();await u.login();await u.respond(catalog);await u.respond({},503);
 console.log('PROBE after 503 page: library.hidden=',u.node('library').hidden,'notice=',u.node('notice').textContent);
 assert.equal(u.node('library').hidden,true);
});
test('PROBE 404 Missing is shown identically to verification failure',async()=>{
 const u=ui();await u.login();await u.respond(catalog);await u.respond(pageA);
 u.node('rows').children[0].click();await tick();await u.respond({},404);
 console.log('PROBE after 404 source: notice=',u.node('notice').textContent,'locked=',u.node('library').hidden);
});
test('PROBE bidi override text is not routed to hex view',async()=>{
 const u=ui();await u.login();await u.respond(catalog);await u.respond(pageA);
 u.node('rows').children[0].click();await tick();
 await u.respond({record:{sequence:3,manifest:'m',receipt:'r'},scope:'A',writer:'w',service_issuer:'s',signature:'v',admission:'a',content_trust:'t',total_bytes:9,offset:0,next:null,bytes_hex:'61e280ae6263',utf8:'a‮bc'});
 console.log('PROBE bidi range label=',u.node('range').textContent);
});
