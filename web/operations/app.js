'use strict';
let token='', snapshot=null, busy=false, generation=0, inspectorTrigger=null, inspectorAttempt=null, attemptButtons=new Map();
const $=id=>document.getElementById(id);
const count=n=>Number(n||0).toLocaleString();
const time=n=>n?new Date(n*1000).toLocaleString():'Not observed';
const bytes=n=>n>=1048576?(n/1048576).toFixed(1)+' MiB':n>=1024?(n/1024).toFixed(1)+' KiB':count(n)+' B';
function notice(text,kind=''){if($('notice').textContent!==text)$('notice').textContent=text;const name='notice '+kind;if($('notice').className!==name)$('notice').className=name;}
function rows(){
  const focused=document.activeElement?.getAttribute('data-attempt');
  attemptButtons=new Map();
  $('rows').replaceChildren();
  const query=$('search').value.trim().toLowerCase();
  const list=(snapshot?.recent||[]).filter(x=>(!$('gaps-only').checked||x.capture.recording_gap)&&[x.capture.attempt,x.capture.observer,x.capture.outcome||''].some(v=>v.toLowerCase().includes(query)));
  $('sample-count').textContent=list.length+' shown / '+(snapshot?.recent||[]).length+' in the latest sample. Search does not scan older history.';
  for(const item of list){const h=item.capture;const tr=document.createElement('tr');
    for(const [i,value] of [h.attempt.slice(0,12)+'…',h.observer,count(h.observed),count(h.locally_queued),count(h.unconfirmed),h.outcome||'No terminal report',time(item.updated_at)].entries()){
      const td=document.createElement('td');if(i===0){const button=document.createElement('button');button.className='attempt-link';button.textContent=value;button.title=h.attempt;button.setAttribute('aria-label','Inspect attempt '+h.attempt);button.setAttribute('data-attempt',h.attempt);attemptButtons.set(h.attempt,button);button.addEventListener('click',()=>inspect(item,button));td.title=h.attempt;td.append(button);}else td.textContent=value;if(i===4&&h.unconfirmed)td.className='gap';tr.append(td);
    }$('rows').append(tr);
  }
  if(focused){if(attemptButtons.has(focused))attemptButtons.get(focused).focus();else $('search').focus();}
  $('empty').hidden=list.length>0;$('empty').textContent=query?'No matching attempts in the latest sample.':$('gaps-only').checked?'No recording gaps in these recent summaries.':'No capture attempts have been reported yet.';
}
function inspect(item,trigger){
  inspectorTrigger=trigger;inspectorAttempt=item.capture.attempt;
  const h=item.capture;
  $('attempt-id').value=h.attempt;
  $('inspect-fields').replaceChildren();
  for(const [label,value] of [['Observer',h.observer],['Updated',time(item.updated_at)],['Capture observations',count(h.observed)],['Locally queued',count(h.locally_queued)],['Unconfirmed',count(h.unconfirmed)],['Recording gap',h.recording_gap?'Observed':'Not reported; completeness unknown'],['Remote acknowledgment',h.remote_acknowledged?'Observed':'Not observed'],['Provider status',h.status===null||h.status===undefined?'Not observed':String(h.status)],['Outcome',h.outcome||'No terminal report']]){
    const dt=document.createElement('dt'),dd=document.createElement('dd');dt.textContent=label;dd.textContent=value;$('inspect-fields').append(dt);$('inspect-fields').append(dd);
  }
  $('copy-result').textContent='';
  $('inspector').showModal();$('inspect-close').focus();
}
function closeInspector(){
  if($('inspector').open)$('inspector').close();
  $('attempt-id').value='';$('inspect-fields').replaceChildren();$('copy-result').textContent='';
  const trigger=inspectorTrigger?.isConnected?inspectorTrigger:attemptButtons.get(inspectorAttempt);inspectorTrigger=null;inspectorAttempt=null;
  if(trigger?.isConnected)trigger.focus();else if(snapshot)$('search').focus();
}
$('inspect-close').addEventListener('click',closeInspector);
$('inspector').addEventListener('cancel',e=>{e.preventDefault();closeInspector();});
$('copy-id').addEventListener('click',async()=>{
  const current=generation,value=$('attempt-id').value;
  try{await navigator.clipboard.writeText(value);if(current===generation&&$('inspector').open)$('copy-result').textContent='Identifier copied.';}
  catch{if(current===generation&&$('inspector').open){$('attempt-id').focus();$('attempt-id').select();$('copy-result').textContent='Select and copy the identifier above.';}}
});
function journalState(j,now){
  const fresh=Number.isFinite(j.last_success_at)&&j.last_success_at>0&&j.last_success_at<=now+5&&now-j.last_success_at<=5;
  const used=j.pages_used-j.free_pages;
  const nearCauses=[];if(used>=j.pages_limit*0.9)nearCauses.push('pages');if(j.attempts_used>=j.attempts_limit*0.9)nearCauses.push('attempts');if(Number.isFinite(j.sessions_limit)&&j.sessions_limit>0&&j.sessions_used>=j.sessions_limit*0.9)nearCauses.push('reporter sessions');const near=nearCauses.length>0;const sessionsExhausted=j.exhausted_observed===true&&j.exhaustion_reason==='session_limit';
  $('journal-state').textContent=sessionsExhausted?'Reporter capacity exhausted':j.exhausted_observed===true?'Exhaustion recorded':j.schema===1?'Legacy · persistence unknown':near?'Near capacity limit':fresh?'Write observed':'Persistence unknown';
  $('journal-capacity').value=Math.min(100,100*used/j.pages_limit);
  $('journal-pages').textContent=bytes(j.pages_used*j.page_size)+' allocated / '+bytes(j.pages_limit*j.page_size)+' page ceiling · '+bytes(j.free_pages*j.page_size)+' reusable';
  $('journal-limits').textContent=count(j.attempts_used)+' / '+count(j.attempts_limit)+' attempts · '+count(j.sessions_used)+' / '+(j.sessions_limit===null?'legacy unbounded':count(j.sessions_limit))+' reporter sessions · '+bytes(j.reserve_bytes)+' control reserve';
  $('journal-persistence').textContent='Last successful persistence observation: '+time(j.last_success_at)+(j.exhaustion_reason?' · '+j.exhaustion_reason:'');
  $('journal-scope').textContent='Scope: '+j.scope+'. Loss counts are lower bounds, not a count of missing raw messages.';
  return {fresh,near,nearCauses,sessionsExhausted,exhausted:j.exhausted_observed===true};
}
function render(s){snapshot=s;const w=s.worker,q=w?.queue;const now=Date.now()/1000;const age=w?Math.max(0,now-w.sampled_at):Infinity;const workerCurrent=!!w&&Number.isFinite(w.sampled_at)&&w.sampled_at<=now+5&&age<=45;
  const storage=journalState(s.journal,now);
  $('data').hidden=false;$('login').hidden=true;$('lock').hidden=false;$('refresh').disabled=false;
  $('updated').textContent='Read '+new Date(s.read_at*1000).toLocaleTimeString();
  $('pending').textContent=q?count(q.pending):'—';$('bytes').textContent=q?bytes(q.pending_bytes)+' awaiting delivery':'No queue sample';
  $('acked').textContent=q?count(q.next-q.pending):'—';$('acktime').textContent='Last worker ack: '+time(w?.last_ack_at);
  $('gaps').textContent=count(s.unconfirmed);$('attempts').textContent=count(s.attempts);$('telemetry').textContent=count(s.telemetry_dropped)+' health telemetry loss observations (at least) · '+count(w?.telemetry_failures)+' worker reports failed';
  $('worker').textContent=!w?'No worker':!workerCurrent?'Stale · '+w.state:w.state;
  $('retry').textContent=w?.state==='retrying'?'Retry delay: '+w.retry_seconds+'s · '+count(w.consecutive_failures)+' consecutive failures':w?.state==='idle'?'Queue empty at last sample':'Exact retained bytes, in order';
  $('capacity').value=q?Math.min(100,100*q.pending_bytes/q.budget):0;$('capacity-label').textContent=q?bytes(q.pending_bytes)+' / '+bytes(q.budget):'No queue sample';
  $('age').textContent=w?.nonempty_since?'Queue observed continuously nonempty since '+time(w.nonempty_since)+'. This is not oldest-event age.':'No continuous backlog currently observed.';
  const reporters=s.reporters||[];
  const unclosed=reporters.filter(r=>!r.clean);
  const stale=unclosed.filter(r=>!Number.isFinite(r.updated_at)||now-r.updated_at>5||r.updated_at>now+5);
  const unseen=Math.max(0,s.unclosed_sessions-unclosed.length);
  const history=[];
  if(s.unconfirmed)history.push(count(s.unconfirmed)+' unconfirmed capture observations');
  if(s.telemetry_dropped)history.push(count(s.telemetry_dropped)+' health telemetry loss observations (at least)');
  if(w?.telemetry_failures)history.push(count(w.telemetry_failures)+' worker reports failed');
  if(stale.length)history.push(count(stale.length)+' sampled unclosed sessions without a current heartbeat');
  if(unseen)history.push(count(unseen)+' unclosed sessions outside the recent sample');
  $('coverage-history').textContent=history.length?history.join(' · '):'No gaps reported in the retained observations. This does not establish complete capture.';
  if(storage.sessionsExhausted)notice('New reporter registration is exhausted. Attempt summaries may still persist; coverage is incomplete. Owner rotation preserves history.','warning');
  else if(storage.exhausted)notice('Health journal exhaustion was recorded. Capture and delivery continue; journal history requires owner rotation.','warning');
  else if(!workerCurrent)notice('Worker status is missing or stale. These values do not establish current service health.','warning');
  else if(w.state==='retrying')notice('Archive delivery is retrying. Retained evidence remains queued.','warning');
  else if(!storage.fresh)notice('Health persistence has no recent successful observation. Loss counts are lower bounds and coverage is unknown.','warning');
  else if(storage.near)notice('Health journal is near its capacity limit ('+storage.nearCauses.join(', ')+'). Prepare owner rotation; evidence queue capacity is separate.','warning');
  else if(stale.length||unseen)notice('A health reporter is stale or has no recent sampled heartbeat. Capture coverage is unknown.','warning');
  else if(!unclosed.length)notice('No active capture reporter is recorded. Capture coverage is unknown.','warning');
  else notice('Status is current. Capture completion and archive acknowledgment are separate observations.');
  rows();if(overviewData)labelOverview();
}
async function refresh(){if(!token||busy)return;busy=true;const current=generation;const controller=new AbortController();const timeout=setTimeout(()=>controller.abort(),8000);try{const r=await fetch('/api/status',{headers:{Authorization:'Bearer '+token},cache:'no-store',credentials:'omit',redirect:'error',signal:controller.signal});if(!r.ok)throw new Error(r.status===401?'Token rejected. Lock and reconnect.':'Status unavailable. Retained values may be stale.');const s=await r.json();if(s.version!==2||!s.journal)throw new Error('Unsupported status version.');if(current===generation)render(s);}catch(e){if(current!==generation)return;notice(e.name==='AbortError'?'Status request timed out. Retained values may be stale.':e.message,'error');$('updated').textContent='Disconnected · last values retained';}finally{clearTimeout(timeout);busy=false;}}
$('connect').addEventListener('submit',e=>{e.preventDefault();generation++;token=$('token').value;$('token').value='';refresh();});
$('refresh').addEventListener('click',refresh);$('gaps-only').addEventListener('change',rows);$('search').addEventListener('input',rows);
$('lock').addEventListener('click',()=>{generation++;token='';snapshot=null;clearOverview();attemptButtons.clear();closeInspector();$('search').value='';$('gaps-only').checked=false;$('rows').replaceChildren();for(const id of ['pending','bytes','acked','acktime','gaps','attempts','telemetry','worker','retry','capacity-label','age','journal-state','journal-pages','journal-limits','journal-persistence','journal-scope','coverage-history','sample-count'])$(id).textContent='';$('capacity').value=0;$('journal-capacity').value=0;$('data').hidden=true;$('login').hidden=false;$('lock').hidden=true;$('refresh').disabled=true;$('updated').textContent='Locked';notice('Locked. Enter your token to reconnect.');$('token').focus();});
setInterval(()=>{refresh();if(overviewEnabled)loadOverview();},5000);

let overviewEnabled=false,overviewKey='',overviewRequest=null,overviewSerial=0,overviewQueued='',overviewData=null,overviewError='';
function clearOverview(){if(overviewRequest)overviewRequest.controller.abort();overviewRequest=null;overviewSerial++;overviewQueued='';overviewData=null;overviewError='';overviewEnabled=false;overviewKey='';$('overview-state').textContent='No overview loaded.';for(const id of ['overview-summary','overview-coverage'])$(id).textContent='';$('overview-sources').replaceChildren();$('overview-cancel').disabled=true;$('overview-build').disabled=false;$('overview-load').disabled=false;}
function validateOverview(s){
 const states=['unavailable','building','cancelling','cancelled','completed','failed','capacity-limited'];
 if(!s||s.version!==1||!states.includes(s.state)||!Number.isSafeInteger(s.job)||s.job<0)throw new Error('Unsupported overview response.');
 if(s.reason!==null&&typeof s.reason!=='string')throw new Error('Invalid overview reason.');
 if(s.last!==null){const v=s.last;
  if(!Number.isSafeInteger(s.last_job)||s.last_job<1||v.version!==1||v.coverage!=='observations-only'||v.capture_completeness!=='unknown'||!Number.isSafeInteger(v.built_at)||v.built_at<0||typeof v.active!=='string'||! /^[a-f0-9]{32}$/.test(v.active)||typeof v.manifest_sha256!=='string'||! /^[a-f0-9]{64}$/.test(v.manifest_sha256)||!Array.isArray(v.sources)||v.sources.length<1||v.sources.length>1024||!v.totals)throw new Error('Invalid overview snapshot.');
  for(const k of ['attempts','sessions','observed','locally_queued','unconfirmed','attempts_with_gaps','telemetry_dropped_lower_bound','unclosed_sessions'])if(typeof v.totals[k]!=='string'||! /^(0|[1-9][0-9]{0,19})$/.test(v.totals[k])||BigInt(v.totals[k])>18446744073709551615n)throw new Error('Invalid overview counter.');
  const seen=new Set();for(const source of v.sources){if(!source||typeof source.generation!=='string'||! /^[a-f0-9]{32}$/.test(source.generation)||seen.has(source.generation)||!source.snapshot||typeof source.snapshot.digest!=='string'||! /^[a-f0-9]{64}$/.test(source.snapshot.digest)||!(source.sealed_sha256===null||typeof source.sealed_sha256==='string'&&/^[a-f0-9]{64}$/.test(source.sealed_sha256)))throw new Error('Invalid overview sources.');seen.add(source.generation);}
  if(v.sources.at(-1).generation!==v.active||v.sources.at(-1).sealed_sha256!==null||v.sources.slice(0,-1).some(x=>x.sealed_sha256===null))throw new Error('Invalid overview frontier.');
 }
}
function labelOverview(){
 const s=overviewData;
 if(overviewError){$('overview-state').textContent=overviewError+(s?.last?' Prior sample retained.':'');return;}
 if(!s)return;
 let label='Overview '+s.state+(s.reason?' · '+s.reason:'')+(s.last&&s.last_job!==s.job?' · Prior sample retained; this refresh has not replaced it.':'');
 if(s.last){const age=Math.floor(Date.now()/1000-s.last.built_at);label+=' · Cached sample · '+(age<0?'sample clock is ahead':age<60?age+'s old':Math.floor(age/60)+'m old');
  const active=snapshot?.active_generation;
  if(typeof active==='string'&&/^[a-f0-9]{32}$/.test(active)&&active!==s.last.active)label+=' · Superseded by active generation '+active+'. Build a new overview.';
 }
 if(overviewQueued)label+=' · Action queued.';
 $('overview-state').textContent=label;
}
function renderOverview(s){validateOverview(s);overviewData=s;overviewError='';const building=s.state==='building'||s.state==='cancelling';$('overview-cancel').disabled=!building;$('overview-build').disabled=building;labelOverview();
 if(!s.last){overviewKey='';for(const id of ['overview-summary','overview-coverage'])$(id).textContent='';$('overview-sources').replaceChildren();return;}
 const v=s.last,key=s.last_job+':'+v.manifest_sha256;if(key===overviewKey)return;overviewKey=key;
 const t=v.totals,n=k=>BigInt(t[k]).toLocaleString();
 $('overview-summary').textContent=n('attempts')+' distinct attempts · '+n('observed')+' observed · '+n('locally_queued')+' locally queued · '+n('unconfirmed')+' unconfirmed · '+n('attempts_with_gaps')+' attempts with gaps · '+n('sessions')+' reporter sessions · at least '+n('telemetry_dropped_lower_bound')+' dropped telemetry observations · '+n('unclosed_sessions')+' unclosed sessions';
 $('overview-coverage').textContent='Complete for '+v.sources.length+' selected observation snapshots, built '+time(v.built_at)+'. Raw capture completeness remains unknown. Active generation: '+v.active+'.';
 $('overview-sources').replaceChildren();for(const source of v.sources){const li=document.createElement('li');li.textContent=source.generation+' · '+(source.sealed_sha256?'sealed SHA-256 '+source.sealed_sha256:'active snapshot')+' · row digest '+source.snapshot.digest;$('overview-sources').append(li);}
}
async function loadOverview(action=''){
 if(!token)return;
 if(overviewRequest){
  if(!action)return;
  if(overviewRequest.action){overviewQueued=action;$('overview-state').textContent='Overview action queued until the current request finishes.';return;}
  overviewRequest.controller.abort();
 }
 overviewEnabled=true;const current=generation,serial=++overviewSerial,controller=new AbortController(),timeout=setTimeout(()=>controller.abort(),8000);overviewRequest={action,controller};$('overview-load').disabled=true;
 try{const r=await fetch('/api/overview'+action,{method:action?'POST':'GET',headers:{Authorization:'Bearer '+token},cache:'no-store',credentials:'omit',redirect:'error',signal:controller.signal});if(!r.ok)throw new Error(r.status===401?'Token rejected.':'Overview unavailable.');const s=await r.json();if(current===generation&&serial===overviewSerial)renderOverview(s);}
 catch(e){if(current===generation&&serial===overviewSerial){overviewError=e.name==='AbortError'?'Overview request timed out.':e.message;labelOverview();}}
 finally{clearTimeout(timeout);if(current===generation&&serial===overviewSerial){overviewRequest=null;$('overview-load').disabled=false;const queued=overviewQueued;overviewQueued='';if(queued)loadOverview(queued);}}
}
$('overview-load').addEventListener('click',()=>loadOverview());$('overview-build').addEventListener('click',()=>loadOverview('/refresh'));$('overview-cancel').addEventListener('click',()=>loadOverview('/cancel'));
