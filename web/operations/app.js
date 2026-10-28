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
  rows();
}
async function refresh(){if(!token||busy)return;busy=true;const current=generation;const controller=new AbortController();const timeout=setTimeout(()=>controller.abort(),8000);try{const r=await fetch('/api/status',{headers:{Authorization:'Bearer '+token},cache:'no-store',credentials:'omit',redirect:'error',signal:controller.signal});if(!r.ok)throw new Error(r.status===401?'Token rejected. Lock and reconnect.':'Status unavailable. Retained values may be stale.');const s=await r.json();if(s.version!==2||!s.journal)throw new Error('Unsupported status version.');if(current===generation)render(s);}catch(e){if(current!==generation)return;notice(e.name==='AbortError'?'Status request timed out. Retained values may be stale.':e.message,'error');$('updated').textContent='Disconnected · last values retained';}finally{clearTimeout(timeout);busy=false;}}
$('connect').addEventListener('submit',e=>{e.preventDefault();generation++;token=$('token').value;$('token').value='';refresh();});
$('refresh').addEventListener('click',refresh);$('gaps-only').addEventListener('change',rows);$('search').addEventListener('input',rows);
$('lock').addEventListener('click',()=>{generation++;token='';snapshot=null;attemptButtons.clear();closeInspector();$('search').value='';$('gaps-only').checked=false;$('rows').replaceChildren();for(const id of ['pending','bytes','acked','acktime','gaps','attempts','telemetry','worker','retry','capacity-label','age','journal-state','journal-pages','journal-limits','journal-persistence','journal-scope','coverage-history','sample-count'])$(id).textContent='';$('capacity').value=0;$('journal-capacity').value=0;$('data').hidden=true;$('login').hidden=false;$('lock').hidden=true;$('refresh').disabled=true;$('updated').textContent='Locked';notice('Locked. Enter your token to reconnect.');$('token').focus();});
setInterval(refresh,5000);
