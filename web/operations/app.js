'use strict';
let token='', snapshot=null, busy=false, generation=0;
const $=id=>document.getElementById(id);
const count=n=>Number(n||0).toLocaleString();
const time=n=>n?new Date(n*1000).toLocaleString():'Not observed';
const bytes=n=>n>=1048576?(n/1048576).toFixed(1)+' MiB':n>=1024?(n/1024).toFixed(1)+' KiB':count(n)+' B';
function notice(text,kind=''){ $('notice').textContent=text;$('notice').className='notice '+kind; }
function rows(){
  $('rows').replaceChildren();
  const list=(snapshot?.recent||[]).filter(x=>!$('gaps-only').checked||x.capture.recording_gap);
  for(const item of list){const h=item.capture;const tr=document.createElement('tr');
    for(const [i,value] of [h.attempt.slice(0,12)+'…',h.observer,count(h.observed),count(h.locally_queued),count(h.unconfirmed),h.outcome||'No terminal report',time(item.updated_at)].entries()){
      const td=document.createElement('td');td.textContent=value;if(i===0)td.title=h.attempt;if(i===4&&h.unconfirmed)td.className='gap';tr.append(td);
    }$('rows').append(tr);
  }
  $('empty').hidden=list.length>0;$('empty').textContent=$('gaps-only').checked?'No recording gaps in these recent summaries.':'No capture attempts have been reported yet.';
}
function render(s){snapshot=s;const w=s.worker,q=w?.queue;const now=Date.now()/1000;const age=w?Math.max(0,now-w.sampled_at):Infinity;const workerCurrent=!!w&&Number.isFinite(w.sampled_at)&&w.sampled_at<=now+5&&age<=45;
  $('data').hidden=false;$('login').hidden=true;$('lock').hidden=false;$('refresh').disabled=false;
  $('updated').textContent='Read '+new Date(s.read_at*1000).toLocaleTimeString();
  $('pending').textContent=q?count(q.pending):'—';$('bytes').textContent=q?bytes(q.pending_bytes)+' awaiting delivery':'No queue sample';
  $('acked').textContent=q?count(q.next-q.pending):'—';$('acktime').textContent='Last worker ack: '+time(w?.last_ack_at);
  $('gaps').textContent=count(s.unconfirmed);$('attempts').textContent=count(s.attempts);$('telemetry').textContent=count(s.telemetry_dropped)+' capture updates lost · '+count(w?.telemetry_failures)+' worker reports failed';
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
  if(s.telemetry_dropped)history.push(count(s.telemetry_dropped)+' capture updates lost');
  if(w?.telemetry_failures)history.push(count(w.telemetry_failures)+' worker reports failed');
  if(stale.length||unseen)history.push(count(stale.length+unseen)+' unclosed sessions without a current heartbeat');
  $('coverage-history').textContent=history.length?history.join(' · '):'No gaps reported in the retained observations. This does not establish complete capture.';
  if(!workerCurrent)notice('Worker status is missing or stale. These values do not establish current service health.','warning');
  else if(w.state==='retrying')notice('Archive delivery is retrying. Retained evidence remains queued.','warning');
  else if(stale.length||unseen)notice('A health reporter is stale or has no recent sampled heartbeat. Capture coverage is unknown.','warning');
  else if(!unclosed.length)notice('No active capture reporter is recorded. Capture coverage is unknown.','warning');
  else notice('Status is current. Capture completion and archive acknowledgment are separate observations.');
  rows();
}
async function refresh(){if(!token||busy)return;busy=true;const current=generation;const controller=new AbortController();const timeout=setTimeout(()=>controller.abort(),8000);try{const r=await fetch('/api/status',{headers:{Authorization:'Bearer '+token},cache:'no-store',credentials:'omit',redirect:'error',signal:controller.signal});if(!r.ok)throw new Error(r.status===401?'Token rejected. Lock and reconnect.':'Status unavailable. Retained values may be stale.');const s=await r.json();if(s.version!==1)throw new Error('Unsupported status version.');if(current===generation)render(s);}catch(e){if(current!==generation)return;notice(e.name==='AbortError'?'Status request timed out. Retained values may be stale.':e.message,'error');$('updated').textContent='Disconnected · last values retained';}finally{clearTimeout(timeout);busy=false;}}
$('connect').addEventListener('submit',e=>{e.preventDefault();generation++;token=$('token').value;$('token').value='';refresh();});
$('refresh').addEventListener('click',refresh);$('gaps-only').addEventListener('change',rows);
$('lock').addEventListener('click',()=>{generation++;token='';snapshot=null;$('rows').replaceChildren();$('data').hidden=true;$('login').hidden=false;$('lock').hidden=true;$('refresh').disabled=true;$('updated').textContent='Locked';notice('Locked. Enter your token to reconnect.');});
setInterval(refresh,5000);
