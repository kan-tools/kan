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
function render(s){snapshot=s;const w=s.worker,q=w?.queue;const age=w?Math.max(0,Date.now()/1000-w.sampled_at):Infinity;
  $('data').hidden=false;$('login').hidden=true;$('lock').hidden=false;$('refresh').disabled=false;
  $('updated').textContent='Read '+new Date(s.read_at*1000).toLocaleTimeString();
  $('pending').textContent=q?count(q.pending):'—';$('bytes').textContent=q?bytes(q.pending_bytes)+' awaiting delivery':'No queue sample';
  $('acked').textContent=q?count(q.next-q.pending):'—';$('acktime').textContent='Last worker ack: '+time(w?.last_ack_at);
  $('gaps').textContent=count(s.unconfirmed);$('attempts').textContent=count(s.attempts);$('telemetry').textContent=count(s.telemetry_dropped)+' capture updates lost · '+count(w?.telemetry_failures)+' worker reports failed';
  $('worker').textContent=!w?'No worker':age>45?'Stale · '+w.state:w.state;
  $('retry').textContent=w?.state==='retrying'?'Retry delay: '+w.retry_seconds+'s · '+count(w.consecutive_failures)+' consecutive failures':w?.state==='idle'?'Queue empty at last sample':'Exact retained bytes, in order';
  $('capacity').value=q?Math.min(100,100*q.pending_bytes/q.budget):0;$('capacity-label').textContent=q?bytes(q.pending_bytes)+' / '+bytes(q.budget):'No queue sample';
  $('age').textContent=w?.nonempty_since?'Queue observed continuously nonempty since '+time(w.nonempty_since)+'. This is not oldest-event age.':'No continuous backlog currently observed.';
  if(age>45)notice('Worker status is missing or stale. These values do not establish current service health.','warning');
  else if((s.reporters||[]).some(r=>!r.clean&&Date.now()/1000-r.updated_at>5))notice('A health reporter is stale or stopped without closing. Capture coverage is unknown.','warning');
  else if(s.unconfirmed||s.telemetry_dropped)notice('Recording or telemetry gaps are retained. Archive progress does not establish complete capture.','warning');
  else if(w?.telemetry_failures)notice('Worker telemetry writes have failed. Delivery continues; reporting coverage is incomplete.','warning');
  else if(!(s.reporters||[]).some(r=>!r.clean))notice('No active capture reporter is recorded. Capture coverage is unknown.','warning');
  else if(s.unclosed_sessions)notice(count(s.unclosed_sessions)+' reporting session(s) are active or ended without a clean close. Coverage across interruption is unknown.','warning');
  else notice('Status is current. Capture completion and archive acknowledgment are separate observations.');
  rows();
}
async function refresh(){if(!token||busy)return;busy=true;const current=generation;const controller=new AbortController();const timeout=setTimeout(()=>controller.abort(),8000);try{const r=await fetch('/api/status',{headers:{Authorization:'Bearer '+token},cache:'no-store',credentials:'omit',redirect:'error',signal:controller.signal});if(!r.ok)throw new Error(r.status===401?'Token rejected. Lock and reconnect.':'Status unavailable. Retained values may be stale.');const s=await r.json();if(s.version!==1)throw new Error('Unsupported status version.');if(current===generation)render(s);}catch(e){if(current!==generation)return;notice(e.name==='AbortError'?'Status request timed out. Retained values may be stale.':e.message,'error');$('updated').textContent='Disconnected · last values retained';}finally{clearTimeout(timeout);busy=false;}}
$('connect').addEventListener('submit',e=>{e.preventDefault();generation++;token=$('token').value;$('token').value='';refresh();});
$('refresh').addEventListener('click',refresh);$('gaps-only').addEventListener('change',rows);
$('lock').addEventListener('click',()=>{generation++;token='';snapshot=null;$('rows').replaceChildren();$('data').hidden=true;$('login').hidden=false;$('lock').hidden=true;$('refresh').disabled=true;$('updated').textContent='Locked';notice('Locked. Enter your token to reconnect.');});
setInterval(refresh,5000);
