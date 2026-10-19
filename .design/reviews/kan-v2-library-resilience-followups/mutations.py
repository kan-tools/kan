from pathlib import Path
import subprocess,re
ROOT=Path.cwd()
OUT=ROOT/'.local-state/followups'
L='src/evidence_library.rs'
R='src/evidence_reader.rs'
C='catalog_verification_failure_is_not_an_empty_authorized_inventory'
old='''let connection = async {
            let Ok(Ok(_request)) = tokio::time::timeout(
                Duration::from_secs(6),
                self.requests.clone().acquire_owned(),
            )
            .await
            else {
                return;
            };
            work.await;
        };
        let _ = tokio::time::timeout(Duration::from_secs(35), connection).await;'''
new='''let Ok(Ok(_request)) = tokio::time::timeout(
                Duration::from_secs(6),
                self.requests.clone().acquire_owned(),
            )
            .await
            else {
                return;
            };
        let _ = tokio::time::timeout(Duration::from_secs(35), work).await;'''
cases=[
 ('R03',L,'Err(Failure::AccessLimited) => {}','Err(Failure::AccessLimited) => partial = true,','evidence_reader',C),
 ('R08',L,'"coverage":if partial {"partial"} else {"complete"},','"coverage":if partial {"partial"} else {"complete"},"failed":configured.len()-scopes.len(),','evidence_reader',C),
 ('R12',R,'.map_err(|_| Failure::Unavailable)?\n        .map_err(|failure|','.map_err(|_| Failure::AccessLimited)?\n        .map_err(|failure|','evidence_reader',C),
 ('R24',L,old,new,'lib','evidence_library::budget_tests::whole_connection_deadline_includes_time_spent_queued'),
 ('R31',L,'let budget = ConnectionBudget::new();\n    let mut tasks','let budget = ConnectionBudget { sockets: Arc::new(Semaphore::new(4096)), requests: Arc::new(Semaphore::new(4)) };\n    let mut tasks','evidence_reader','library_refuses_thirteenth_socket_at_the_live_admission_boundary'),
]
for label,file,old,new,kind,name in cases:
 p=ROOT/file; original=p.read_bytes(); text=original.decode();assert text.count(old)==1,(label,text.count(old))
 try:
  p.write_text(text.replace(old,new))
  cmd=[str(ROOT/'.local-state/cargo.sh'),'test','--features','v2-crypto']+(['--lib'] if kind=='lib' else ['--test',kind])+[name,'--','--exact']
  r=subprocess.run(cmd,capture_output=True,text=True,timeout=180)
  out=r.stdout+r.stderr
  (OUT/(label+'.txt')).write_text(f'{file}\nOLD:\n{old}\nNEW:\n{new}\n$ {cmd}\nexit={r.returncode}\n'+out)
  assert 'could not compile' not in out and re.search(r'^test '+re.escape(name)+r' \.\.\. FAILED$',out,re.M),(label,'no compiled named failure')
  assert 'panicked at' in out,(label,'no assertion/panic')
  print(label,'compiled named failure; inspect panic in raw log',flush=True)
 finally:
  p.write_bytes(original)
 assert p.read_bytes()==original
