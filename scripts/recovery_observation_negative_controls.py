#!/usr/bin/env python3
"""Compile wire-codec controls; retain raw named assertion failures and restore."""
from pathlib import Path
import subprocess
ROOT=Path(__file__).resolve().parents[1]
FILE=ROOT/'src/evidence_recovery_observation.rs'
OUT=ROOT/'.local-state/bundle-codec-author/controls'
NEGATIVE='independently_resigned_hostile_vectors_refuse_with_named_error'
CASES=[
 ('binary-cid-order','cid.to_string(),','format!("{:02x?}", cid.to_bytes()),',NEGATIVE),
 ('bundle-pin','st["bundle"] == Ipld::Bytes(context.bundle.to_vec())','true',NEGATIVE),
 ('predecessor-context','require(&previous.context == context, "previous-context")?;','require(true, "previous-context")?;','signed_cross_context_chain_and_profile_confusion_refuse'),
 ('chain-link','require(link(&st["previous"], 0x71)? == &previous.cid, "predecessor")?;','require(true, "predecessor")?;',NEGATIVE),
 ('signature','crate::sign::verify(&context.observer, &preimage(&cid)?, signature)','true',NEGATIVE),
 ('candidate-cid','require(b["cid"] == b["candidate"], "candidate-cid")?;','require(true, "candidate-cid")?;',NEGATIVE),
 ('loss-order','previous.as_ref().is_none_or(|p| p < &coordinate)','previous.as_ref().is_none_or(|p| p <= &coordinate)',NEGATIVE),
 ('body-fields','let b = closed(v, fields, "body-fields")?;','let Ipld::Map(b) = v else { return Err(invalid("body-fields")); };',NEGATIVE),
]

def main():
    if not __debug__:raise RuntimeError('assertions required')
    OUT.mkdir(parents=True,exist_ok=True);original=FILE.read_text()
    try:
        for name,old,new,test in CASES:
            assert original.count(old)==1,(name,original.count(old))
            FILE.write_text(original.replace(old,new))
            run=subprocess.run(['cargo','test','--features','v2-crypto','--test','evidence_recovery_observation',test,'--','--exact'],cwd=ROOT,capture_output=True,text=True,timeout=180)
            log=run.stdout+run.stderr
            (OUT/(name+'.txt')).write_text(log+'\nexit='+str(run.returncode)+'\n')
            assert run.returncode!=0,name+' SURVIVED'
            assert 'could not compile' not in log,name+' did not compile'
            assert 'test '+test+' ... FAILED' in log,name+' lacks assertion failure'
            print('DEMONSTRATED: '+name,flush=True)
            FILE.write_text(original)
    finally:FILE.write_text(original)
    run=subprocess.run(['cargo','test','--features','v2-crypto','--test','evidence_recovery_observation'],cwd=ROOT,capture_output=True,text=True,timeout=180)
    (OUT/'restored.txt').write_text(run.stdout+run.stderr+'\nexit='+str(run.returncode)+'\n')
    assert run.returncode==0,'restoration failed'
    print(str(len(CASES))+' compiled controls; restored suite passed.',flush=True)

if __name__=='__main__':main()
