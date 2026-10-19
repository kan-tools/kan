from pathlib import Path
import subprocess,sys
out=Path('.local-state/provider-followup')
for name,args in [('clean-return',['clean','-p','kan']),('clippy-retry',['clippy','--features','v2-crypto','--all-targets','--','-D','warnings']),('fmt-final',['fmt','--all','--','--check'])]:
 r=subprocess.run(['sh','.local-state/cargo.sh']+args,capture_output=True,text=True);(out/(name+'.txt')).write_text(r.stdout+r.stderr+'\nexit='+str(r.returncode)+'\n');print(name,r.returncode,flush=True)
 if r.returncode:print((r.stdout+r.stderr)[-3000:]);sys.exit(r.returncode)
