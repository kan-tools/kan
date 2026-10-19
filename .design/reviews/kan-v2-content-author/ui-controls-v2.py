from pathlib import Path
import subprocess,hashlib
p=Path('web/library/app.js');original=p.read_text();out=Path('.local-state/ui-controls-v2');out.mkdir(exist_ok=True)
controls=[('rounded-sequence',"sequences:[...contentSelection]","sequences:[...contentSelection].map(Number)"),('reparsed-pin',"pin_wire:pinWire,sequences:","pin_wire:JSON.stringify(JSON.parse(pinWire)),sequences:"),('late-content',"if (current !== epoch) return null;","if (false) return null;"),('wrong-snapshot',"value.pin_wire!==pinWire||",""),('lock-retains-content',"pinWire = null; contentEnabled = false; clearContent();","pinWire = null; contentEnabled = false;")]
try:
 for name,old,new in controls:
  assert old in original,name
  p.write_text(original.replace(old,new))
  r=subprocess.run(['node','--test','tests/library_ui.test.cjs'],capture_output=True,text=True)
  log=r.stdout+r.stderr;(out/(name+'.txt')).write_text(log+'\nexit='+str(r.returncode)+'\n')
  assert r.returncode and ('AssertionError' in log or 'assertion' in log),name
  print('DEMONSTRATED '+name,flush=True);p.write_text(original)
finally:p.write_text(original)
r=subprocess.run(['node','--test','tests/library_ui.test.cjs'],capture_output=True,text=True);(out/'restored.txt').write_text(r.stdout+r.stderr+'\nexit='+str(r.returncode)+'\n');assert r.returncode==0
print('Restored UI tests pass; source sha256='+hashlib.sha256(p.read_bytes()).hexdigest())
