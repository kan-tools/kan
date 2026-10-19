import json, subprocess, sys
old = json.loads(subprocess.check_output(["git","show","77eaac7:.design/fixtures/copy-plan-v1.json"]))
new = json.load(open(".design/fixtures/copy-plan-v1.json"))
print("positives equal:", old["positive"] == new["positive"], len(new["positive"]))
on = {v["name"]: v["hex"] for v in old["negative"]}
nn = {v["name"]: v for v in new["negative"]}
print("old negatives", len(on), "new", len(nn))
print("old hex unchanged:", all(nn[k]["hex"] == h for k, h in on.items()))
print("added:", sorted(set(nn) - set(on)))
from collections import Counter
print(Counter((v["expectedClass"]) for v in new["negative"]))
for v in new["negative"]: print(f'{v["name"]:28} {v["expectedClass"]:9} {v["expectedReason"]}')
