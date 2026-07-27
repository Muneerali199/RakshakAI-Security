import os
import json
import yaml
from collections import defaultdict

cwe_to_rids = defaultdict(list)
rid_to_path = {} 
rules_dir = "v2/inputs/datasets/rules/semgrep-rules"

for root, _, files in os.walk(rules_dir):
    for file in files:
        if file.endswith((".yaml", ".yml")):
            path = os.path.join(root, file)
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    data = yaml.safe_load(f)
                    if data and 'rules' in data:
                        for rule in data['rules']:
                            rid = rule.get('id')
                            if rid:
                                rid_to_path[rid] = path
                                meta = rule.get('metadata', {})
                                cwes = meta.get('cwe', [])
                                if isinstance(cwes, str): cwes = [cwes]
                                for cwe_str in cwes:
                                    cwe_id = cwe_str.split(':')[0].strip()
                                    if cwe_id not in cwe_to_rids[cwe_id]:
                                        cwe_to_rids[cwe_id].append(rid)
            except Exception: pass

with open('v2/inputs/datasets/cwe_map.json', 'w') as f:
    json.dump({"cwe_to_rids": cwe_to_rids, "rid_to_path": rid_to_path}, f, indent=2)

print(f"CWE map generated.")