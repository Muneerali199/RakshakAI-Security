import json
from collections import defaultdict

with open('v2/inputs/datasets/cwe_map.json', 'r') as f:
    cwe_map = json.load(f)

silver_samples = []

with open('v2/inputs/datasets/eval/benchmark_300.jsonl', 'r') as f:
    for line in f:
        rec = json.loads(line)
        meta = rec.get('_meta', {})
        cwe = meta.get('cwe')
        
        # Criteria: CWE exists in our map, and it's a supported language
        if cwe in cwe_map and meta.get('language') in ['c', 'cpp', 'python', 'java']:
            rec['semgrep_rules'] = cwe_map[cwe]
            silver_samples.append(rec)

with open('v2/inputs/datasets/silver_samples.jsonl', 'w') as f:
    for s in silver_samples:
        f.write(json.dumps(s) + '\n')

print(f"Classified {len(silver_samples)} silver-tier samples.")