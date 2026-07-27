import json
from harness import _run_semgrep

with open('v2/inputs/datasets/silver_samples.jsonl', 'r') as f:
    samples = [json.loads(line) for line in f]

scanned_samples = []

print(f"Scanning {len(samples)} silver-tier samples for baselines...")
for s in samples:
    # The benchmark format is messages[1] is the user prompt containing code
    code = s['messages'][1]['content']
    findings = _run_semgrep(code, s['semgrep_rules'])
    
    # Store baseline
    s['baseline_broad_findings'] = len(findings)
    scanned_samples.append(s)

with open('v2/inputs/datasets/silver_samples_scanned.jsonl', 'w') as f:
    for s in scanned_samples:
        f.write(json.dumps(s) + '\n')

print("Scan complete. Baselines saved to silver_samples_scanned.jsonl.")