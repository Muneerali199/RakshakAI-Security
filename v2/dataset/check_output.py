#!/usr/bin/env python3
"""Check generated reasoning traces quality."""
import json

with open('v2/inputs/datasets/reasoning_traces.jsonl') as f:
    for i, line in enumerate(f):
        r = json.loads(line)
        rid = r.get('id', '?')[:15]
        cwe = r.get('cwe', '?')
        ti = r.get('tokens_in', 0)
        to = r.get('tokens_out', 0)
        cost = r.get('cost', 0)
        print(f'Record {i+1}: id={rid} CWE={cwe} tokens={ti}+{to} cost=${cost}')
        print(f'  reasoning: {r.get("reasoning","")[:200]}')
        print(f'  poc: {r.get("poc","")[:150]}')
        print()
        if i >= 2:
            break
