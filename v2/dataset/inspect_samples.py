"""Inspect 5 ambiguous benchmark records to judge if model or benchmark is correct."""
import json, re
from collections import Counter

with open('v2/inputs/datasets/eval/benchmark_300.jsonl') as f:
    records = [json.loads(line) for line in f if line.strip()]

by_cwe = {}
for r in records:
    by_cwe.setdefault(r['_meta']['cwe'], []).append(r)

for cwe_label in ["CWE-189", "CWE-59", "CWE-399", "CWE-79", "CWE-125"]:
    rec = by_cwe[cwe_label][0]
    msgs = rec['messages']
    user_content = ''
    for m in msgs:
        if m['role'] == 'user':
            user_content = m['content']
    
    # Extract code blocks
    code_blocks = re.findall(r'```(?:\w+)?\n(.*?)```', user_content, re.DOTALL)
    code = code_blocks[0] if code_blocks else user_content
    
    # Skip license headers - get the last 400 chars of the code
    code_body = code[-600:] if len(code) > 600 else code

    meta = rec['_meta']
    print('=' * 80)
    print(f'BENCHMARK: {cwe_label}')
    print(f'Source: {meta.get("source", "?")}')
    print(f'Language: {meta.get("language", "?")}')
    print(f'Severity: {meta.get("severity", "?")}')
    print()
    print('CODE BODY (last 600 chars):')
    print(code_body)
    print()
    print('EXPECTED ASSISTANT OUTPUT (msg[2]):')
    if len(msgs) > 2 and msgs[2]['role'] == 'assistant':
        print(msgs[2]['content'][:300])
    print()
    print('-' * 80)
    print()
