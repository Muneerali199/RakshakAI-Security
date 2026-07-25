#!/usr/bin/env python3
"""PoC Quality Evaluation for generated reasoning traces.

Evaluates PoC outputs on 6 dimensions (Relevance, Exploitability, Completeness,
Precision, Safety, Correctness) using DeepSeek-V4-Pro via NVIDIA NIM.

Usage:
  python v2/dataset/evaluate_poc.py --traces v2/inputs/datasets/reasoning_traces.jsonl \\
      --data v2/inputs/datasets/instruct_quality/train.jsonl \\
      --output v2/inputs/datasets/poc_eval_results.jsonl \\
      --max 100
"""
import json
import os
import re
import sys
import time
import random
import threading
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import Counter
from openai import OpenAI

random.seed(42)

NVIDIA_KEY = "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"
BASE_URL = "https://integrate.api.nvidia.com/v1"
MODEL = "deepseek-ai/deepseek-v4-pro"
CONCURRENCY = 5
MAX_RETRIES = 3
LOCK = threading.Lock()

POC_EVAL_SYSTEM = "You are a security researcher evaluating proof-of-concept exploit quality. Score each dimension as 1-5."

POC_EVAL_TEMPLATE = """Evaluate the following PoC for a {cwe} ({cwe_label}) vulnerability in {language} code.

The PoC was generated to trigger this vulnerability shown in the vulnerable code.

[Vulnerable Code]
```{language}
{vuln_code}
```

[Generated PoC]
```{language}
{poc}
```

Score the PoC on each dimension from 1 (worst) to 5 (best):

1. **Relevance** — Does the PoC directly target the CWE/vulnerability described?
2. **Exploitability** — How likely is the PoC to actually trigger the vulnerability?
3. **Completeness** — Is the PoC self-contained (setup, trigger, verification)?
4. **Precision** — Does the PoC exploit the exact root cause without unnecessary steps?
5. **Safety** — Is the PoC safe (no destructive side effects beyond the target)?
6. **Correctness** — Is the PoC technically correct (valid syntax, correct API usage)?

Return your evaluation in this exact format:

<analysis>
Brief analysis of the PoC quality.
</analysis>
Relevance: X/5
Exploitability: X/5
Completeness: X/5
Precision: X/5
Safety: X/5
Correctness: X/5
<total_score>XX</total_score>"""

CWE_LABELS = {
    "CWE-119": "Buffer overflow",
    "CWE-787": "Out-of-bounds write",
    "CWE-188": "Reliance on untrusted input",
    "CWE-128": "Wrap-around error",
    "CWE-127": "Buffer under-read",
    "CWE-123": "Write-what-where condition",
    "CWE-124": "Buffer underwrite",
    "CWE-120": "Buffer copy without checking size",
    "CWE-200": "Information disclosure",
    "CWE-287": "Improper authentication",
    "CWE-197": "Numeric truncation error",
    "CWE-20": "Improper input validation",
    "CWE-190": "Integer overflow",
    "CWE-416": "Use-after-free",
    "CWE-476": "Null pointer dereference",
    "CWE-125": "Out-of-bounds read",
    "CWE-122": "Heap-based buffer overflow",
    "CWE-415": "Double free",
    "CWE-189": "Numeric error",
    "CWE-399": "Resource management errors",
}

def load_index(data_path):
    """Build ID -> record lookup from instruct_quality."""
    index = {}
    with open(data_path) as f:
        for line in f:
            d = json.loads(line)
            meta = d.get("_meta", {})
            rid = meta.get("id", "")
            if rid:
                code = ""
                msgs = d.get("messages", [])
                if len(msgs) >= 2:
                    m = re.search(r'```\w*\n(.*?)```', msgs[1].get("content", ""), re.DOTALL)
                    if m:
                        code = m.group(1).strip()
                index[rid] = {
                    "code": code,
                    "language": meta.get("language", "c"),
                    "cwe": meta.get("cwe", ""),
                }
    return index

def load_traces(traces_path):
    with open(traces_path) as f:
        return [json.loads(line) for line in f]

def parse_eval_scores(content):
    scores = {}
    for dim in ["Relevance", "Exploitability", "Completeness", "Precision", "Safety", "Correctness"]:
        m = re.search(rf'{dim}:\s*(\d+)/5', content)
        if m:
            scores[dim] = int(m.group(1))
    m = re.search(r'<total_score>\s*(\d+)\s*</total_score>', content)
    total = int(m.group(1)) if m else sum(scores.values())
    analysis = ""
    am = re.search(r'<analysis>(.*?)</analysis>', content, re.DOTALL)
    if am:
        analysis = am.group(1).strip()
    return scores, total, analysis

def call_nvidia_eval(client, prompt):
    for attempt in range(MAX_RETRIES):
        try:
            resp = client.chat.completions.create(
                model=MODEL,
                messages=[
                    {"role": "system", "content": POC_EVAL_SYSTEM},
                    {"role": "user", "content": prompt},
                ],
                max_tokens=1000,
                temperature=0.1,
            )
            return resp.choices[0].message.content or ""
        except Exception as e:
            if "429" in str(e) and attempt < MAX_RETRIES - 1:
                wait = 2 ** attempt + random.uniform(0, 1)
                print(f"  RATE_LIMIT, retry {attempt+1}/{MAX_RETRIES} in {wait:.1f}s", flush=True)
                time.sleep(wait)
            else:
                raise

def evaluate_one(trace, lookup):
    rid = trace.get("id", "")
    poc = trace.get("poc", "N/A")
    if poc in ("N/A", "", None):
        return None
    if rid not in lookup:
        return None
    
    info = lookup[rid]
    cwe = trace.get("cwe", info.get("cwe", "CWE-119"))
    cwe_label = CWE_LABELS.get(cwe, "Security vulnerability")
    lang = trace.get("language", info.get("language", "c"))
    vuln_code = info.get("code", "")
    
    if len(vuln_code) < 20:
        return None
    
    prompt = POC_EVAL_TEMPLATE.format(
        cwe=cwe, cwe_label=cwe_label, language=lang,
        vuln_code=vuln_code[:4000], poc=poc[:3000],
    )
    
    client = OpenAI(base_url=BASE_URL, api_key=NVIDIA_KEY, timeout=120)
    content = call_nvidia_eval(client, prompt)
    if not content:
        return None
    
    scores, total, analysis = parse_eval_scores(content)
    
    return {
        "id": rid,
        "cwe": cwe,
        "scores": scores,
        "total_score": total,
        "analysis": analysis,
        "poc_length": len(poc),
    }

def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--traces", default="v2/inputs/datasets/reasoning_traces.jsonl")
    parser.add_argument("--data", default="v2/inputs/datasets/instruct_quality/train.jsonl")
    parser.add_argument("--output", default="v2/inputs/datasets/poc_eval_results.jsonl")
    parser.add_argument("--max", type=int, default=None)
    args = parser.parse_args()
    
    print("Loading index...", flush=True)
    lookup = load_index(args.data)
    print(f"Indexed {len(lookup)} records", flush=True)
    
    traces = load_traces(args.traces)
    if args.max:
        traces = traces[:args.max]
    print(f"Loaded {len(traces)} traces", flush=True)
    
    # Filter to only those with PoCs and valid lookups
    todo = [t for t in traces if t.get("poc", "N/A") not in ("N/A", "", None) and t.get("id") in lookup]
    print(f"To evaluate: {len(todo)} (have valid PoC + lookup)", flush=True)
    
    # Skip already-evaluated
    done_ids = set()
    if os.path.exists(args.output):
        with open(args.output) as f:
            for line in f:
                d = json.loads(line)
                done_ids.add(d.get("id", ""))
    todo = [t for t in todo if t["id"] not in done_ids]
    print(f"Remaining after resume: {len(todo)}", flush=True)
    
    stats = Counter()
    with ThreadPoolExecutor(max_workers=CONCURRENCY) as executor:
        futures = {executor.submit(evaluate_one, t, lookup): t for t in todo}
        for f in as_completed(futures):
            try:
                result = f.result()
                if result:
                    with LOCK:
                        with open(args.output, "a") as out:
                            out.write(json.dumps(result, ensure_ascii=False) + "\n")
                    score = result.get("total_score", 0)
                    stats[f"score_{score//6 if score else 0}"] += 1
                    avg = sum([s.get("total_score", 0) for s in [result]])
                    print(f"  ID={result['id'][:12]} CWE={result['cwe']} total={result['total_score']}/30", flush=True)
            except Exception as e:
                print(f"  ERROR: {e}", flush=True)
    
    print(f"\nDone! Evaluated {sum(stats.values())} PoCs", flush=True)
    print(f"Score distribution: {dict(stats)}", flush=True)

if __name__ == "__main__":
    main()
