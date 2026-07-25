#!/usr/bin/env python3
"""Generate reasoning traces + PoC outputs for best C/C++ records using NVIDIA NIM DeepSeek V4 Pro."""
import json
import os
import time
import random
import sys
import re
import threading
from pathlib import Path
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from openai import OpenAI

random.seed(42)

DATA_PATH = Path("v2/inputs/datasets/instruct_quality/train.jsonl")
OUT_PATH = Path("v2/inputs/datasets/reasoning_traces.jsonl")
PROGRESS_PATH = Path("v2/inputs/datasets/reasoning_progress.json")
TARGET = 15000
MAX_COST = 20.0
CONCURRENCY = 3
MAX_RETRIES = 10
RATE_RESET_AT = None
LOCK = threading.Lock()

CWE_PRIORITY = {
    "CWE-119": 8000,
    "CWE-787": 1000,
    "CWE-188": 500,
    "CWE-128": 500,
    "CWE-127": 500,
    "CWE-123": 500,
    "CWE-124": 500,
    "CWE-120": 500,
    "CWE-200": 500,
    "CWE-287": 300,
    "CWE-197": 300,
    "CWE-20": 300,
    "CWE-190": 300,
    "CWE-416": 300,
    "CWE-476": 300,
    "CWE-125": 300,
    "CWE-122": 200,
    "CWE-415": 200,
    "CWE-189": 200,
    "CWE-399": 200,
}

SYSTEM_PROMPT = "You are a security analyst specializing in C/C++ vulnerability analysis. Always output valid JSON."

USER_TEMPLATE = """Analyze the following {language} code for vulnerability {cwe} ({cwe_label}) - {task} task.

Produce a JSON object with exactly two keys:
- "reasoning": step-by-step analysis (300-600 words). Walk through entry points, data flow to the vulnerable sink, why the check is insufficient, the trigger condition, and impact.
- "poc": short PoC (C code, input, or sequence) that triggers the vulnerability. If not applicable set to "N/A".

Code:
```{language}
{code}
```"""

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

NVIDIA_KEY = "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"
BASE_URL = "https://integrate.api.nvidia.com/v1"
MODEL = "minimaxai/minimax-m3"
INPUT_COST_PER_M = 0.0
OUTPUT_COST_PER_M = 0.0

def extract_code(user_msg):
    m = re.search(r'```\w*\n(.*?)```', user_msg, re.DOTALL)
    return m.group(1).strip() if m else user_msg[:2000]

def select_candidates():
    buckets = defaultdict(list)

    with open(DATA_PATH) as f:
        for line in f:
            d = json.loads(line)
            meta = d["_meta"]
            lang = meta.get("language", "").lower()
            cwe = meta.get("cwe", "")

            if lang not in ("c", "cpp"):
                continue
            if not cwe or cwe == "CWE-UNKNOWN":
                continue

            msgs = d.get("messages", [])
            if len(msgs) < 2:
                continue
            user_code = extract_code(msgs[1].get("content", ""))
            if len(user_code) < 50:
                continue

            buckets[cwe].append((d, user_code))

    selected = []
    selected_ids = set()
    remaining = TARGET

    for cwe, take in sorted(CWE_PRIORITY.items(), key=lambda x: -x[1]):
        if remaining <= 0:
            break
        pool = buckets.get(cwe, [])
        random.shuffle(pool)
        n = min(take, len(pool), remaining)
        for rec in pool[:n]:
            selected.append(rec)
            selected_ids.add(rec[0]["_meta"].get("id", ""))
        remaining -= n

    if remaining > 0:
        others = []
        for cwe, pool in buckets.items():
            if cwe not in CWE_PRIORITY:
                others.extend(pool)
        random.shuffle(others)
        n = min(len(others), remaining)
        for rec in others[:n]:
            selected.append(rec)
            selected_ids.add(rec[0]["_meta"].get("id", ""))
        remaining -= n

    if remaining > 0:
        pool = buckets.get("CWE-119", [])
        extra = [x for x in pool if x[0]["_meta"].get("id", "") not in selected_ids]
        random.shuffle(extra)
        n = min(len(extra), remaining)
        for rec in extra[:n]:
            selected.append(rec)
            selected_ids.add(rec[0]["_meta"].get("id", ""))
        remaining -= n

    random.shuffle(selected)
    print(f"Selected {len(selected)} records across {len(CWE_PRIORITY)}+ CWE classes", flush=True)

    cwe_counts = Counter()
    lang_counts = Counter()
    task_counts = Counter()
    for d, _ in selected:
        meta = d["_meta"]
        cwe_counts[meta.get("cwe", "")] += 1
        lang_counts[meta.get("language", "")] += 1
        task_counts[meta.get("task", "")] += 1

    print(f"  CWEs: {dict(cwe_counts.most_common(10))}", flush=True)
    print(f"  Langs: {dict(lang_counts)}", flush=True)
    print(f"  Tasks: {dict(task_counts)}", flush=True)

    return selected

def load_progress():
    if PROGRESS_PATH.exists():
        with open(PROGRESS_PATH) as f:
            return json.load(f)
    return {"completed": 0, "cost": 0.0, "ids": []}

def save_progress(progress):
    with open(PROGRESS_PATH, "w") as f:
        json.dump(progress, f)

def call_nvidia(record, user_code):
    meta = record["_meta"]
    cwe = meta.get("cwe", "CWE-119")
    cwe_label = CWE_LABELS.get(cwe, "Security vulnerability")
    lang = meta.get("language", "c")
    task = meta.get("task", "report")

    user_prompt = USER_TEMPLATE.format(
        language=lang, cwe=cwe, cwe_label=cwe_label,
        code=user_code[:4000], task=task,
    )

    client = OpenAI(base_url=BASE_URL, api_key=NVIDIA_KEY, timeout=300)

    # Rate limit: ~1.5s jitter between calls to stay under 40 RPM
    time.sleep(random.uniform(0.5, 2.0))

    for attempt in range(MAX_RETRIES):
        try:
            resp = client.chat.completions.create(
                model=MODEL,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": user_prompt},
                ],
                max_tokens=2000,
                temperature=0.3,
            )
            break
        except Exception as e:
            if "429" in str(e) and attempt < MAX_RETRIES - 1:
                wait = 5 * (attempt + 1) + random.uniform(0, 2)
                print(f"  RATE_LIMIT on {meta.get('id','?')[:20]}, retry {attempt+1}/{MAX_RETRIES} in {wait:.1f}s", flush=True)
                time.sleep(wait)
            else:
                raise

    content = resp.choices[0].message.content or ""

    cleaned = re.sub(r'^```(?:json)?\s*|\s*```$', '', content.strip(), flags=re.DOTALL)
    json_match = re.search(r'\{.*\}', cleaned, re.DOTALL)
    if json_match:
        try:
            result = json.loads(json_match.group())
        except json.JSONDecodeError:
            frag = json_match.group()
            r_match = re.search(r'"reasoning"\s*:\s*"((?:[^"\\]|\\.)*)', frag)
            reasoning = r_match.group(1) if r_match else ""
            result = {"reasoning": reasoning[:2000] if reasoning else content[:1000], "poc": "N/A"}
    else:
        r_match = re.search(r'"reasoning"\s*:\s*"((?:[^"\\]|\\.)*)', content)
        reasoning = r_match.group(1) if r_match else content[:1000]
        result = {"reasoning": reasoning, "poc": "N/A"}

    in_tokens = resp.usage.prompt_tokens
    out_tokens = resp.usage.completion_tokens
    cost = (in_tokens / 1_000_000 * INPUT_COST_PER_M) + (out_tokens / 1_000_000 * OUTPUT_COST_PER_M)

    return {
        "id": meta.get("id", "unknown"),
        "cwe": cwe,
        "language": lang,
        "task": task,
        "reasoning": result.get("reasoning", ""),
        "poc": result.get("poc", "N/A"),
        "tokens_in": in_tokens,
        "tokens_out": out_tokens,
        "cost": 0.0,
    }

def process_one(rec, code, progress):
    try:
        with LOCK:
            if progress["completed"] >= TARGET:
                return False
        result = call_nvidia(rec, code)
        with LOCK:
            if progress["completed"] >= TARGET:
                return False
            with open(OUT_PATH, "a") as f:
                f.write(json.dumps(result, ensure_ascii=False) + "\n")
            progress["completed"] += 1
            progress["ids"].append(result["id"])
            save_progress(progress)
            done = progress["completed"]
        rem = TARGET - done
        eta_h = rem * 25 / 3600 / CONCURRENCY
        print(f"  [{done}/{TARGET}] ID={result['id'][:20]} CWE={result['cwe']} ({rem} rem, ~{eta_h:.1f}h)", flush=True)
        return True
    except Exception as e:
        print(f"  ERROR on {rec['_meta'].get('id','?')[:20]}: {e}", flush=True)
        time.sleep(5)
        return False

def process_records(todo, progress):
    total = len(todo)
    with ThreadPoolExecutor(max_workers=CONCURRENCY) as executor:
        futures = []
        for rec, code in todo:
            if progress["completed"] >= TARGET:
                break
            futures.append(executor.submit(process_one, rec, code, progress))

        for f in as_completed(futures):
            if progress["completed"] >= TARGET:
                break
            try:
                f.result()
            except Exception as e:
                print(f"  UNHANDLED ERROR: {e}", flush=True)

def main():
    progress = load_progress()
    done_ids = set(progress["ids"])

    print("Loading candidates...", flush=True)
    candidates = select_candidates()

    todo = [(d, code) for d, code in candidates if d["_meta"].get("id", "") not in done_ids]
    print(f"Already done: {len(done_ids)}, To process: {len(todo)}", flush=True)

    process_records(todo, progress)

    print(f"\nDone! Completed: {progress['completed']}", flush=True)
    print(f"Output: {OUT_PATH}", flush=True)

if __name__ == "__main__":
    main()
