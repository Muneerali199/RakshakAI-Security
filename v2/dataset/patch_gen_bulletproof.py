#!/usr/bin/env python3
"""Bulletproof patch generator — Mistral API, reliable, checkpointed."""
import json, os, sys, time, hashlib, re, traceback
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests

META_DIR = Path("v2/inputs/datasets/phase_b/meta")
OUT_DIR = Path("v2/inputs/datasets/phase_b/patches")
OUT_DIR.mkdir(parents=True, exist_ok=True)

BATCH = 10
WORKERS = 3
DELAY = 3.0
MISTRAL_KEY = "YOUR_MISTRAL_API_KEY_HERE"
NVIDIA_KEY = "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"

PROMPT = """Fix the security vulnerability in each code snippet. Return ONLY a valid JSON object.

Return format: {{"vuln_abc123": "fixed code here", "vuln_def456": "fixed code here"}}

Rules:
- Fix the vulnerability, don't change functionality
- Keep same language and code style
- Return ONLY valid JSON, no other text

Code to fix:
{batches}"""


def code_hash(code): return "vuln_" + hashlib.md5(code.encode()).hexdigest()[:6]


def load_samples():
    samples = []
    for f in sorted(META_DIR.glob("*.jsonl")):
        for line in open(f):
            s = json.loads(line)
            code = s.get("vulnerable_code", "")
            if s.get("is_vulnerable", True) and not s.get("patched_code") and len(code) > 20:
                s["_ch"] = code_hash(code)
                samples.append(s)
    return samples


def extract_json(text):
    text = text.strip()
    m = re.search(r"```(?:json)?\s*\n?(.*?)\n?```", text, re.DOTALL)
    if m: text = m.group(1).strip()
    brace = text.find("{")
    if brace >= 0:
        text = text[brace:]
        depth = 0
        for i, c in enumerate(text):
            if c == "{": depth += 1
            if c == "}": depth -= 1
            if depth == 0:
                try: return json.loads(text[:i+1])
                except: break
    try: return json.loads(text)
    except: return None


def call_api(url, key, model, messages, timeout=90):
    for attempt in range(3):
        try:
            r = requests.post(url, headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
                             json={"model": model, "messages": messages, "temperature": 0.1, "max_tokens": 2048},
                             timeout=timeout)
            if r.status_code == 200: return r.json()
            if r.status_code == 429:
                t = 10 * (attempt + 1)
                time.sleep(t); continue
            return None
        except Exception:
            if attempt < 2: time.sleep(5)
    return None


def process_batch(batch):
    entries = [f"[{s['_ch']}] ({s.get('language','text')}):\n{s['vulnerable_code'][:2500]}" for s in batch]
    prompt = PROMPT.format(batches="\n\n---\n\n".join(entries))
    messages = [{"role": "user", "content": prompt}]

    result = call_api("https://api.mistral.ai/v1/chat/completions", MISTRAL_KEY, "codestral-latest", messages)
    if not result:
        result = call_api("https://integrate.api.nvidia.com/v1/chat/completions", NVIDIA_KEY, "meta/llama-3.1-8b-instruct", messages)
    if not result: return []

    content = result.get("choices", [{}])[0].get("message", {}).get("content", "")
    if not content: return []

    parsed = extract_json(content)
    if not parsed: return []

    results = []
    for s in batch:
        h = s["_ch"]
        patch = parsed.get(h) or parsed.get(h.replace("vuln_", ""))
        if patch and isinstance(patch, str) and len(patch) > 10 and patch.strip() != s["vulnerable_code"].strip():
            s["patched_code"] = patch
            results.append(s)
    return results


def main():
    print("Loading samples needing patches...", flush=True)
    samples = load_samples()
    print(f"  {len(samples):,} need patches", flush=True)

    ckpt_file = OUT_DIR / "checkpoint_bulletproof.json"
    done = set()
    if ckpt_file.exists():
        try: done = set(json.loads(open(ckpt_file).read()).get("done", []))
        except: pass
        print(f"  Checkpoint: {len(done):,} done", flush=True)

    remaining = [s for s in samples if (s.get("fingerprint","") or s.get("id","")) not in done]
    print(f"  Remaining: {len(remaining):,}", flush=True)
    if not remaining: print("All done!"); return

    batches = [remaining[i:i+BATCH] for i in range(0, len(remaining), BATCH)]
    out_file = OUT_DIR / "patches_bulletproof.jsonl"
    start = time.time()
    total_ok = len(done)
    errors = 0

    for i in range(0, len(batches), WORKERS):
        chunk = batches[i:i+WORKERS]
        batch_results = []

        with ThreadPoolExecutor(max_workers=len(chunk)) as ex:
            futs = {ex.submit(process_batch, b): b for b in chunk}
            for f in as_completed(futs):
                try:
                    batch_results.extend(f.result())
                except Exception:
                    errors += 1

        if batch_results:
            with open(out_file, "a") as f:
                for s in batch_results:
                    rec = {"id": s.get("id",""), "fingerprint": s.get("fingerprint","") or s["_ch"],
                           "language": s.get("language",""), "cwe": s.get("cwe",""),
                           "vulnerable_code": s["vulnerable_code"], "patched_code": s["patched_code"]}
                    f.write(json.dumps(rec) + "\n")
                    done.add(rec["fingerprint"])
            with open(ckpt_file, "w") as cf:
                json.dump({"done": list(done), "errors": errors}, cf)

        total_ok = len(done)
        processed = i + len(chunk)
        if processed % 15 == 0:
            elapsed = time.time() - start
            rate = processed / elapsed if elapsed > 0 else 0
            eta = (len(batches) - processed) / rate if rate > 0 else 0
            print(f"  [{processed}/{len(batches)}] ok={total_ok} err={errors} "
                  f"rate={rate:.2f} b/s eta={eta:.0f}s", flush=True)

        time.sleep(DELAY)

    elapsed = time.time() - start
    print(f"\nDone in {elapsed:.0f}s. Patched: {total_ok:,}, Errors: {errors}", flush=True)
    print(f"Merge: python3 v2/dataset/merge_patches.py", flush=True)

if __name__ == "__main__":
    main()
