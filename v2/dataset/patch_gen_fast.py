#!/usr/bin/env python3
"""
Generate patches using Mistral codestral (50 RPM, free) + NVIDIA fallback (30 RPM).
Fast mode — processes ALL samples needing patches, not just top 20 CWEs.

Usage: python3 v2/dataset/patch_gen_fast.py
"""
import json, os, sys, time, hashlib, re
from pathlib import Path
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional
import requests

META_DIR = Path("v2/inputs/datasets/phase_b/meta")
OUT_DIR = Path("v2/inputs/datasets/phase_b/patches")
OUT_DIR.mkdir(parents=True, exist_ok=True)

PROVIDERS = {
    "mistral": {
        "url": "https://api.mistral.ai/v1/chat/completions",
        "key": "YOUR_MISTRAL_API_KEY_HERE",
        "model": "codestral-latest",
        "rpm": 50,
    },
    "nvidia": {
        "url": "https://integrate.api.nvidia.com/v1/chat/completions",
        "key": "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",
        "model": "meta/llama-3.1-8b-instruct",
        "rpm": 30,
    },
}

BATCH_SIZE = 10
# Calculate workers from RPM: leave 20% headroom
MISTRAL_WORKERS = max(1, int(PROVIDERS["mistral"]["rpm"] * 0.8 / 6))  # 6 batches/min
NVIDIA_WORKERS = max(1, int(PROVIDERS["nvidia"]["rpm"] * 0.8 / 6))
print(f"Mistral workers: {MISTRAL_WORKERS}, NVIDIA workers: {NVIDIA_WORKERS}")

PATCH_PROMPT = """You are a security code reviewer. Fix ALL security vulnerabilities in the code below. Return ONLY a valid JSON object where each identifier maps to its fixed version.

Rules:
- Fix the vulnerability without changing functionality
- Keep same language and code style
- Return ONLY valid JSON, no markdown fences, no explanation

Format:
{{"vuln_abc123": "fixed code line 1\\nfixed code line 2"}}

Code to fix:
{batches}"""


def call_api(provider: str, messages: list, timeout=120) -> Optional[dict]:
    cfg = PROVIDERS[provider]
    for attempt in range(3):
        try:
            r = requests.post(
                cfg["url"],
                headers={"Authorization": f"Bearer {cfg['key']}", "Content-Type": "application/json"},
                json={"model": cfg["model"], "messages": messages, "temperature": 0.1, "max_tokens": 2048},
                timeout=timeout
            )
            if r.status_code == 200:
                return r.json()
            if r.status_code == 429:
                wait = 10 * (attempt + 1)
                time.sleep(wait)
                continue
            return None
        except Exception:
            time.sleep(3)
    return None


def extract_json(text: str) -> Optional[dict]:
    text = text.strip()
    m = re.search(r"```(?:json)?\s*\n?(.*?)\n?```", text, re.DOTALL)
    if m:
        text = m.group(1).strip()
    brace_start = text.find("{")
    if brace_start >= 0:
        text = text[brace_start:]
        depth = 0
        for i, c in enumerate(text):
            if c == "{": depth += 1
            if c == "}": depth -= 1
            if depth == 0:
                try:
                    return json.loads(text[:i+1])
                except json.JSONDecodeError:
                    break
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


def code_hash(code: str) -> str:
    return "vuln_" + hashlib.md5(code.encode()).hexdigest()[:6]


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


def process_batch(batch: list) -> list:
    entries = []
    for s in batch:
        lang = s.get("language", "text")
        code = s["vulnerable_code"][:2500]
        entries.append(f"[{s['_ch']}] ({lang}):\n{code}")

    prompt = PATCH_PROMPT.format(batches="\n\n---\n\n".join(entries))
    messages = [{"role": "user", "content": prompt}]

    # Try Mistral first, fall back to NVIDIA
    result = call_api("mistral", messages)
    if not result:
        result = call_api("nvidia", messages)
    if not result:
        return []

    content = result.get("choices", [{}])[0].get("message", {}).get("content", "")
    if not content:
        return []

    parsed = extract_json(content)
    if not parsed:
        return []

    results = []
    for s in batch:
        h = s["_ch"]
        patch = parsed.get(h) or parsed.get(h.replace("vuln_", ""))
        if patch and isinstance(patch, str) and len(patch) > 10 and patch.strip() != s["vulnerable_code"].strip():
            s["patched_code"] = patch
            results.append(s)
    return results


def main():
    print("=" * 60)
    print("Fast Patch Generator — Mistral + NVIDIA")
    print("=" * 60)

    print("\n1. Loading samples needing patches...")
    all_samples = load_samples()
    print(f"   {len(all_samples):,} need patches")

    # Checkpoint
    checkpoint_file = OUT_DIR / "checkpoint_fast.json"
    done = set()
    if checkpoint_file.exists():
        done = set(json.loads(checkpoint_file.read_text()).get("done", []))
        print(f"   Checkpoint: {len(done):,} already done")

    remaining = [s for s in all_samples
                 if (s.get("fingerprint", "") or s.get("id", "")) not in done]
    print(f"   Remaining: {len(remaining):,}")

    if not remaining:
        print("   All done!")
        return

    batches = [remaining[i:i + BATCH_SIZE] for i in range(0, len(remaining), BATCH_SIZE)]
    print(f"   Batches: {len(batches):,}")

    # Use Mistral's RPM as max parallelism
    max_workers = MISTRAL_WORKERS
    worker_delay = 60.0 / PROVIDERS["mistral"]["rpm"]  # seconds between submissions

    out_file = OUT_DIR / "patches_fast.jsonl"
    print(f"\n2. Generating patches (workers={max_workers}, delay={worker_delay:.1f}s)...")
    start = time.time()
    total_ok = 0

    for batch_start in range(0, len(batches), max_workers):
        slice_end = min(batch_start + max_workers, len(batches))
        current = batches[batch_start:slice_end]
        results = []

        with ThreadPoolExecutor(max_workers=len(current)) as executor:
            fut_map = {executor.submit(process_batch, b): b for b in current}
            for future in as_completed(fut_map):
                try:
                    results.extend(future.result())
                except Exception:
                    pass

        # Flush to file
        with open(out_file, "a") as f:
            for s in results:
                rec = {
                    "id": s.get("id", ""),
                    "fingerprint": s.get("fingerprint", "") or s.get("_ch", ""),
                    "language": s.get("language", ""),
                    "cwe": s.get("cwe", ""),
                    "vulnerable_code": s["vulnerable_code"],
                    "patched_code": s["patched_code"],
                }
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
                done.add(rec["fingerprint"])

        total_ok = len(done)
        with open(checkpoint_file, "w") as cf:
            json.dump({"done": list(done), "total_ok": total_ok}, cf)

        processed = batch_start + len(current)
        if processed % 20 == 0:
            elapsed = time.time() - start
            rate = processed / elapsed if elapsed > 0 else 0
            eta = (len(batches) - processed) / rate if rate > 0 else 0
            print(f"   [{processed}/{len(batches)}] ok={total_ok} "
                  f"rate={rate:.1f} batch/s eta={eta:.0f}s", flush=True)

        # Rate limit delay
        if batch_start + max_workers < len(batches):
            time.sleep(worker_delay)

    elapsed = time.time() - start
    print(f"\n3. Done in {elapsed:.0f}s")
    print(f"   Patched: {total_ok:,}")
    print(f"   Speed:   {total_ok/elapsed:.1f} samples/s")

    print("\n4. Stats:")
    patched = [json.loads(l) for l in open(out_file)]
    if patched:
        langs = Counter(s.get("language", "?") for s in patched)
        cwes = Counter(s.get("cwe", "CWE-000") for s in patched)
        print(f"   Records: {len(patched):,}")
        print(f"   Languages: {dict(langs.most_common(6))}")
        print(f"   CWEs: {len(cwes)} unique ({len(cwes)} new patches)")
    print(f"\n5. Merge: python3 v2/dataset/merge_patches.py")
    print(f"   Then:  python3 v2/dataset/to_instruct.py")
    print(f"   Then:  python3 v2/dataset/rating_current.py")

if __name__ == "__main__":
    main()
