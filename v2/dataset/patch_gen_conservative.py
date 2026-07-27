#!/usr/bin/env python3
"""
Generate patches for top 20 CWEs using ASI:One mini (free model).
Conservative rate-limiting to avoid 429s.
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

ASI_API = "https://api.asi1.ai/v1/chat/completions"
BATCH_SIZE = 10
MAX_WORKERS = 25
DELAY_BETWEEN = 0.2  # seconds between batch submissions
ASI_MODEL = "asi1"

# Top 20 CWEs that need patches
TARGET_CWES = {
    "CWE-79", "CWE-22", "CWE-20", "CWE-200", "CWE-UNKNOWN",
    "CWE-502", "CWE-94", "CWE-400", "CWE-89", "CWE-284",
    "CWE-352", "CWE-787", "CWE-863", "CWE-918", "CWE-000",
    "CWE-862", "CWE-74", "CWE-287", "CWE-78", "CWE-416",
}

PATCH_PROMPT = """You are a security code reviewer. Fix ALL security vulnerabilities in the code below. Return ONLY a valid JSON object mapping each identifier to its fixed version.

Rules:
- Fix the vulnerability without changing functionality
- Keep same language and code style
- Return ONLY valid JSON, no markdown, no explanation

Format:
{{"vuln_abc123": "fixed code line 1\\nfixed code line 2"}}

{batches}"""


def get_api_key() -> Optional[str]:
    key = os.environ.get("ASI_ONE_API_KEY") or os.environ.get("ASI1_API_KEY")
    if key:
        return key
    for p in [Path.home() / ".rakshak" / ".env", Path(".env")]:
        if p.exists():
            for line in open(p):
                if "ASI_ONE_API_KEY" in line and "=" in line:
                    val = line.split("=", 1)[1].strip().strip("\"'")
                    if val:
                        return val
    return None


def code_hash(code: str) -> str:
    return "vuln_" + hashlib.md5(code.encode()).hexdigest()[:6]


def load_samples():
    samples = []
    for f in sorted(META_DIR.glob("*.jsonl")):
        for line in open(f):
            s = json.loads(line)
            cwe = (s.get("cwe") or "CWE-000")
            code = s.get("vulnerable_code", "")
            if s.get("is_vulnerable", True) and not s.get("patched_code") and len(code) > 20 and cwe in TARGET_CWES:
                s["_ch"] = code_hash(code)
                samples.append(s)
    return samples


def call_asi(messages: list) -> Optional[dict]:
    for attempt in range(5):
        try:
            r = requests.post(
                ASI_API,
                headers={"Authorization": f"Bearer {get_api_key()}", "Content-Type": "application/json"},
                json={"model": ASI_MODEL, "messages": messages, "temperature": 0.1, "max_tokens": 2048},
                timeout=120
            )
            if r.status_code == 200:
                return r.json()
            if r.status_code == 429:
                wait = min(30 * (attempt + 1), 120)
                print(f"   [429] retry in {wait}s...", flush=True)
                time.sleep(wait)
                continue
            return None
        except requests.Timeout:
            print(f"   [timeout] retry {attempt+1}/5", flush=True)
            time.sleep(5)
        except Exception as e:
            print(f"   [error] {e}", flush=True)
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


def process_batch(batch: list) -> list:
    entries = []
    for s in batch:
        lang = s.get("language", "text")
        code = s["vulnerable_code"][:2500]
        entries.append(f"[{s['_ch']}] ({lang}):\n{code}")

    prompt = PATCH_PROMPT.format(batches="\n\n---\n\n".join(entries))
    result = call_asi([{"role": "user", "content": prompt}])
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
        if patch and isinstance(patch, str) and len(patch) > 10 and patch != s["vulnerable_code"]:
            s["patched_code"] = patch
            results.append(s)
    return results


def main():
    api_key = get_api_key()
    if not api_key:
        print("ERROR: No API key found")
        sys.exit(1)

    print(f"Key: {api_key[:8]}...{api_key[-4:]}")
    print(f"Target CWEs: {len(TARGET_CWES)} ({', '.join(sorted(TARGET_CWES)[:5])}...)")
    print(f"Model: {ASI_MODEL}, Batch: {BATCH_SIZE}/call, Workers: {MAX_WORKERS}, Delay: {DELAY_BETWEEN}s")

    print("\n1. Loading samples...")
    all_samples = load_samples()
    print(f"   {len(all_samples):,} samples need patches (top 20 CWEs)")

    # Checkpoint
    checkpoint_file = OUT_DIR / "checkpoint_conservative.json"
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

    out_file = OUT_DIR / "patches_conservative.jsonl"
    batches = [remaining[i:i + BATCH_SIZE] for i in range(0, len(remaining), BATCH_SIZE)]
    print(f"   Batches: {len(batches):,}")

    print("\n2. Generating patches (conservative mode)...")
    start = time.time()
    total_ok = 0

    for batch_idx in range(0, len(batches), MAX_WORKERS):
        slice_end = min(batch_idx + MAX_WORKERS, len(batches))
        current_batches = batches[batch_idx:slice_end]
        results_batch = []

        with ThreadPoolExecutor(max_workers=len(current_batches)) as executor:
            fut_map = {executor.submit(process_batch, b): b for b in current_batches}
            for future in as_completed(fut_map):
                try:
                    results_batch.extend(future.result())
                except Exception:
                    pass

        # Flush
        to_save = []
        with open(out_file, "a") as f:
            for s in results_batch:
                rec = {
                    "id": s.get("id", ""),
                    "fingerprint": s.get("fingerprint", "") or s.get("_ch", ""),
                    "language": s.get("language", ""),
                    "cwe": s.get("cwe", ""),
                    "vulnerable_code": s["vulnerable_code"],
                    "patched_code": s["patched_code"],
                }
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
                to_save.append(rec["fingerprint"])
            done.update(to_save)
            with open(checkpoint_file, "w") as cf:
                json.dump({"done": list(done), "total_ok": len(done)}, cf)

        total_ok = len(done)
        processed = batch_idx + len(current_batches)

        if processed % 20 == 0:
            elapsed = time.time() - start
            rate = processed / elapsed if elapsed > 0 else 0
            eta = (len(batches) - processed) / rate if rate > 0 else 0
            print(f"   [{processed}/{len(batches)}] ok={total_ok} "
                  f"rate={rate:.2f} batch/s eta={eta:.0f}s", flush=True)

        # Delay between worker groups
        if batch_idx + MAX_WORKERS < len(batches):
            time.sleep(DELAY_BETWEEN)

    elapsed = time.time() - start
    print(f"\n3. Done in {elapsed:.0f}s")
    print(f"   Patched: {total_ok:,}")
    print(f"   Speed:   {total_ok/elapsed:.1f} samples/s")

    print(f"\n4. Stats:")
    patched = [json.loads(l) for l in open(out_file)]
    langs = Counter(s.get("language", "?") for s in patched)
    cwes = Counter(s.get("cwe", "CWE-000") for s in patched)
    print(f"   Records: {len(patched):,}")
    print(f"   Languages: {dict(langs.most_common(6))}")
    print(f"   CWEs: {len(cwes)} unique")
    print(f"\n5. Merge: python3 v2/dataset/merge_patches_conservative.py")

if __name__ == "__main__":
    main()
