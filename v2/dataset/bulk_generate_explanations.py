#!/usr/bin/env python3
"""Generate security explanations using Mistral API (fast batch processing)."""
import json
import time
import sys
import urllib.request
import urllib.error
import traceback
import signal
from pathlib import Path

MISTRAL_KEY = "YOUR_MISTRAL_API_KEY_HERE"
TARGET = 30_000
SLEEP_BETWEEN = 0.3

# Track state for graceful exit
total_generated = 0
total_processed = 0
should_exit = False

def handle_signal(sig, frame):
    global should_exit
    print(f"\nSignal {sig} received, finishing current file...")
    should_exit = True

signal.signal(signal.SIGTERM, handle_signal)
signal.signal(signal.SIGINT, handle_signal)

def generate_explanation(sample: dict) -> str:
    code = sample.get("vulnerable_code", "")[:600]
    lang = sample.get("language", "unknown")
    cwe = sample.get("cwe") or "CWE-UNKNOWN"
    severity = sample.get("severity") or "medium"

    prompt = f"Explain {cwe} vulnerability in {lang} in 1-2 sentences:\n{code[:300]}\nAnswer:"

    for attempt in range(3):
        try:
            mdata = json.dumps({
                "model": "mistral-small-latest",
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": 100, "temperature": 0.1
            }).encode()
            req = urllib.request.Request(
                "https://api.mistral.ai/v1/chat/completions", data=mdata,
                headers={"Content-Type": "application/json", "Authorization": f"Bearer {MISTRAL_KEY}"}
            )
            with urllib.request.urlopen(req, timeout=30) as resp:
                text = json.loads(resp.read().decode()).get("choices", [{}])[0].get("message", {}).get("content", "")
                if text:
                    return text.split("\n")[0][:300]
        except urllib.error.HTTPError as e:
            if e.code == 429:
                time.sleep(10)
            elif attempt < 2:
                time.sleep(3)
        except Exception:
            if attempt < 2:
                time.sleep(3)

    return f"{cwe} vulnerability in {lang} code (severity: {severity})"

def main():
    global total_generated, total_processed, should_exit

    meta_dir = Path("v2/inputs/datasets/phase_b/meta")
    output_dir = Path("v2/inputs/datasets/phase_b/meta_with_explanations")
    output_dir.mkdir(exist_ok=True)

    print(f"Generating {TARGET:,} explanations using Mistral...", flush=True)
    print()

    for meta_file in sorted(meta_dir.glob("*.jsonl")):
        if should_exit:
            break
        print(f"Processing {meta_file.name}...", flush=True)

        with open(meta_file) as f:
            samples_in = [json.loads(line) for line in f if line.strip()]

        samples_out = []
        for i, sample in enumerate(samples_in):
            if should_exit:
                samples_out.extend(samples_in[i:])
                break

            total_processed += 1

            if not sample.get("is_vulnerable"):
                samples_out.append(sample)
                continue

            existing = sample.get("explanation", "")
            if len(existing) > 80 and any(t in existing.lower() for t in ["vulnerability", "exploit", "attack", "injection"]):
                samples_out.append(sample)
                continue

            if total_generated < TARGET:
                print(f"  [{total_generated}/{TARGET}] proc={total_processed}", flush=True)
                try:
                    new_exp = generate_explanation(sample)
                except Exception:
                    new_exp = f"{sample.get('cwe') or 'CWE-UNKNOWN'} vulnerability in {sample.get('language', 'unknown')} code"
                    traceback.print_exc()
                sample["explanation"] = new_exp
                sample["explanation_source"] = "mistral-small-latest"
                total_generated += 1
                time.sleep(SLEEP_BETWEEN)

            samples_out.append(sample)

            if should_exit or total_generated >= TARGET:
                samples_out.extend(samples_in[i+1:])
                break

        out_path = output_dir / meta_file.name
        with open(out_path, "w") as f:
            for s in samples_out:
                f.write(json.dumps(s) + "\n")
        print(f"  Wrote {len(samples_out):,} -> {out_path.name}", flush=True)

        if total_generated >= TARGET:
            print(f"\nReached {TARGET:,} explanations!", flush=True)
            break

    if not should_exit:
        import shutil
        backup = Path("v2/inputs/datasets/phase_b/meta_backup")
        if backup.exists():
            shutil.rmtree(backup)
        shutil.move(str(meta_dir), str(backup))
        shutil.move(str(output_dir), str(meta_dir))
        print(f"Done. Original backed up to {backup}", flush=True)
    else:
        print(f"\nGracefully stopped. Generated {total_generated}/{TARGET}", flush=True)

if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        pass
    except:
        traceback.print_exc()
