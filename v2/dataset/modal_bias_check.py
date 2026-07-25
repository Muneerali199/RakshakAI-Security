"""Evaluate all non-CWE-119 benchmark records to check for CWE-119 bias."""
import json, re, time
import modal
from openai import OpenAI
from collections import Counter

NVIDIA_KEY = "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"

app = modal.App("rakshak-bias-check")

image = (
    modal.Image.debian_slim(python_version="3.11")
    .apt_install("git")
    .pip_install("torch", "accelerate", "peft", "huggingface_hub", "openai", "bitsandbytes")
    .pip_install("git+https://github.com/huggingface/transformers.git")
)

def extract_cwe(text):
    if not text:
        return ""
    depth = start = 0
    for i, ch in enumerate(text):
        if ch == '{':
            if depth == 0:
                start = i
            depth += 1
        elif ch == '}':
            depth -= 1
            if depth == 0 and start >= 0:
                try:
                    obj = json.loads(text[start:i+1])
                    val = obj.get("cwe") or obj.get("CWE") or ""
                    if val:
                        return val.strip().upper()
                except json.JSONDecodeError:
                    pass
                start = -1
    m = re.search(r'CWE[- ](\d+)', text, re.IGNORECASE)
    if m:
        return f"CWE-{m.group(1)}"
    m = re.search(r'cwe[:\s]*(\d+)', text, re.IGNORECASE)
    if m:
        return f"CWE-{m.group(1)}"
    return ""

@app.function(image=image, gpu="T4", timeout=7200)
def eval_non119(records):
    from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
    from peft import PeftModel
    import torch, sys

    print("Loading model...", flush=True)
    t0 = time.time()
    bnb = BitsAndBytesConfig(load_in_4bit=True)
    base = AutoModelForCausalLM.from_pretrained(
        "Qwen/Qwen3.5-9B", quantization_config=bnb, device_map="auto",
    )
    model = PeftModel.from_pretrained(base, "Muneerali199/rakshak-cwe-v2")
    tokenizer = AutoTokenizer.from_pretrained("Qwen/Qwen3.5-9B")
    print(f"Loaded in {time.time()-t0:.1f}s", flush=True)

    nim = OpenAI(base_url="https://integrate.api.nvidia.com/v1", api_key=NVIDIA_KEY)

    def query_nim(system, user, max_tokens=4096, timeout=180):
        for attempt in range(3):
            try:
                r = nim.chat.completions.create(
                    model="deepseek-ai/deepseek-v4-pro",
                    messages=[{"role": "system", "content": system}, {"role": "user", "content": user}],
                    temperature=0.1, max_tokens=max_tokens, timeout=timeout,
                )
                return r.choices[0].message.content
            except Exception as e:
                if attempt < 2:
                    time.sleep(5)
                else:
                    return f'[ERROR: {e}]'

    results = []
    for i, rec in enumerate(records):
        msgs = rec["messages"]
        meta = rec.get("_meta", {})
        expected = meta.get("cwe", "N/A").strip().upper()
        sys_p, user_m = msgs[0]["content"], msgs[1]["content"]

        # RakshakAI
        t1 = time.time()
        prompt = tokenizer.apply_chat_template(msgs[:-1], tokenize=False, add_generation_prompt=True)
        inp = tokenizer(prompt, return_tensors="pt").to(model.device)
        with torch.no_grad():
            out = model.generate(**inp, max_new_tokens=512, do_sample=False, pad_token_id=tokenizer.eos_token_id)
        r_raw = tokenizer.decode(out[0][inp.input_ids.shape[1]:], skip_special_tokens=True).strip()
        rt = time.time() - t1

        r_cwe = extract_cwe(r_raw)
        retried = False
        if r_cwe == "":
            retried = True
            strict_usr = user_m + "\n\n(What is the CWE classification? Respond with just the CWE ID.)"
            strict_msgs = [{"role": "system", "content": sys_p}, {"role": "user", "content": strict_usr}]
            strict_prompt = tokenizer.apply_chat_template(strict_msgs, tokenize=False, add_generation_prompt=True)
            inp2 = tokenizer(strict_prompt, return_tensors="pt").to(model.device)
            with torch.no_grad():
                out2 = model.generate(**inp2, max_new_tokens=64, do_sample=False, pad_token_id=tokenizer.eos_token_id)
            r_raw2 = tokenizer.decode(out2[0][inp2.input_ids.shape[1]:], skip_special_tokens=True).strip()
            r_cwe = extract_cwe(r_raw2)
            r_raw += "\n---RETRY---\n" + r_raw2

        # DeepSeek
        t2 = time.time()
        d_raw = query_nim(sys_p, user_m, max_tokens=4096, timeout=180)
        dt = time.time() - t2
        d_cwe = extract_cwe(d_raw)

        results.append({
            "cwe": expected,
            "rakshak": r_cwe if r_cwe else "NONE",
            "rakshak_raw": r_raw[:400],
            "rakshak_time": round(rt, 1),
            "rakshak_retried": retried,
            "deepseek": d_cwe if d_cwe else "NONE",
            "deepseek_raw": d_raw[:400],
            "deepseek_time": round(dt, 1),
        })

        sys.stdout.write(f"[{i+1}/{len(records)}] {expected:14s} → R: {results[-1]['rakshak']:14s} D: {results[-1]['deepseek']:14s} ({rt:.0f}s/{dt:.0f}s)\n")
        sys.stdout.flush()

    return results

@app.local_entrypoint()
def main():
    BM = "/Users/macbook/Desktop/RakshakAI/v2/inputs/datasets/eval/benchmark_300.jsonl"
    with open(BM) as f:
        all_records = [json.loads(line) for line in f if line.strip()]

    cwe_counts = Counter(r['_meta']['cwe'] for r in all_records)
    by_cwe = {}
    for r in all_records:
        by_cwe.setdefault(r['_meta']['cwe'], []).append(r)

    non119 = sorted([c for c in cwe_counts if c != "CWE-119"], key=lambda c: -cwe_counts[c])
    records = [by_cwe[c][0] for c in non119]

    print(f"Benchmark: {len(all_records)} records, {len(cwe_counts)} CWE classes")
    print(f"Non-CWE-119 records: {len(records)}")
    print("CWE list:", ", ".join(non119), flush=True)

    out = eval_non119.remote(records)

    # Metrics
    r_preds = Counter(r["rakshak"] for r in out)
    d_preds = Counter(r["deepseek"] for r in out)
    r_correct = sum(1 for r in out if r["rakshak"] == r["cwe"])
    d_correct = sum(1 for r in out if r["deepseek"] == r["cwe"])
    r_bias119 = sum(1 for r in out if r["rakshak"] == "CWE-119")
    d_bias119 = sum(1 for r in out if r["deepseek"] == "CWE-119")
    total = len(out)

    print()
    print("=" * 72)
    print("BIAS ANALYSIS — NON-CWE-119 SAMPLES".center(72))
    print("=" * 72)

    for name, preds, correct, bias in [
        ("RakshakAI v2", r_preds, r_correct, r_bias119),
        ("DeepSeek-V4-Pro", d_preds, d_correct, d_bias119),
    ]:
        print(f"\n{name}:")
        print(f"  Accuracy:                    {correct}/{total} = {correct/total*100:.1f}%")
        print(f"  Predicts CWE-119 (bias):     {bias}/{total} = {bias/total*100:.0f}%")
        print(f"  Prediction distribution:")
        for cwe, cnt in preds.most_common():
            print(f"    {cwe:20s}: {cnt:>3}  {'#' * cnt}")

    print(f"\n{'='*72}")
    print("PER-RECORD TABLE".center(72))
    print("=" * 72)
    print(f"{'#':>3} {'Expected':<16} {'RakshakPred':<16} {'DSPred':<16} {'R_ok':>4} {'D_ok':>4}")
    print("-" * 72)
    for i, r in enumerate(out):
        rok = "✓" if r["rakshak"] == r["cwe"] else "✗"
        dok = "✓" if r["deepseek"] == r["cwe"] else "✗"
        print(f"{i+1:>3} {r['cwe']:<16} {r['rakshak']:<16} {r['deepseek']:<16} {rok:>4} {dok:>4}")
        if r["rakshak"] == "NONE":
            print(f"     RAW: {r['rakshak_raw'][:200]}")
        if r["rakshak_retried"]:
            print(f"     (retried)")

    path = "/Users/macbook/Desktop/RakshakAI/v2/inputs/datasets/eval/results/bias_check.json"
    with open(path, "w") as f:
        json.dump({"results": out, "summary": {
            "total": total,
            "rakshak_accuracy": round(r_correct/total*100, 1),
            "rakshak_bias_rate": round(r_bias119/total*100, 1),
            "deepseek_accuracy": round(d_correct/total*100, 1),
            "deepseek_bias_rate": round(d_bias119/total*100, 1),
            "rakshak_119_count": r_bias119,
            "deepseek_119_count": d_bias119,
        }}, f, indent=2)
    print(f"\nSaved to bias_check.json", flush=True)
