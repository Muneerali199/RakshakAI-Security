import json, re, time
import modal
from openai import OpenAI

NVIDIA_KEY = "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"
RESULTS_FILE = "/Users/macbook/Desktop/RakshakAI/v2/inputs/datasets/eval/results/leaderboard_20.json"

app = modal.App("rakshak-eval")

image = (
    modal.Image.debian_slim(python_version="3.11")
    .apt_install("git")
    .pip_install("torch", "accelerate", "peft", "huggingface_hub", "openai", "bitsandbytes")
    .pip_install("git+https://github.com/huggingface/transformers.git")
)

def extract_cwe(text):
    """Extract CWE ID from model output. Tries JSON parse first, then regex fallback."""
    if not text:
        return ""
    # 1) Try JSON — find balanced braces
    depth = 0
    start = -1
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
    # 2) Regex fallback — CWE-NNNN or CWE NNNN
    m = re.search(r'CWE[- ](\d+)', text, re.IGNORECASE)
    if m:
        return f"CWE-{m.group(1)}"
    # 3) Bare number preceded by "cwe"
    m = re.search(r'cwe[:\s]*(\d+)', text, re.IGNORECASE)
    if m:
        return f"CWE-{m.group(1)}"
    return ""

@app.function(image=image, gpu="T4", timeout=7200)
def run_eval(records):
    from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
    from peft import PeftModel
    import torch

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

    def call_nim(system, user, max_tokens=256, timeout=120):
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
                    print(f"  NIM retry {attempt+1}: {e}", flush=True)
                    time.sleep(5)
                else:
                    return f'[ERROR: {e}]'

    results = {"rakshak": [], "deepseek": []}

    for i, rec in enumerate(records):
        msgs = rec["messages"]
        meta = rec.get("_meta", {})
        expected_cwe = meta.get("cwe", "N/A").strip().upper()
        code = ""
        for m in msgs:
            if m["role"] == "user":
                cbs = re.findall(r'```(?:\w+)?\n(.*?)```', m["content"], re.DOTALL)
                code = cbs[0] if cbs else m["content"]
        sys_p, user_m = msgs[0]["content"], msgs[1]["content"]

        print(f"\n{'='*80}", flush=True)
        print(f"[{i+1}/{len(records)}] Ground Truth: {expected_cwe}", flush=True)

        # --- RakshakAI (first attempt) ---
        t1 = time.time()
        prompt = tokenizer.apply_chat_template(msgs[:-1], tokenize=False, add_generation_prompt=True)
        inp = tokenizer(prompt, return_tensors="pt").to(model.device)
        with torch.no_grad():
            out = model.generate(
                **inp, max_new_tokens=512, do_sample=False,
                pad_token_id=tokenizer.eos_token_id,
            )
        r_raw = tokenizer.decode(out[0][inp.input_ids.shape[1]:], skip_special_tokens=True).strip()
        rt = time.time() - t1
        r_cwe = extract_cwe(r_raw)
        retried = False
        if r_cwe == "":
            print(f"  Rakshak ({rt:.1f}s) no CWE found — retrying with strict prompt", flush=True)
            t1b = time.time()
            strict_usr = user_m + "\n\n(What is the CWE classification? Respond with just the CWE ID.)"
            strict_msgs = [{"role": "system", "content": sys_p}, {"role": "user", "content": strict_usr}]
            strict_prompt = tokenizer.apply_chat_template(strict_msgs, tokenize=False, add_generation_prompt=True)
            inp2 = tokenizer(strict_prompt, return_tensors="pt").to(model.device)
            with torch.no_grad():
                out2 = model.generate(
                    **inp2, max_new_tokens=64, do_sample=False,
                    pad_token_id=tokenizer.eos_token_id,
                )
            r_raw2 = tokenizer.decode(out2[0][inp2.input_ids.shape[1]:], skip_special_tokens=True).strip()
            rt2 = time.time() - t1b
            r_cwe = extract_cwe(r_raw2)
            print(f"  Rakshak retry ({rt2:.1f}s) CWE={r_cwe}: {r_raw2[:120]}", flush=True)
            r_raw = r_raw + "\n---RETRY---\n" + r_raw2
            rt = rt + rt2
            retried = True
        r_ok = r_cwe == expected_cwe
        print(f"  Rakshak ({rt:.1f}s) CWE={r_cwe} {'✓' if r_ok else '✗'}: {r_raw[:160]}", flush=True)
        if r_cwe == "":
            print(f"  >>> PARSER FAILED. Raw output:\n{r_raw[:500]}", flush=True)
        results["rakshak"].append({
            "raw": r_raw, "pred_cwe": r_cwe, "expected_cwe": expected_cwe,
            "correct": r_ok, "time_s": round(rt, 1), "retried": retried,
        })

        # --- DeepSeek ---
        t2 = time.time()
        d_raw = call_nim(sys_p, user_m, max_tokens=4096, timeout=180)
        dt = time.time() - t2
        d_cwe = extract_cwe(d_raw)
        d_ok = d_cwe == expected_cwe
        print(f"  DeepSeek ({dt:.1f}s) CWE={d_cwe} {'✓' if d_ok else '✗'}: {d_raw[:160]}", flush=True)
        if d_cwe == "":
            print(f"  >>> PARSER FAILED. Raw output:\n{d_raw[:500]}", flush=True)
        results["deepseek"].append({
            "raw": d_raw, "pred_cwe": d_cwe, "expected_cwe": expected_cwe,
            "correct": d_ok, "time_s": round(dt, 1),
        })

    # --- Metrics ---
    print(f"\n{'='*80}", flush=True)
    print(f"{'LEADERBOARD':^80}", flush=True)
    print(f"{'='*80}")
    for name, label in [("rakshak", "RakshakAI v2"), ("deepseek", "DeepSeek-V4-Pro")]:
        entries = results[name]
        total = len(entries)
        correct = sum(1 for e in entries if e["correct"])
        parsed = sum(1 for e in entries if e["pred_cwe"])
        acc = correct / total * 100 if total else 0
        avg_t = sum(e["time_s"] for e in entries) / total
        print(f"\n{label}:")
        print(f"  CWE Accuracy:      {acc:.1f}% ({correct}/{total})")
        print(f"  CWE Parse Rate:    {parsed}/{total} ({parsed/total*100:.0f}%)")
        print(f"  Avg Time/Sample:   {avg_t:.1f}s")
        print(f"  Total Time:        {sum(e['time_s'] for e in entries):.0f}s")
        for e in entries:
            if not e["correct"]:
                print(f"  WRONG: expected={e['expected_cwe']} predicted={e['pred_cwe']!r}", flush=True)

    return results

@app.local_entrypoint()
def main():
    with open("/Users/macbook/Desktop/RakshakAI/v2/inputs/datasets/eval/benchmark_300.jsonl") as f:
        all_records = [json.loads(line) for line in f if line.strip()]

    from collections import Counter
    cwe_counts = Counter(r['_meta']['cwe'] for r in all_records)
    print(f"Full benchmark: {len(all_records)} records, {len(cwe_counts)} CWE classes", flush=True)

    # Stratified sample: 10 CWE-119 + 1 each from next 10 most common non-119 classes
    by_cwe = {}
    for r in all_records:
        by_cwe.setdefault(r['_meta']['cwe'], []).append(r)

    records = by_cwe.get("CWE-119", [])[:10]
    others = [c for c in cwe_counts if c != "CWE-119"]
    others.sort(key=lambda c: -cwe_counts[c])
    for c in others[:10]:
        records.append(by_cwe[c][0])

    print(f"Eval set: {len(records)} records", flush=True)
    for r in records:
        print(f"  {r['_meta']['cwe']}", flush=True)

    out = run_eval.remote(records)

    with open(RESULTS_FILE, "w") as f:
        json.dump(out, f, indent=2)
    print(f"\nResults saved to {RESULTS_FILE}", flush=True)
