#!/usr/bin/env python3
"""Full RakshakAI 72-sample benchmark runner 
Usage: python3 run_real_benchmark.py HF_TOKEN

Runs checkpoint-375 on all 72 samples (57 CWEs, 11 languages).
Uploads results to HF automatically.
"""

import json, os, re, sys, time
import torch
from huggingface_hub import HfApi, snapshot_download
from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
from peft import PeftModel

HF_TOKEN = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("HF_TOKEN")
if not HF_TOKEN:
    raise SystemExit("Usage: python3 run_real_benchmark.py HF_TOKEN")

print("=" * 55)
print("  RAKSHAKAI FULL BENCHMARK RUNNER")
print(f"  Time: {time.strftime('%Y-%m-%d %H:%M:%S')}")
print("=" * 55)

# ─── 1. Download benchmark ───
print("\n[1/5] Downloading benchmark...")
from huggingface_hub import hf_hub_download
bench_path = hf_hub_download(
    "Muneerali199/rakshak-cwe-14b-sft-final",
    "benchmarks/comprehensive_benchmark.jsonl",
    repo_type="model", token=HF_TOKEN,
)
samples = [json.loads(l) for l in open(bench_path) if l.strip()]
print(f"  Loaded {len(samples)} samples")

# ─── 2. Load model ───
print("\n[2/5] Loading base model in 4-bit NF4...")
bnb = BitsAndBytesConfig(
    load_in_4bit=True,
    bnb_4bit_quant_type="nf4",
    bnb_4bit_compute_dtype=torch.bfloat16,
)
base = AutoModelForCausalLM.from_pretrained(
    "Qwen/Qwen2.5-Coder-14B-Instruct",
    quantization_config=bnb,
    device_map="auto",
    torch_dtype=torch.bfloat16,
    trust_remote_code=True,
)
tok = AutoTokenizer.from_pretrained("Qwen/Qwen2.5-Coder-14B-Instruct", trust_remote_code=True)
if tok.pad_token_id is None:
    tok.pad_token_id = tok.eos_token_id

# Free up some GPU memory before loading adapter
torch.cuda.empty_cache()
mem = torch.cuda.memory_allocated() / 1e9
print(f"  Base model VRAM: {mem:.1f}GB / {torch.cuda.get_device_properties(0).total_memory/1e9:.1f}GB")

print("  Loading LoRA adapter...")
adapter = snapshot_download("Muneerali199/rakshak-cwe-14b-sft-step375", token=HF_TOKEN)
model = PeftModel.from_pretrained(base, adapter)
model.eval()
torch.cuda.empty_cache()
mem = torch.cuda.memory_allocated() / 1e9
print(f"  Total VRAM: {mem:.1f}GB / {torch.cuda.get_device_properties(0).total_memory/1e9:.1f}GB")

# ─── 3. Run samples ───
print(f"\n[3/5] Running {len(samples)} samples...")

def build_prompt(code, lang):
    return (f"Analyze the following {lang} code for security vulnerabilities. "
            f"Identify CWE, severity, root cause, attack scenario, and secure fix.\n"
            f"```{lang}\n{code}\n```")

def extract_cwe(text):
    m = re.search(r'CWE-(\d+)', text, re.IGNORECASE)
    return f"CWE-{m.group(1)}" if m else ""

results, t0 = [], time.time()
for i, s in enumerate(samples):
    code, lang = s.get("vulnerable_code",""), s.get("language","python")
    msgs = [{"role": "user", "content": build_prompt(code, lang)}]
    inp = tok.apply_chat_template(msgs, return_tensors="pt", add_generation_prompt=True).to(model.device)

    ts = time.time()
    try:
        with torch.no_grad():
            out = model.generate(inp, max_new_tokens=512, temperature=0.1,
                                 do_sample=False, pad_token_id=tok.pad_token_id)
        raw = tok.decode(out[0][inp.shape[1]:], skip_special_tokens=True)
    except Exception as e:
        raw = f"ERROR: {e}"
    dur = time.time() - ts

    pred_cwe = extract_cwe(raw)
    true_cwe = s.get("cwe","")
    results.append({
        "id": s.get("id",f"s{i}"), "language": lang, "true_cwe": true_cwe,
        "true_severity": s.get("severity",""), "true_vuln": s.get("is_vulnerable",True),
        "pred_cwe": pred_cwe, "pred_vuln": bool(pred_cwe), "duration_s": round(dur,2),
    })

    ok = "✓" if pred_cwe.upper() == true_cwe.upper() else "✗"
    eta = (time.time()-t0)/(i+1)*(len(samples)-i-1)/60
    print(f"  [{i+1}/{len(samples)}] {eta:3.0f}m ETA | {ok} {s.get('id',''):25s} "
          f"pred={pred_cwe or '?':8s} true={true_cwe:8s} | {dur:.0f}s")

total = time.time() - t0

# ─── 4. Compute metrics ───
print(f"\n[4/5] Computing metrics...")
n = len(results)
cwe_exact = sum(1 for r in results if r["pred_cwe"].upper() == r["true_cwe"].upper())
cwe_family = sum(1 for r in results if r["pred_cwe"] and r["true_cwe"]
                 and r["pred_cwe"].split("-")[-1] == r["true_cwe"].split("-")[-1])
vuln_ok = sum(1 for r in results if r["pred_vuln"] == r["true_vuln"])

print(f"\n{'='*55}")
print(f"  RESULTS — checkpoint-375 on {n} samples")
print(f"{'='*55}")
print(f"  Vulnerability Detection: {vuln_ok}/{n} ({vuln_ok/n*100:.1f}%)")
print(f"  CWE Exact Match:        {cwe_exact}/{n} ({cwe_exact/n*100:.1f}%)")
print(f"  CWE Family Match:       {cwe_family}/{n} ({cwe_family/n*100:.1f}%)")
print(f"  Total time:             {total/60:.1f}m ({total/n:.1f}s/sample)")
print(f"{'='*55}")

# Language breakdown
from collections import defaultdict
ls = defaultdict(lambda: {"t":0,"o":0})
for r in results:
    lang = r["language"]
    ls[lang]["t"] += 1
    if r["pred_cwe"].upper() == r["true_cwe"].upper():
        ls[lang]["o"] += 1
print(f"\n  {'Language':12s} {'Total':6s} {'OK':6s} {'Acc':6s}")
for lang in sorted(ls):
    st = ls[lang]
    print(f"  {lang:12s} {st['t']:6d} {st['o']:6d} {st['o']/st['t']*100:5.1f}%")

# ─── 5. Upload ───
print(f"\n[5/5] Uploading results to HF...")
output = {
    "model": "Muneerali199/rakshak-cwe-14b-sft-step375",
    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    "n_samples": n, "total_time_s": round(total,2),
    "avg_time_per_sample_s": round(total/n,2),
    "metrics": {
        "vuln_detection_accuracy": round(vuln_ok/n*100,2),
        "cwe_exact_accuracy": round(cwe_exact/n*100,2),
        "cwe_family_accuracy": round(cwe_family/n*100,2),
    },
    "results": results,
}
with open("benchmark_results.json","w") as f:
    json.dump(output, f, indent=2)
print("  Saved: benchmark_results.json")

api = HfApi(token=HF_TOKEN)
api.upload_file(
    path_or_fileobj="benchmark_results.json",
    path_in_repo="benchmarks/results/full_benchmark_results.json",
    repo_id="Muneerali199/rakshak-cwe-14b-sft-final",
    repo_type="model",
)
print("  Uploaded: hf.co/Muneerali199/rakshak-cwe-14b-sft-final/benchmarks/results/full_benchmark_results.json")
print(f"\n{'='*55}")
print("  DONE — benchmark complete!")
print(f"{'='*55}")
