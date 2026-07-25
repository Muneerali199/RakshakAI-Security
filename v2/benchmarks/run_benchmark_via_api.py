#!/usr/bin/env python3
"""Run 72-sample benchmark via Modal API, then upload to HF."""
import json, os, re, sys, time
import requests

API_URL = "https://alimuneerali245--rakshak-api-rakshakmodel-analyze-endpoint.modal.run"
HF_TOKEN = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("HF_TOKEN", "")

print("=" * 55)
print("  RAKSHAKAI BENCHMARK via Modal API")
print(f"  API: {API_URL}")
print("=" * 55)

# Load benchmark samples
from huggingface_hub import hf_hub_download
bench_path = hf_hub_download(
    "Muneerali199/rakshak-cwe-14b-sft-final",
    "benchmarks/comprehensive_benchmark.jsonl",
    repo_type="model", token=HF_TOKEN,
)
samples = [json.loads(l) for l in open(bench_path) if l.strip()]
print(f"Loaded {len(samples)} samples\n")

def call_api(code, lang):
    resp = requests.post(API_URL, json={"code": code, "language": lang, "max_tokens": 512}, timeout=180)
    resp.raise_for_status()
    return resp.json()

results, t0, errors = [], time.time(), 0
for i, s in enumerate(samples):
    code, lang = s.get("vulnerable_code",""), s.get("language","python")
    ts = time.time()
    try:
        data = call_api(code, lang)
        pred_cwe = data.get("cwe","")
        dur = data.get("duration_s", time.time()-ts)
    except Exception as e:
        pred_cwe = ""
        dur = time.time()-ts
        errors += 1
        data = {"raw_output": f"API_ERROR: {e}"}

    true_cwe = s.get("cwe","")
    results.append({
        "id": s.get("id",f"s{i}"), "language": lang,
        "true_cwe": true_cwe, "true_severity": s.get("severity",""),
        "true_vuln": s.get("is_vulnerable",True),
        "pred_cwe": pred_cwe, "pred_vuln": bool(pred_cwe),
        "duration_s": round(dur, 2),
        "raw_output": data.get("raw_output",""),
    })

    elapsed = time.time()-t0
    eta = (elapsed/(i+1))*(len(samples)-i-1)/60
    ok = "✓" if pred_cwe.upper()==true_cwe.upper() else "✗"
    print(f"[{i+1}/{len(samples)}] {eta:3.0f}m ETA | {ok} {s.get('id',''):25s} "
          f"pred={pred_cwe or '?':8s} true={true_cwe:8s} | {dur:.1f}s")
    sys.stdout.flush()

total = time.time()-t0
n = len(results)
cwe_exact = sum(1 for r in results if r["pred_cwe"].upper()==r["true_cwe"].upper())
cwe_family = sum(1 for r in results if r["pred_cwe"] and r["true_cwe"] and r["pred_cwe"].split("-")[-1]==r["true_cwe"].split("-")[-1])
vuln_ok = sum(1 for r in results if r["pred_vuln"]==r["true_vuln"])

print(f"\n{'='*55}")
print(f"  RESULTS — checkpoint-375 via Modal API")
print(f"{'='*55}")
print(f"  Vulnerability Detection: {vuln_ok}/{n} ({vuln_ok/n*100:.1f}%)")
print(f"  CWE Exact Match:        {cwe_exact}/{n} ({cwe_exact/n*100:.1f}%)")
print(f"  CWE Family Match:       {cwe_family}/{n} ({cwe_family/n*100:.1f}%)")
print(f"  Total time:             {total/60:.1f}m ({total/n:.1f}s/sample)")
print(f"  Errors:                 {errors}")
print(f"{'='*55}\n")

# Language breakdown
from collections import defaultdict
ls = defaultdict(lambda: {"t":0,"o":0,"b":0})
for r in results:
    ls[r["language"]]["t"] += 1
    if r["pred_cwe"].upper()==r["true_cwe"].upper(): ls[r["language"]]["o"] += 1
    if r["pred_cwe"].upper()!=r["true_cwe"].upper() and r["pred_cwe"]: ls[r["language"]]["b"] += 1
print(f"  {'Language':12s} {'Total':6s} {'OK':6s} {'Acc':6s}")
for lang in sorted(ls):
    st = ls[lang]
    print(f"  {lang:12s} {st['t']:6d} {st['o']:6d} {st['o']/st['t']*100:5.1f}%")

# Upload to HF
print(f"\nUploading to HF...")
output = {
    "model": "Muneerali199/rakshak-cwe-14b-sft-step375",
    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    "n_samples": n, "total_time_s": round(total,2),
    "avg_time_per_sample_s": round(total/n,2),
    "via": "modal-api",
    "api_url": API_URL,
    "gpu": "A10G",
    "metrics": {
        "vuln_detection_accuracy": round(vuln_ok/n*100,2),
        "cwe_exact_accuracy": round(cwe_exact/n*100,2),
        "cwe_family_accuracy": round(cwe_family/n*100,2),
    },
    "results": results,
}
with open("benchmark_results_api.json","w") as f:
    json.dump(output, f, indent=2)

from huggingface_hub import HfApi
api = HfApi(token=HF_TOKEN)
api.upload_file(
    path_or_fileobj="benchmark_results_api.json",
    path_in_repo="benchmarks/results/full_benchmark_results.json",
    repo_id="Muneerali199/rakshak-cwe-14b-sft-final",
    repo_type="model",
)
print(f"Uploaded: hf.co/Muneerali199/rakshak-cwe-14b-sft-final/benchmarks/results/full_benchmark_results.json")
print(f"\n{'='*55}")
print(f"  DONE")
print(f"{'='*55}")
