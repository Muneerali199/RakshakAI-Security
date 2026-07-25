#!/usr/bin/env python3
"""Run 72-sample benchmark through Groq API for cross-model comparison."""
import json, os, re, sys, time, html
import requests
from huggingface_hub import hf_hub_download, HfApi

GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")
HF_TOKEN = os.environ.get("HF_TOKEN", "")
GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"

if len(sys.argv) < 2:
    print("Usage: python run_groq_benchmark.py <model_id> [label]")
    print("  model_id: e.g. llama-3.3-70b-versatile, qwen/qwen3.6-27b, llama-3.1-8b-instant")
    print("  label:    short label for results file (default: auto-derived from model)")
    sys.exit(1)

MODEL = sys.argv[1]
LABEL = sys.argv[2] if len(sys.argv) > 2 else MODEL.split("/")[-1].replace("-", "_")

SYSTEM_PROMPT = """You are a security-specialized code analysis model. Analyze the code snippet for security vulnerabilities.

Think through your analysis step by step, then respond with a JSON object containing:
{
  "is_vulnerable": true/false,
  "vulnerability_type": "<CWE-XXX or null if not vulnerable>",
  "severity": "<critical|high|medium|low|clean>",
  "explanation": "<root cause explanation>",
  "patched_code": "<fixed code or null if already secure>",
  "secure_fix_recommendation": "<how to fix it>"
}
If the code is secure, set is_vulnerable=false, severity="clean", and all other fields to appropriate null/clean values."""

print("=" * 60)
print(f"  RAKSHAKAI BENCHMARK via Groq API")
print(f"  Model: {MODEL}")
print(f"  Label: {LABEL}")
print("=" * 60)

# Load benchmark samples
bench_path = hf_hub_download(
    "Muneerali199/rakshak-cwe-14b-sft-final",
    "benchmarks/comprehensive_benchmark.jsonl",
    repo_type="model", token=HF_TOKEN,
)
samples = [json.loads(l) for l in open(bench_path) if l.strip()]
print(f"Loaded {len(samples)} samples\n")

def call_groq(code, lang, retries=3):
    user_content = f"Analyze the following {lang} code for security vulnerabilities:\n\n```{lang}\n{code}\n```"
    
    for attempt in range(retries):
        try:
            resp = requests.post(GROQ_URL, json={
                "model": MODEL,
                "messages": [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": user_content},
                ],
                "temperature": 0.0,
                "max_tokens": 1024,
            }, headers={
                "Authorization": f"Bearer {GROQ_API_KEY}",
                "Content-Type": "application/json",
            }, timeout=60)
            
            if resp.status_code == 429:
                wait = 10 * (attempt + 1)
                print(f"  [429 rate limited, waiting {wait}s...]")
                time.sleep(wait)
                continue
            
            resp.raise_for_status()
            data = resp.json()
            raw = data["choices"][0]["message"]["content"]
            
            # Extract CWE using regex
            m = re.search(r"CWE-(\d+)", raw, re.IGNORECASE)
            cwe = f"CWE-{m.group(1)}" if m else ""
            
            # Try JSON extraction for additional info
            json_match = re.search(r'\{.*"is_vulnerable".*\}', raw, re.DOTALL)
            is_vuln = None
            if json_match:
                try:
                    parsed = json.loads(json_match.group())
                    is_vuln = parsed.get("is_vulnerable")
                    if not cwe and parsed.get("vulnerability_type"):
                        cwe = parsed["vulnerability_type"]
                except json.JSONDecodeError:
                    pass
            
            return {
                "raw_output": raw,
                "cwe": cwe,
                "is_vulnerable": is_vuln,
                "tokens": data.get("usage", {}).get("total_tokens", 0),
                "finish_reason": data["choices"][0].get("finish_reason", ""),
            }
        except Exception as e:
            if attempt < retries - 1:
                wait = 5 * (attempt + 1)
                print(f"  [Error: {e}, retrying in {wait}s...]")
                time.sleep(wait)
            else:
                return {"raw_output": f"ERROR: {e}", "cwe": "", "is_vulnerable": None, "tokens": 0, "finish_reason": "error"}

results, t0, errors = [], time.time(), 0
for i, s in enumerate(samples):
    code = s.get("vulnerable_code", "")
    lang = s.get("language", "python")
    
    ts = time.time()
    data = call_groq(code, lang)
    dur = time.time() - ts
    
    pred_cwe = data.get("cwe", "")
    pred_vuln = data.get("is_vulnerable")
    
    if not pred_cwe and pred_vuln is None:
        errors += 1
    
    true_cwe = s.get("cwe", "")
    true_vuln = s.get("is_vulnerable", True)
    
    results.append({
        "id": s.get("id", f"s{i}"),
        "language": lang,
        "true_cwe": true_cwe,
        "true_severity": s.get("severity", ""),
        "true_vuln": true_vuln,
        "pred_cwe": pred_cwe,
        "pred_vuln": bool(pred_cwe) if pred_vuln is None else bool(pred_vuln),
        "pred_vuln_raw": pred_vuln,
        "duration_s": round(dur, 2),
        "tokens": data.get("tokens", 0),
        "finish_reason": data.get("finish_reason", ""),
        "raw_output": data.get("raw_output", "")[:500],
    })
    
    elapsed = time.time() - t0
    eta = (elapsed / (i + 1)) * (len(samples) - i - 1) / 60
    ok = "✓" if pred_cwe.upper() == true_cwe.upper() else "✗"
    print(f"[{i+1}/{len(samples)}] {eta:3.0f}m ETA | {ok} {s.get('id',''):25s} "
          f"pred={pred_cwe or '?':8s} true={true_cwe:8s} | {dur:.1f}s")
    sys.stdout.flush()
    
    # Rate limit: sleep 2s between requests to avoid 429
    if i < len(samples) - 1:
        time.sleep(1.5)

total = time.time() - t0
n = len(results)
cwe_exact = sum(1 for r in results if r["pred_cwe"] and r["true_cwe"] and r["pred_cwe"].upper() == r["true_cwe"].upper())
cwe_family = sum(1 for r in results if r["pred_cwe"] and r["true_cwe"] and r["pred_cwe"].rsplit("-", 1)[-1] == r["true_cwe"].rsplit("-", 1)[-1])
vuln_ok = sum(1 for r in results if r["pred_vuln"] == r["true_vuln"])

print(f"\n{'=' * 60}")
print(f"  RESULTS — {LABEL} via Groq")
print(f"{'=' * 60}")
print(f"  Vulnerability Detection: {vuln_ok}/{n} ({vuln_ok/n*100:.1f}%)")
print(f"  CWE Exact Match:        {cwe_exact}/{n} ({cwe_exact/n*100:.1f}%)")
print(f"  CWE Family Match:       {cwe_family}/{n} ({cwe_family/n*100:.1f}%)")
print(f"  Total time:             {total/60:.1f}m ({total/n:.1f}s/sample)")
print(f"  Total tokens:           {sum(r['tokens'] for r in results)}")
print(f"  Errors:                 {errors}")
print(f"{'=' * 60}\n")

# Language breakdown
from collections import defaultdict
ls = defaultdict(lambda: {"t": 0, "o": 0, "b": 0})
for r in results:
    ls[r["language"]]["t"] += 1
    if r["pred_cwe"].upper() == r["true_cwe"].upper():
        ls[r["language"]]["o"] += 1
    elif r["pred_cwe"]:
        ls[r["language"]]["b"] += 1

print(f"  {'Language':12s} {'Total':6s} {'OK':6s} {'Acc':6s}")
for lang in sorted(ls):
    st = ls[lang]
    acc = st["o"] / st["t"] * 100 if st["t"] else 0
    print(f"  {lang:12s} {st['t']:6d} {st['o']:6d} {acc:5.1f}%")

# Upload to HF
output = {
    "model": MODEL,
    "label": LABEL,
    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    "n_samples": n,
    "total_time_s": round(total, 2),
    "avg_time_per_sample_s": round(total / n, 2),
    "via": "groq-api",
    "api_url": GROQ_URL,
    "metrics": {
        "vuln_detection_accuracy": round(vuln_ok / n * 100, 2),
        "cwe_exact_accuracy": round(cwe_exact / n * 100, 2),
        "cwe_family_accuracy": round(cwe_family / n * 100, 2),
    },
    "results": results,
}

outfile = f"benchmark_results_groq_{LABEL}.json"
with open(outfile, "w") as f:
    json.dump(output, f, indent=2)

api = HfApi(token=HF_TOKEN)
hf_path = f"benchmarks/results/groq_{LABEL}_results.json"
api.upload_file(
    path_or_fileobj=outfile,
    path_in_repo=hf_path,
    repo_id="Muneerali199/rakshak-cwe-14b-sft-final",
    repo_type="model",
)
print(f"\nUploaded: hf.co/Muneerali199/rakshak-cwe-14b-sft-final/{hf_path}")
print(f"\n{'=' * 60}")
print(f"  DONE")
print(f"{'=' * 60}")
