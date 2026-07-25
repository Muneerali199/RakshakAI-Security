#!/usr/bin/env python3
"""Multi-model eval: RakshakAI v3 vs DeepSeek-V4-Pro vs base Qwen2.5-Coder-7B.

Compares models on the benchmark_300.jsonl using the *exact same chat messages*
(system/user format the models were trained on) for a fair comparison.

Usage:
  python v2/dataset/v3_eval.py --max 30
"""
import json, os, re, sys, time, requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from openai import OpenAI

NVIDIA_KEY = "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"
RAKSHAK_URL = "https://alimuneerali245--chat-completions.modal.run"
BENCHMARK_PATH = "v2/inputs/datasets/eval/benchmark_300.jsonl"

nim = OpenAI(base_url="https://integrate.api.nvidia.com/v1", api_key=NVIDIA_KEY)

# ─── Judge ────────────────────────────────────────────────────────────────────
JUDGE_SYSTEM = "You are a security evaluation judge. Score model responses on C/C++ vulnerability analysis."
JUDGE_TEMPLATE = """Evaluate this model's response to a C/C++ vulnerability analysis task.

[Expected CWE]: {expected_cwe}
[Code]:
```{language}
{code}
```

[Model Response]:
{response}

Score on these 3 dimensions (1-5):

1. **CWE Accuracy** — Does the response identify the correct CWE? Score based on exact or close match.
2. **Reasoning Quality** — Is the analysis step-by-step, technically correct, and thorough?
3. **PoC Quality** — If a PoC is provided, is it valid, targeted, and executable? (If no PoC, score 1.)

Return ONLY a JSON object:
{{"cwe_accuracy": <1-5>, "reasoning_quality": <1-5>, "poc_quality": <1-5>, "predicted_cwe": "<extracted or null>", "explanation": "<1 sentence>"}}"""

def judge_response(expected_cwe, code, language, response_text):
    prompt = JUDGE_TEMPLATE.format(expected_cwe=expected_cwe, code=code, language=language, response=response_text)
    try:
        resp = nim.chat.completions.create(
            model="deepseek-ai/deepseek-v4-pro",
            messages=[{"role": "system", "content": JUDGE_SYSTEM}, {"role": "user", "content": prompt}],
            temperature=0.1, max_tokens=1024,
        )
        text = resp.choices[0].message.content
        m = re.search(r'\{.*\}', text, re.DOTALL)
        if m: return json.loads(m.group())
        return {"cwe_accuracy": 1, "reasoning_quality": 1, "poc_quality": 1, "predicted_cwe": None, "explanation": "Parse fail"}
    except Exception as e:
        return {"cwe_accuracy": 1, "reasoning_quality": 1, "poc_quality": 1, "predicted_cwe": None, "explanation": f"Error: {e}"}

# ─── Model helpers ────────────────────────────────────────────────────────────

def query_deepseek(messages):
    try:
        resp = nim.chat.completions.create(
            model="deepseek-ai/deepseek-v4-pro",
            messages=messages,
            temperature=0.3, max_tokens=4096,
        )
        return resp.choices[0].message.content
    except Exception as e:
        return f"[ERROR: {e}]"

def query_rakshak_v3(messages):
    try:
        resp = requests.post(
            RAKSHAK_URL,
            json={"messages": messages, "max_tokens": 4096, "temperature": 0.3},
            timeout=300,
        )
        resp.raise_for_status()
        return resp.json()["choices"][0]["message"]["content"]
    except Exception as e:
        return f"[ERROR: {e}]"

def query_base_qwen(messages):
    """Base Qwen2.5-Coder-7B-Instruct via Ollama (local)."""
    try:
        ollama = OpenAI(base_url="http://localhost:11434/v1", api_key="ollama")
        resp = ollama.chat.completions.create(
            model="qwen2.5-coder:7b",
            messages=messages,
            temperature=0.3, max_tokens=4096,
        )
        return resp.choices[0].message.content
    except Exception as e:
        return None  # silent fail if Ollama not running

def extract_code(messages):
    for m in messages:
        if m["role"] == "user":
            cbs = re.findall(r'```(?:\w+)?\n(.*?)```', m["content"], re.DOTALL)
            if cbs: return cbs[0]
            return m["content"]
    return ""

def get_language(meta):
    lang = meta.get("language", "")
    return {"c": "C", "cpp": "C++"}.get(lang, lang)

def warm_rakshak():
    """Warm up the Modal endpoint (cold start ~2-3 min)."""
    print("Warming RakshakAI v3 endpoint (cold start may take ~2 min)...")
    t0 = time.time()
    try:
        resp = requests.post(
            RAKSHAK_URL,
            json={"messages": [{"role": "user", "content": "Say hello"}], "max_tokens": 10, "temperature": 0.1},
            timeout=310,
        )
        print(f"  Warmup done in {time.time()-t0:.1f}s")
    except Exception as e:
        print(f"  Warmup failed: {e}")

# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--max", type=int, default=30, help="Records per model")
    parser.add_argument("--concurrency", type=int, default=2, help="Workers")
    parser.add_argument("--skip-warmup", action="store_true")
    args = parser.parse_args()

    with open(BENCHMARK_PATH) as f:
        records = [json.loads(line) for line in f if line.strip()]
    records = records[:args.max]
    print(f"Benchmark: {len(records)} records loaded")

    if not args.skip_warmup:
        warm_rakshak()

    models = {
        "rakshak-v3": {"fn": query_rakshak_v3, "label": "RakshakAI v3 (ours)"},
        "deepseek-v4": {"fn": query_deepseek, "label": "DeepSeek-V4-Pro"},
        "base-qwen": {"fn": query_base_qwen, "label": "Qwen2.5-Coder-7B (base)"},
    }

    all_results = {}

    for model_key, cfg in models.items():
        print(f"\n{'='*60}")
        print(f"Evaluating {cfg['label']} on {len(records)} records...")
        print(f"{'='*60}")

        results = []
        done = 0

        def process_one(rec):
            msgs = rec.get("messages", [])
            meta = rec.get("_meta", {})
            expected_cwe = meta.get("cwe", "UNKNOWN")
            language = get_language(meta)
            code = extract_code(msgs)

            system_msgs = [{"role": m["role"], "content": m["content"]} for m in msgs if m["role"] in ("system", "user")]

            response = cfg["fn"](system_msgs)
            scores = judge_response(expected_cwe, code, language, response)

            return {
                "id": meta.get("id", "unknown"),
                "expected_cwe": expected_cwe,
                "language": language,
                "model": model_key,
                "response_len": len(response),
                "scores": scores,
            }

        with ThreadPoolExecutor(max_workers=args.concurrency) as ex:
            fut_map = {ex.submit(process_one, rec): i for i, rec in enumerate(records)}
            for fut in as_completed(fut_map):
                results.append(fut.result())
                done += 1
                if done % 10 == 0 or done == len(records):
                    recent = results[-min(10, len(results)):]
                    avg_cwe = sum(r["scores"]["cwe_accuracy"] for r in recent) / len(recent)
                    avg_reason = sum(r["scores"]["reasoning_quality"] for r in recent) / len(recent)
                    print(f"  [{done}/{len(records)}] CWE_acc={avg_cwe:.2f} Reason={avg_reason:.2f}")

        all_results[model_key] = results

    # ─── Leaderboard ───
    print(f"\n{'='*70}")
    print(f"{'LEADERBOARD':^70}")
    print(f"{'='*70}")
    print(f"{'Model':<25} {'CWE Acc':>8} {'Reason':>8} {'PoC':>8} {'Overall':>8} {'N':>5}")
    print(f"{'-'*65}")

    for model_key, cfg in sorted(models.items(), key=lambda x: -(
        sum(r["scores"]["cwe_accuracy"] for r in all_results.get(x[0], [])) / max(len(all_results.get(x[0], [])), 1)
        if x[0] in all_results and all_results[x[0]] else 0
    )):
        if model_key not in all_results or not all_results[model_key]:
            continue
        scores = [r["scores"] for r in all_results[model_key]]
        cwe = sum(s["cwe_accuracy"] for s in scores) / len(scores)
        reas = sum(s["reasoning_quality"] for s in scores) / len(scores)
        poc = sum(s["poc_quality"] for s in scores) / len(scores)
        overall = (cwe + reas + poc) / 3
        print(f"{cfg['label']:<25} {cwe:>7.2f}/5  {reas:>7.2f}/5  {poc:>7.2f}/5  {overall:>7.2f}/5  {len(scores):>4}")

    # Save
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    out_dir = "v2/inputs/datasets/eval/results"
    combined = []
    for model_key, results in all_results.items():
        with open(f"{out_dir}/{model_key}_{timestamp}.jsonl", "w") as f:
            for r in results:
                f.write(json.dumps(r) + "\n")
                combined.append(r)

    model_scores = {}
    for model_key, results in all_results.items():
        if not results: continue
        scores = [r["scores"] for r in results]
        model_scores[model_key] = {
            "cwe_accuracy": round(sum(s["cwe_accuracy"] for s in scores) / len(scores), 3),
            "reasoning_quality": round(sum(s["reasoning_quality"] for s in scores) / len(scores), 3),
            "poc_quality": round(sum(s["poc_quality"] for s in scores) / len(scores), 3),
            "overall": round(
                (sum(s["cwe_accuracy"] for s in scores) + sum(s["reasoning_quality"] for s in scores) + sum(s["poc_quality"] for s in scores))
                / (3 * len(scores)), 3),
            "num_samples": len(results),
        }
    with open(f"{out_dir}/leaderboard_v3_{timestamp}.json", "w") as f:
        json.dump(model_scores, f, indent=2)

    print(f"\nSaved to {out_dir}/")

if __name__ == "__main__":
    main()
