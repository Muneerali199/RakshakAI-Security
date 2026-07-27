#!/usr/bin/env python3
"""Multi-model evaluation benchmark for C/C++ security reasoning.

Evaluates models on CWE classification accuracy, reasoning quality, and PoC quality
using a held-out benchmark of C/C++ vulnerable code records.

Usage:
  python v2/dataset/run_eval.py --models qwen35,realmythos,deepseek,kimi --max 100
  python v2/dataset/run_eval.py --models qwen35 --max 10  # local baseline quick test

Models:
  qwen35      Qwen3.5-9B base (via Ollama/LM Studio — local)
  deepseek    DeepSeek-V4-Pro (via NVIDIA NIM — free)
  realmythos  RealMythos pocwriter-v1 (via Ollama — local)
  kimi        Kimi-K2.7-Code (via Nebius — ~$2 budget)
  glm52       GLM-5.2 (via Nebius)
  nemotron    Nemotron-3-Ultra-550b (via Nebius)
"""
import json
import os
import re
import sys
import time
import hashlib
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import Counter
from openai import OpenAI

# ─── Config ──────────────────────────────────────────────────────────────────
NVIDIA_KEY = "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"
NEBIUS_KEY = "v1.CmMKHHN0YXRpY2tleS1lMDB6czBzcTBreTZhMHhobmYSIXNlcnZpY2VhY2NvdW50LWUwMHlwaGI1Mm40YnIyMzlibTILCKv3k9IGEKH_9H06DAiq-qudBxCA_-y3AkACWgNlMDA.AAAAAAAAAAEmAVbybQZahvwGuLPkMmVAUzqgGcxJixOnhmpjirCZIyjtDsuIN2BMXEBni3Ek-IDciDB7OV-XEc4HNiOwjxoM"
BENCHMARK_PATH = "v2/inputs/datasets/eval/benchmark_300.jsonl"
OUTPUT_DIR = "v2/inputs/datasets/eval/results"
JUDGE_CONCURRENCY = 5

# ─── Judge prompt ────────────────────────────────────────────────────────────
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

# ─── Model configs ───────────────────────────────────────────────────────────
MODELS = {}

# DeepSeek-V4-Pro via NVIDIA NIM (free)
MODELS["deepseek"] = {
    "client": OpenAI(base_url="https://integrate.api.nvidia.com/v1", api_key=NVIDIA_KEY),
    "model": "deepseek-ai/deepseek-v4-pro",
    "type": "nim",
    "params": {"temperature": 0.3, "max_tokens": 4096},
}

# Kimi-K2.7-Code via Nebius
MODELS["kimi"] = {
    "client": OpenAI(base_url="https://api.tokenfactory.nebius.com/v1/", api_key=NEBIUS_KEY),
    "model": "moonshotai/Kimi-K2.7-Code",
    "type": "nebius",
    "params": {"temperature": 0.3, "max_tokens": 4096},
}

# GLM-5.2 via Nebius
MODELS["glm52"] = {
    "client": OpenAI(base_url="https://api.tokenfactory.nebius.com/v1/", api_key=NEBIUS_KEY),
    "model": "zai-org/GLM-5.2",
    "type": "nebius",
    "params": {"temperature": 0.3, "max_tokens": 4096},
}

# Nemotron-3-Ultra-550b via Nebius
MODELS["nemotron"] = {
    "client": OpenAI(base_url="https://api.tokenfactory.nebius.com/v1/", api_key=NEBIUS_KEY),
    "model": "nvidia/Nemotron-3-Ultra-550b-a55b",
    "type": "nebius",
    "params": {"temperature": 0.3, "max_tokens": 4096},
}

# Qwen2.5-Coder-7B via Ollama (local, cached)
_ollama = OpenAI(base_url="http://localhost:11434/v1", api_key="ollama")
MODELS["qwen25"] = {
    "client": _ollama,
    "model": "qwen2.5-coder:7b",
    "type": "ollama",
    "params": {"temperature": 0.3, "max_tokens": 4096},
}

# Judge uses DeepSeek-V4-Pro (free)
judge_client = OpenAI(base_url="https://integrate.api.nvidia.com/v1", api_key=NVIDIA_KEY)

# ─── Eval prompt ─────────────────────────────────────────────────────────────
SYSTEM_PROMPT = "You are a security code analyst. Analyze the given C/C++ code for vulnerabilities. Identify the CWE, explain the root cause step by step, and provide a proof-of-concept exploit."

USER_PROMPT_TEMPLATE = """Analyze this {language} code for security vulnerabilities:

```{language}
{code}
```

1. Is this code vulnerable? (Yes/No)
2. What CWE classification applies?
3. Explain the vulnerability step by step.
4. Provide a PoC (proof-of-concept) that triggers the vulnerability."""


def extract_code_from_messages(messages):
    """Extract the vulnerable code from the assistant-style messages format."""
    for m in messages:
        if m["role"] == "user":
            content = m["content"]
            # Try to extract code block
            code_blocks = re.findall(r'```(?:\w+)?\n(.*?)```', content, re.DOTALL)
            if code_blocks:
                return code_blocks[0]
            return content
    return ""


def get_language(meta):
    lang = meta.get("language", "")
    return {"c": "C", "cpp": "C++"}.get(lang, lang)


def query_model(model_cfg, system, user_msg):
    """Send a query to a model and return the response text."""
    try:
        resp = model_cfg["client"].chat.completions.create(
            model=model_cfg["model"],
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user_msg},
            ],
            **model_cfg["params"],
        )
        return resp.choices[0].message.content
    except Exception as e:
        return f"[ERROR: {e}]"


def judge_response(expected_cwe, code, language, response_text):
    """Score a model response using DeepSeek-V4-Pro judge."""
    prompt = JUDGE_TEMPLATE.format(
        expected_cwe=expected_cwe,
        code=code,
        language=language,
        response=response_text,
    )
    try:
        resp = judge_client.chat.completions.create(
            model="deepseek-ai/deepseek-v4-pro",
            messages=[
                {"role": "system", "content": JUDGE_SYSTEM},
                {"role": "user", "content": prompt},
            ],
            temperature=0.1,
            max_tokens=1024,
        )
        text = resp.choices[0].message.content
        # Parse JSON from response
        json_match = re.search(r'\{.*\}', text, re.DOTALL)
        if json_match:
            return json.loads(json_match.group())
        return {"cwe_accuracy": 1, "reasoning_quality": 1, "poc_quality": 1, "predicted_cwe": None, "explanation": "Failed to parse judge output"}
    except Exception as e:
        return {"cwe_accuracy": 1, "reasoning_quality": 1, "poc_quality": 1, "predicted_cwe": None, "explanation": f"Judge error: {e}"}


def run_eval(model_name, records, max_records=None, concurrency=3):
    """Run evaluation for one model on the benchmark."""
    cfg = MODELS[model_name]
    total = len(records)
    if max_records:
        records = records[:max_records]
        total = len(records)

    print(f"\n{'='*60}")
    print(f"Evaluating {model_name} on {total} records (concurrency={concurrency})...")
    print(f"{'='*60}")

    def process_one(rec):
        meta = rec.get("_meta", {})
        expected_cwe = meta.get("cwe", "UNKNOWN")
        language = get_language(meta)
        code = extract_code_from_messages(rec.get("messages", []))
        user_msg = USER_PROMPT_TEMPLATE.format(language=language, code=code)
        response = query_model(cfg, SYSTEM_PROMPT, user_msg)
        scores = judge_response(expected_cwe, code, language, response)
        return {
            "id": meta.get("id", "unknown"),
            "expected_cwe": expected_cwe,
            "language": language,
            "model": model_name,
            "response": response[:500],
            "response_len": len(response),
            "scores": scores,
        }

    results = []
    done = 0
    with ThreadPoolExecutor(max_workers=concurrency) as ex:
        fut_map = {ex.submit(process_one, rec): i for i, rec in enumerate(records)}
        for fut in as_completed(fut_map):
            results.append(fut.result())
            done += 1
            if done % 10 == 0 or done == total:
                recent = results[-min(10, len(results)):]
                avg_cwe = sum(r["scores"]["cwe_accuracy"] for r in recent) / len(recent)
                avg_reason = sum(r["scores"]["reasoning_quality"] for r in recent) / len(recent)
                print(f"  [{done}/{total}] CWE_acc={avg_cwe:.1f} Reason={avg_reason:.1f}")

    return results


def print_leaderboard(all_results):
    """Print a leaderboard comparing all models."""
    print(f"\n{'='*70}")
    print(f"{'LEADERBOARD':^70}")
    print(f"{'='*70}")
    print(f"{'Model':<25} {'CWE Acc':>10} {'Reasoning':>10} {'PoC Qual':>10} {'Overall':>10}")
    print(f"{'-'*65}")

    model_scores = {}
    for model_name, results in all_results.items():
        scores = [r["scores"] for r in results]
        cwe_acc = sum(s["cwe_accuracy"] for s in scores) / len(scores)
        reasoning = sum(s["reasoning_quality"] for s in scores) / len(scores)
        poc = sum(s["poc_quality"] for s in scores) / len(scores)
        overall = (cwe_acc + reasoning + poc) / 3
        model_scores[model_name] = (cwe_acc, reasoning, poc, overall)

    for model_name, (cwe_acc, reasoning, poc, overall) in sorted(
        model_scores.items(), key=lambda x: -x[1][3]
    ):
        label = {"qwen35": "Qwen3.5-9B (base)", "qwen25": "Qwen2.5-Coder-7B", "deepseek": "DeepSeek-V4-Pro", "realmythos": "RealMythos pocwriter-v1", "kimi": "Kimi-K2.7-Code", "glm52": "GLM-5.2", "nemotron": "Nemotron-3-Ultra-550b"}.get(model_name, model_name)
        print(f"{label:<25} {cwe_acc:>7.2f}/5  {reasoning:>7.2f}/5  {poc:>7.2f}/5  {overall:>7.2f}/5")


def save_results(all_results, output_dir):
    """Save results to disk."""
    path = Path(output_dir)
    path.mkdir(parents=True, exist_ok=True)
    timestamp = time.strftime("%Y%m%d_%H%M%S")

    combined = []
    for model_name, results in all_results.items():
        combined.extend(results)
        with open(path / f"{model_name}_{timestamp}.jsonl", "w") as f:
            for r in results:
                f.write(json.dumps(r) + "\n")

    with open(path / f"all_{timestamp}.jsonl", "w") as f:
        for r in combined:
            f.write(json.dumps(r) + "\n")

    # Save leaderboard as JSON
    model_scores = {}
    for model_name, results in all_results.items():
        scores = [r["scores"] for r in results]
        model_scores[model_name] = {
            "cwe_accuracy": round(sum(s["cwe_accuracy"] for s in scores) / len(scores), 3),
            "reasoning_quality": round(sum(s["reasoning_quality"] for s in scores) / len(scores), 3),
            "poc_quality": round(sum(s["poc_quality"] for s in scores) / len(scores), 3),
            "overall": round((sum(s["cwe_accuracy"] for s in scores) + sum(s["reasoning_quality"] for s in scores) + sum(s["poc_quality"] for s in scores)) / (3 * len(scores)), 3),
            "num_samples": len(results),
        }
    with open(path / f"leaderboard_{timestamp}.json", "w") as f:
        json.dump(model_scores, f, indent=2)

    print(f"\nResults saved to {path}/")
    return path


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--models", default="deepseek", help="Comma-separated: qwen35,deepseek,realmythos,kimi,glm52,nemotron")
    parser.add_argument("--max", type=int, default=None, help="Max records to evaluate per model")
    parser.add_argument("--output", default=OUTPUT_DIR)
    parser.add_argument("--concurrency", type=int, default=3, help="Concurrent workers")
    args = parser.parse_args()

    # Load benchmark
    with open(BENCHMARK_PATH) as f:
        records = [json.loads(line) for line in f if line.strip()]
    print(f"Loaded {len(records)} benchmark records from {BENCHMARK_PATH}")

    model_list = [m.strip() for m in args.models.split(",")]
    all_results = {}

    for model_name in model_list:
        if model_name not in MODELS:
            print(f"Unknown model: {model_name}. Available: {list(MODELS.keys())}")
            continue
        results = run_eval(model_name, records, max_records=args.max, concurrency=args.concurrency)
        all_results[model_name] = results

    if all_results:
        print_leaderboard(all_results)
        save_results(all_results, args.output)
