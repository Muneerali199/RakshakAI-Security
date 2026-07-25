"""
RakshakAI vs Big Models — Side-by-Side Security Benchmark.

Usage:
    python3 v2/scripts/benchmark_vs_big_models.py \
        --our-model Muneerali199/rakshak-cwe-v3 \
        --benchmark v2/outputs/eval/security_benchmark.jsonl \
        --out v2/outputs/eval/vs_big_models.md

Requires:
    pip install openai  # for OpenRouter API calls to GPT-4/Claude/Gemini
"""
import argparse
import json
import os
import re
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# ── Config: OpenRouter endpoints ──
OPENROUTER_API_KEY = os.environ.get("OPENROUTER_API_KEY", "")
OR_BASE = "https://openrouter.ai/api/v1"

BIG_MODELS = {
    "gpt-4o": "openai/gpt-4o",
    "claude-sonnet": "anthropic/claude-3.5-sonnet",
    "gemini-flash": "google/gemini-2.0-flash-001",
}

SYSTEM_PROMPT = (
    "You are a security code analysis model. "
    "Respond as a single JSON object with fields: vulnerability, cwe, "
    "severity, confidence, root_cause, attack_scenario, secure_fix, "
    "patched_code, references. No prose outside JSON."
)


@dataclass
class Result:
    model: str
    correct_vuln: int = 0
    total_vuln: int = 0
    correct_cwe: int = 0
    total_cwe: int = 0
    parse_failures: int = 0
    total_latency: float = 0.0


def extract_json(text: str) -> dict | None:
    """Extract first JSON object from text."""
    # Try ```json ... ``` or ``` ... ```
    m = re.search(r'```(?:json)?\s*\n?(.*?)\n?```', text, re.DOTALL)
    if m:
        text = m.group(1)
    # Find first { ... }
    m = re.search(r'\{.*\}', text, re.DOTALL)
    if not m:
        return None
    try:
        return json.loads(m.group())
    except json.JSONDecodeError:
        return None


def load_our_model(model_name: str):
    from transformers import AutoModelForCausalLM, AutoTokenizer
    import torch

    print(f"Loading our model: {model_name}")
    tokenizer = AutoTokenizer.from_pretrained(model_name, trust_remote_code=True)
    model = AutoModelForCausalLM.from_pretrained(
        model_name,
        device_map="auto",
        torch_dtype=torch.float16,
        trust_remote_code=True,
    )
    return model, tokenizer


def predict_our_model(model, tokenizer, prompt: str) -> tuple[dict | None, float]:
    import torch

    start = time.time()
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": prompt},
    ]
    text = tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
    inputs = tokenizer(text, return_tensors="pt").to(model.device)
    with torch.no_grad():
        outputs = model.generate(
            **inputs,
            max_new_tokens=1024,
            temperature=0.1,
            do_sample=False,
        )
    reply = tokenizer.decode(outputs[0][inputs.input_ids.shape[1]:], skip_special_tokens=True)
    latency = time.time() - start
    return extract_json(reply), latency


def predict_api(model_id: str, prompt: str, api_key: str) -> tuple[dict | None, float]:
    from openai import OpenAI

    client = OpenAI(base_url=OR_BASE, api_key=api_key)
    start = time.time()
    try:
        resp = client.chat.completions.create(
            model=model_id,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            max_tokens=1024,
            temperature=0.1,
        )
        reply = resp.choices[0].message.content
        latency = time.time() - start
        return extract_json(reply), latency
    except Exception as e:
        print(f"  API error for {model_id}: {e}")
        return None, time.time() - start


def has_vulnerability(sample: dict) -> bool:
    """Ground truth: does the sample contain a vulnerability?"""
    # Expected field: ground_truth_cwe, or cwe, or label, or vulnerable
    return bool(sample.get("vulnerable", sample.get("label", True)))


def main():
    parser = argparse.ArgumentParser(description="Benchmark our model vs GPT-4/Claude/Gemini")
    parser.add_argument("--our-model", default="Muneerali199/rakshak-cwe-v3")
    parser.add_argument("--benchmark", default="v2/outputs/eval/security_benchmark.jsonl")
    parser.add_argument("--out", default="v2/outputs/eval/vs_big_models.md")
    args = parser.parse_args()

    # Load benchmark samples
    samples = []
    with open(args.benchmark) as f:
        for line in f:
            line = line.strip()
            if line:
                samples.append(json.loads(line))
    print(f"Loaded {len(samples)} benchmark samples")

    if not samples:
        print("ERROR: No benchmark samples loaded. Create one first.")
        sys.exit(1)

    # Load our model
    our_model, our_tokenizer = load_our_model(args.our_model)

    # Results storage
    results: dict[str, Result] = {}

    # Run each model on each sample
    for model_key in ["our-model", "gpt-4o", "claude-sonnet", "gemini-flash"]:
        r = Result(model=model_key)
        results[model_key] = r
        print(f"\n{'='*60}")
        print(f"Evaluating: {model_key}")
        print(f"{'='*60}")

        for i, sample in enumerate(samples):
            code = sample.get("code", sample.get("prompt", ""))
            ground_cwe = sample.get("ground_truth_cwe", sample.get("cwe", ""))
            is_vuln = has_vulnerability(sample)

            prompt = f"Analyze this code for security vulnerabilities:\n\n```\n{code}\n```"

            print(f"  [{i+1}/{len(samples)}] ", end="", flush=True)

            if model_key == "our-model":
                pred, lat = predict_our_model(our_model, our_tokenizer, prompt)
            else:
                if not OPENROUTER_API_KEY:
                    print("SKIP (no API key)")
                    continue
                pred, lat = predict_api(BIG_MODELS[model_key], prompt, OPENROUTER_API_KEY)

            r.total_latency += lat

            if pred is None:
                r.parse_failures += 1
                print(f"PARSE_FAIL ({lat:.1f}s)")
                continue

            # Check vulnerability detection
            pred_vuln = bool(pred.get("vulnerability", "").strip())
            if pred_vuln == is_vuln:
                r.correct_vuln += 1
            r.total_vuln += 1

            # Check CWE classification
            pred_cwe = str(pred.get("cwe", ""))
            if pred_cwe and ground_cwe and pred_cwe.strip() == ground_cwe.strip():
                r.correct_cwe += 1
            r.total_cwe += 1

            mark = "✓" if pred_vuln == is_vuln else "✗"
            print(f"{mark} cwe_pred={pred_cwe} cwe_true={ground_cwe} ({lat:.1f}s)")

    # ── Generate report ──
    lines = [
        "# RakshakAI vs Big Models — Security Benchmark",
        "",
        f"Benchmark: `{args.benchmark}` ({len(samples)} samples)",
        f"Date: {time.strftime('%Y-%m-%d')}",
        "",
        "## Vulnerability Detection",
        "",
        "| Model | Accuracy | Parse Fail | Avg Latency | Total Time |",
        "|-------|----------|------------|-------------|------------|",
    ]

    for model_key in ["our-model", "gpt-4o", "claude-sonnet", "gemini-flash"]:
        r = results[model_key]
        vuln_acc = r.correct_vuln / max(1, r.total_vuln) * 100
        avg_lat = r.total_latency / max(1, r.total_vuln)
        lines.append(
            f"| {model_key} | {vuln_acc:.1f}% | {r.parse_failures} | "
            f"{avg_lat:.2f}s | {r.total_latency:.1f}s |"
        )

    lines += [
        "",
        "## CWE Classification Accuracy",
        "",
        "| Model | Top-1 Accuracy |",
        "|-------|----------------|",
    ]

    for model_key in ["our-model", "gpt-4o", "claude-sonnet", "gemini-flash"]:
        r = results[model_key]
        cwe_acc = r.correct_cwe / max(1, r.total_cwe) * 100
        lines.append(f"| {model_key} | {cwe_acc:.1f}% |")

    report = "\n".join(lines) + "\n"

    # Save
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(report)
    print(f"\n\nReport saved to {out_path}")
    print(report)


if __name__ == "__main__":
    main()
