#!/usr/bin/env python3
"""RakshakAI v2 — Public Benchmark Framework

Evaluates a model on CWE classification, vulnerability detection,
severity prediction, and secure fix quality.

Usage:
    python v2/benchmarks/public_benchmark.py \\
        --model Qwen/Qwen2.5-Coder-7B-Instruct \\
        --benchmark v2/benchmarks/security_benchmark.jsonl \\
        --output v2/benchmarks/results.json

Output metrics: precision, recall, F1, accuracy, false positive rate.
"""

import argparse
import json
import re
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

try:
    import numpy as np
    from sklearn.metrics import (
        accuracy_score,
        classification_report,
        confusion_matrix,
        f1_score,
        precision_score,
        recall_score,
    )
    HAS_SKLEARN = True
except ImportError:
    HAS_SKLEARN = False


# ---------------------------------------------------------------------------
# Parsers — extract structured fields from model output
# ---------------------------------------------------------------------------

def extract_cwe(text: str) -> str | None:
    """Extract the first CWE identifier like CWE-89 or CWE-79."""
    m = re.search(r'CWE-\d+', text, re.IGNORECASE)
    return m.group(0).upper() if m else None


def extract_is_vulnerable(text: str) -> bool | None:
    """Determine if the model classified the code as vulnerable."""
    lower = text.lower()
    if any(w in lower for w in ["no vulnerability", "not vulnerable", "no security issue"]):
        return False
    if any(w in lower for w in ["vulnerable", "vulnerability", "security issue", "unsafe", "insecure"]):
        return True
    if any(w in lower for w in ["benign", "clean"]):
        if "vulnerab" not in lower:
            return False
    return None


def extract_severity(text: str) -> str | None:
    """Extract severity level: critical, high, medium, low."""
    lower = text.lower()
    for level in ["critical", "high", "medium", "low"]:
        if level in lower:
            return level
    return None


def extract_fix_quality(text: str, reference_code: str) -> float:
    """Heuristic fix quality score 0.0–1.0.

    Checks for:
    - Presence of code blocks
    - Use of safe APIs (parameterized queries, safe hashing, etc.)
    - Absence of vulnerable patterns
    """
    score = 0.0
    if "```" in text:
        score += 0.3
    safe_patterns = [
        r"execute\(.*%s|execute\(.*\?|execute\(.*\$1",
        r"parameterized|preparedstatement|parameterized_query",
        r"hashlib\.(sha256|sha384|sha512|blake2)",
        r"scrypt|argon2|bcrypt|pbkdf2",
        r"defang|sanitize|escape|validate",
    ]
    for pat in safe_patterns:
        if re.search(pat, text, re.IGNORECASE):
            score += 0.1
    dangerous_patterns = [
        r"cursor\.execute\(f['\"]",
        r"\.format\(.*\buser\b|\.format\(.*\binput\b",
        r"\+.*request|request.*\+",
        r"pickle\.loads",
        r"md5\(|sha1\(",
    ]
    for pat in dangerous_patterns:
        if re.search(pat, text, re.IGNORECASE):
            score -= 0.15
    return max(0.0, min(1.0, score))


# ---------------------------------------------------------------------------
# Evaluation tasks
# ---------------------------------------------------------------------------

def evaluate_cwe_classification(
    model_outputs: list[str],
    ground_truth: list[str],
) -> dict:
    """Evaluate CWE classification accuracy."""
    predicted = [extract_cwe(out) for out in model_outputs]
    is_none = sum(1 for p in predicted if p is None)
    # Normalize CWE IDs
    corrected_pred = []
    corrected_true = []
    for p, t in zip(predicted, ground_truth):
        if p and t:
            corrected_pred.append(p.strip().upper())
            corrected_true.append(t.strip().upper())

    if len(corrected_pred) < 2:
        return {
            "n_samples": len(ground_truth),
            "n_parsed": len(corrected_pred),
            "n_parse_failures": is_none,
            "accuracy": None,
            "f1_macro": None,
            "f1_weighted": None,
            "error": "Too few parseable samples",
        }

    acc = accuracy_score(corrected_true, corrected_pred)
    f1_macro = f1_score(corrected_true, corrected_pred, average="macro", zero_division=0)
    f1_weighted = f1_score(corrected_true, corrected_pred, average="weighted", zero_division=0)

    return {
        "n_samples": len(ground_truth),
        "n_parsed": len(corrected_pred),
        "n_parse_failures": is_none,
        "accuracy": round(float(acc), 4),
        "f1_macro": round(float(f1_macro), 4),
        "f1_weighted": round(float(f1_weighted), 4),
    }


def evaluate_vulnerability_detection(
    model_outputs: list[str],
    ground_truth: list[bool],
) -> dict:
    """Evaluate binary vulnerability detection: precision, recall, F1, accuracy, FPR."""
    predicted = [extract_is_vulnerable(out) for out in model_outputs]
    parsed = [(p, t) for p, t in zip(predicted, ground_truth) if p is not None]
    if len(parsed) < 2:
        return {
            "n_samples": len(ground_truth),
            "n_parsed": len(parsed),
            "error": "Too few parseable samples",
        }
    pred_bin, true_bin = zip(*parsed)
    tn = sum(1 for p, t in zip(pred_bin, true_bin) if p == 0 and t == 0)
    fp = sum(1 for p, t in zip(pred_bin, true_bin) if p == 1 and t == 0)
    fn = sum(1 for p, t in zip(pred_bin, true_bin) if p == 0 and t == 1)
    tp = sum(1 for p, t in zip(pred_bin, true_bin) if p == 1 and t == 1)

    eps = 1e-10
    precision = tp / (tp + fp + eps)
    recall = tp / (tp + fn + eps)
    f1 = 2 * precision * recall / (precision + recall + eps)
    accuracy = (tp + tn) / (tp + tn + fp + fn + eps)
    fpr = fp / (fp + tn + eps)

    return {
        "n_samples": len(ground_truth),
        "n_parsed": len(parsed),
        "true_positives": tp,
        "false_positives": fp,
        "true_negatives": tn,
        "false_negatives": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "accuracy": round(accuracy, 4),
        "false_positive_rate": round(fpr, 4),
    }


def evaluate_severity_prediction(
    model_outputs: list[str],
    ground_truth: list[str],
) -> dict:
    """Evaluate severity level prediction (exact match)."""
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    predicted = [extract_severity(out) for out in model_outputs]
    matched = [(p, t) for p, t in zip(predicted, ground_truth) if p and t]

    if len(matched) < 2:
        return {
            "n_samples": len(ground_truth),
            "n_parsed": len(matched),
            "accuracy": None,
            "error": "Too few parseable samples",
        }
    pred_s, true_s = zip(*matched)
    acc = sum(1 for p, t in zip(pred_s, true_s) if p.lower() == t.lower()) / len(matched)

    ordinal_acc = 0.0
    for p, t in zip(pred_s, true_s):
        p_i = severity_order.get(p.lower(), 1)
        t_i = severity_order.get(t.lower(), 1)
        if abs(p_i - t_i) <= 1:
            ordinal_acc += 1.0
    ordinal_acc /= len(matched)

    return {
        "n_samples": len(ground_truth),
        "n_parsed": len(matched),
        "exact_match_accuracy": round(acc, 4),
        "ordinal_accuracy_within_1": round(ordinal_acc, 4),
    }


def evaluate_fix_quality(
    model_outputs: list[str],
    reference_codes: list[str],
) -> dict:
    """Evaluate secure fix quality on a 0–1 scale."""
    scores = [extract_fix_quality(out, ref) for out, ref in zip(model_outputs, reference_codes)]
    mean_score = float(np.mean(scores)) if scores else 0.0
    pass_rate = sum(1 for s in scores if s >= 0.6) / len(scores) if scores else 0.0
    return {
        "n_samples": len(scores),
        "mean_quality_score": round(mean_score, 4),
        "pass_rate_at_0.6": round(pass_rate, 4),
        "score_distribution": {
            "0.0–0.2": int(sum(1 for s in scores if s < 0.2)),
            "0.2–0.4": int(sum(1 for s in scores if 0.2 <= s < 0.4)),
            "0.4–0.6": int(sum(1 for s in scores if 0.4 <= s < 0.6)),
            "0.6–0.8": int(sum(1 for s in scores if 0.6 <= s < 0.8)),
            "0.8–1.0": int(sum(1 for s in scores if s >= 0.8)),
        },
    }


# ---------------------------------------------------------------------------
# Benchmark runner
# ---------------------------------------------------------------------------

def run_benchmark(
    model_fn: callable,
    benchmark_path: str,
    max_samples: int | None = None,
) -> dict:
    """Run full benchmark: load data, call model, evaluate all tasks."""
    # Load benchmark
    samples = []
    with open(benchmark_path) as f:
        for line in f:
            samples.append(json.loads(line))
    if max_samples:
        samples = samples[:max_samples]

    if not samples:
        return {"error": "Benchmark file is empty"}

    print(f"[benchmark] Loaded {len(samples)} samples from {benchmark_path}")

    # Build ground truth
    cwe_ground = []
    vuln_ground = []
    severity_ground = []
    reference_codes = []

    for s in samples:
        cwe_ground.append(s.get("cwe", ""))
        vuln_ground.append(s.get("is_vulnerable", True))
        severity_ground.append(s.get("severity", "high"))
        reference_codes.append(s.get("patched_code", ""))

    # Run model
    print("[benchmark] Running model inference...")
    model_outputs = []
    t0 = time.time()
    for i, s in enumerate(samples):
        code = s.get("vulnerable_code", "")
        lang = s.get("language", "python")
        prompt = (
            f"Analyze the following {lang} code for security vulnerabilities. "
            f"Identify the vulnerability type (CWE), severity, root cause, "
            f"attack scenario, and provide a secure fix with patched code.\n"
            f"```{lang}\n{code}\n```"
        )
        output = model_fn(prompt, s)
        model_outputs.append(output)
        if (i + 1) % 10 == 0:
            elapsed = time.time() - t0
            print(f"[benchmark]  {i + 1}/{len(samples)} ({elapsed:.1f}s)")

    total_time = time.time() - t0
    print(f"[benchmark] Inference complete: {total_time:.1f}s total, "
          f"{total_time / len(samples):.2f}s per sample")

    # Evaluate
    results = {
        "metadata": {
            "benchmark": benchmark_path,
            "n_samples": len(samples),
            "total_inference_time_s": round(total_time, 2),
            "avg_inference_time_s": round(total_time / len(samples), 3),
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        },
        "cwe_classification": evaluate_cwe_classification(model_outputs, cwe_ground),
        "vulnerability_detection": evaluate_vulnerability_detection(model_outputs, vuln_ground),
        "severity_prediction": evaluate_severity_prediction(model_outputs, severity_ground),
        "fix_quality": evaluate_fix_quality(model_outputs, reference_codes),
    }

    # Overall score
    scores = []
    if results["vulnerability_detection"].get("f1"):
        scores.append(results["vulnerability_detection"]["f1"])
    if results["cwe_classification"].get("accuracy"):
        scores.append(results["cwe_classification"]["accuracy"])
    if results["severity_prediction"].get("exact_match_accuracy"):
        scores.append(results["severity_prediction"]["exact_match_accuracy"])
    if results["fix_quality"].get("mean_quality_score"):
        scores.append(results["fix_quality"]["mean_quality_score"])

    results["overall_score"] = round(float(np.mean(scores)), 4) if scores else None
    return results


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="RakshakAI v2 — Public Benchmark")
    parser.add_argument("--model", default="Qwen/Qwen2.5-Coder-7B-Instruct",
                        help="HF model name or path")
    parser.add_argument("--benchmark", default="v2/benchmarks/security_benchmark.jsonl",
                        help="Path to benchmark JSONL")
    parser.add_argument("--output", default="v2/benchmarks/results.json",
                        help="Path to write results JSON")
    parser.add_argument("--max-samples", type=int, default=None,
                        help="Cap on benchmark samples (for quick tests)")
    parser.add_argument("--dummy", action="store_true",
                        help="Use dummy model for testing the framework")
    args = parser.parse_args()

    if args.dummy:
        def dummy_model(prompt, sample):
            cwe = sample.get("cwe", "CWE-89")
            sev = sample.get("severity", "high")
            return (
                f"Vulnerability detected: {cwe}. Severity: {sev}. "
                f"This code contains a security vulnerability. "
                f"The secure fix is to use parameterized queries. "
                f"```python\n{sample.get('patched_code', '')}\n```"
            )
        model_fn = dummy_model
    else:
        try:
            from transformers import AutoModelForCausalLM, AutoTokenizer
            import torch
            print(f"[benchmark] Loading model: {args.model}")
            tokenizer = AutoTokenizer.from_pretrained(args.model, trust_remote_code=True)
            model = AutoModelForCausalLM.from_pretrained(
                args.model,
                device_map="auto",
                torch_dtype=torch.bfloat16,
                trust_remote_code=True,
            )
            model.eval()

            def hf_model(prompt, sample):
                messages = [{"role": "user", "content": prompt}]
                inputs = tokenizer.apply_chat_template(
                    messages, return_tensors="pt", add_generation_prompt=True
                ).to(model.device)
                with torch.no_grad():
                    outputs = model.generate(
                        inputs,
                        max_new_tokens=512,
                        temperature=0.1,
                        do_sample=False,
                        pad_token_id=tokenizer.pad_token_id or tokenizer.eos_token_id,
                    )
                return tokenizer.decode(outputs[0][inputs.shape[1]:], skip_special_tokens=True)
            model_fn = hf_model
        except ImportError:
            print("ERROR: transformers not installed. Use --dummy for framework testing.")
            sys.exit(1)
        except Exception as e:
            print(f"ERROR loading model: {e}")
            sys.exit(1)

    results = run_benchmark(model_fn, args.benchmark, args.max_samples)

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\n[benchmark] Results written to {out_path}")
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
