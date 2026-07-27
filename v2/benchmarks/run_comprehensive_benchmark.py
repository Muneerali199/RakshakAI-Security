#!/usr/bin/env python3
"""RakshakAI — Comprehensive 72-Sample Benchmark Runner

Evaluates a model on 72 CWE vulnerability samples across 57 CWE types
and 11 programming languages.

Metrics:
  - CWE classification accuracy (exact + family)
  - Vulnerability detection (precision, recall, F1, FPR)
  - Severity prediction (exact match + ordinal)
  - Overall pass rate

Usage:
    # Dummy test (no model needed):
    python v2/benchmarks/run_comprehensive_benchmark.py --mode dummy

    # Full eval on GPU with LoRA adapter:
    python v2/benchmarks/run_comprehensive_benchmark.py \\
        --mode hf \\
        --base-model Qwen/Qwen2.5-Coder-14B-Instruct \\
        --adapter Muneerali199/rakshak-cwe-14b-sft-step375 \\
        --load-in-4bit

    # Push results to HF:
        ... --push-to-hub --hf-repo Muneerali199/rakshak-cwe-14b-sft-final

Output:
    v2/benchmarks/results/results_{timestamp}.json
    v2/benchmarks/results/per_sample_{timestamp}.jsonl
"""
import argparse, json, os, re, sys, time, hashlib
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Tuple

# ── Utilities ────────────────────────────────────────────────────────

def extract_cwe(text: str) -> Optional[str]:
    m = re.search(r'CWE-\d+', text, re.IGNORECASE)
    return m.group(0).upper() if m else None

def extract_is_vulnerable(text: str) -> Optional[bool]:
    lower = text.lower()
    if any(w in lower for w in ["no vulnerability", "not vulnerable", "no security issue"]):
        return False
    if any(w in lower for w in ["vulnerable", "vulnerability", "security issue", "unsafe", "insecure"]):
        return True
    if any(w in lower for w in ["benign", "clean"]):
        if "vulnerab" not in lower:
            return False
    return None

def extract_severity(text: str) -> Optional[str]:
    lower = text.lower()
    for level in ["critical", "high", "medium", "low"]:
        if level in lower:
            return level
    return None

def extract_json_from_response(text: str) -> Optional[dict]:
    match = re.search(r'```(?:json)?\n(.*?)\n```', text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(1))
        except json.JSONDecodeError:
            pass
    return None

def get_cwe_family(cwe: str) -> str:
    parts = cwe.split("-")
    return parts[-1] if len(parts) > 1 else ""

def normalize_cwe(cwe: str) -> str:
    c = cwe.strip().upper()
    if not c.startswith("CWE-"):
        c = "CWE-" + c
    return c

# ── Build prompt ────────────────────────────────────────────────────

def build_prompt(code: str, lang: str) -> str:
    return (
        f"Analyze the following {lang} code for security vulnerabilities. "
        f"Identify the vulnerability type (CWE), severity, root cause, "
        f"attack scenario, and provide a secure fix with patched code.\n"
        f"```{lang}\n{code}\n```"
    )

# ── Inference backends ──────────────────────────────────────────────

class DummyModel:
    def generate(self, prompt: str, sample: dict) -> str:
        cwe = sample.get("cwe", "CWE-89")
        sev = sample.get("severity", "high")
        patch = sample.get("patched_code", "")
        return (
            f"Vulnerability detected: {cwe}. Severity: {sev}. "
            f"This code contains a security vulnerability. "
            f"The secure fix is to use parameterized queries. "
            f"```python\n{patch}\n```"
        )

def load_hf_model(base_model: str, adapter: Optional[str] = None,
                  load_in_4bit: bool = False, load_in_8bit: bool = False):
    from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
    import torch

    tokenizer = AutoTokenizer.from_pretrained(base_model, trust_remote_code=True)
    if tokenizer.pad_token_id is None:
        tokenizer.pad_token_id = tokenizer.eos_token_id

    quant_config = None
    if load_in_4bit:
        quant_config = BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_compute_dtype=torch.bfloat16,
            bnb_4bit_quant_type="nf4",
        )
    elif load_in_8bit:
        quant_config = BitsAndBytesConfig(load_in_8bit=True)

    model = AutoModelForCausalLM.from_pretrained(
        base_model,
        quantization_config=quant_config,
        device_map="auto",
        torch_dtype=torch.bfloat16 if not quant_config else None,
        trust_remote_code=True,
    )

    if adapter:
        from peft import PeftModel
        model = PeftModel.from_pretrained(model, adapter)

    model.eval()

    def generate(prompt: str, sample: dict) -> str:
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
                pad_token_id=tokenizer.pad_token_id,
            )
        return tokenizer.decode(outputs[0][inputs.shape[1]:], skip_special_tokens=True)

    return generate

# ── Metrics ─────────────────────────────────────────────────────────

def compute_metrics(results: List[dict]) -> dict:
    vuln_preds = []
    vuln_trues = []
    cwe_correct = 0
    cwe_family_correct = 0
    cwe_total_parsed = 0
    sev_exact = 0
    sev_ordinal = 0
    sev_total = 0
    total = len(results)

    for r in results:
        # Vulnerability detection
        p_vuln = r["predicted_vulnerable"]
        t_vuln = r["true_vulnerable"]
        if p_vuln is not None:
            vuln_preds.append(p_vuln)
            vuln_trues.append(t_vuln)

        # CWE classification
        p_cwe = r["predicted_cwe"]
        t_cwe = r["true_cwe"]
        if p_cwe and t_cwe:
            cwe_total_parsed += 1
            if normalize_cwe(p_cwe) == normalize_cwe(t_cwe):
                cwe_correct += 1
            if get_cwe_family(p_cwe) == get_cwe_family(t_cwe):
                cwe_family_correct += 1

        # Severity
        p_sev = r["predicted_severity"]
        t_sev = r["true_severity"]
        if p_sev and t_sev:
            sev_total += 1
            if p_sev.lower() == t_sev.lower():
                sev_exact += 1
            sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
            pi = sev_order.get(p_sev.lower(), -1)
            ti = sev_order.get(t_sev.lower(), -1)
            if pi >= 0 and ti >= 0 and abs(pi - ti) <= 1:
                sev_ordinal += 1

    # Binary classification metrics
    eps = 1e-10
    tn = sum(1 for p, t in zip(vuln_preds, vuln_trues) if p == 0 and t == 0)
    fp = sum(1 for p, t in zip(vuln_preds, vuln_trues) if p == 1 and t == 0)
    fn = sum(1 for p, t in zip(vuln_preds, vuln_trues) if p == 0 and t == 1)
    tp = sum(1 for p, t in zip(vuln_preds, vuln_trues) if p == 1 and t == 1)

    precision = tp / (tp + fp + eps)
    recall = tp / (tp + fn + eps)
    f1 = 2 * precision * recall / (precision + recall + eps)
    accuracy = (tp + tn) / (tp + tn + fp + fn + eps)
    fpr = fp / (fp + tn + eps)
    spec = tn / (tn + fp + eps)

    # Vulnerability pass rate: % of vulnerable code detected
    vuln_pass_rate = tp / (tp + fn + eps) if (tp + fn) > 0 else 0
    # Clean pass rate: % of clean code correctly identified
    clean_pass_rate = tn / (tn + fp + eps) if (tn + fp) > 0 else 0

    return {
        "n_total": total,
        "n_vulnerable": sum(1 for r in results if r["true_vulnerable"]),
        "n_clean": sum(1 for r in results if not r["true_vulnerable"]),
        "vulnerability_detection": {
            "true_positives": tp,
            "false_positives": fp,
            "true_negatives": tn,
            "false_negatives": fn,
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "specificity": round(spec, 4),
            "f1_score": round(f1, 4),
            "accuracy": round(accuracy, 4),
            "false_positive_rate": round(fpr, 4),
            "vuln_pass_rate": round(vuln_pass_rate, 4),
            "clean_pass_rate": round(clean_pass_rate, 4),
        },
        "cwe_classification": {
            "n_parsed": cwe_total_parsed,
            "n_unparsed": total - cwe_total_parsed,
            "exact_match_accuracy": round(cwe_correct / cwe_total_parsed, 4) if cwe_total_parsed > 0 else 0,
            "family_accuracy": round(cwe_family_correct / cwe_total_parsed, 4) if cwe_total_parsed > 0 else 0,
            "exact_correct": cwe_correct,
            "family_correct": cwe_family_correct,
        },
        "severity_prediction": {
            "n_parsed": sev_total,
            "exact_match_accuracy": round(sev_exact / sev_total, 4) if sev_total > 0 else 0,
            "ordinal_accuracy": round(sev_ordinal / sev_total, 4) if sev_total > 0 else 0,
        },
    }

# ── Load benchmark ──────────────────────────────────────────────────

def load_benchmark(path: str) -> List[dict]:
    samples = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                samples.append(json.loads(line))
    return samples

# ── Run benchmark ───────────────────────────────────────────────────

def run_benchmark(model_fn, samples: List[dict]) -> Tuple[List[dict], float]:
    results = []
    t0 = time.time()
    for i, s in enumerate(samples):
        code = s.get("vulnerable_code", "")
        lang = s.get("language", "python")
        prompt = build_prompt(code, lang)

        t_start = time.time()
        try:
            raw_output = model_fn(prompt, s)
            duration = time.time() - t_start
        except Exception as e:
            raw_output = f"ERROR: {e}"
            duration = time.time() - t_start

        # Parse output
        parsed = extract_json_from_response(raw_output)
        predicted_cwe = None
        predicted_severity = None
        predicted_vulnerable = None

        if parsed:
            vulns = parsed.get("vulnerabilities", [])
            if vulns:
                predicted_cwe = vulns[0].get("cwe", "")
                predicted_severity = vulns[0].get("severity", "")
                predicted_vulnerable = True
            else:
                predicted_vulnerable = False
        else:
            predicted_cwe = extract_cwe(raw_output)
            predicted_severity = extract_severity(raw_output)
            predicted_vulnerable = extract_is_vulnerable(raw_output)

        # Ground truth
        true_cwe = s.get("cwe", "")
        true_severity = s.get("severity", "high")
        true_vulnerable = s.get("is_vulnerable", True)

        result = {
            "id": s.get("id", f"sample-{i}"),
            "language": lang,
            "true_cwe": true_cwe,
            "true_severity": true_severity,
            "true_vulnerable": true_vulnerable,
            "predicted_cwe": predicted_cwe or "",
            "predicted_severity": predicted_severity or "",
            "predicted_vulnerable": predicted_vulnerable,
            "cwe_exact_match": normalize_cwe(predicted_cwe or "") == normalize_cwe(true_cwe),
            "cwe_family_match": get_cwe_family(predicted_cwe or "") == get_cwe_family(true_cwe),
            "vuln_detected_correctly": (
                predicted_vulnerable == true_vulnerable if predicted_vulnerable is not None else None
            ),
            "duration_s": round(duration, 3),
            "response_preview": raw_output[:300],
        }
        results.append(result)

        if (i + 1) % 10 == 0 or i == len(samples) - 1:
            elapsed = time.time() - t0
            rate = (i + 1) / elapsed if elapsed > 0 else 0
            print(f"  [{i+1}/{len(samples)}] {result['id']} | CWE: {predicted_cwe or '?'} (true: {true_cwe}) | {duration:.1f}s | {rate:.1f} samples/s")

    total_time = time.time() - t0
    return results, total_time

# ── Generate markdown report ────────────────────────────────────────

def generate_report(metrics: dict, results: List[dict], total_time: float, args) -> str:
    vd = metrics["vulnerability_detection"]
    cwe = metrics["cwe_classification"]
    sev = metrics["severity_prediction"]

    lines = [
        "# Comprehensive Benchmark Results",
        "",
        f"**Date**: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}",
        f"**Model**: {args.adapter or args.base_model or 'dummy'}",
        f"**Base Model**: {args.base_model or 'N/A'}",
        f"**Samples**: {metrics['n_total']} ({metrics['n_vulnerable']} vulnerable, {metrics['n_clean']} clean)",
        f"**Total Time**: {total_time:.1f}s ({total_time/max(metrics['n_total'], 1):.2f}s/sample)",
        "",
        "---",
        "",
        "## Vulnerability Detection",
        f"- Precision: {vd['precision']:.2%}",
        f"- Recall: {vd['recall']:.2%}",
        f"- F1 Score: {vd['f1_score']:.2%}",
        f"- Accuracy: {vd['accuracy']:.2%}",
        f"- False Positive Rate: {vd['false_positive_rate']:.2%}",
        f"- Specificity: {vd['specificity']:.2%}",
        f"- Vuln Pass Rate: {vd['vuln_pass_rate']:.2%}",
        f"- Clean Pass Rate: {vd['clean_pass_rate']:.2%}",
        f"- TP: {vd['true_positives']} FP: {vd['false_positives']} TN: {vd['true_negatives']} FN: {vd['false_negatives']}",
        "",
        "## CWE Classification",
        f"- Exact Match Accuracy: {cwe['exact_match_accuracy']:.2%}",
        f"- Family Accuracy: {cwe['family_accuracy']:.2%}",
        f"- Parsed: {cwe['n_parsed']}/{metrics['n_total']}",
        "",
        "## Severity Prediction",
        f"- Exact Match Accuracy: {sev['exact_match_accuracy']:.2%}",
        f"- Ordinal Accuracy (±1 level): {sev['ordinal_accuracy']:.2%}",
        "",
        "---",
        "",
        "## Per-Sample Results",
        "",
        "| ID | Language | True CWE | Predicted CWE | CWE Match | Vuln Match | Severity |",
        "|---|---|---|---|---|---|---|",
    ]
    for r in results:
        cwe_icon = "✅" if r["cwe_family_match"] else "❌"
        vuln_icon = "✅" if r["vuln_detected_correctly"] else "❌"
        lines.append(
            f"| {r['id']} | {r['language']} | {r['true_cwe']} | "
            f"{r['predicted_cwe'] or '?'} | {cwe_icon} | {vuln_icon} | "
            f"{r['predicted_severity'] or '?'} |"
        )

    lines.extend([
        "",
        f"## Confusion Matrix",
        f"```",
        f"                Predicted Vuln   Predicted Clean",
        f"Actual Vuln     {vd['true_positives']:<5}              {vd['false_negatives']:<5}",
        f"Actual Clean    {vd['false_positives']:<5}              {vd['true_negatives']:<5}",
        f"```",
        "",
        f"## CWE Coverage",
        f"Correct families: {cwe['family_correct']}/{metrics['n_total']}",
        f"Exact matches: {cwe['exact_correct']}/{cwe['n_parsed']}",
    ])
    return "\n".join(lines)

# ── Charts generator ────────────────────────────────────────────────

def generate_charts(metrics: dict, results: List[dict], output_dir: str):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        import numpy as np
    except ImportError:
        print("matplotlib not installed — skipping chart generation")
        return

    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    bg = "#0a0a0f"
    fg = "#aaaaaa"

    # 1. Overall metrics bar chart
    fig, ax = plt.subplots(figsize=(10, 6))
    fig.patch.set_facecolor(bg)
    ax.set_facecolor(bg)
    vd = metrics["vulnerability_detection"]
    cwe = metrics["cwe_classification"]
    sev = metrics["severity_prediction"]

    bars_data = [
        ("Detection\nF1", vd["f1_score"] * 100),
        ("Detection\nPrecision", vd["precision"] * 100),
        ("Detection\nRecall", vd["recall"] * 100),
        ("Detection\nAccuracy", vd["accuracy"] * 100),
        ("CWE\nExact", cwe["exact_match_accuracy"] * 100),
        ("CWE\nFamily", cwe["family_accuracy"] * 100),
        ("Severity\nExact", sev["exact_match_accuracy"] * 100),
        ("Severity\nOrdinal", sev["ordinal_accuracy"] * 100),
    ]
    names = [b[0] for b in bars_data]
    vals = [b[1] for b in bars_data]
    colors = ["#00ff88" if v >= 80 else "#ffcc00" if v >= 50 else "#ff4444" for v in vals]

    bars = ax.bar(names, vals, color=colors, edgecolor="white", linewidth=0.5)
    for bar, v in zip(bars, vals):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 1,
                f"{v:.1f}%", ha="center", fontsize=10, fontweight="bold", color="white")
    ax.set_ylim(0, 105)
    ax.set_title("RakshakAI 14B — Comprehensive Benchmark Metrics", fontsize=14, fontweight="bold", color="white", pad=15)
    ax.tick_params(colors=fg, labelsize=9)
    for s in ["top", "right"]:
        ax.spines[s].set_visible(False)
    ax.spines["left"].set_color("#333")
    ax.spines["bottom"].set_color("#333")
    ax.set_ylabel("Score (%)", color=fg)
    ax.grid(axis="y", alpha=0.15, color="white")
    plt.tight_layout()
    plt.savefig(out / "benchmark_metrics.png", dpi=200, bbox_inches="tight", facecolor=bg)
    plt.close()
    print(f"  Chart saved: {out / 'benchmark_metrics.png'}")

    # 2. Per-language breakdown
    fig, ax = plt.subplots(figsize=(12, 5))
    fig.patch.set_facecolor(bg)
    ax.set_facecolor(bg)
    by_lang = defaultdict(list)
    for r in results:
        by_lang[r["language"]].append(r)
    langs = sorted(by_lang.keys())
    lang_acc = []
    lang_counts = []
    for lang in langs:
        corr = sum(1 for r in by_lang[lang] if r["vuln_detected_correctly"])
        lang_acc.append(corr / len(by_lang[lang]) * 100 if by_lang[lang] else 0)
        lang_counts.append(len(by_lang[lang]))

    bars = ax.bar(langs, lang_acc, color="#00ccff", edgecolor="white", linewidth=0.5)
    for bar, acc, cnt in zip(bars, lang_acc, lang_counts):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 1,
                f"{acc:.0f}%\n(n={cnt})", ha="center", fontsize=8, fontweight="bold", color="white")
    ax.set_ylim(0, 110)
    ax.set_title("Detection Accuracy by Language", fontsize=14, fontweight="bold", color="white", pad=15)
    ax.tick_params(colors=fg, labelsize=9)
    for s in ["top", "right"]:
        ax.spines[s].set_visible(False)
    ax.spines["left"].set_color("#333")
    ax.spines["bottom"].set_color("#333")
    ax.set_ylabel("Pass Rate (%)", color=fg)
    ax.grid(axis="y", alpha=0.15, color="white")
    plt.tight_layout()
    plt.savefig(out / "accuracy_by_language.png", dpi=200, bbox_inches="tight", facecolor=bg)
    plt.close()
    print(f"  Chart saved: {out / 'accuracy_by_language.png'}")

    # 3. Per-CWE breakdown (top 20)
    fig, ax = plt.subplots(figsize=(14, 6))
    fig.patch.set_facecolor(bg)
    ax.set_facecolor(bg)
    by_cwe = defaultdict(list)
    for r in results:
        tcwe = r["true_cwe"]
        if tcwe == "CWE-000":
            continue
        by_cwe[tcwe].append(r)
    sorted_cwe = sorted(by_cwe.items(), key=lambda x: len(x[1]), reverse=True)[:25]
    cwe_names = [c[0] for c in sorted_cwe]
    cwe_acc = []
    cwe_cnt = []
    for cwe_name, cwe_results in sorted_cwe:
        corr = sum(1 for r in cwe_results if r["cwe_family_match"])
        cwe_acc.append(corr / len(cwe_results) * 100)
        cwe_cnt.append(len(cwe_results))

    bars = ax.barh(cwe_names, cwe_acc, color=["#00ff88" if a >= 80 else "#ffcc00" if a >= 50 else "#ff4444" for a in cwe_acc],
                   edgecolor="white", linewidth=0.5, height=0.6)
    for bar, acc, cnt in zip(bars, cwe_acc, cwe_cnt):
        ax.text(bar.get_width() + 1, bar.get_y() + bar.get_height() / 2,
                f"{acc:.0f}% (n={cnt})", va="center", fontsize=8, color="white")
    ax.set_xlim(0, 110)
    ax.set_title("Detection Accuracy by CWE Type", fontsize=14, fontweight="bold", color="white", pad=15)
    ax.tick_params(colors=fg, labelsize=9)
    for s in ["top", "right"]:
        ax.spines[s].set_visible(False)
    ax.spines["left"].set_color("#333")
    ax.spines["bottom"].set_color("#333")
    ax.set_xlabel("Pass Rate (%)", color=fg)
    ax.grid(axis="x", alpha=0.15, color="white")
    plt.tight_layout()
    plt.savefig(out / "accuracy_by_cwe.png", dpi=200, bbox_inches="tight", facecolor=bg)
    plt.close()
    print(f"  Chart saved: {out / 'accuracy_by_cwe.png'}")

# ── Main ────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="RakshakAI Comprehensive Benchmark Runner")
    parser.add_argument("--mode", choices=["dummy", "hf"], default="dummy",
                        help="dummy=test framework, hf=load from HF")
    parser.add_argument("--base-model", default="Qwen/Qwen2.5-Coder-14B-Instruct",
                        help="Base model name or path")
    parser.add_argument("--adapter", default=None,
                        help="PEFT LoRA adapter (HF repo or local path)")
    parser.add_argument("--benchmark", default=None,
                        help="Path to benchmark JSONL (default: comprehensive_benchmark.jsonl)")
    parser.add_argument("--output-dir", default="v2/benchmarks/results",
                        help="Output directory for results and charts")
    parser.add_argument("--load-in-4bit", action="store_true",
                        help="Load base model in 4-bit quantization")
    parser.add_argument("--load-in-8bit", action="store_true",
                        help="Load base model in 8-bit quantization")
    parser.add_argument("--max-samples", type=int, default=None,
                        help="Cap on number of samples to evaluate")
    parser.add_argument("--generate-charts", action="store_true",
                        help="Generate matplotlib charts")
    parser.add_argument("--push-to-hub", action="store_true",
                        help="Push results to HuggingFace")
    parser.add_argument("--hf-repo", default="Muneerali199/rakshak-cwe-14b-sft-final",
                        help="HF repo to push results to")
    parser.add_argument("--hf-token", default=None,
                        help="HF token (default: env HF_TOKEN)")
    args = parser.parse_args()

    # Benchmark path
    if args.benchmark is None:
        args.benchmark = str(Path(__file__).resolve().parent / "comprehensive_benchmark.jsonl")

    if not os.path.exists(args.benchmark):
        print(f"ERROR: Benchmark not found: {args.benchmark}")
        print("Run build_comprehensive_benchmark.py first")
        sys.exit(1)

    # Load samples
    samples = load_benchmark(args.benchmark)
    if args.max_samples:
        samples = samples[:args.max_samples]
    print(f"\n{'='*60}")
    print(f" RakshakAI Comprehensive Benchmark")
    print(f"{'='*60}")
    print(f" Samples: {len(samples)} ({sum(1 for s in samples if s.get('is_vulnerable', True))} vulnerable, "
          f"{sum(1 for s in samples if not s.get('is_vulnerable', True))} clean)")
    print(f" Mode: {args.mode}")
    if args.adapter:
        print(f" Adapter: {args.adapter}")
    print(f" Base: {args.base_model}")
    print(f"{'='*60}\n")

    # Load model
    if args.mode == "dummy":
        model = DummyModel().generate
        print("[dummy] Using dummy model (correct answers from ground truth)")
    elif args.mode == "hf":
        print(f"[hf] Loading model...")
        model = load_hf_model(
            args.base_model,
            adapter=args.adapter,
            load_in_4bit=args.load_in_4bit,
            load_in_8bit=args.load_in_8bit,
        )
        print("[hf] Model loaded")

    # Run
    results, total_time = run_benchmark(model, samples)

    # Compute metrics
    metrics = compute_metrics(results)
    metrics["timestamp"] = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    metrics["config"] = {
        "mode": args.mode,
        "base_model": args.base_model,
        "adapter": args.adapter,
        "n_samples": len(samples),
    }

    # Print summary
    vd = metrics["vulnerability_detection"]
    cwe_m = metrics["cwe_classification"]
    sev = metrics["severity_prediction"]
    print(f"\n{'='*60}")
    print(f" RESULTS")
    print(f"{'='*60}")
    print(f" Vulnerability Detection:")
    print(f"   F1:        {vd['f1_score']:.2%}")
    print(f"   Precision: {vd['precision']:.2%}")
    print(f"   Recall:    {vd['recall']:.2%}")
    print(f"   Accuracy:  {vd['accuracy']:.2%}")
    print(f"   FPR:       {vd['false_positive_rate']:.2%}")
    print(f" CWE Classification:")
    print(f"   Exact:     {cwe_m['exact_match_accuracy']:.2%}")
    print(f"   Family:    {cwe_m['family_accuracy']:.2%}")
    print(f" Severity:")
    print(f"   Exact:     {sev['exact_match_accuracy']:.2%}")
    print(f"   Ordinal:   {sev['ordinal_accuracy']:.2%}")
    print(f" Time: {total_time:.1f}s total, {total_time/len(samples):.2f}s/sample")
    print(f"{'='*60}\n")

    # Save results
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    # Full results JSON
    output = {
        "metrics": metrics,
        "summary": {
            "vulnerability_detection_f1": vd["f1_score"],
            "vulnerability_detection_accuracy": vd["accuracy"],
            "cwe_exact_accuracy": cwe_m["exact_match_accuracy"],
            "cwe_family_accuracy": cwe_m["family_accuracy"],
            "severity_exact_accuracy": sev["exact_match_accuracy"],
            "total_samples": len(samples),
            "total_time_s": round(total_time, 2),
            "avg_time_per_sample_s": round(total_time / len(samples), 3),
        },
    }
    results_path = out_dir / f"results_{timestamp}.json"
    with open(results_path, "w") as f:
        json.dump(output, f, indent=2)
    print(f"Results saved: {results_path}")

    # Per-sample results
    per_sample_path = out_dir / f"per_sample_{timestamp}.jsonl"
    with open(per_sample_path, "w") as f:
        for r in results:
            f.write(json.dumps(r) + "\n")
    print(f"Per-sample saved: {per_sample_path}")

    # Markdown report
    report = generate_report(metrics, results, total_time, args)
    report_path = out_dir / f"report_{timestamp}.md"
    with open(report_path, "w") as f:
        f.write(report)
    print(f"Report saved: {report_path}")

    # Charts
    if args.generate_charts:
        print(f"\nGenerating charts...")
        generate_charts(metrics, results, str(out_dir))

    # Push to HF
    if args.push_to_hub:
        try:
            token = args.hf_token or os.environ.get("HF_TOKEN")
            if not token:
                print("ERROR: --hf-token or HF_TOKEN env var required for push-to-hub")
                sys.exit(1)
            from huggingface_hub import HfApi
            api = HfApi(token=token)
            repoid = args.hf_repo

            # Upload results
            api.upload_file(
                path_or_fileobj=str(results_path),
                path_in_repo=f"benchmarks/results/{results_path.name}",
                repo_id=repoid, repo_type="model",
            )
            api.upload_file(
                path_or_fileobj=str(per_sample_path),
                path_in_repo=f"benchmarks/results/{per_sample_path.name}",
                repo_id=repoid, repo_type="model",
            )
            api.upload_file(
                path_or_fileobj=str(report_path),
                path_in_repo=f"benchmarks/results/{report_path.name}",
                repo_id=repoid, repo_type="model",
            )

            # Also upload benchmark JSONL
            api.upload_file(
                path_or_fileobj=args.benchmark,
                path_in_repo="benchmarks/comprehensive_benchmark.jsonl",
                repo_id=repoid, repo_type="model",
            )

            # Upload charts
            if args.generate_charts:
                for chart in out_dir.glob("*.png"):
                    api.upload_file(
                        path_or_fileobj=str(chart),
                        path_in_repo=f"benchmarks/{chart.name}",
                        repo_id=repoid, repo_type="model",
                    )

            # Update README badge section
            readme_path = out_dir / "README_benchmark.md"
            with open(readme_path, "w") as f:
                f.write(f"## Benchmark Results ({timestamp})\n\n")
                f.write(f"| Metric | Score |\n|---|---|\n")
                f.write(f"| Vulnerability Detection F1 | {vd['f1_score']:.2%} |\n")
                f.write(f"| Vulnerability Detection Accuracy | {vd['accuracy']:.2%} |\n")
                f.write(f"| CWE Exact Match | {cwe_m['exact_match_accuracy']:.2%} |\n")
                f.write(f"| CWE Family Match | {cwe_m['family_accuracy']:.2%} |\n")
                f.write(f"| Severity Exact | {sev['exact_match_accuracy']:.2%} |\n")
                f.write(f"| Severity Ordinal | {sev['ordinal_accuracy']:.2%} |\n")
                f.write(f"| Samples | {len(samples)} ({metrics['n_vulnerable']} vuln, {metrics['n_clean']} clean) |\n")

            api.upload_file(
                path_or_fileobj=str(readme_path),
                path_in_repo="benchmarks/README.md",
                repo_id=repoid, repo_type="model",
            )

            print(f"Results pushed to HF: {repoid}/tree/main/benchmarks/results/")
        except Exception as e:
            print(f"ERROR pushing to HF: {e}")

    # Latest symlink
    latest_path = out_dir / "latest.json"
    with open(latest_path, "w") as f:
        json.dump(output["summary"], f, indent=2)
    print(f"Latest summary: {latest_path}")

    # Return pass rate for exit code
    final_score = vd["f1_score"]
    print(f"\n Final Score: {final_score:.2%}")
    sys.exit(0 if final_score >= 0.5 else 1)

if __name__ == "__main__":
    main()
