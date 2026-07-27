"""
RakshakAI v2 Phase B — Evaluation harness.

Evaluates Phase B model on the 500-sample locked benchmark.
Uses 8-bit for inference (4-bit NF4 is broken on ROCm/bnb 0.49.2).

Metrics: Detection F1, CWE acc, severity acc, fix quality, FPR, FNR,
          per-CWE breakdown, parse-failure rate.

Usage:
    python v2/scripts/evaluate_phase_b.py
    python v2/scripts/evaluate_phase_b.py --quick  (50 benchmark samples)
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
import hashlib
from collections import defaultdict, Counter
from pathlib import Path

os.environ["CUDA_VISIBLE_DEVICES"] = "0"
os.environ["HIP_VISIBLE_DEVICES"] = "0"
os.environ["TOKENIZERS_PARALLELISM"] = "false"

BASE_MODEL_PATH = "/workspace/RakshakAI/v2/inputs/models/Qwen2.5-Coder-7B-Instruct"
ADAPTER_PATH = "/workspace/RakshakAI/v2/outputs/runs/phase_b/final"
BENCHMARK_PATH = "/workspace/RakshakAI/v2/inputs/datasets/phase_b/benchmark_hard/benchmark_hard.jsonl"
LOCK_PATH = "/workspace/RakshakAI/v2/inputs/datasets/phase_b/benchmark_hard/BENCHMARK_LOCK_HARD.json"
OUTPUT_DIR = "/workspace/RakshakAI/v2/outputs/eval/phase_b"


def load_benchmark(path: str, max_samples: int | None = None) -> list[dict]:
    samples = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            samples.append(json.loads(line))
    if max_samples:
        samples = samples[:max_samples]
    return samples


def verify_lock(bench_path: str, lock_path: str) -> bool:
    content = Path(bench_path).read_bytes()
    actual = hashlib.sha256(content).hexdigest()
    lock = json.loads(Path(lock_path).read_text())
    expected = lock.get("sha256", "")
    ok = actual == expected
    if not ok:
        print(f"[WARN] SHA-256 mismatch! Expected={expected}, Actual={actual}")
    else:
        print(f"[OK] Benchmark SHA-256 verified: {actual}")
    return ok


def make_messages(code: str, lang: str) -> list[dict]:
    system = (
        "You are RakshakAI v2, a security-specialized code analysis model. "
        "Analyze the code snippet for security vulnerabilities. "
        "Think through your analysis step by step, then respond with a JSON object containing:\n"
        "{\n"
        '  "is_vulnerable": true/false,\n'
        '  "vulnerability_type": "<CWE-XXX or null>",\n'
        '  "severity": "<critical|high|medium|low|clean>",\n'
        '  "explanation": "<root cause>",\n'
        '  "patched_code": "<fixed code or null>",\n'
        '  "secure_fix_recommendation": "<fix description>"\n'
        "}\n"
        "If secure, set is_vulnerable=false, severity='clean'."
    )
    user = f"Analyze the following {lang} code for security vulnerabilities:\n\n```{lang}\n{code}\n```"
    return [{"role": "system", "content": system}, {"role": "user", "content": user}]


def generate(model, tokenizer, messages: list[dict], device: str) -> str:
    import torch
    inputs = tokenizer.apply_chat_template(
        messages, return_tensors="pt", add_generation_prompt=True
    ).to(device)
    attn_mask = torch.ones_like(inputs)
    with torch.no_grad():
        outputs = model.generate(
            inputs,
            attention_mask=attn_mask,
            max_new_tokens=512,
            do_sample=False,
            pad_token_id=tokenizer.pad_token_id or tokenizer.eos_token_id,
        )
    return tokenizer.decode(outputs[0][inputs.shape[1]:], skip_special_tokens=True)


def parse_json_output(text: str) -> dict | None:
    text = text.strip()
    start = text.find("{")
    end = text.rfind("}")
    if start >= 0 and end > start:
        try:
            return json.loads(text[start:end+1])
        except json.JSONDecodeError:
            pass
    return None


def extract_is_vulnerable(text: str, parsed: dict | None) -> bool | None:
    if parsed:
        v = parsed.get("is_vulnerable")
        if v is not None:
            return bool(v)
    lower = text.lower()
    if any(w in lower for w in ["no vulnerability", "not vulnerable", "secure", "benign", "clean", "is_vulnerable\": false"]):
        return False
    if any(w in lower for w in ["vulnerable", "vulnerability", "security issue", "unsafe", "insecure", "is_vulnerable\": true"]):
        return True
    return None


def extract_cwe(text: str, parsed: dict | None) -> str | None:
    if parsed:
        cwe = parsed.get("vulnerability_type") or parsed.get("cwe")
        if cwe and re.match(r"^CWE-\d+$", str(cwe).strip().upper()):
            return str(cwe).strip().upper()
    m = re.search(r"CWE-\d+", text, re.IGNORECASE)
    return m.group(0).upper() if m else None


def extract_severity(text: str, parsed: dict | None) -> str | None:
    if parsed:
        sev = parsed.get("severity")
        if sev and sev.lower() in ("critical", "high", "medium", "low", "clean"):
            return sev.lower()
    lower = text.lower()
    for level in ["critical", "high", "medium", "low", "clean"]:
        if level in lower:
            return level
    return None


def extract_fix_quality(text: str, parsed: dict | None) -> float:
    score = 0.0
    raw = text
    if parsed:
        raw = json.dumps(parsed)
    if "```" in raw:
        score += 0.3
    safe = [
        r"execute\(.*\?|execute\(.*\$1|execute\(.*%s",
        r"parameterized|preparedstatement",
        r"html\.escape|markupsafe\.escape|escapeHtml",
        r"strncpy|snprintf|strlcpy|strcpy_s",
        r"subprocess\.run\(\[|execFileSync",
        r"filepath\.join|path\.resolve",
        r"textContent|innerText",
        r"setString\(|setInt\(|setObject\(",
        r"bcrypt|argon2|scrypt|pbkdf2",
    ]
    for pat in safe:
        if re.search(pat, raw, re.IGNORECASE):
            score += 0.1
    dangerous = [
        r"\.format\(.*\b(user|input|name|id)\b|f['\"].*\{.*" + r"\b(user|input|name|id)\b",
        r"shell=True",
        r"eval\(|exec\(|pickle\.loads",
        r"\.innerHTML\s*\+?=",
        r"system\(|popen\(|execSync\(",
        r"strcpy\(|sprintf\(|gets\(",
    ]
    for pat in dangerous:
        if re.search(pat, raw, re.IGNORECASE):
            score -= 0.15
    return max(0.0, min(1.0, score))


def evaluate_model(model, tokenizer, device: str, name: str, samples: list[dict]) -> dict:
    print(f"\n{'='*60}")
    print(f"Evaluating: {name}  ({len(samples)} samples)")
    print(f"{'='*60}")

    outputs = []
    latencies = []
    t0 = time.time()

    for i, s in enumerate(samples):
        code = s.get("vulnerable_code", "")
        lang = s.get("language", "python")
        messages = make_messages(code, lang)
        t1 = time.time()
        generated = generate(model, tokenizer, messages, device)
        latencies.append(time.time() - t1)
        parsed = parse_json_output(generated)
        outputs.append({
            "id": s.get("id", i),
            "raw": generated,
            "parsed": parsed,
            "latency_s": latencies[-1],
        })
        if (i + 1) % 25 == 0:
            elapsed = time.time() - t0
            print(f"  [{i+1}/{len(samples)}] {elapsed:.0f}s elapsed, avg {elapsed/(i+1):.1f}s/sample")

    total_time = time.time() - t0
    print(f"  Done: {total_time:.0f}s total, {total_time/len(samples):.1f}s avg/sample")

    # --- Metrics ---
    results = {
        "name": name,
        "n_samples": len(samples),
        "total_time_s": round(total_time, 2),
        "avg_latency_s": round(sum(latencies) / len(latencies), 3),
    }

    # Vulnerability detection
    vuln_pred, vuln_true = [], []
    for o, s in zip(outputs, samples):
        p = extract_is_vulnerable(o["raw"], o["parsed"])
        t = s.get("is_vulnerable")
        if p is not None and t is not None:
            vuln_pred.append(p)
            vuln_true.append(t)

    eps = 1e-10
    tp = sum(1 for p, t in zip(vuln_pred, vuln_true) if p and t)
    fp = sum(1 for p, t in zip(vuln_pred, vuln_true) if p and not t)
    fn = sum(1 for p, t in zip(vuln_pred, vuln_true) if not p and t)
    tn = sum(1 for p, t in zip(vuln_pred, vuln_true) if not p and not t)

    precision = tp / (tp + fp + eps)
    recall = tp / (tp + fn + eps)
    f1 = 2 * precision * recall / (precision + recall + eps)
    accuracy = (tp + tn) / (tp + tn + fp + fn + eps)
    fpr = fp / (fp + tn + eps)
    fnr = fn / (fn + tp + eps)

    results["detection"] = {
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "accuracy": round(accuracy, 4),
        "fpr": round(fpr, 4),
        "fnr": round(fnr, 4),
        "n_parseable": len(vuln_pred),
        "n_parse_failures": len(samples) - len(vuln_pred),
    }

    # CWE classification (only for correctly identified vulnerable)
    cwe_pred, cwe_true = [], []
    for o, s, p, t in zip(outputs, samples, vuln_pred, vuln_true):
        if not t:
            continue  # only score CWE on actually-vulnerable samples
        cwe_p = extract_cwe(o["raw"], o["parsed"])
        cwe_t = s.get("cwe")
        if cwe_p and cwe_t:
            cwe_pred.append(cwe_p.upper())
            cwe_true.append(cwe_t.upper())

    cwe_acc = sum(1 for p, t in zip(cwe_pred, cwe_true) if p == t) / len(cwe_pred) if cwe_pred else 0.0
    results["cwe"] = {
        "accuracy": round(cwe_acc, 4),
        "n_evaluable": len(cwe_pred),
    }

    # Severity accuracy
    sev_correct, sev_total = 0, 0
    for o, s in zip(outputs, samples):
        p = extract_severity(o["raw"], o["parsed"])
        t = s.get("severity")
        if p and t:
            sev_total += 1
            if p == t.lower():
                sev_correct += 1
    sev_acc = sev_correct / sev_total if sev_total else 0.0
    results["severity"] = {
        "accuracy": round(sev_acc, 4),
        "n_evaluable": sev_total,
    }

    # Fix quality
    fix_scores = [extract_fix_quality(o["raw"], o["parsed"]) for o in outputs if s.get("is_vulnerable") is True]
    fix_mean = sum(fix_scores) / len(fix_scores) if fix_scores else 0.0
    fix_pass = sum(1 for s in fix_scores if s >= 0.6) / len(fix_scores) if fix_scores else 0.0
    results["fix_quality"] = {
        "mean_score": round(fix_mean, 4),
        "pass_rate_0.6": round(fix_pass, 4),
        "n_evaluable": len(fix_scores),
    }

    # Per-CWE breakdown
    per_cwe: dict = defaultdict(lambda: {"n": 0, "tp": 0, "fp": 0, "fn": 0, "tn": 0, "cwe_correct": 0, "cwe_total": 0})
    for o, s in zip(outputs, samples):
        gt_cwe = s.get("cwe") or "NONE"
        gt_vuln = s.get("is_vulnerable")
        pred_vuln = extract_is_vulnerable(o["raw"], o["parsed"])
        pred_cwe = extract_cwe(o["raw"], o["parsed"])
        k = gt_cwe.upper()
        per_cwe[k]["n"] += 1
        if pred_vuln is not None:
            if pred_vuln and gt_vuln is True:
                per_cwe[k]["tp"] += 1
            elif pred_vuln and (gt_vuln is False or gt_vuln is None):
                per_cwe[k]["fp"] += 1
            elif not pred_vuln and gt_vuln is True:
                per_cwe[k]["fn"] += 1
            else:
                per_cwe[k]["tn"] += 1
        if gt_vuln is True and pred_cwe:
            per_cwe[k]["cwe_total"] += 1
            if pred_cwe.upper() == gt_cwe.upper():
                per_cwe[k]["cwe_correct"] += 1

    per_cwe_report = {}
    for cwe, v in sorted(per_cwe.items()):
        eps = 1e-10
        prec = v["tp"] / (v["tp"] + v["fp"] + eps)
        rec = v["tp"] / (v["tp"] + v["fn"] + eps)
        f1_cwe = 2 * prec * rec / (prec + rec + eps)
        cwe_acc_cwe = v["cwe_correct"] / v["cwe_total"] if v["cwe_total"] else 0.0
        per_cwe_report[cwe] = {
            "n": v["n"],
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1": round(f1_cwe, 4),
            "cwe_accuracy": round(cwe_acc_cwe, 4),
        }
    results["per_cwe"] = per_cwe_report

    parse_failures = sum(1 for o in outputs if o["parsed"] is None)
    results["parse_failures"] = parse_failures
    results["parse_failure_rate"] = round(parse_failures / len(outputs), 4)

    # Language breakdown
    lang_results: dict = defaultdict(lambda: {"n": 0, "tp": 0, "fp": 0, "fn": 0, "tn": 0})
    for o, s in zip(outputs, samples):
        lang = s.get("language", "unknown")
        gt_vuln = s.get("is_vulnerable")
        pred_vuln = extract_is_vulnerable(o["raw"], o["parsed"])
        lang_results[lang]["n"] += 1
        if pred_vuln is not None and gt_vuln is not None:
            if pred_vuln and gt_vuln is True:
                lang_results[lang]["tp"] += 1
            elif pred_vuln and (gt_vuln is False or gt_vuln is None):
                lang_results[lang]["fp"] += 1
            elif not pred_vuln and gt_vuln is True:
                lang_results[lang]["fn"] += 1
            else:
                lang_results[lang]["tn"] += 1
    lang_report = {}
    for lang, v in lang_results.items():
        eps = 1e-10
        prec = v["tp"] / (v["tp"] + v["fp"] + eps)
        rec = v["tp"] / (v["tp"] + v["fn"] + eps)
        f1_lang = 2 * prec * rec / (prec + rec + eps)
        lang_report[lang] = {
            "n": v["n"],
            "f1": round(f1_lang, 4),
            "precision": round(prec, 4),
            "recall": round(rec, 4),
        }
    results["per_language"] = lang_report

    # Save outputs
    out_dir = Path(OUTPUT_DIR)
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"eval_{name.replace('/', '_').replace(' ', '_')}.json"
    out_path.write_text(json.dumps(results, indent=2))
    print(f"\n[results] saved to {out_path}")

    # Raw outputs
    raw_path = out_dir / f"outputs_{name.replace('/', '_').replace(' ', '_')}.jsonl"
    with raw_path.open("w") as f:
        for o in outputs:
            f.write(json.dumps(o, ensure_ascii=False) + "\n")
    print(f"[raw] saved to {raw_path}")

    return results


def print_summary(results: dict):
    d = results.get("detection", {})
    cwe = results.get("cwe", {})
    sev = results.get("severity", {})
    fx = results.get("fix_quality", {})

    print(f"\n{'='*60}")
    print(f"SUMMARY: {results['name']}")
    print(f"{'='*60}")
    print(f"  Samples:              {results['n_samples']}")
    print(f"  Total time:           {results['total_time_s']:.0f}s")
    print(f"  Avg latency:          {results['avg_latency_s']:.2f}s")
    print(f"  Parse failures:       {results.get('parse_failures', '?')} ({results.get('parse_failure_rate', 0)*100:.1f}%)")
    print(f"")
    print(f"  ── Vulnerability Detection ──")
    print(f"  F1:                   {d.get('f1', '?'):.4f}")
    print(f"  Precision:            {d.get('precision', '?'):.4f}")
    print(f"  Recall:               {d.get('recall', '?'):.4f}")
    print(f"  Accuracy:             {d.get('accuracy', '?'):.4f}")
    print(f"  FPR:                  {d.get('fpr', '?'):.4f}")
    print(f"  FNR:                  {d.get('fnr', '?'):.4f}")
    print(f"  TP/FP/FN/TN:          {d.get('tp',0)}/{d.get('fp',0)}/{d.get('fn',0)}/{d.get('tn',0)}")
    print(f"")
    print(f"  ── CWE Classification ──")
    print(f"  Accuracy:             {cwe.get('accuracy', '?'):.4f}  ({cwe.get('n_evaluable', 0)} samples)")
    print(f"")
    print(f"  ── Severity ──")
    print(f"  Accuracy:             {sev.get('accuracy', '?'):.4f}  ({sev.get('n_evaluable', 0)} samples)")
    print(f"")
    print(f"  ── Fix Quality ──")
    print(f"  Mean score:           {fx.get('mean_score', '?'):.4f}")
    print(f"  Pass@0.6:             {fx.get('pass_rate_0.6', '?'):.4f}")
    print(f"  Evaluable:            {fx.get('n_evaluable', 0)} (vuln only)")
    print(f"")
    print(f"  ── Per-Language F1 ──")
    for lang, v in sorted(results.get("per_language", {}).items()):
        print(f"  {lang:12s}  F1={v['f1']:.4f}  n={v['n']}")
    print(f"")


def main():
    import argparse
    ap = argparse.ArgumentParser(description="Phase B evaluation")
    ap.add_argument("--quick", action="store_true", help="Run on 50 samples only")
    ap.add_argument("--base-only", action="store_true", help="Only evaluate base model")
    ap.add_argument("--adapter-only", action="store_true", help="Only evaluate adapter")
    args = ap.parse_args()

    # Verify benchmark
    if Path(LOCK_PATH).exists():
        verify_lock(BENCHMARK_PATH, LOCK_PATH)

    # Load benchmark
    max_samp = 50 if args.quick else None
    samples = load_benchmark(BENCHMARK_PATH, max_samp)
    print(f"[eval] Loaded {len(samples)} benchmark samples")

    import torch
    from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig

    results = []

    # --- Evaluate base model (8-bit) ---
    if not args.adapter_only:
        print("\n[base] Loading base model (8-bit)...")
        tokenizer = AutoTokenizer.from_pretrained(BASE_MODEL_PATH, trust_remote_code=True)
        if tokenizer.pad_token is None:
            tokenizer.pad_token = tokenizer.eos_token

        bnb_config = BitsAndBytesConfig(
            load_in_8bit=True,
        )
        model = AutoModelForCausalLM.from_pretrained(
            BASE_MODEL_PATH,
            quantization_config=bnb_config,
            device_map="auto",
            torch_dtype=torch.bfloat16,
            trust_remote_code=True,
        )
        model.eval()
        device = model.device
        r = evaluate_model(model, tokenizer, device, "Qwen2.5-Coder-7B-Instruct (8-bit)", samples)
        results.append(r)
        print_summary(r)
        del model
        torch.cuda.empty_cache()

    # --- Evaluate Phase B adapter ---
    if not args.base_only:
        print("\n[adapter] Loading Phase B model (8-bit base + QLoRA adapter)...")
        tokenizer = AutoTokenizer.from_pretrained(BASE_MODEL_PATH, trust_remote_code=True)
        if tokenizer.pad_token is None:
            tokenizer.pad_token = tokenizer.eos_token

        bnb_config = BitsAndBytesConfig(
            load_in_8bit=True,
        )
        from peft import PeftModel
        model = AutoModelForCausalLM.from_pretrained(
            BASE_MODEL_PATH,
            quantization_config=bnb_config,
            device_map="auto",
            torch_dtype=torch.bfloat16,
            trust_remote_code=True,
        )
        model = PeftModel.from_pretrained(model, ADAPTER_PATH)
        model.eval()
        device = model.device
        r = evaluate_model(model, tokenizer, device, "Phase-B-adapter (8-bit)", samples)
        results.append(r)
        print_summary(r)
        del model
        torch.cuda.empty_cache()

    # --- Comparison ---
    if len(results) == 2:
        print(f"\n{'='*60}")
        print("COMPARISON: Base vs Phase B")
        print(f"{'='*60}")
        b, p = results
        for metric in ["f1", "precision", "recall", "fpr", "fnr"]:
            bv = b["detection"].get(metric, 0)
            pv = p["detection"].get(metric, 0)
            delta = pv - bv
            arrow = "▲" if delta > 0 else "▼" if delta < 0 else "="
            print(f"  Detection {metric:12s}: Base={bv:.4f}  PhaseB={pv:.4f}  {arrow}{delta:+.4f}")
        print(f"  CWE Accuracy:           Base={b['cwe']['accuracy']:.4f}  PhaseB={p['cwe']['accuracy']:.4f}  {'▲' if p['cwe']['accuracy'] > b['cwe']['accuracy'] else '▼'}{p['cwe']['accuracy']-b['cwe']['accuracy']:+.4f}")
        print(f"  Severity Accuracy:      Base={b['severity']['accuracy']:.4f}  PhaseB={p['severity']['accuracy']:.4f}  {'▲' if p['severity']['accuracy'] > b['severity']['accuracy'] else '▼'}{p['severity']['accuracy']-b['severity']['accuracy']:+.4f}")
        print(f"  Fix Quality:            Base={b['fix_quality']['mean_score']:.4f}  PhaseB={p['fix_quality']['mean_score']:.4f}  {'▲' if p['fix_quality']['mean_score'] > b['fix_quality']['mean_score'] else '▼'}{p['fix_quality']['mean_score']-b['fix_quality']['mean_score']:+.4f}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
