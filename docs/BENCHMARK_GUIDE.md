# RakshakAI v2 — Benchmark Guide

This document describes how to evaluate RakshakAI v2 (or any HuggingFace-compatible model) using the public benchmark framework.

---

## Overview

The benchmark evaluates four capabilities:

| Task | Metric | Target |
|------|--------|--------|
| **Vulnerability detection** | Precision, Recall, F1, Accuracy, FPR | F1 ≥ 0.85 |
| **CWE classification** | Top-1 accuracy, macro F1 | Accuracy ≥ 0.78 |
| **Severity prediction** | Exact match, ordinal accuracy (±1) | Ordinal ≥ 0.85 |
| **Secure fix quality** | Heuristic quality score (0–1), pass rate | Score ≥ 0.60 |

**Overall score:** Mean of the four task scores.

---

## Benchmark datasets

| Dataset | Samples | Languages | CWEs | Source |
|---------|---------|-----------|------|--------|
| `v2/benchmarks/security_benchmark.jsonl` | 31 | Python, JS, Java, C, C++, Go, Rust | 26 | Locked, manually reviewed |
| `v2/inputs/datasets/raw/securityeval_converted.jsonl` | 121 | Python, C, C++ | 13 | SecurityEval v2.1 |
| `v2/inputs/datasets/instruct/test.jsonl` | 5,459 | 13 languages | 682 | Instruct-formatted test split |

---

## Running the benchmark

### Prerequisites

```bash
pip install torch transformers scikit-learn
```

### Quick test with dummy model

```bash
python v2/benchmarks/public_benchmark.py --dummy --max-samples 5
```

This runs 5 samples through a mock model to verify the framework works.

### Full evaluation

```bash
# Evaluate RakshakAI v2
python v2/benchmarks/public_benchmark.py \
  --model /workspace/rakshakai/v2/outputs/merged/rakshakai-v2-bf16 \
  --benchmark v2/benchmarks/security_benchmark.jsonl \
  --output v2/benchmarks/results.json

# Evaluate against a HuggingFace model
python v2/benchmarks/public_benchmark.py \
  --model Qwen/Qwen2.5-Coder-7B-Instruct \
  --benchmark v2/benchmarks/security_benchmark.jsonl \
  --output v2/benchmarks/results_baseline.json
```

### Compare models

```bash
python v2/scripts/compare_benchmarks.py \
  --baseline v2/benchmarks/results_baseline.json \
  --candidate v2/benchmarks/results.json
```

---

## Understanding the output

### Vulnerability detection

```
{
  "precision": 0.9231,
  "recall": 0.8571,
  "f1": 0.8889,
  "accuracy": 0.9000,
  "false_positive_rate": 0.0435
}
```

- **True positive:** Vulnerable code correctly flagged
- **False positive:** Benign code flagged as vulnerable
- **False negative:** Vulnerable code missed
- **FPR target:** ≤ 0.08 for production

### CWE classification

```
{
  "accuracy": 0.8125,
  "f1_macro": 0.7843,
  "f1_weighted": 0.8210
}
```

Only counted for samples where the model outputs a parseable CWE ID. `f1_macro` treats each CWE equally; `f1_weighted` accounts for class imbalance.

### Severity prediction

```
{
  "exact_match_accuracy": 0.6842,
  "ordinal_accuracy_within_1": 0.8947
}
```

Exact match is strict; ordinal allows ±1 level (e.g., predicting "high" for "medium" is accepted).

### Fix quality

```
{
  "mean_quality_score": 0.7234,
  "pass_rate_at_0.6": 0.7419
}
```

The quality score is a heuristic based on code block presence, safe API usage, and absence of dangerous patterns. A score ≥ 0.6 is considered a passing fix.

---

## Interpretation targets

| Stage | Min overall score |
|-------|-------------------|
| Development checkpoint | 0.55 |
| Pre-release candidate | 0.70 |
| Production release | 0.80 |

---

## Adding new benchmarks

1. Create a JSONL file with these fields:
   - `id`: unique identifier
   - `language`: programming language
   - `vulnerable_code`: the vulnerable code snippet
   - `patched_code` (optional): the secure version
   - `cwe`: CWE identifier (e.g., "CWE-89")
   - `severity`: "critical", "high", "medium", or "low"
   - `is_vulnerable`: `true` or `false`
   - `explanation`: description of the vulnerability
2. Run the benchmark with `--benchmark path/to/new_benchmark.jsonl`
3. Submit results to the RakshakAI project for inclusion in the leaderboard
