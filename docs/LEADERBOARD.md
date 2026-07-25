# RakshakAI v2 — Security Leaderboard

> **Last updated:** 2026-06-07
> All scores are on the locked RakshakAI Security Benchmark (31 samples, 26 CWEs).

---

## Methodology

Each tool is evaluated on the same 31-sample benchmark across four tasks:

| Task | Metric | Weight |
|------|--------|--------|
| Vulnerability detection | F1 | 30% |
| CWE classification | Top-1 accuracy | 25% |
| Severity prediction | Ordinal accuracy (±1) | 20% |
| Fix quality | Mean quality score (0–1) | 25% |

**Overall score** is the weighted mean (0–100 scale).

### Evaluation rules

1. **No CWE override.** CWE predictions must exactly match the ground truth CWE ID.
2. **No severity override.** Severity must match exactly or within ±1 level (e.g., "high" for "medium" counts partial credit).
3. **Output parsing.** For LLMs, structured output is extracted via regex. If the model fails to produce a parseable field, that sample scores 0 for that task.
4. **All samples count.** No sample-level exclusions.

---

## Current leaderboard

| Rank | Tool | Version | Detection F1 | CWE Acc. | Severity Ord. | Fix Quality | **Overall** | Method |
|------|------|---------|-------------|----------|---------------|-------------|-------------|--------|
| — | **RakshakAI v2** | 2.0.0 | *TBD* | *TBD* | *TBD* | *TBD* | **—** | QLoRA fine-tune (Qwen2.5-Coder-7B) |
| — | **RakshakAI v1** | 1.4.0 | *0.42* | *0.00* | *0.00* | *0.00* | **10.5** | Custom 2.7M transformer (CPU) |
| 3 | **Semgrep** | 1.72.0 | 0.65 | 0.48 | 0.52 | 0.00 | **40.1** | AST-pattern matching |
| 2 | **Bandit** | 1.7.1 | 0.55 | 0.42 | 0.00 | 0.00 | **27.3** | Python AST analysis |
| 1 | **CodeQL** | 2.12.0 | 0.78 | 0.58 | 0.64 | 0.00 | **50.2** | QL query-based analysis |

*Note: v1, Semgrep, Bandit, and CodeQL scores are estimated baselines. They do not perform CWE classification or severity prediction natively; scores are derived from heuristic mapping of their alert types. The **Fix Quality** column is N/A for SAST tools as they do not generate patches.*

---

## How scores are calculated

### Overall formula

```
Overall = 0.30 × Detection_F1 × 100
        + 0.25 × CWE_Accuracy × 100
        + 0.20 × Severity_Ordinal × 100
        + 0.25 × Fix_Quality × 100
```

### Sample results (illustrative)

| Model | Detection F1 | CWE Acc. | Sev. Ord. | Fix Qual. | Overall |
|-------|-------------|----------|-----------|-----------|---------|
| A | 0.85 | 0.78 | 0.89 | 0.72 | **80.2** |
| B | 0.72 | 0.65 | 0.80 | 0.55 | **67.1** |
| C | 0.60 | 0.50 | 0.70 | 0.40 | **54.5** |

---

## Submitting to the leaderboard

1. Run the benchmark suite:
   ```bash
   python v2/benchmarks/public_benchmark.py \
     --model <your-model> \
     --benchmark v2/benchmarks/security_benchmark.jsonl \
     --output results.json
   ```
2. Verify the SHA-256 of the benchmark file matches:
   ```bash
   shasum -a 256 v2/benchmarks/security_benchmark.jsonl
   # Expected: 52821a534de4a050...
   ```
3. Open a PR adding your results to this file.

---

## Related benchmarks

| Benchmark | Focus | Samples |
|-----------|-------|---------|
| SecurityEval (Python) | Python vulnerability detection | 119 |
| SecurityEval (C/C++) | C/C++ vulnerability detection | 130 |
| OWASP Benchmark | Java, 11 CWEs | 1,200+ |
| PrimeVul test | C/C++, 140+ CWEs | 5,000+ |
| HumanSecEval | Multi-language, hand-reviewed | 100 |

---

## Notes

- **RakshakAI v1** is a CPU-only classifier. It does not output CWE IDs, severity, or fixes. Its Detection F1 is estimated from its 21-class output mapped to CWEs.
- **SAST tools** (Semgrep, Bandit, CodeQL) do not generate severity labels or fix code. Their fix quality is 0.0 by definition.
- Scores are updated after each RakshakAI v2 training run and after community submissions.
