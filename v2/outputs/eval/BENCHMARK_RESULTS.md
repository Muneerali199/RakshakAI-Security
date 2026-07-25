# RakshakAI — Security Benchmark Results

## Our Model vs Big Models

| Model | Vulnerability Detection | CWE Accuracy | Avg Latency | Cost/Scan |
|-------|----------------------|--------------|-------------|-----------|
| **RakshakAI v3** (ours) | **XX.X%** | **XX.X%** | **X.XXs** | **$0** |
| GPT-4o | XX.X% | XX.X% | X.XXs | $0.03 |
| Claude Sonnet | XX.X% | XX.X% | X.XXs | $0.02 |
| Gemini 2.0 Flash | XX.X% | XX.X% | X.XXs | $0.01 |

> Run `python3 v2/scripts/benchmark_vs_big_models.py` after training to fill this table.
> Requires `OPENROUTER_API_KEY` for big model API calls.

---

## Vulnerability Detection

| Metric | Base Qwen2.5-Coder-7B | RakshakAI v3 (7B QLoRA) | RakshakAI v3 (14B QLoRA) |
|--------|----------------------|------------------------|-------------------------|
| Precision | — | — | — |
| Recall | — | — | — |
| F1 | — | — | — |
| Accuracy | — | — | — |
| False Positive Rate | — | — | — |

## CWE Classification

| Metric | Base Qwen2.5-Coder-7B | RakshakAI v3 (7B) | RakshakAI v3 (14B) |
|--------|----------------------|-------------------|--------------------|
| Top-1 Accuracy | — | — | — |
| Top-3 Accuracy | — | — | — |

## Inference Speed

| Model | Total Time | Avg/Sample |
|-------|------------|------------|
| RakshakAI v3 (7B, quantized) | — | — |
| RakshakAI v3 (14B, quantized) | — | — |

---

*Results will be populated after training + evaluation. See [TRAIN_V3.md](../../TRAIN_V3.md) and [BEAT_BIG_MODELS.md](../../BEAT_BIG_MODELS.md).*
