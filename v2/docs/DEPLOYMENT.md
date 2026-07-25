# RakshakAI v2 — Deployment Architecture

## Tier model

| Tier | Engine | Latency | Cost / 1k calls | Use |
|---|---|---|---|---|
| **0 — Regex prefilter** | Python rules | <1 ms | ~$0 | Drop obvious junk (e.g. empty files) |
| **1 — v1 CPU classifier** | `rakshakai.inference` (v1 model) | 5–50 ms | ~$0 | "Reflex" 21-class label; bypasses LLM if confident-clean |
| **2 — v2 LLM** | Qwen2.5-Coder-7B (AWQ 4-bit, vLLM) | 0.5–2.5 s | ~$0.40 | Structured 9-field review |
| **3 — Judge LLM** (eval only) | gpt-4o-mini | 2–4 s | ~$0.20 / 100 reviews | Scoring HumanSecEval, optional escalation |

The FastAPI server wires tiers 1 + 2. Tier 0 is a one-liner in the request handler. Tier 3 is offline.

## Single-host production layout

```
                        ┌─────────────────────────┐
   VS Code  ──HTTPS──▶  │  FastAPI  (uvicorn)     │  ◀── GitHub Action
   CLI      ──HTTP ──▶  │  /v2/scan, /review, …  │  ◀── Web dashboard
                        └────────┬────────────────┘
                                 │
                ┌────────────────┼────────────────┐
                │                                │
                ▼                                ▼
       v1 prefilter (CPU)              vLLM (1× MI300X)
       `rakshakai.inference`            AWQ 4-bit Qwen2.5-Coder-7B
       21-class, <50 ms                0.5–2.5 s p95
```

Containerization:

```yaml
# docker-compose.yml
services:
  rakshakai-v1:
    image: ghcr.io/Muneerali199/rakshakai:v1-latest
    expose: ["8000"]
  rakshakai-v2:
    image: ghcr.io/Muneerali199/rakshakai:v2-awq-latest
    deploy:
      resources:
        reservations:
          devices:
            - capabilities: [gpu]
    environment:
      RAKSHAK_V2_V1_PREFILTER: "1"
      RAKSHAK_V2_URL: "http://rakshakai-v1:8000"
    ports: ["8080:8080"]
```

## Cloud options

### A. Single host, both tiers (cheapest)

Run the FastAPI server on the same MI300X that vLLM uses; v1's CPU footprint is negligible.

| Cloud | Hourly | Notes |
|---|---|---|
| AMD Developer Cloud | $2.00 | Easiest ROCm support |
| RunPod community | $2.39 | Hourly billing |
| Vultr | $2.49 | Stable |
| CoreWeave | $3.49 | Best ROCm maturity |

### B. CPU-only deployment (no GPU)

Use the **GGUF Q5_K_M** export with `llama-server` from llama.cpp. Latency p95 ≈ 5–10 s on a 16-core CPU. Fine for batch / nightly scans, too slow for IDE on-save.

### C. Edge deployment (developer laptop)

```bash
# Ollama
ollama serve
# (import GGUF)
ollama create rakshakai-v2 -f v2/deploy/Modelfile.rakshakai-v2
ollama run rakshakai-v2 "scan this code: ..."
```

## SLA targets

| Metric | Target |
|---|---|
| Availability (p99) | 99.5% monthly |
| Latency p50 (tier 2) | < 1.0 s |
| Latency p95 (tier 2) | < 2.5 s |
| Throughput | 10 requests/s sustained on 1× MI300X |
| Cost per scan | < $0.001 at the planned mix |
| Hallucination rate | < 5% on HumanSecEval |

## Observability

- **Structured logs** in JSON: `request_id, code_hash, engine, latency_ms, cwe, severity`.
- **W&B Weave** for trace-level debugging of slow or wrong responses.
- **Prometheus** `/metrics` endpoint: latency histogram, per-CWE counts, parse-error rate.
- **Alerting**: parse-error rate > 5%, latency p95 > 3 s, GPU mem > 90% for > 5 min.

## Update cadence

| Change | Frequency | Cost |
|---|---|---|
| New CVE → eval set | Weekly (Sunday 02:00 UTC cron) | <$1 / week |
| Re-fine-tune | Monthly if eval F1 drops > 3 pts | ~$15 |
| Base model upgrade | On upstream major release (e.g. Qwen3) | ~$30 |

## Disaster recovery

- All LoRA checkpoints mirrored to S3 (`s3://rakshakai-v2/ckpt/`).
- Merged bf16 + AWQ GGUF stored in HuggingFace Hub under `Muneerali199/rakshakai-v2`.
- Eval report from the last successful run pinned in W&B; serve the model that produced it.
- If GPU is unavailable, the v1 prefilter still answers at <50 ms with 21-class labels.
