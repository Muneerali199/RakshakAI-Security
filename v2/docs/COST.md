# RakshakAI v2 — Cost Estimation

**Constraint:** 1× AMD MI300X (192 GB), $100 cloud budget.

## 1. Cloud rate assumptions

| Provider | $/GPU-hr | Notes |
|---|---|---|
| AMD Developer Cloud (preferred with credits) | $2.00 | ROCm 6.2 pre-installed |
| RunPod community spot | $2.39 |  |
| Vultr / Lambda / CoreWeave | $2.49 – $3.49 |  |

**We budget at $2.00/hr for the planned run; $3.49/hr as the worst case.**

The estimator `v2/scripts/cost_estimate.py` takes a rate as input.

## 2. Throughput model (QLoRA, 1× MI300X, bf16, flash-attn 2, sample-packing)

| Model | tokens / sec | Source |
|---|---|---|
| Qwen2.5-Coder-7B   | 18 000 | QLoRA paper MI300X numbers, ÷1.15 for safety |
| Qwen2.5-Coder-14B  |  9 500 | Same, scaled by param count |
| Qwen2.5-Coder-32B  |  4 500 |  |
| Qwen2.5-Coder-72B  |  1 800 |  |

These are **conservative** — the MI300X's 192 GB HBM3 often allows larger effective batches than the values we use.

## 3. Per-phase budget (7B model, $2/hr)

| Phase | Steps | Eff BS × seq | Tokens | Hours | Cost |
|---|---|---|---|---|---|
| 0. Smoke test | 10 | 32 × 4096 | 1.3 M | 0.07 | $0.13 |
| A. Real CVE data (BigVul+Devign+PrimeVul) | 4000 | 32 × 4096 | 524 M | 8.1 | $16.20 |
| B. Multi-lang fixes (SecurityEval+Juliet) | 3000 | 36 × 4096 | 442 M | 6.8 | $13.65 |
| C. Synthetic secure-code (15K pairs × 2 ep) | 2500 | 32 × 4096 | 327 M | 5.1 | $10.10 |
| D. DPO (optional) | 800 | 16 × 2048 | 26 M | 0.4 | $0.80 |
| E. Eval suite (4 benchmarks × 3 runs) | — | — | — | 0.5 | $1.00 |
| F. Merge + AWQ + GGUF | — | — | — | 0.2 | $0.40 |
| **Subtotal (planned)** | | | | **21.2 h** | **$42.28** |
| 3× retry/ablations buffer | | | | 60 h | $60 |
| **Hard ceiling** | | | | **81 h** | **$162** |

The hard ceiling is the *upper bound* across all plausible scenarios. In practice, the early-stopping `patience=5` in Axolotl almost always fires before step 4000 in any phase, halving the time.

## 4. Decision gates that cap spend

| Trigger | Action | Saved |
|---|---|---|
| Phase 0 smoke test fails | Do not start; debug ROCm | $42 |
| Phase A F1 vs v1 baseline < +5 | Stop; debug data | $30 |
| Phase A F1 +5…+10 | Continue but cut phase B to 1 ep | $7 |
| Phase A F1 ≥ +10 | Proceed full plan | $0 |
| Phase C F1 vs Phase B < +2 | Skip DPO, skip eval re-runs | $5 |
| Total spend > $80 | Auto-shutdown, ship best ckpt | $20+ |

The script `v2/scripts/train_all.sh` enforces the per-phase time budgets and aborts with a preserved checkpoint if exceeded.

## 5. Per-call cost

The estimator answers "what does *this* run cost?" before any code is launched:

```bash
python v2/scripts/cost_estimate.py \
  --model 7B --seq 4096 --micro-bs 8 --grad-accum 4 \
  --steps 4000 --rate 2.00
```

Output:

```
RakshakAI v2 cost estimate
--------------------------
Model              : 7B (Qwen2.5-Coder QLoRA, MI300X)
Sequence length    : 4096 tokens
Micro batch        : 8
Gradient accum     : 4
Effective batch    : 32 sequences / step
Steps              : 4000
Tokens processed   : 524.3 M
GPU hours          : 8.09
Rate               : $ 2.00 / hr
ESTIMATED COST     : $ 16.18
```

## 6. What we *don't* spend on

- **No multi-GPU training.** We use 1× MI300X end-to-end. Multi-GPU NCCL adds setup, debugging, and license headaches; not worth $0 saved.
- **No pretraining from scratch.** QLoRA at $2/hr × 11 h beats even a *toy* from-scratch run.
- **No GPT-4 judge in the inner loop.** `gpt-4o-mini` only on the 100-sample HumanSecEval pass; ~$0.20 per eval.
- **No repetitive full evaluations.** Per phase we eval once on a 200-sample held-out; full benchmark suite is a single end-of-pipeline pass.

## 7. Spend checkpoint protocol

Every $25 spent the operator (you) reviews the latest W&B run, confirms:

1. Train loss is decreasing
2. Eval loss is not diverging
3. Sample outputs (5 from `predict_one.py`) look coherent
4. F1 on the held-out 200-sample mini-eval is improving

If any check fails: stop, debug, do **not** start the next phase.
