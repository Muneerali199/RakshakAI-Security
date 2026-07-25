# Train RakshakAI v3 — 500K CWE Dataset

## Prerequisites

1. **Modal account** with credits → https://modal.com
2. **HuggingFace token** with write access → https://hf.co/settings/tokens
3. **Dataset**: Push your 500K dataset to HF as `Muneerali199/rakshak-cwe-v3-data`

## Run Training (Modal A10G ~$10-15)

```bash
# Set secrets
export HF_TOKEN="hf_your_token_here"

# Launch training (takes ~6-8 hours)
modal run v2/modal_v3_train.py::train --detach
```

The script:
- Base: `Qwen/Qwen2.5-Coder-7B-Instruct`
- Method: QLoRA (4-bit NF4, rank 32)
- Batch: eff. batch size 8 (1 per device × 8 grad accum)
- Steps: 2000
- Sequence: 2048 tokens
- Output: pushes LoRA adapter to `Muneerali199/rakshak-cwe-v3`

## For 500K Full SFT (more compute)

Use the axolotl config:

```bash
# Requires GPU with 80GB+ (A100/H100)
export HF_TOKEN="hf_your_token_here"
accelerate launch v2/scripts/train_sft.py --config v2/configs/lightning_500k_sft.yaml
```

## Evaluation

```bash
# After training, run eval:
python3 v2/scripts/evaluate.py --model Muneerali199/rakshak-cwe-v3 --benchmark v2/outputs/eval/security_benchmark.jsonl
```

This populates `v2/outputs/eval/BENCHMARK_RESULTS.md` with real numbers.
