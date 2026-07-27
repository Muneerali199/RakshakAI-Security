# RakshakAI v2 — Hyperparameter Recommendations

Final, opinionated, with the *reason* for every value. These are the exact
values in `v2/configs/*.yaml`; this document is the explanation.

## Base model

| Field | Value | Reason |
|---|---|---|
| `base_model` | `Qwen/Qwen2.5-Coder-7B-Instruct` | Best <10B open coder for code+security reasoning; Apache-2.0 |
| `model_type` | `Qwen2ForCausalLM` | Required by HF Transformers |
| `tokenizer_type` | `Qwen2Tokenizer` | Built-in 128K vocab, code-aware BPE |

## Quantization (QLoRA)

| Field | Value | Reason |
|---|---|---|
| `load_in_4bit` | `true` | Single MI300X, 7B bf16 = 14 GB; NF4 = 5 GB; saves 9 GB for activations |
| `bnb_4bit_quant_type` | `nf4` | Dettmers et al. — strictly better than FP4 for normal-distributed weights |
| `bnb_4bit_use_double_quant` | `true` | Quantizes the quantization constants; saves ~0.4 GB at zero accuracy cost |
| `bnb_4bit_compute_dtype` | `bfloat16` | MI300X has no fp16 tensor cores; bf16 only |

## LoRA

| Field | Value | Reason |
|---|---|---|
| `adapter` | `lora` | Not QLoRA — Axolotl's "lora" mode with `load_in_4bit: true` *is* QLoRA |
| `lora_r` | `64` | 7B with 9-field structured output benefits from high rank; 16 underfits, 128 is wasteful |
| `lora_alpha` | `128` | α/r = 2 is the QLoRA paper's stable choice |
| `lora_dropout` | `0.05` | High rank already regularizes; large dropout hurts more than helps |
| `lora_target_modules` | `all-linear` | Covers q/k/v/o + gate/up/down; security patterns are non-local |
| `lora_modules_to_save` | `["lm_head", "embed_tokens"]` | Output vocabulary is security-rich; this is the cheapest way to keep it accurate |
| `lora_use_rslora` | `true` | Rank-stabilized: scales `α/√r`, more stable at r≥32 |
| `lora_bias` | `none` | Standard for QLoRA; saves memory |

## Sequence and batch

| Field | Value | Reason |
|---|---|---|
| `sequence_len` | `4096` | 95% of CVE-bearing functions fit; larger = wasted compute on padding |
| `sample_packing` | `true` | With flash-attn, 3-4× throughput on short examples |
| `flash_attention` | `true` | Mandatory for 4K ctx on 7B in 30 GB |
| `pad_to_sequence_len` | `false` | Sample packing already eliminates padding |
| `micro_batch_size` | `8` (A), `6` (B), `4` (C) | Phase A packs tightest; phases B/C have longer assistant outputs |
| `gradient_accumulation_steps` | `4` (A), `6` (B), `8` (C) | Inverse to micro_bs; effective batch = 32 |
| `group_by_length` | `false` | Sample packing already amortizes length variance |
| `eval_batch_size` | `= micro_batch_size` | Match training memory profile |

## Optimizer

| Field | Value | Reason |
|---|---|---|
| `optimizer` | `paged_adamw_8bit` | Cuts optimizer state 4× (1 GB instead of 4 GB on LoRA-only trainables) |
| `lr` | `2.0e-4` (A), `1.0e-4` (B/C), `5.0e-6` (DPO) | QLoRA paper for A; refined for continued phases; DPO standard |
| `lr_scheduler` | `cosine` | Standard for SFT; smooth decay to zero |
| `warmup_ratio` | `0.03` | 3% warmup; matches QLoRA paper |
| `weight_decay` | `0.0` | LoRA weights only; weight decay empirically hurts |
| `max_grad_norm` | `1.0` | Clip bf16 spikes; standard |
| `bf16` | `true` | MI300X CDNA3: bf16 only, no fp16 |
| `tf32` | `false` | Not meaningful for bf16 |
| `gradient_checkpointing` | `true` | Trades 30% compute for 60% activation memory |
| `gradient_checkpointing_kwargs.use_reentrant` | `false` | Required for the modern torch impl; avoids silent gradient errors |
| `neftune_noise_alpha` | `5` | NEFTune: 4-6% absolute accuracy lift on instruction following (NEFTune paper) |

## Steps and early stopping

| Field | Value | Reason |
|---|---|---|
| `max_steps` | 4000 / 3000 / 2500 / 800 | ~2 epochs on each phase's data; cuts automatically via early stop |
| `eval_steps` | `100` (A), `80` (B), `60` (C) | Tied to ~1 epoch on each phase's data |
| `save_steps` | `= eval_steps` | Top-3 by `eval_loss` always available |
| `save_total_limit` | `3` | Disk ceiling |
| `evaluation_strategy` | `steps` | We need mid-training signal |
| `load_best_model_at_end` | `true` | Ship the best, not the last |
| `metric_for_best_model` | `eval_loss` | Cheaper proxy; supplement with `predict_one.py` eyeball checks |
| `greater_is_better` | `false` | Loss should go down |
| `early_stopping_patience` | `5` (A/B), `4` (C) | 5 evals × 100 steps = 500 steps of no improvement = stop |
| `early_stopping_threshold` | `0.001` | Avoids stopping on noise |

## DPO (Phase D, optional)

| Field | Value | Reason |
|---|---|---|
| `dpo_beta` | `0.1` | Standard; lower = more weight on reward, more divergence risk |
| `dpo_loss_type` | `sigmoid` | Standard; try `ipo` if training becomes unstable |
| `dpo_label_smoothing` | `0.0` | Off by default |
| `lr` | `5.0e-6` | DPO is sensitive to LR; 1e-5 already destroys the model |
| `max_grad_norm` | `1.0` | Same as SFT |
| `gradient_accumulation_steps` | `8` | DPO memory profile is ~2× SFT |
| `max_steps` | `800` | DPO over-trains fast; we cap at ~1 epoch on 10K pairs |

## Inference (after training)

| Field | Value | Reason |
|---|---|---|
| `dtype` (vLLM) | `bfloat16` (merged) / `float16` (AWQ) | Match the quantization format |
| `gpu_memory_utilization` | `0.85` | Leaves 15% for KV cache and CUDA context |
| `max_model_len` | `8192` | 2× training seq len, covers 99% of PR diffs |
| `tensor_parallel_size` | `1` | One MI300X; do not enable TP |
| `enforce_eager` | `false` | CUDA graphs help; the MI300X kernel cache warms in ~1 minute |
| `temperature` | `0.0` | Greedy; security reviews must be reproducible |
| `max_tokens` | `1500` | Enough for full 9-field JSON + 200-line patch |

## Sanity-check recipe

Before any full run, do this 5-minute smoke test:

```bash
# 1. 10-step microtraining
python -m axolotl.cli.train v2/configs/phase_a_sft.yaml --max-steps 10 \
  --output-dir /tmp/axolotl-smoke

# 2. Predict on a known-vulnerable snippet
python v2/scripts/predict_one.py \
  --model /tmp/axolotl-smoke/merged \
  --code 'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")' \
  --language python
```

If step 2 returns valid JSON with `cwe=CWE-89`, the pipeline is healthy.
