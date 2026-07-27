# RakshakAI v2 — Training Smoke Test Guide

> Use this guide to validate that the training pipeline is correct **before** launching a full 4,000-step run. The smoke test runs 10–50 steps and confirms: model loads, data flows, loss decreases, checkpoints save, and no hardware errors occur.

---

## 1. ROCm verification (before anything)

```bash
# Confirm ROCm sees the GPU
rocm-smi

# Expected output:
# ======================== ROCm System Management Interface ========================
# GPU  Temp   Perf  Pwr  VRAM%
# 0    45°C   auto  75W  0%

# ROCm version
cat /opt/rocm/.info/version
# Expected: 6.2.x or later

# PyTorch sees ROCm
python3 -c "import torch; print(f'ROCm: {torch.cuda.is_available()}, devices: {torch.cuda.device_count()}')"
# Expected: ROCm: True, devices: 1
```

## 2. Quick inference test (2 minutes)

```bash
# Load Qwen2.5-Coder-7B-Instruct and generate one response
python3 << 'EOF'
from transformers import AutoModelForCausalLM, AutoTokenizer
import torch

model_name = "Qwen/Qwen2.5-Coder-7B-Instruct"
tokenizer = AutoTokenizer.from_pretrained(model_name, trust_remote_code=True)
model = AutoModelForCausalLM.from_pretrained(
    model_name,
    device_map="auto",
    torch_dtype=torch.bfloat16,
    trust_remote_code=True,
)

messages = [{"role": "user", "content": "Say 'Hello from RakshakAI' and nothing else."}]
inputs = tokenizer.apply_chat_template(messages, return_tensors="pt").to(model.device)
outputs = model.generate(inputs, max_new_tokens=50)
print(tokenizer.decode(outputs[0], skip_special_tokens=True))
# Expected: "Hello from RakshakAI"
EOF
```

## 3. Smoke training run (10–50 steps, ~5 minutes)

### Step 3a: Create a smoke-test config

```bash
cp v2/configs/phase_a_sft.yaml v2/configs/smoke_test.yaml
```

Edit `v2/configs/smoke_test.yaml`:

```yaml
# Changes from phase_a_sft.yaml:
max_steps: 10                     # Was: 4000
eval_steps: 5                     # Run eval mid-run
save_steps: 10                    # Save final checkpoint
logging_steps: 1                  # Log every step
output_dir: /workspace/rakshakai/v2/outputs/smoke_test

# Reduce batch size for speed:
micro_batch_size: 2
gradient_accumulation_steps: 2

# Disable wandb for smoke test:
report_to: none
```

### Step 3b: Launch smoke test

```bash
accelerate launch -m axolotl.cli.train v2/configs/smoke_test.yaml 2>&1 | tee v2/outputs/smoke_test/smoke.log
```

## 4. Expected output and validation

### Loss behavior

| Step | Loss (approximate) | Notes |
|------|-------------------|-------|
| Step 0 | ~4.0–6.0 | Random-initialized LoRA, before any learning |
| Step 1 | ~3.0–5.0 | First gradient update |
| Step 5 | ~2.0–3.5 | Loss should clearly decrease |
| Step 10 | ~1.5–3.0 | Lower than step 5 — confirming learning |

**Pass condition:** Loss at step 10 < loss at step 1.
**Fail condition:** Loss stays flat or increases → check for data loading errors, learning rate issues, or NaN loss.

### GPU memory

Check `rocm-smi` during training:

```
GPU Memory (rocm-smi):
┌──────────────────────────────────────────────┐
│ GPU  VRAM%  Used    Available                │
│ 0    15%    28.5 GB 163.5 GB (of 192 GB)     │
└──────────────────────────────────────────────┘
```

**Pass condition:** Used VRAM < 50 GB (for 7B QLoRA). If > 60 GB, reduce `micro_batch_size`.
**Fail condition:** VRAM usage exceeds available memory → OOM error. Reduce `micro_batch_size` or `sequence_len`.

### Training speed

Look for this line in the log:

```
2026-06-07 12:00:00 | 10/10 [00:45<00:00, 0.22it/s]
```

Expected throughput for 10 steps with micro_bs=2, seq=4096:

| GPU | Expected speed | Notes |
|-----|---------------|-------|
| MI300X (single) | 0.2–0.5 it/s | Higher with flash_attention + sample_packing |
| MI300X (QLoRA NF4) | 0.3–0.8 it/s | Dependent on sequence length and batch |

**Pass condition:** Training completes without errors, speed is in expected range.

### Checkpoint

```bash
ls -la /workspace/rakshakai/v2/outputs/smoke_test/

# Expected:
# drwxr-xr-x  ... checkpoint-10/
# -rw-r--r--  ... logging.jsonl
# -rw-r--r--  ... train_log.txt
# -rw-r--r--  ... smt_ckpt_meta.json
```

**Pass condition:** Checkpoint directory exists with model files (adapter_model.safetensors, adapter_config.json).

## 5. Validation checklist

```bash
#!/usr/bin/env bash
# smoke_test_validate.sh — run after smoke test

ERRORS=0

echo "=== Smoke Test Validation ==="

# Check 1: No errors in log
if grep -i "error\|traceback\|cuda error\|nan\|out of memory" v2/outputs/smoke_test/smoke.log; then
    echo "❌ ERRORS FOUND in log"
    ERRORS=$((ERRORS + 1))
else
    echo "✅ No errors in log"
fi

# Check 2: Checkpoint file exists
if ls v2/outputs/smoke_test/checkpoint-*/adapter_model.safetensors 2>/dev/null; then
    echo "✅ Checkpoint saved"
else
    echo "❌ No checkpoint found"
    ERRORS=$((ERRORS + 1))
fi

# Check 3: Log contains step 10
if grep -q "10/10" v2/outputs/smoke_test/smoke.log; then
    echo "✅ All 10 steps completed"
else
    echo "❌ Training did not reach step 10"
    ERRORS=$((ERRORS + 1))
fi

# Check 4: Loss decreased
FIRST_LOSS=$(grep "loss:" v2/outputs/smoke_test/smoke.log | head -1 | grep -oP 'loss: \K[\d.]+')
LAST_LOSS=$(grep "loss:" v2/outputs/smoke_test/smoke.log | tail -1 | grep -oP 'loss: \K[\d.]+')
if python3 -c "exit(0 if $LAST_LOSS < $FIRST_LOSS else 1)"; then
    echo "✅ Loss decreased: $FIRST_LOSS → $LAST_LOSS"
else
    echo "❌ Loss did not decrease: $FIRST_LOSS → $LAST_LOSS"
    ERRORS=$((ERRORS + 1))
fi

echo ""
if [ $ERRORS -eq 0 ]; then
    echo "✅ ALL SMOKE TESTS PASSED — ready for full training"
else
    echo "❌ $ERRORS test(s) failed — investigate before proceeding"
fi
```

## 6. Failure recovery

| Symptom | Likely cause | Fix |
|---------|-------------|-----|
| `CUDA out of memory` | Batch size too large | Reduce `micro_batch_size` from 8 → 4 → 2 |
| `RuntimeError: expected scalar type Half but found Float` | Mixed-precision mismatch | Set `bf16: true` and `tf32: false` in config |
| Loss stays at ~4.0 for 10 steps | Learning rate too low, or data not loading | Check `datasets` path in config, verify data is non-empty |
| `wandb: Network error` | No internet / wandb blocked | Set `report_to: none` in config |
| Loss = NaN | FP16 overflow, gradient explosion | Reduce LR, enable `max_grad_norm: 1.0`, check for bad data |
| `tokenizer.eos_token` error | Tokenizer not loaded | Verify `tokenizer_type: Qwen2Tokenizer` in config |
| `dataset_prepared_path` conflict | Stale prepared data | Delete `dataset_prepared_path` directory and retry |
| Model loads but generates garbage | Tokenizer mismatch with model | Confirm `tokenizer_type` matches `base_model` |
| Speed < 0.1 it/s | sample_packing overhead with small batch | Only occurs at small step counts; full run will be faster. Or check flash_attention is enabled |

## 7. Cleanup

```bash
# Remove smoke test artifacts (before launching full training)
rm -rf v2/outputs/smoke_test
rm -f v2/configs/smoke_test.yaml
rm -rf /workspace/rakshakai/v2/inputs/datasets/pack/smoke_test_prepared
```
