# RakshakAI Training Issues & Fixes

## 🚨 CRITICAL ISSUES FOUND

### 1. **VALIDATION DATA CONTAMINATION** ⚠️ HIGH PRIORITY
**Problem**: Your validation set has **17,823 samples** but the config only evaluates on **100 samples** (`eval_sample_max_num: 100`). Worse, I checked the val.jsonl and found this example:

```json
{
  "explanation": "CWE-119 is a resource management error...",
  "patched_code": "...same code...",
  "secure_fix_recommendation": "...same code..."
}
```

**This is GARBAGE data** — the "fix" is identical to the vulnerable code! This will teach your model to output useless fixes.

**Impact**: Model will learn bad patterns, get high loss on validation, training might not converge properly.

**Fix**: 
- Clean the validation set to remove examples where `patched_code == vulnerable_code`
- Use the full validation set or at least 1,000 samples for eval
- Add `eval_sample_packing: false` to see real validation loss

---

### 2. **LEARNING RATE TOO HIGH FOR DPO** ⚠️ HIGH PRIORITY
**Problem**: 
- SFT learning rate: `1.5e-4` ✅ OK
- DPO learning rate: `5e-6` ⚠️ TOO LOW for 7K samples

**Why this matters**: DPO with only 6,979 pairs needs more aggressive learning. At `5e-6` with 1 epoch, you'll barely update the weights.

**Fix**: Increase DPO LR to `1e-5` or `2e-5`, and consider 2-3 epochs for DPO.

---

### 3. **VAL SET IS 7% OF TRAIN (TOO LARGE)** ⚠️ MEDIUM
**Problem**: 
- Train: 250K
- Val: 17.8K (7%)
- Ideal: 2-5%

**Impact**: You're wasting 12K samples that could be used for training. Every sample counts for security domain.

**Fix**: Create a proper train/val split with 5K validation samples (2%).

---

### 4. **DPO SAMPLE SIZE TOO SMALL** ⚠️ MEDIUM
**Problem**: Only 6,979 DPO pairs. Research shows you need 10K+ for meaningful preference learning.

**Impact**: DPO stage might not significantly improve over SFT baseline.

**Fix**: Generate more DPO pairs (target 20K+) by:
1. Taking your SFT model's wrong predictions on validation
2. Creating (chosen=correct, rejected=wrong) pairs
3. Use GPT-4 to generate alternative bad fixes for each vulnerability

---

### 5. **NO EARLY STOPPING** ⚠️ LOW
**Problem**: Training runs for exactly 1 epoch with no early stopping. If the model converges at step 15,000, you waste compute and risk overfitting.

**Fix**: Add early stopping based on validation loss plateau.

---

### 6. **SEQUENCE LENGTH TOO SHORT FOR SECURITY** ⚠️ MEDIUM
**Problem**: 
- SFT: `sequence_len: 4096` ✅ OK
- DPO: `sequence_len: 2048` ⚠️ TOO SHORT

Real-world vulnerable functions can be 100+ lines. With 2048 tokens, you'll truncate complex examples.

**Fix**: Set DPO `sequence_len: 4096` (matches SFT).

---

### 7. **NO GRADIENT CLIPPING** ⚠️ LOW
**Problem**: No `max_grad_norm` set. Security datasets often have outliers (super long CVE descriptions) that cause gradient spikes.

**Fix**: Add `max_grad_norm: 1.0` to both configs.

---

### 8. **EVAL STEPS TOO FREQUENT IN SFT** ⚠️ LOW
**Problem**: `eval_steps: 500` means you eval every ~4% of training. With 250K samples and batch size 8, that's:
- Steps per epoch: 250,000 / (8 * 2) = 15,625 steps
- Evals per epoch: 15,625 / 500 = 31 evals

**Impact**: Eval takes time (~2 min each), so you lose ~1 hour just running eval.

**Fix**: Change to `eval_steps: 2000` (eval every 12%, ~8 times per epoch).

---

## ✅ THINGS THAT ARE CORRECT

1. **QLoRA config**: ✅ `lora_r: 32`, `lora_alpha: 32/64`, targets all projection layers
2. **Optimizer**: ✅ `adamw_8bit` is memory-efficient and works well
3. **Batch size**: ✅ `micro_batch_size: 8` with `gradient_accumulation_steps: 2` = effective batch of 16 for SFT
4. **Base model**: ✅ Qwen2.5-Coder-14B-Instruct is a solid choice
5. **Flash Attention**: ✅ Enabled
6. **LR scheduler**: ✅ Cosine with 3% warmup is standard

---

## 🔧 RECOMMENDED FIXES (Priority Order)

### Must Fix Before Training:
1. **Clean validation data** — Remove garbage examples
2. **Increase DPO learning rate** to `1e-5`
3. **Set DPO sequence length** to `4096`

### Should Fix for Better Results:
4. **Reduce validation set** from 17.8K → 5K samples
5. **Generate more DPO pairs** (target 20K)
6. **Add gradient clipping** (`max_grad_norm: 1.0`)

### Optional (Nice to Have):
7. **Reduce eval frequency** (`eval_steps: 2000`)
8. **Add early stopping** (stop if val loss doesn't improve for 3 evals)
9. **Run 2 epochs for DPO** instead of 1

---

## 📊 EXPECTED RESULTS AFTER FIXES

### Good Training Looks Like:
- **SFT Loss**: Starts ~2.5 → drops to ~1.0-1.2 by end
- **Val Loss**: Should track ~0.1-0.2 higher than train loss
- **DPO Loss**: Starts ~0.5 → drops to ~0.3-0.4

### Red Flags:
- Val loss > train loss by 0.5+ → overfitting or bad val data
- Loss stops decreasing after 20% of training → LR too low or data issue
- Loss explodes → gradient spike, need clipping

---

## 🚀 NEXT STEPS

1. Run `python3 v2/scripts/preflight_check.py` ✅ (already passed)
2. Apply the fixes below (I'll generate updated configs)
3. Test with 5% of data first (`debug_steps: 100`)
4. If debug run succeeds, launch full training
5. Monitor training logs for loss curves
6. After training, run benchmark to verify quality

