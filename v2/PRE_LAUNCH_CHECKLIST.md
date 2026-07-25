# Pre-Launch Checklist for RakshakAI Training

**DO NOT START TRAINING until ALL items are checked ✅**

---

## 📋 Critical Checklist (Must Pass)

### 1. Datasets ✅
- [ ] `train_87k_with_reasoning.jsonl` exists (259,269 lines, 1.2GB)
- [ ] `val_cleaned.jsonl` exists (5,000 lines, 13MB)
- [ ] `dpo_train.jsonl` exists (6,979 lines, 10MB)
- [ ] All files have valid JSON format
- [ ] Datasets uploaded to HuggingFace: `Muneerali199/rakshak-cwe-v3-data`

**Verify:**
```bash
cd v2/inputs/datasets/axolotl
wc -l train_87k_with_reasoning.jsonl val_cleaned.jsonl dpo_train.jsonl
head -n 1 train_87k_with_reasoning.jsonl | python3 -m json.tool
```

---

### 2. Configs ✅
- [ ] `v2/configs/lightning_14b_sft_PRODUCTION.yaml` points to `train_87k_with_reasoning.jsonl`
- [ ] `v2/configs/lightning_14b_dpo_PRODUCTION.yaml` points to `dpo_train.jsonl`
- [ ] SFT learning rate: `1.5e-4` ✓
- [ ] DPO learning rate: `1e-5` ✓
- [ ] DPO sequence length: `4096` ✓
- [ ] Gradient clipping enabled in both configs
- [ ] 4-bit quantization enabled
- [ ] Flash attention enabled

**Verify:**
```bash
grep "path:" v2/configs/lightning_14b_sft_PRODUCTION.yaml
grep "learning_rate:" v2/configs/lightning_14b_sft_PRODUCTION.yaml
grep "max_grad_norm:" v2/configs/lightning_14b_sft_PRODUCTION.yaml
```

---

### 3. Scripts ✅
- [ ] `v2/scripts/train_production.sh` uses PRODUCTION configs
- [ ] `v2/scripts/install_dependencies.sh` exists
- [ ] `v2/scripts/pre_training_audit.py` exists
- [ ] All scripts have execute permissions

**Verify:**
```bash
chmod +x v2/scripts/*.sh v2/scripts/*.py
head -20 v2/scripts/train_production.sh | grep PRODUCTION
```

---

### 4. Environment ✅
- [ ] Running on Lightning.ai A100 80GB instance
- [ ] CUDA available (check with `nvidia-smi`)
- [ ] HF_TOKEN environment variable set (for auto-upload)
- [ ] GitHub repo accessible (for git clone)
- [ ] Sufficient disk space (>100GB free)

**Verify:**
```bash
nvidia-smi
echo $HF_TOKEN
df -h | grep " /$"
```

---

### 5. Dependencies ✅
- [ ] PyTorch 2.5.1 installed
- [ ] transformers 4.47.1 installed
- [ ] axolotl 0.6.0 installed
- [ ] bitsandbytes installed
- [ ] peft installed
- [ ] accelerate installed

**Verify:**
```bash
bash v2/scripts/install_dependencies.sh
```

---

### 6. Pre-Training Audit ✅
- [ ] Run `python3 v2/scripts/pre_training_audit.py`
- [ ] Zero critical errors
- [ ] Warnings reviewed and acceptable
- [ ] Dataset using `train_87k_with_reasoning.jsonl` (NOT `train_250k.jsonl`)

**Verify:**
```bash
python3 v2/scripts/pre_training_audit.py
# Must output: ✅ READY FOR TRAINING!
```

---

## 💰 Budget Check

- **Instance**: Lightning.ai A100 80GB
- **Rate**: $2.50/hour
- **Budget**: $14.00 = 5.6 hours max
- **Estimated time**: 
  - SFT: ~3.6 hours
  - DPO: ~1.6 hours
  - Total: ~5.2 hours = ~$13.00
- **Buffer**: $1.00 for overhead

✅ Budget sufficient

---

## 🎯 Expected Results

### Good Training Looks Like:

**SFT (259K samples, ~3.6h)**:
```
Step 1000:   train_loss=2.45, eval_loss=2.52
Step 5000:   train_loss=1.85, eval_loss=1.91
Step 10000:  train_loss=1.38, eval_loss=1.44
Step 15000:  train_loss=1.20, eval_loss=1.26  ← GOOD
```

**DPO (7K pairs, 2 epochs, ~1.6h)**:
```
Epoch 1 Step 500:  train_loss=0.52, dpo_loss=0.48
Epoch 2 Step 1000: train_loss=0.36, dpo_loss=0.33  ← GOOD
```

### Red Flags to Watch For:

❌ **Loss = NaN** → Gradient explosion (shouldn't happen with clipping)
❌ **Val loss > train loss by 0.5+** → Overfitting or bad data
❌ **Loss stops decreasing** → Learning rate too low
❌ **CUDA OOM** → Reduce micro_batch_size from 8 to 4

---

## 🚀 Launch Commands

### Option A: Automated (Recommended)
```bash
# On your laptop:
bash v2/scripts/lightning_shot.sh s_abc123@ssh.lightning.ai 14b

# Or if lightning_shot.sh needs updating:
scp v2/scripts/train_production.sh lightning:~/
ssh lightning
bash ~/train_production.sh
```

### Option B: Manual
```bash
# SSH to Lightning
ssh s_abc123@ssh.lightning.ai

# Clone repo
git clone https://github.com/Muneerali199/RakshakAI.git ~/RakshakAI --depth 1
cd ~/RakshakAI

# Set token
export HF_TOKEN="hf_your_token_here"

# Run training
bash v2/scripts/train_production.sh
```

---

## 📊 Monitoring During Training

### Check Progress:
```bash
# SSH to Lightning and tail logs
ssh lightning
tail -f ~/train_sft.log

# Look for:
# - Loss decreasing steadily
# - No NaN values
# - Eval loss close to train loss (<0.2 difference)
```

### Check GPU Usage:
```bash
watch -n 1 nvidia-smi
# Should show ~70-75GB used on A100 80GB
```

### Check Disk Space:
```bash
df -h
# Should have >50GB free throughout training
```

---

## ✅ Final Sign-Off

Before spending $13, verify:

- [ ] Read this entire checklist
- [ ] Run `python3 v2/scripts/pre_training_audit.py` → PASSED
- [ ] Confirmed using `train_87k_with_reasoning.jsonl` (259K with reasoning)
- [ ] Confirmed using `val_cleaned.jsonl` (5K garbage-free)
- [ ] Confirmed using PRODUCTION configs (not v2_FIXED or original)
- [ ] HF_TOKEN set for auto-upload
- [ ] Budget sufficient ($14 for ~5.2 hours)
- [ ] Ready to monitor logs during training

**I confirm all items above are checked:** _______________

**Date:** _______________

**Launch training:** `bash v2/scripts/train_production.sh`

---

## 🆘 Emergency Contacts

If training fails:
1. Check last 50 lines of log: `tail -50 ~/train_sft.log`
2. Check for OOM: `dmesg | grep -i "out of memory"`
3. Check disk space: `df -h`
4. Re-run audit: `python3 v2/scripts/pre_training_audit.py`

Common fixes:
- **OOM**: Reduce `micro_batch_size` from 8 to 4 in config
- **Loss=NaN**: Already fixed with gradient clipping
- **Slow download**: Use tarball instead of HF download
- **Wrong dataset**: Re-run audit, it will catch this

---

## 📝 Post-Training TODO

After training completes:
1. [ ] Check final loss values (SFT ~1.2, DPO ~0.35)
2. [ ] Verify models uploaded to HuggingFace
3. [ ] Download adapters locally
4. [ ] Run benchmark: `python3 v2/scripts/benchmark_vs_big_models.py`
5. [ ] Test model on sample vulnerabilities
6. [ ] Document results in README
7. [ ] Create model card on HuggingFace

---

**Good luck! 🚀**
