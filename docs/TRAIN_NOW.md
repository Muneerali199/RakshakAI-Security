# RakshakAI v2 — Train Now

**Date:** 2026-06-07
**Target:** 1× AMD MI300X (64 GB HBM3, $2/hr typical)
**Pipeline:** Phase A SFT → Phase B SFT → Phase C SFT → [Phase D DPO]
**Total cost (7B, all SFT):** ~$400 / ~200 GPU hrs

---

## 1. Pre-flight checklist

| Check | Status |
|-------|--------|
| All 8 hard gates pass | ✅ audit.py exit 0 |
| Dataset volume | 96,050 unique cleaned, 44,281 balanced, 66,371 instruct |
| Packed records | 58,312 train + 2,748 val + 5,459 test (4096 tok) |
| Packed tokens (train) | ~239M tokens (58,312 × 4096) |
| Benchmark isolated | ✅ SHA-256 locked, 0 leakage |
| YAML configs valid | ✅ 5/5 load, all required keys present |
| Dataset paths exist | ✅ pack/phase_{a,b,c}.jsonl all present |
| Tokenizer | Qwen2.5-Coder-7B-Instruct (151,665 vocab) |

### Known gaps
- **Phase D DPO data does not exist yet** — must generate after SFT completes
- **YAML paths reference `/workspace/rakshakai/` (Docker)** — update to actual mount point on your MI300X machine
- **YAML paths lack `.jsonl` extension** — axolotl auto-detects `.jsonl` for file paths in most versions, but verify with `ls` on your target machine

---

## 2. Environment setup (MI300X)

```bash
# --- ROCm + Python ---
sudo apt update && sudo apt install -y rocm-libs rocm-dev python3.10-venv
python3.10 -m venv venv
source venv/bin/activate

# --- Axolotl (ROCm fork or mainline) ---
pip install torch==2.4.0 --index-url https://download.pytorch.org/whl/rocm6.1
git clone https://github.com/OpenAccess-AI-Collective/axolotl
cd axolotl
pip install -e .
cd ..

# --- Dataset sync ---
# Copy the entire v2 directory from your dev machine:
#   rsync -avz --progress /Users/macbook/Desktop/RakshakAI/v2/ user@mi300x:/workspace/rakshakai/v2/
# Or clone the repo if it's on GitHub:
#   git clone https://github.com/your-org/rakshakai /workspace/rakshakai
```

---

## 3. Config path fixes

On the MI300X machine, update each YAML's dataset path to point to your actual data directory. The configs currently use `/workspace/rakshakai/v2/inputs/datasets/pack/phase_a`.

**If your data lands at `/workspace/rakshakai/v2/` — no changes needed.**

**If your data is elsewhere** (e.g., `/home/user/rakshakai/v2/`), run:

```bash
find /workspace/rakshakai/v2/configs -name '*.yaml' -exec sed -i \
  's|/workspace/rakshakai|/home/user/rakshakai|g' {} +
```

The configs expect these files to exist:
```
/workspace/rakshakai/v2/inputs/datasets/pack/phase_a.jsonl
/workspace/rakshakai/v2/inputs/datasets/pack/phase_b.jsonl
/workspace/rakshakai/v2/inputs/datasets/pack/phase_c.jsonl
```

Verify with:
```bash
ls -lh /workspace/rakshakai/v2/inputs/datasets/pack/
```

---

## 4. Launch commands

### Phase A: SFT on real-world CVE-bearing code

```bash
accelerate launch -m axolotl.cli.train \
  /workspace/rakshakai/v2/configs/phase_a_sft.yaml
```

| Setting | Value |
|---------|-------|
| Model | Qwen2.5-Coder-7B-Instruct |
| LoRA r | 64, all-linear, rsLoRA |
| Quant | NF4 double-quant |
| Seq len | 4096, sample_packing |
| Eff batch | 8 × 4 = 32 |
| Steps | 4,000 (~2.2 epochs) |
| Est. time | **~81 GPU hrs** |
| Est. cost | **~$162** |
| Output | `/workspace/rakshakai/v2/outputs/runs/phase_a/` |

Monitor loss: `tail -f outputs/runs/phase_a/logs.jsonl | python3 -m json.tool`

Expected eval loss convergence: ~0.8–1.2 after 4,000 steps.

---

### Phase B: SFT on multi-language snippets + fixes

**Only after Phase A completes.**

```bash
accelerate launch -m axolotl.cli.train \
  /workspace/rakshakai/v2/configs/phase_b_sft.yaml
```

| Setting | Value |
|---------|-------|
| LR | 1.0e-4 (lower — refine, not overwrite) |
| Eff batch | 6 × 6 = 36 |
| Steps | 3,000 |
| Est. time | **~68 GPU hrs** |
| Est. cost | **~$137** |

---

### Phase C: SFT on synthetic instruction pairs

**Only after Phase B completes.**

```bash
accelerate launch -m axolotl.cli.train \
  /workspace/rakshakai/v2/configs/phase_c_sft.yaml
```

| Setting | Value |
|---------|-------|
| Eff batch | 4 × 8 = 32 |
| Steps | 2,500 |
| Est. time | **~51 GPU hrs** |
| Est. cost | **~$101** |

---

### Merge LoRA → full weights (after Phase C)

```bash
python3 -m axolotl.cli.merge_lora \
  --base_model Qwen/Qwen2.5-Coder-7B-Instruct \
  --lora_dir /workspace/rakshakai/v2/outputs/runs/phase_c \
  --output_dir /workspace/rakshakai/v2/outputs/merged/rakshakai-v2-bf16
```

---

### Phase D: DPO preference tuning (optional)

**Phase D data does not exist yet.** Generate DPO preference pairs before launching:

```bash
# Generate DPO pairs from the training set (vuln → generic_fix vs minimal_fix)
PYTHONPATH=. python3 v2/dataset/to_dpo_pairs.py \
  --input v2/inputs/datasets/pack/train.jsonl \
  --output v2/inputs/datasets/pack/phase_d_dpo.jsonl
```

Then launch:

```bash
accelerate launch -m axolotl.cli.train \
  /workspace/rakshakai/v2/configs/phase_d_dpo.yaml
```

| Setting | Value |
|---------|-------|
| Model | Merged Phase C weights |
| LoRA r | 32 (smaller — preference tuning) |
| Seq len | 2048 (shorter — preference pairs) |
| Eff batch | 2 × 8 = 16 |
| Steps | 800 |
| Est. time | **~4 GPU hrs** |
| Est. cost | **~$8** |

---

### 14B Ablation (optional, separate run)

```bash
accelerate launch -m axolotl.cli.train \
  /workspace/rakshakai/v2/configs/ablation_14b.yaml
```

| Setting | Value |
|---------|-------|
| Model | Qwen2.5-Coder-14B-Instruct |
| Eff batch | 4 × 8 = 32 |
| Est. time | **~162 GPU hrs** |
| Est. cost | **~$324** |

---

## 5. Cost tracking sheet

Run `watch` with the cost estimator:

```bash
# Running cost tracker (tokens processed → dollars)
watch -n 60 '
  STEPS=$(tail -1 /workspace/rakshakai/v2/outputs/runs/phase_a/logs.jsonl 2>/dev/null \
    | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get(\"step\",0))" 2>/dev/null || echo 0)
  echo "Step: $STEPS / 4000"
  echo "Progress: $(python3 -c "print(f\"{int($STEPS)/4000*100:.1f}%\")")"
  echo "Est. cost so far: \$(python3 -c "print(f\"{int($STEPS)/4000*162:.2f}\")")"
'
```

## 6. Budget summary

| Segment | Time | Cost |
|---------|------|------|
| Phase A (7B SFT) | 81 hrs | $162 |
| Phase B (7B SFT) | 68 hrs | $137 |
| Phase C (7B SFT) | 51 hrs | $101 |
| Phase D (7B DPO) | 4 hrs | $8 |
| **7B total** | **204 hrs** | **$408** |
| 14B ablation (A only) | 162 hrs | $324 |

All estimates at 1,800 tok/s QLoRA throughput on 1× MI300X (conservative). Real throughput with flash_attention + sample_packing + NF4 may be 20–40% higher, reducing costs proportionally.

---

## 7. Evaluation

After Phase C completes (or after DPO), run the benchmark:

```bash
PYTHONPATH=. python3 v2/dataset/eval_benchmark.py \
  --model /workspace/rakshakai/v2/outputs/merged/rakshakai-v2-bf16 \
  --benchmark v2/benchmarks/security_benchmark.jsonl \
  --output v2/benchmarks/eval_results.json
```

Compare against the baseline (Phase A → Phase B → Phase C progression) to confirm per-CWE recall improvements.
