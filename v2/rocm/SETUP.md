# RakshakAI v2 — AMD MI300X + ROCm Setup Guide

Target: **1× AMD MI300X, 192 GB HBM3, ROCm 6.2, PyTorch 2.4+**

Tested on: Ubuntu 22.04, ROCm 6.2.4, amdgpu-driver 6.2.4, MI300X 192GB.

---

## 1. Host prerequisites

```bash
# Verify the kernel sees the GPU
lspci | grep -i amd | grep MI300
# Expect: 03:00.0 Display controller: Advanced Micro Devices, Inc. [AMD/ATI] MI300X [Instinct MI300X]

# Kernel must be 5.15+ (Ubuntu 22.04 LTS is fine)
uname -r
```

### Driver install (Ubuntu 22.04)

```bash
sudo apt update && sudo apt install -y wget gnupg2
wget -qO - https://repo.radeon.com/rocm/rocm.gpg.key | sudo gpg --dearmor -o /etc/apt/trusted.gpg.d/rocm.gpg
echo "deb [arch=amd64] https://repo.radeon.com/rocm/apt/6.2.4 ubuntu main" \
  | sudo tee /etc/apt/sources.list.d/rocm.list
sudo apt update
sudo apt install -y rocm-dev rocm-libs rocm-utils rocm-cmake \
  rocm-dkms rocm-ml-libraries miopen-hip rocfft hipsparse hipblas \
  hsa-rocr-dev hsakmt-roct-dev hsa-ext-rocr-dev
echo "export PATH=/opt/rocm/bin:\$PATH" | sudo tee -a /etc/profile.d/rocm.sh
echo "export LD_LIBRARY_PATH=/opt/rocm/lib:/opt/rocm/lib64:\$LD_LIBRARY_PATH" | sudo tee -a /etc/profile.d/rocm.sh
sudo usermod -aG video,render $USER
sudo reboot
```

### Verify ROCm sees the MI300X

```bash
rocm-smi
# Should show: 1× MI300X, 192 GB, GPU-Util 0%
rocminfo | grep -A2 "Marketing Name"
# Expect: Marketing Name:  AMD Instinct MI300X
```

---

## 2. Python environment

### Option A — pip (recommended for tight control)

```bash
conda create -n rakshak python=3.11 -y
conda activate rakshak

# PyTorch ROCm 6.2 wheel (official AMD index)
pip install --index-url https://download.pytorch.org/whl/rocm6.2 \
  torch==2.4.1+rocm6.2 torchvision==0.19.1+rocm6.2 \
  torchaudio==2.4.1+rocm6.2

# bitsandbytes ROCm wheel (must match PyTorch ABI)
pip install bitsandbytes==0.43.3

# Flash-Attn 2 (ROCm build)
MAX_JOBS=8 pip install flash-attn==2.5.9.post1 --no-build-isolation

# Training & serving
pip install -U "transformers>=4.43" "peft>=0.11" "accelerate>=0.33" \
  "trl>=0.9.6" "datasets>=2.20" "deepspeed>=0.14" \
  "vllm>=0.5.3" "autoawq>=0.2.5" "axolotl==0.7.0" \
  "wandb>=0.17" "scikit-learn>=1.5" "pandas>=2.2" "pyarrow>=16" \
  "fastapi>=0.111" "uvicorn[standard]>=0.30" "pydantic>=2.7" \
  "tree-sitter==0.21" "tree-sitter-languages" "langdetect>=1.0.9"
```

### Option B — Docker (reproducible, what we ship)

See `v2/rocm/Dockerfile`. Build:

```bash
cd v2/rocm
docker build -t rakshakai-v2:rocm6.2 .
docker run --rm -it --device=/dev/kfd --device=/dev/dri \
  --group-add video --group-add render --ipc=host \
  -v $PWD/..:/workspace/rakshakai \
  -e HF_TOKEN=$HF_TOKEN -e WANDB_API_KEY=$WANDB_API_KEY \
  rakshakai-v2:rocm6.2
```

---

## 3. Smoke test (must pass before any training)

Run `v2/rocm/smoke_test.py`:

```bash
python v2/rocm/smoke_test.py
# Expected output:
#   [OK] PyTorch sees 1 GPU
#   [OK] GPU is MI300X, 192 GB
#   [OK] bf16 matmul works
#   [OK] bitsandbytes NF4 quantize+dequantize works
#   [OK] flash-attn 2 attention works
#   [OK] all-good
```

If any check fails, **do not start training**. Common fixes:

| Failure | Fix |
|---|---|
| `torch.cuda.is_available() == False` | Reboot after `usermod -aG video`; check `rocm-smi` |
| MI300X reported as 0 GB | BIOS: enable Above 4G Decoding, ReBAR; check PCIe is Gen5 x16 |
| bitsandbytes import error | Reinstall matching wheel: `pip install --force-reinstall --no-deps bitsandbytes==0.43.3` |
| flash-attn OOM in compile | Reduce `MAX_JOBS` to 4; ensure `HSA_OVERRIDE_GFX_VERSION` is unset (MI300X = gfx942, autodetected) |

---

## 4. Critical environment variables

Put in `v2/rocm/env.sh` (sourced by every training/eval run):

```bash
export HIP_VISIBLE_DEVICES=0                # use only GPU 0
export HSA_FORCE_FINE_GRAIN_PCIE=1          # avoid coarse-grain pcie atomics
export NCCL_MIN_NCHANNELS=112               # saturate Infinity Fabric
export NCCL_DEBUG=INFO                      # first run only
export TRANSFORMERS_CACHE=/workspace/rakshakai/v2/inputs/hf_cache
export HF_HOME=/workspace/rakshakai/v2/inputs/hf_home
export TOKENIZERS_PARALLELISM=false
export OMP_NUM_THREADS=8
export BNB_CUDA_VERSION=130                 # matches ROCm 6.2 ABI
export PYTORCH_ROCM_ALLOC_CONF=expandable_segments:True
export VLLM_USE_V1=1
```

---

## 5. Hyperparameters that matter on MI300X (CDNA3 specifics)

| Knob | Value | Why |
|---|---|---|
| `bf16: true` | required | CDNA3 has no fp16 tensor cores; bf16 only |
| `gradient_checkpointing: true` | required | Allows 4K context with bs≥8 |
| `attn_implementation: flash_attention_2` | required | O(N) memory; ~2× faster on CDNA3 |
| `optim: paged_adamw_8bit` | required | Cuts optimizer state 4× |
| `lr: 2e-4` | for LoRA r=64 | Standard QLoRA recipe for 7B |
| `micro_batch_size: 8` | at seq 4096 | Adjust if OOM |
| `gradient_accumulation_steps: 4` | → eff bs 32 | Smooth loss |
| `sample_packing: true` | with flash_attn | 3–4× throughput on short examples |
| `pad_to_sequence_len: false` | with packing | Avoid wasted compute |
| `dataset_prepared_path: .../pack/` | 4096-token packed shards | One pass, no on-the-fly tokenization |
| `lora_dropout: 0.05` | low | High rank already regularizes |
| `lora_target_modules: all-linear` | full coverage | Best CWE coverage |
| `lora_r: 64, lora_alpha: 128` | high rank | Capture 9-field schema |
| `lora_use_rslora: true` | enabled | Stable at r≥32 |
| `neftune_noise_alpha: 5` | enabled | Instruction-following boost |
| `warmup_ratio: 0.03` | cosine | Standard |
| `weight_decay: 0.0` | for LoRA | Standard |
| `max_grad_norm: 1.0` | | Clip to avoid bf16 spikes |
| `eval_steps: 100` | | Tied to ~1 epoch on 40K pairs |
| `save_steps: 100` | | Same; keeps top-3 |
| `early_stopping_patience: 5` | | Stops automatically |

---

## 6. Storage layout on the GPU host

```
/workspace/rakshakai/
├── v2/
│   ├── inputs/
│   │   ├── hf_cache/                # downloaded base models
│   │   ├── hf_home/                 # HF datasets cache
│   │   └── datasets/
│   │       ├── raw/                 # tarballs / git clones
│   │       ├── clean/               # cleaned parquet
│   │       ├── dedup/               # deduped parquet
│   │       ├── instruct/            # 9-field schema JSONL
│   │       └── pack/                # tokenized, packed, ready-to-train
│   ├── outputs/
│   │   ├── runs/                    # axolotl run dirs
│   │   ├── merged/                  # merged base+lora in bf16
│   │   ├── awq/                     # AWQ 4-bit for vLLM
│   │   └── gguf/                    # Q5_K_M for llama.cpp
│   └── logs/
```

Use a **NVMe scratch** for `inputs/datasets/pack/`; HBM reads it once then caches.
