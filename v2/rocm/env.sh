#!/usr/bin/env bash
# Source this from every training/eval session: `source v2/rocm/env.sh`
set -euo pipefail

# --- GPU selection: we only ever use GPU 0 on a single-MI300X host ---
export HIP_VISIBLE_DEVICES=0
export CUDA_VISIBLE_DEVICES=0

# --- ROCm-specific ---
export HSA_FORCE_FINE_GRAIN_PCIE=1
export NCCL_MIN_NCHANNELS=112
# export NCCL_DEBUG=INFO   # uncomment for first debugging run only

# --- PyTorch / memory ---
export PYTORCH_ROCM_ALLOC_CONF=expandable_segments:True
export TOKENIZERS_PARALLELISM=false
export OMP_NUM_THREADS=8

# --- bitsandbytes / vLLM ABI ---
export BNB_CUDA_VERSION=130
export VLLM_USE_V1=1

# --- HF caches ---
: "${REPO_ROOT:=/workspace/rakshakai}"
export HF_HOME="$REPO_ROOT/v2/inputs/hf_home"
export TRANSFORMERS_CACHE="$REPO_ROOT/v2/inputs/hf_cache"
export HF_DATASETS_CACHE="$REPO_ROOT/v2/inputs/hf_home/datasets"
mkdir -p "$HF_HOME" "$TRANSFORMERS_CACHE" "$HF_DATASETS_CACHE"

# --- W&B ---
if [[ -n "${WANDB_API_KEY:-}" ]]; then
    export WANDB_PROJECT="rakshakai-v2"
    export WANDB_ENTITY="${WANDB_ENTITY:-rakshakai}"
fi

echo "[env] HIP_VISIBLE_DEVICES=$HIP_VISIBLE_DEVICES"
echo "[env] HF_HOME=$HF_HOME"
echo "[env] PyTorch CUDA available: $(python -c 'import torch;print(torch.cuda.is_available())' 2>/dev/null || echo unknown)"
