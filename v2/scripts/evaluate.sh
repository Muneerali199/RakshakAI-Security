#!/usr/bin/env bash
# RakshakAI v2 — end-to-end evaluation.
# Assumes: merged model in v2/outputs/merged/rakshakai-v2-bf16
#          AWQ 4-bit in v2/outputs/awq/rakshakai-v2-awq (optional)
set -euo pipefail

source v2/rocm/env.sh

MERGED="v2/outputs/merged/rakshakai-v2-bf16"
AWQ=""
[[ -d "v2/outputs/awq/rakshakai-v2-awq" ]] && AWQ="--awq v2/outputs/awq/rakshakai-v2-awq"

python v2/scripts/evaluate.py \
    --model "$MERGED" \
    $AWQ \
    --out "v2/outputs/eval/main" \
    --judge-model "${JUDGE_MODEL:-gpt-4o-mini}"
