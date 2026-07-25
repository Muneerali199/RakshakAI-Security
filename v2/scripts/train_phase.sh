#!/usr/bin/env bash
# RakshakAI v2 — Train a single phase with Axolotl on a single MI300X.
#
# Usage:
#   bash v2/scripts/train_phase.sh --phase a
#   bash v2/scripts/train_phase.sh --phase b --resume-from v2/outputs/runs/phase_a/ckpt
#   bash v2/scripts/train_phase.sh --phase d
#
# Before running:
#   source v2/rocm/env.sh
#   python v2/rocm/smoke_test.py
set -euo pipefail

PHASE="a"
RESUME_FROM=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --phase) PHASE="$2"; shift 2 ;;
    --resume-from) RESUME_FROM="$2"; shift 2 ;;
    *) echo "unknown flag: $1"; exit 1 ;;
  esac
done

CONFIG="v2/configs/phase_${PHASE}_sft.yaml"
[[ "$PHASE" == "d" ]] && CONFIG="v2/configs/phase_d_dpo.yaml"

if [[ ! -f "$CONFIG" ]]; then
  echo "[train] config not found: $CONFIG"; exit 1
fi

EXTRA=""
if [[ -n "$RESUME_FROM" ]]; then
  EXTRA="--resume-from $RESUME_FROM"
fi

echo "[train] phase=$PHASE  config=$CONFIG  resume_from=${RESUME_FROM:-none}"

cd /workspace/RakshakAI
accelerate launch -m axolotl.cli.train "$CONFIG" $EXTRA
