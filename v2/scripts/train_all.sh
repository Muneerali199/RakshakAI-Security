#!/usr/bin/env bash
# RakshakAI v2 — Run all training phases (A, B, C) sequentially with checkpoints.
# Optional DPO phase D is gated on Phase C quality.
#
# This is the script that drains the budget. Each phase has a cost ceiling
# baked in; if it overruns, the script aborts and the partial checkpoint
# is preserved.

set -euo pipefail

PHASE_A_BUDGET_MIN=240   # 4h
PHASE_B_BUDGET_MIN=180   # 3h
PHASE_C_BUDGET_MIN=140   # 2.3h

run_phase() {
  local phase="$1"
  local budget_min="$2"
  echo ""
  echo "=========================================================="
  echo " Phase $phase  (budget ${budget_min} min)"
  echo "=========================================================="
  SECONDS=0
  bash v2/scripts/train_phase.sh --phase "$phase"
  local elapsed=$SECONDS
  if (( elapsed / 60 > budget_min )); then
    echo "[pipeline] Phase $phase exceeded budget ($((elapsed/60)) min > ${budget_min} min)"
    echo "[pipeline] ABORTING to preserve credits. Checkpoint is saved at:"
    ls -la "v2/outputs/runs/phase_${phase}/" || true
    exit 2
  fi
  echo "[pipeline] Phase $phase OK in $((elapsed/60)) min"
}

run_phase a "$PHASE_A_BUDGET_MIN"
run_phase b "$PHASE_B_BUDGET_MIN"
run_phase c "$PHASE_C_BUDGET_MIN"

echo "[pipeline] all SFT phases complete."
echo "[pipeline] Next: bash v2/scripts/evaluate.sh"
