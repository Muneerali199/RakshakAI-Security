#!/usr/bin/env bash
# Package Phase B data + scripts for droplet upload.
# Usage: bash v2/scripts/package_phase_b.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PACKAGE="$REPO_ROOT/rakshak_phase_b.tar.gz"

echo "[package] Packing from $REPO_ROOT -> $PACKAGE"

# Verify key files exist
for f in \
    v2/inputs/datasets/phase_b/pack/train.jsonl \
    v2/inputs/datasets/phase_b/pack/val.jsonl \
    v2/inputs/datasets/phase_b/pack/test.jsonl \
    v2/inputs/datasets/phase_b/benchmark_hard/benchmark_hard.jsonl \
    "v2/inputs/datasets/phase_b/benchmark_hard/BENCHMARK_LOCK_HARD.json" \
    v2/configs/phase_b_sft.yaml \
    v2/scripts/train_phase.sh \
    v2/scripts/evaluate_phase_b.py \
    v2/rocm/env.sh \
    v2/rocm/smoke_test.py; do
    if [[ ! -f "$REPO_ROOT/$f" ]]; then
        echo "[ERROR] Missing: $REPO_ROOT/$f"
        exit 1
    fi
done

cd "$REPO_ROOT"

# Create tar.gz (exclude checkpoints, cache, and raw source data)
tar czf "$PACKAGE" \
    v2/inputs/datasets/phase_b/pack/train.jsonl \
    v2/inputs/datasets/phase_b/pack/val.jsonl \
    v2/inputs/datasets/phase_b/pack/test.jsonl \
    v2/inputs/datasets/phase_b/benchmark_hard/ \
    v2/configs/phase_b_sft.yaml \
    v2/scripts/train_phase.sh \
    v2/scripts/evaluate_phase_b.py \
    v2/rocm/env.sh \
    v2/rocm/smoke_test.py

echo ""
echo "[package] Created: $PACKAGE"
ls -lh "$PACKAGE"
echo ""
echo "[package] Upload:"
echo "  scp $PACKAGE root@129.212.185.215:/root/rakshak_phase_b.tar.gz"
echo ""
echo "[package] On droplet, extract:"
echo "  cd /root/RakshakAI && tar xzf /root/rakshak_phase_b.tar.gz"
echo ""
echo "[package] Then run:"
echo "  source v2/rocm/env.sh"
echo "  bash v2/scripts/train_phase.sh --phase b"
echo ""
echo "[package] After training, evaluate:"
echo "  python v2/scripts/evaluate_phase_b.py"
echo ""
echo "[package] To compare with base:"
echo "  python v2/scripts/evaluate_phase_b.py --base-only --adapter-only"
