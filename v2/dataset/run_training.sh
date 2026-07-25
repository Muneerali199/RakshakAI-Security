#!/bin/bash
# RakshakAI v2 — Lightning Training Launcher
# Usage: bash v2/dataset/run_training.sh
#
# Run this on Lightning AI Studio or any GPU machine with 24GB+ VRAM.
# For A100: uses micro_batch=32, grad_accum=2 (default config)
# For A10G/L4 (24GB): pass --low-vram flag

set -e

CONFIG="v2/configs/lightning_rakshak.yaml"
TRAIN_DATA="v2/inputs/datasets/train_merged.jsonl"
VAL_DATA="v2/inputs/datasets/val_merged.jsonl"

echo "=== RakshakAI v2 Training ==="
echo "Model: Qwen3.5-9B (QLoRA)"
echo "Data: $TRAIN_DATA ($(wc -l < $TRAIN_DATA) records)"
echo "Val:   $VAL_DATA ($(wc -l < $VAL_DATA) records)"
echo ""

# Install axolotl if not present
pip list 2>/dev/null | grep -q axolotl || {
    echo "Installing axolotl..."
    pip install axolotl --quiet
}

# Adjust batch for low VRAM if requested
if [ "$1" = "--low-vram" ]; then
    echo "→ Low VRAM mode: micro_batch=16, grad_accum=4"
    # Create a temporary config with adjusted batch
    sed 's/micro_batch_size: 32/micro_batch_size: 16/' $CONFIG | \
    sed 's/gradient_accumulation_steps: 2/gradient_accumulation_steps: 4/' > /tmp/rakshak_config.yaml
    CONFIG="/tmp/rakshak_config.yaml"
fi

# Check files exist
for f in "$TRAIN_DATA" "$VAL_DATA"; do
    if [ ! -f "$f" ]; then
        echo "ERROR: $f not found!"
        exit 1
    fi
done

echo "Starting training..."
echo "Config: $CONFIG"
echo "Output: v2/model/rakshak_sft/"
echo ""

accelerate launch -m axolotl.cli.train "$CONFIG"

echo ""
echo "=== Training complete! ==="
echo "Model saved to v2/model/rakshak_sft/"
