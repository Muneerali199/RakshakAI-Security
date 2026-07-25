#!/bin/bash
# RakshakAI v2 — Launch Training on B200
# Hardware: 1× NVIDIA B200 (192GB HBM3e)
# Budget: $187.50 for 30 hours
set -e

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║     RakshakAI v2 — B200 Training                            ║"
echo "║     Target: Beat Mythos 5 & GPT-5.6 Terra on security       ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

MODE=${1:-fullft}  # fullft or qlora
CONFIG="v2/configs/b200_${MODE}.yaml"
OUTPUT_DIR="v2/runs/b200_${MODE}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

if [ ! -f "$CONFIG" ]; then
    echo "❌ Config not found: $CONFIG"
    exit 1
fi

echo "📊 GPU:"
nvidia-smi --query-gpu=name,memory.total --format=csv
echo ""

echo "🚀 Mode: $MODE"
echo "   Config: $CONFIG"
echo "   Output: $OUTPUT_DIR"
echo ""
echo "⏱️  Time estimates (B200 192GB):"
if [ "$MODE" = "fullft" ]; then
    echo "    Full FT + 2 epochs: ~11 hours"
    echo "    + Eval benchmarks: ~3 hours"
    echo "    + Iteration buffer: ~6 hours"
    echo "    Total: ~20 hours — $125"
else
    echo "    QLoRA + 3 epochs: ~5 hours"
    echo "    + Eval benchmarks: ~3 hours"
    echo "    + Iteration buffer: ~12 hours"
    echo "    Total: ~20 hours — $125"
fi
echo ""

read -p "Start training? (y/N): " -n 1 -r
echo ""
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "❌ Cancelled"
    exit 0
fi

mkdir -p "$OUTPUT_DIR/logs"

echo "{\"timestamp\":\"$TIMESTAMP\",\"mode\":\"$MODE\",\"config\":\"$CONFIG\",\"gpu\":\"B200\"}" > "$OUTPUT_DIR/training_info.json"

echo ""
echo "🚀 TRAINING STARTED — $(date)"
echo ""

python -m axolotl.cli.train "$CONFIG" 2>&1 | tee "$OUTPUT_DIR/logs/train_${TIMESTAMP}.log"

if [ $? -eq 0 ]; then
    echo ""
    echo "✅ TRAINING COMPLETED — $(date)"
    echo ""
    echo "📁 Model: $OUTPUT_DIR"
    echo ""
    echo "🎯 Run evaluation:"
    echo "   python v2/scripts/evaluate_phase_b.py --model $OUTPUT_DIR --benchmarks all"
    echo ""
    echo "📊 TensorBoard: tensorboard --logdir=$OUTPUT_DIR/logs"
else
    echo ""
    echo "❌ TRAINING FAILED"
    echo "   Logs: $OUTPUT_DIR/logs/train_${TIMESTAMP}.log"
    exit 1
fi
