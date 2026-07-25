#!/bin/bash
# RakshakAI v2 — Launch Phase B Training (OPTIMIZED for MI300X)
# Target: Beat trillion-param models on security tasks
# Hardware: 1× MI300X (192GB VRAM)
# Budget: $70 (~35 GPU hours at $1.99/hr)
# Expected time: ~28 hours

set -e

echo "╔═══════════════════════════════════════════════════════════════════════════╗"
echo "║        RakshakAI v2 Phase B Training - OPTIMIZED                          ║"
echo "║        Target: Beat 1T param models on security tasks                     ║"
echo "╚═══════════════════════════════════════════════════════════════════════════╝"
echo ""

# Configuration
CONFIG=${1:-v2/configs/phase_b_sft_optimized.yaml}
OUTPUT_DIR="v2/runs/phase_b_optimized"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Check config exists
if [ ! -f "$CONFIG" ]; then
    echo "❌ Config file not found: $CONFIG"
    exit 1
fi

# Check MI300X is available
if ! command -v rocm-smi &> /dev/null; then
    echo "⚠️  rocm-smi not found. Are you on MI300X?"
    echo "   Continuing anyway (will use CUDA if available)..."
else
    echo "✅ ROCm detected"
    rocm-smi --showproductname
    echo ""
fi

# Environment setup
export PYTORCH_CUDA_ALLOC_CONF="expandable_segments:True"
export HF_HOME="${HF_HOME:-$HOME/.cache/huggingface}"

# Log GPU info
echo "📊 GPU Information:"
if command -v rocm-smi &> /dev/null; then
    rocm-smi --showmeminfo vram
elif command -v nvidia-smi &> /dev/null; then
    nvidia-smi --query-gpu=name,memory.total --format=csv
fi
echo ""

# Training parameters
echo "🚀 Training Configuration:"
echo "  Config: $CONFIG"
echo "  Output: $OUTPUT_DIR"
echo "  Dataset: Improved Phase B (350K samples)"
echo "  LoRA rank: 64 (optimized for data size)"
echo "  Effective batch: 64 (8 micro × 8 accum)"
echo "  Learning rate: 2e-5"
echo "  Epochs: 3 (with early stopping)"
echo "  Sample packing: Enabled (30-50% speedup)"
echo ""

# Cost estimate
echo "💰 Cost Estimate (MI300X @ $1.99/hr):"
echo "  Expected time: ~28 hours"
echo "  Expected cost: ~$56"
echo "  Your budget: $70"
echo "  Buffer: $14"
echo ""

# Ask for confirmation
read -p "Start training? (y/N): " -n 1 -r
echo ""
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "❌ Training cancelled"
    exit 0
fi

# Create output directory
mkdir -p "$OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR/logs"

# Save training metadata
cat > "$OUTPUT_DIR/training_info.json" <<EOF
{
  "timestamp": "$TIMESTAMP",
  "config": "$CONFIG",
  "output_dir": "$OUTPUT_DIR",
  "hardware": "MI300X 192GB",
  "budget": "$70",
  "target": "Beat trillion-param models on security",
  "optimizations": [
    "LoRA rank 64",
    "Learning rate 2e-5",
    "Effective batch 64",
    "Sample packing enabled",
    "Early stopping patience 5",
    "Group by length enabled"
  ]
}
EOF

# Launch training with monitoring
echo ""
echo "╔═══════════════════════════════════════════════════════════════════════════╗"
echo "║                         TRAINING STARTED                                   ║"
echo "╚═══════════════════════════════════════════════════════════════════════════╝"
echo ""
echo "⏱️  Started at: $(date)"
echo "📁 Logs: $OUTPUT_DIR/logs/"
echo "📊 TensorBoard: tensorboard --logdir=$OUTPUT_DIR/logs"
echo ""

# Run training
python -m axolotl.cli.train "$CONFIG" 2>&1 | tee "$OUTPUT_DIR/logs/train_${TIMESTAMP}.log"

# Check if training succeeded
if [ $? -eq 0 ]; then
    echo ""
    echo "╔═══════════════════════════════════════════════════════════════════════════╗"
    echo "║                       ✅ TRAINING COMPLETED                                ║"
    echo "╚═══════════════════════════════════════════════════════════════════════════╝"
    echo ""
    echo "⏱️  Finished at: $(date)"
    echo "📁 Model saved: $OUTPUT_DIR"
    echo ""
    echo "🎯 Next Steps:"
    echo "  1. Evaluate: python v2/scripts/evaluate_phase_b.py --model $OUTPUT_DIR"
    echo "  2. Quantize: python v2/scripts/export_gguf.py --model $OUTPUT_DIR"
    echo "  3. Deploy: python v2/deploy/server.py --model $OUTPUT_DIR"
    echo ""
    
    # Calculate actual cost
    if [ -f "$OUTPUT_DIR/logs/train_${TIMESTAMP}.log" ]; then
        TRAIN_TIME=$(grep -oP "Training completed in \K[0-9.]+" "$OUTPUT_DIR/logs/train_${TIMESTAMP}.log" || echo "unknown")
        if [ "$TRAIN_TIME" != "unknown" ]; then
            COST=$(echo "$TRAIN_TIME * 1.99 / 3600" | bc -l)
            echo "💰 Actual Cost: \$$(printf '%.2f' $COST) (${TRAIN_TIME}s training time)"
        fi
    fi
    
else
    echo ""
    echo "╔═══════════════════════════════════════════════════════════════════════════╗"
    echo "║                       ❌ TRAINING FAILED                                   ║"
    echo "╚═══════════════════════════════════════════════════════════════════════════╝"
    echo ""
    echo "Check logs: $OUTPUT_DIR/logs/train_${TIMESTAMP}.log"
    echo ""
    exit 1
fi
