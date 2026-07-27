#!/bin/bash
# RakshakAI v3 training — improved data, 8000 samples, target 85%+
cd "$(dirname "$0")"
export PYTHONWARNINGS="ignore"
export TRAINING_RUN=1

echo "Starting RakshakAI v3 training..."
echo "Config: 8000 samples, d_model=192, 4 layers, 25 epochs, improved data"
echo "Log: training_v3.log"
date

python3 -m rakshakai.train \
  --num-samples 8000 \
  --d-model 192 \
  --num-heads 6 \
  --d-ff 384 \
  --num-layers 4 \
  --vocab-size 8000 \
  --max-length 256 \
  --batch-size 12 \
  --epochs 25 \
  --lr 3e-4 \
  --dropout 0.15 \
  --output-dir models/rakshakai-v1/ \
  2>&1 | tee training_v3.log

echo ""
echo "Training complete!"
date
