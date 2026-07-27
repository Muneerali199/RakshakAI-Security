#!/bin/bash
# Wrapper that keeps system awake during training
exec caffeinate -i python3 -m rakshakai.train \
  --num-samples 10000 \
  --epochs 25 \
  --lr 1e-4 \
  --output-dir models/rakshakai-v3/ \
  --resume models/rakshakai-v2/best_model.pt
