#!/bin/bash
# RakshakAI Training Deployment Script
# Run this locally: bash deploy_and_train.sh

SSH_HOST="root@36.150.116.220"
SSH_PORT="30395"
SCRIPT_PATH="/Users/macbook/Desktop/RakshakAI/v2/scripts/radeon_train_fixed.py"

echo "🚀 Deploying training to Radeon Cloud..."

# Copy the training script to remote server
echo "📤 Uploading training script..."
scp -P $SSH_PORT $SCRIPT_PATH $SSH_HOST:/workspace/train.py

# Execute setup and training on remote server
echo "🔧 Setting up environment and starting training..."
ssh -p $SSH_PORT $SSH_HOST << 'ENDSSH'
cd /workspace
mkdir -p output checkpoint dataset

echo "📦 Installing dependencies..."
pip install -q transformers peft datasets bitsandbytes accelerate huggingface_hub

echo "🎯 Starting training in background..."
nohup python3 -u train.py > training.log 2>&1 &

echo "✅ Training started!"
echo "📊 Monitor with: ssh root@36.150.116.220 -p 30395 'tail -f /workspace/training.log'"
echo "🔍 Check GPU: ssh root@36.150.116.220 -p 30395 'rocm-smi'"

# Show initial output
sleep 5
tail -20 training.log
ENDSSH

echo ""
echo "✅ Deployment complete!"
echo ""
echo "📊 Monitor training:"
echo "   ssh -p $SSH_PORT $SSH_HOST 'tail -f /workspace/training.log'"
echo ""
echo "🔍 Check GPU usage:"
echo "   ssh -p $SSH_PORT $SSH_HOST 'rocm-smi'"
echo ""
echo "⏱️  Expected: ~1-2s/iteration, 15-20 min total"
