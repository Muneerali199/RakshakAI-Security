#!/bin/bash
# RakshakAI — Single-shot setup + SFT + DPO on Lightning.ai
# Usage:
#   bash v2/scripts/lightning_shot.sh s_abc123@ssh.lightning.ai          # 7B (fits 12 credits)
#   bash v2/scripts/lightning_shot.sh s_abc123@ssh.lightning.ai 14b      # 14B (fits 14 credits)
set -e
SSH_HOST="$1"
MODEL_SIZE="${2:-7b}"

if [ -z "$SSH_HOST" ]; then
    echo "Usage: $0 <ssh-host> [7b|14b]"
    echo "Example: $0 s_abc123@ssh.lightning.ai 14b"
    exit 1
fi

RUNNER="_remote_run.sh"
if [ "$MODEL_SIZE" = "14b" ]; then
    RUNNER="train_production.sh"
    echo "[*] 14B PRODUCTION mode — A100 80GB ($2.50/hr, ~5.2h = ~$13.00)"
    echo "[*] Dataset: 259K (250K SFT + 9K DeepSeek reasoning traces)"
else
    echo "[*] 7B mode — H100 ($3.50/hr)"
fi

echo "[1/4] Copying dataset + runner..."
# Tarball is optional — remote runner falls back to HF download if missing
if [ -f /tmp/axolotl_dataset.tar.gz ]; then
    echo "  Dataset tarball found (266MB — includes reasoning traces), copying..."
    scp -o StrictHostKeyChecking=no /tmp/axolotl_dataset.tar.gz "$SSH_HOST:~/"
else
    echo "  No tarball — remote will download from HuggingFace (1.2GB)"
fi
scp -o StrictHostKeyChecking=no "v2/scripts/$RUNNER" "$SSH_HOST:~/"

echo "[2/4] Executing remote setup → SFT → DPO..."
ssh -o StrictHostKeyChecking=no "$SSH_HOST" "bash ~/$RUNNER" &

echo "[3/4] Launched!"
echo "  Monitor: ssh $SSH_HOST \"tail -f ~/RakshakAI/train_sft.log\""
echo "  Monitor: ssh $SSH_HOST \"tail -f ~/RakshakAI/train_dpo.log\""
echo ""
echo "[4/4] Download model when done:"
if [ "$MODEL_SIZE" = "14b" ]; then
    echo "  scp -r $SSH_HOST:~/RakshakAI/v2/model/sft_14b/ ./"
    echo "  scp -r $SSH_HOST:~/RakshakAI/v2/model/dpo_14b/ ./"
else
    echo "  scp -r $SSH_HOST:~/RakshakAI/v2/model/sft/ ./"
    echo "  scp -r $SSH_HOST:~/RakshakAI/v2/model/dpo/ ./"
fi
