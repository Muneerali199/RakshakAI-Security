#!/usr/bin/env bash
# Launch Phase B training on MI300X droplet.
# Usage: bash v2/scripts/launch_phase_b.sh
# Prerequisites: sshpass installed, droplet running at 129.212.185.215
set -euo pipefail

DROPLET="root@129.212.185.215"
PASS="RakshakAI@2026"
LOCAL_PKG="/Users/macbook/Desktop/RakshakAI/rakshak_phase_b.tar.gz"
SSH_CMD="sshpass -p '$PASS' ssh -o StrictHostKeyChecking=no"
SCP_CMD="sshpass -p '$PASS' scp -o StrictHostKeyChecking=no"

echo "[launch] ============================================="
echo "[launch] Phase B: Multi-task SFT on 192K balanced data"
echo "[launch] ============================================="

# Step 1: Verify droplet is alive
echo "[launch] Step 1: Checking droplet..."
$SSH_CMD "$DROPLET" "echo 'Droplet OK'" || {
    echo "[ERROR] Droplet unreachable. Start it first."
    exit 1
}

# Step 2: Upload package
echo "[launch] Step 2: Uploading package (71MB)..."
$SCP_CMD "$LOCAL_PKG" "$DROPLET:/root/rakshak_phase_b.tar.gz"

# Step 3: Extract in repo
echo "[launch] Step 3: Extracting data..."
$SSH_CMD "$DROPLET" "cd /root/RakshakAI && tar xzf /root/rakshak_phase_b.tar.gz"

# Step 4: Source env and verify GPU
echo "[launch] Step 4: Verifying environment..."
$SSH_CMD "$DROPLET" "cd /root/RakshakAI && source v2/rocm/env.sh && python v2/rocm/smoke_test.py"

# Step 5: Launch training
echo "[launch] Step 5: Starting Phase B training..."
echo "[launch] Estimated: 8000 steps, ~4h, ~$8 cost"
$SSH_CMD "$DROPLET" "cd /root/RakshakAI && source v2/rocm/env.sh && nohup bash v2/scripts/train_phase.sh --phase b > /root/phase_b_train.log 2>&1 &"
echo "[launch] Training launched in background. Monitor with:"
echo "  $SSH_CMD \"$DROPLET\" tail -f /root/phase_b_train.log"

# Step 6: Wait and evaluate (optional)
echo ""
echo "[launch] After training completes (~4h):"
echo "  $SSH_CMD \"$DROPLET\" 'cd /root/RakshakAI && source v2/rocm/env.sh && python v2/scripts/evaluate_phase_b.py'"
echo ""
echo "[launch] To compare base vs adapter:"
echo "  $SSH_CMD \"$DROPLET\" 'cd /root/RakshakAI && source v2/rocm/env.sh && python v2/scripts/evaluate_phase_b.py --base-only --adapter-only'"
