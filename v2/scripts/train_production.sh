#!/bin/bash
# RakshakAI 14B Training - PRODUCTION VERSION
# Uses 259K samples WITH REASONING TRACES
# All critical issues fixed
set -eo pipefail
cd ~

# Ensure pip is in PATH (Lightning.ai puts it in miniconda3)
export PATH="/home/zeus/miniconda3/bin:$PATH"
which pip >/dev/null 2>&1 || { echo "ERROR: pip not found"; exit 1; }

START=$SECONDS
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║   RakshakAI 14B Production Training                         ║"
echo "║   Dataset: 259K (250K + 9K reasoning traces)                ║"
echo "║   A100 80GB @ \$2.50/hr · Budget: \$14 = 5.6h                ║"
echo "╚══════════════════════════════════════════════════════════════╝"

echo "[1/7] Cloning repo..."
if [ -d ~/RakshakAI/.git ]; then
    echo "  Repo already exists — pulling latest..."
    cd ~/RakshakAI && git pull 2>&1 | tail -3
else
    rm -rf ~/RakshakAI 2>/dev/null
    GIT_ASKPASS=echo git clone https://github.com/Muneerali199/RakshakAI.git ~/RakshakAI --depth 1 2>&1 | tail -3
fi

echo "[2/7] Installing dependencies..."
cd ~/RakshakAI
bash v2/scripts/install_dependencies.sh 2>&1 | tail -15

echo "[3/7] Loading datasets..."
mkdir -p ~/RakshakAI/v2/inputs/datasets/axolotl ~/RakshakAI/v2/model ~/RakshakAI/v2/prepared

DST=~/RakshakAI/v2/inputs/datasets/axolotl

if [ -f ~/axolotl_dataset.tar.gz ]; then
    echo "  Found tarball — extracting..."
    tar -xzf ~/axolotl_dataset.tar.gz -C "$DST"
    for f in train_87k_with_reasoning.jsonl val_cleaned.jsonl dpo_train.jsonl; do
        if [ -f "$DST/$f" ]; then
            sz=$(du -h "$DST/$f" | cut -f1)
            echo "  ✓ $f ($sz)"
        fi
    done
else
    echo "  No tarball — downloading from HuggingFace..."
    pip install --break-system-packages huggingface-hub 2>&1 | tail -1
    python3 << 'EOF'
from huggingface_hub import hf_hub_download
import os, shutil

dst = os.path.expanduser('~/RakshakAI/v2/inputs/datasets/axolotl')
required_files = [
    'train_87k_with_reasoning.jsonl',
    'val_cleaned.jsonl',
    'dpo_train.jsonl',
]
for filename in required_files:
    print(f"Downloading {filename}...")
    try:
        path = hf_hub_download('Muneerali199/rakshak-cwe-v3-data', filename, repo_type='dataset')
        shutil.copy(path, f'{dst}/{filename}')
        size_mb = os.path.getsize(f'{dst}/{filename}') / 1024 / 1024
        lines = sum(1 for _ in open(f'{dst}/{filename}'))
        print(f"  ✓ {filename}: {lines:,} lines ({size_mb:.0f}MB)")
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        exit(1)
print("\n✅ All datasets downloaded")
EOF
fi

echo "[4/7] Validating setup..."
python3 v2/scripts/pre_training_audit.py 2>&1 | tail -50

if [ $? -ne 0 ]; then
    echo "❌ Pre-training audit FAILED! Aborting."
    exit 1
fi

echo "[5/7] Starting SFT training (~3.6h with reasoning data)..."
echo "  Dataset: train_87k_with_reasoning.jsonl (259K samples)"
echo "  Validation: val_cleaned.jsonl (5K samples, garbage-free)"
cd ~/RakshakAI
python -m axolotl.cli.train v2/configs/lightning_14b_sft_PRODUCTION.yaml 2>&1 | tee ~/train_sft.log

SFT_END=$SECONDS
SFT_DURATION=$((SFT_END - START))
echo "✓ SFT complete: $((SFT_DURATION / 60)) minutes"

# Verify SFT output
if [ ! -d "v2/model/sft_14b" ]; then
    echo "❌ ERROR: SFT training failed, no output directory"
    exit 1
fi

# Check for final checkpoint
if [ ! -f "v2/model/sft_14b/adapter_config.json" ]; then
    echo "❌ ERROR: SFT adapter not found"
    exit 1
fi

echo "[6/7] Starting DPO training (~1.6h, 2 epochs)..."
echo "  Preprocessing DPO data..."
python3 v2/scripts/preprocess_dpo.py \
  v2/inputs/datasets/axolotl/dpo_train.jsonl \
  v2/inputs/datasets/axolotl/dpo_train_processed.jsonl
echo "  Dataset: dpo_train_processed.jsonl (7K pairs)"
echo "  Base: SFT adapter from previous step"
python -m axolotl.cli.train v2/configs/lightning_14b_dpo_PRODUCTION.yaml 2>&1 | tee ~/train_dpo.log

DPO_END=$SECONDS
DPO_DURATION=$((DPO_END - SFT_END))
echo "✓ DPO complete: $((DPO_DURATION / 60)) minutes"

# Verify DPO output
if [ ! -d "v2/model/dpo_14b" ]; then
    echo "❌ ERROR: DPO training failed"
    exit 1
fi

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║   TRAINING COMPLETE!                                        ║"
echo "║   SFT: $((SFT_DURATION / 60))m    DPO: $((DPO_DURATION / 60))m    Total: $(((DPO_END - START) / 60))m        ║"
echo "╚══════════════════════════════════════════════════════════════╝"

# Extract metrics
echo ""
echo "📊 Training Metrics:"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "SFT Final Loss:"
tail -30 ~/train_sft.log | grep -i "loss" | tail -3
echo ""
echo "DPO Final Loss:"
tail -30 ~/train_dpo.log | grep -i "loss" | tail -3
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

echo "[7/7] Uploading to HuggingFace..."
if [ -n "$HF_TOKEN" ]; then
    python3 << 'EOFPY'
from huggingface_hub import HfApi
import os

api = HfApi()
token = os.environ['HF_TOKEN']

print("Uploading SFT adapter...")
try:
    api.upload_folder(
        folder_path='v2/model/sft_14b',
        path_in_repo='sft_14b',
        repo_id='Muneerali199/rakshak-cwe-v3',
        token=token,
        ignore_patterns=['*.safetensors', 'optimizer.pt', 'training_args.bin', 'checkpoint-*'],
    )
    print("✓ SFT adapter uploaded")
except Exception as e:
    print(f"✗ SFT upload failed: {e}")

print("\nUploading DPO adapter...")
try:
    api.upload_folder(
        folder_path='v2/model/dpo_14b',
        path_in_repo='dpo_14b',
        repo_id='Muneerali199/rakshak-cwe-v3',
        token=token,
        ignore_patterns=['*.safetensors', 'optimizer.pt', 'training_args.bin', 'checkpoint-*'],
    )
    print("✓ DPO adapter uploaded")
except Exception as e:
    print(f"✗ DPO upload failed: {e}")

print("\n✅ Models available at: https://huggingface.co/Muneerali199/rakshak-cwe-v3")
EOFPY
else
    echo "⚠️  HF_TOKEN not set - skipping auto-upload"
    echo "Manual upload:"
    echo "  export HF_TOKEN='hf_...'"
    echo "  huggingface-cli upload Muneerali199/rakshak-cwe-v3 v2/model/sft_14b"
    echo "  huggingface-cli upload Muneerali199/rakshak-cwe-v3 v2/model/dpo_14b"
fi

END=$SECONDS
TOTAL_HOURS=$(echo "scale=2; ($END - $START) / 3600" | bc)
TOTAL_COST=$(echo "scale=2; $TOTAL_HOURS * 2.50" | bc)

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                    FINAL SUMMARY                            ║"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║  Training time: $TOTAL_HOURS hours                          ║"
echo "║  Cost: \$$TOTAL_COST / \$14.00 budget                       ║"
echo "║  Dataset: 259K samples (250K + 9K reasoning)                ║"
echo "║  Output: v2/model/sft_14b & v2/model/dpo_14b                ║"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║  Next: Run benchmark to verify quality                      ║"
echo "║  python3 v2/scripts/benchmark_vs_big_models.py              ║"
echo "╚══════════════════════════════════════════════════════════════╝"
