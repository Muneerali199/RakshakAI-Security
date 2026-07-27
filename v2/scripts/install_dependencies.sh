#!/bin/bash
# Install all dependencies for RakshakAI training on Lightning.ai
# Run this BEFORE training to avoid mid-training crashes
set -e

# Detect pip (Lightning.ai puts it in miniconda3)
if command -v pip &>/dev/null; then
    PIP=pip
elif [ -f /home/zeus/miniconda3/bin/pip ]; then
    PIP=/home/zeus/miniconda3/bin/pip
else
    echo "ERROR: pip not found. Set PATH to include pip."
    exit 1
fi

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  RakshakAI Dependency Installation (Lightning.ai)           ║"
echo "║  Using: $PIP"
echo "╚══════════════════════════════════════════════════════════════╝"

START=$SECONDS

echo "[1/5] Updating pip..."
$PIP install --upgrade pip --break-system-packages 2>&1 | tail -3

echo "[2/5] Installing PyTorch 2.5.1..."
$PIP install --break-system-packages torch==2.5.1 --index-url https://download.pytorch.org/whl/cu121 2>&1 | tail -5

echo "[3/5] Installing core ML libraries..."
$PIP install --break-system-packages \
    transformers==4.47.1 \
    accelerate==1.2.1 \
    peft==0.14.0 \
    datasets==2.21.0 \
    sentencepiece==0.2.0 \
    protobuf==5.29.2 \
    2>&1 | tail -5

echo "[4/5] Installing training utilities..."
$PIP install --break-system-packages \
    bitsandbytes==0.45.0 \
    tensorboard==2.18.0 \
    wandb==0.19.1 \
    scipy==1.14.1 \
    2>&1 | tail -5

echo "[5/5] Installing axolotl 0.6.0..."
$PIP install --break-system-packages axolotl==0.6.0 2>&1 | tail -5

# Verify installations
echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  Verifying installations...                                  ║"
echo "╚══════════════════════════════════════════════════════════════╝"

python3 << 'EOF'
import sys

checks = []

try:
    import torch
    cuda_available = torch.cuda.is_available()
    checks.append(f"✓ PyTorch {torch.__version__} (CUDA: {cuda_available})")
    if not cuda_available:
        print("⚠️  WARNING: CUDA not detected!")
except ImportError as e:
    checks.append(f"✗ PyTorch: FAILED ({e})")
    sys.exit(1)

try:
    import transformers
    checks.append(f"✓ transformers {transformers.__version__}")
except ImportError as e:
    checks.append(f"✗ transformers: FAILED ({e})")
    sys.exit(1)

try:
    import peft
    checks.append(f"✓ peft installed")
except ImportError as e:
    checks.append(f"✗ peft: FAILED ({e})")
    sys.exit(1)

try:
    import bitsandbytes
    checks.append(f"✓ bitsandbytes installed")
except ImportError as e:
    checks.append(f"✗ bitsandbytes: FAILED ({e})")
    sys.exit(1)

try:
    from axolotl.cli import train
    checks.append(f"✓ axolotl installed")
except ImportError as e:
    checks.append(f"✗ axolotl: FAILED ({e})")
    sys.exit(1)

try:
    import accelerate
    checks.append(f"✓ accelerate installed")
except ImportError as e:
    checks.append(f"✗ accelerate: FAILED ({e})")
    sys.exit(1)

for check in checks:
    print(check)

print("\n✅ All dependencies installed successfully!")
EOF

END=$SECONDS
DURATION=$((END - START))

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  Installation complete in ${DURATION}s                          ║"
echo "║  Ready to train!                                             ║"
echo "╚══════════════════════════════════════════════════════════════╝"
