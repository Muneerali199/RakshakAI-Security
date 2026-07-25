#!/bin/bash
# Remote runner for RakshakAI — H100 optimized, fits 12 credits
set -e
cd ~

START=$SECONDS
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║   H100 @ 3.50 cr/hr · 12 cr budget = 3.43h                  ║"
echo "║   SFT (250K) ~2.3h + DPO (7K pairs) ~0.5h = ~2.8h ✓        ║"
echo "╚══════════════════════════════════════════════════════════════╝"

echo "[1/5] Cloning repo..."
GIT_ASKPASS=echo git clone https://github.com/Muneerali199/RakshakAI.git ~/RakshakAI --depth 1 2>&1 | tail -3

echo "[2/5] Preparing dataset..."
mkdir -p ~/RakshakAI/v2/inputs/datasets/axolotl ~/RakshakAI/v2/model ~/RakshakAI/v2/prepared

# Try tarball first, fall back to HF download
if [ -f ~/axolotl_dataset.tar.gz ]; then
    echo "  Extracting local tarball..."
    tar xzf ~/axolotl_dataset.tar.gz -C ~/RakshakAI/v2/inputs/datasets/axolotl/
    rm ~/axolotl_dataset.tar.gz
else
    echo "  Downloading from HuggingFace..."
    pip install --break-system-packages huggingface-hub -q 2>&1 | tail -1
    python3 -c "
from huggingface_hub import hf_hub_download
import os
dst = os.path.expanduser('~/RakshakAI/v2/inputs/datasets/axolotl')
for f in ['train_250k.jsonl', 'val.jsonl', 'dpo_train.jsonl']:
    path = hf_hub_download('Muneerali199/rakshak-cwe-v3-data', f, repo_type='dataset')
    os.system(f'cp {path} {dst}/{f}')
    size_mb = os.path.getsize(f'{dst}/{f}') / 1024 / 1024
    print(f'  Downloaded {f} ({size_mb:.0f}MB)')
"
fi
echo "  Train:" $(wc -l < ~/RakshakAI/v2/inputs/datasets/axolotl/train_250k.jsonl)
echo "  DPO:" $(wc -l < ~/RakshakAI/v2/inputs/datasets/axolotl/dpo_train.jsonl)
echo "  Val:" $(wc -l < ~/RakshakAI/v2/inputs/datasets/axolotl/val.jsonl)

echo "[3/5] Installing dependencies..."
pip install --break-system-packages torch==2.5.1 transformers==4.47.1 accelerate peft datasets bitsandbytes tensorboard sentencepiece axolotl==0.6.0 2>&1 | tail -3
python3 -c "import torch; print(f'  PyTorch {torch.__version__}, CUDA: {torch.cuda.is_available()}')"

echo "[4/5] SFT phase (~2.3h)..."
cd ~/RakshakAI
python -m axolotl.cli.train v2/configs/lightning_fast.yaml 2>&1 | tee ~/train_sft.log
SFT_END=$SECONDS
echo "SFT done: $(( (SFT_END - START) / 60 )) min elapsed"

echo "[5/5] DPO phase (~0.5h)..."
python -m axolotl.cli.train v2/configs/lightning_dpo.yaml 2>&1 | tee ~/train_dpo.log
END=$SECONDS
echo "Total: $(( (END - START) / 60 )) min"

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║   DONE! Fit in 12 credits? Approx $(( (END - START) / 60 * 350 / 100 )) cents = $(( (END - START) / 60 * 35 / 10 )) credits ║"
echo "║   SFT: v2/model/sft/   DPO: v2/model/dpo/                   ║"
echo "╚══════════════════════════════════════════════════════════════╝"
