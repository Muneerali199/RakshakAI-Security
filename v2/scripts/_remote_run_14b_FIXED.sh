#!/bin/bash
# RakshakAI — 14B QLoRA for Lightning.ai (FIXED VERSION)
# This version uses improved configs with better hyperparameters
set -e
cd ~

START=$SECONDS
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║   RakshakAI 14B Training (FIXED VERSION)                    ║"
echo "║   14B on A100 @ 2.50 cr/hr · 14 cr budget = 5.6h           ║"
echo "║   SFT (250K) ~3.5h + DPO (7K x2 epochs) ~1.6h = ~5.1h      ║"
echo "╚══════════════════════════════════════════════════════════════╝"

echo "[1/6] Cloning repo..."
GIT_ASKPASS=echo git clone https://github.com/Muneerali199/RakshakAI.git ~/RakshakAI --depth 1 2>&1 | tail -3

echo "[2/6] Preparing dataset..."
mkdir -p ~/RakshakAI/v2/inputs/datasets/axolotl ~/RakshakAI/v2/model ~/RakshakAI/v2/prepared

# Try tarball first, fall back to HF download
if [ -f ~/axolotl_dataset.tar.gz ]; then
    echo "  Extracting local tarball..."
    tar xzf ~/axolotl_dataset.tar.gz -C ~/RakshakAI/v2/inputs/datasets/axolotl/
    rm ~/axolotl_dataset.tar.gz
else
    echo "  Downloading from HuggingFace..."
    pip install --break-system-packages huggingface-hub 2>&1 | tail -1
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
echo "  Val (raw):" $(wc -l < ~/RakshakAI/v2/inputs/datasets/axolotl/val.jsonl)

echo "[3/6] Preparing cleaned validation data..."
cd ~/RakshakAI
# Try to download pre-cleaned val from HF first
python3 -c "
from huggingface_hub import hf_hub_download
import os
dst = os.path.expanduser('~/RakshakAI/v2/inputs/datasets/axolotl')
path = hf_hub_download('Muneerali199/rakshak-cwe-v3-data', 'val_cleaned.jsonl', repo_type='dataset')
os.system(f'cp {path} {dst}/val_cleaned.jsonl')
sz = os.path.getsize(f'{dst}/val_cleaned.jsonl') / 1024
print(f'  Downloaded pre-cleaned val ({sz:.0f}KB)')
" 2>/dev/null || {
    echo "  Pre-cleaned not found, cleaning locally..."
    python3 v2/scripts/clean_validation_data.py 2>&1 | tail -5
}
echo "  Val (cleaned):" $(wc -l < ~/RakshakAI/v2/inputs/datasets/axolotl/val_cleaned.jsonl)

echo "[4/6] Installing dependencies..."
pip install --break-system-packages torch==2.5.1 transformers==4.47.1 accelerate peft datasets bitsandbytes tensorboard sentencepiece axolotl==0.6.0 2>&1 | tail -5
python3 -c "import torch; print(f'  PyTorch {torch.__version__}, CUDA: {torch.cuda.is_available()}')"
python3 -c "from transformers import AutoModel; print('  transformers OK')"
python3 -c "from axolotl.cli import train; print('  axolotl OK')"

# Check if reasoning-enhanced dataset is available
REASONING_CONFIG="v2/configs/lightning_14b_sft_v2_FIXED.yaml"
if python3 -c "from huggingface_hub import hf_hub_url; import requests; r=requests.head(hf_hub_url('Muneerali199/rakshak-cwe-v3-data', 'train_87k_with_reasoning.jsonl', repo_type='dataset')); exit(0 if r.status_code==200 else 1)" 2>/dev/null; then
    echo "[5/6] 14B SFT phase (~3.6h with REASONING data)..."
    echo "  Using 250K SFT + 9K DeepSeek reasoning traces"
    cd ~/RakshakAI
    # Download the reasoning-enhanced dataset
    python3 -c "
from huggingface_hub import hf_hub_download
import os
dst = os.path.expanduser('~/RakshakAI/v2/inputs/datasets/axolotl')
path = hf_hub_download('Muneerali199/rakshak-cwe-v3-data', 'train_87k_with_reasoning.jsonl', repo_type='dataset')
os.system(f'cp {path} {dst}/train_87k_with_reasoning.jsonl')
sz = os.path.getsize(f'{dst}/train_87k_with_reasoning.jsonl') / 1024 / 1024
print(f'Downloaded reasoning-enhanced dataset ({sz:.0f}MB)')
"
    python -m axolotl.cli.train v2/configs/lightning_14b_sft_v2_REASONING.yaml 2>&1 | tee ~/train_sft.log
else
    echo "[5/6] 14B SFT phase (~3.5h with FIXED config)..."
    echo "  Using standard 250K SFT data"
    cd ~/RakshakAI
    python -m axolotl.cli.train v2/configs/lightning_14b_sft_v2_FIXED.yaml 2>&1 | tee ~/train_sft.log
fi
SFT_END=$SECONDS
echo "SFT done: $(( (SFT_END - START) / 60 )) min elapsed"

# Check if training succeeded
if [ ! -d "v2/model/sft_14b" ]; then
    echo "❌ ERROR: SFT training failed, no output directory"
    exit 1
fi

echo "[6/6] 14B DPO phase (~1.6h with FIXED config)..."
echo "  Changes: higher LR (1e-5), 2 epochs, 4096 seq len, gradient clipping"
python -m axolotl.cli.train v2/configs/lightning_14b_dpo_v2_FIXED.yaml 2>&1 | tee ~/train_dpo.log
END=$SECONDS

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║   TRAINING COMPLETE! Total: $(( (END - START) / 60 )) min     ║"
echo "║   SFT: v2/model/sft_14b    DPO: v2/model/dpo_14b            ║"
echo "╚══════════════════════════════════════════════════════════════╝"

# Extract loss metrics from logs
echo ""
echo "📊 Training Metrics:"
echo "SFT Final Loss:"
tail -20 ~/train_sft.log | grep -i "loss" | tail -3
echo ""
echo "DPO Final Loss:"
tail -20 ~/train_dpo.log | grep -i "loss" | tail -3

if [ -n "$HF_TOKEN" ]; then
    echo ""
    echo "[7/7] Pushing models to HuggingFace..."
    python3 -c "
from huggingface_hub import HfApi
import os
api = HfApi()
print('Uploading SFT adapter...')
api.upload_folder(
    folder_path='v2/model/sft_14b',
    path_in_repo='sft_14b',
    repo_id='Muneerali199/rakshak-cwe-v3',
    token='$HF_TOKEN',
    ignore_patterns=['*.safetensors', 'optimizer.pt', 'training_args.bin', 'checkpoint-*'],
)
print('Uploading DPO adapter...')
api.upload_folder(
    folder_path='v2/model/dpo_14b',
    path_in_repo='dpo_14b',
    repo_id='Muneerali199/rakshak-cwe-v3',
    token='$HF_TOKEN',
    ignore_patterns=['*.safetensors', 'optimizer.pt', 'training_args.bin', 'checkpoint-*'],
)
print('✅ Models pushed to https://huggingface.co/Muneerali199/rakshak-cwe-v3')
"
else
    echo ""
    echo "  [SKIP] HF_TOKEN not set. Push manually:"
    echo "    export HF_TOKEN=\"hf_...\""
    echo "    huggingface-cli upload Muneerali199/rakshak-cwe-v3 v2/model/sft_14b --repo-type model"
    echo "    huggingface-cli upload Muneerali199/rakshak-cwe-v3 v2/model/dpo_14b --repo-type model"
fi

END=$SECONDS
HOURS=$(echo "scale=1; (END - START) / 3600" | bc)
COST=$(echo "scale=2; $HOURS * 2.50" | bc)

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║   FINAL SUMMARY                                             ║"
echo "║   Time: $HOURS hours                                       ║"
echo "║   Cost: ~\$$COST / \$14 budget                             ║"
echo "║                                                              ║"
echo "║   Next: Run benchmark_vs_big_models.py to test quality      ║"
echo "╚══════════════════════════════════════════════════════════════╝"
