#!/bin/bash
# RakshakAI — 14B QLoRA for Lightning.ai (fits 14 credits)
set -e
cd ~

START=$SECONDS
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║   14B on A100 @ 2.50 cr/hr · 14 cr budget = 5.6h           ║"
echo "║   SFT (250K) ~3.5h + DPO (7K) ~0.8h + Eval ~0.5h = ~4.8h  ║"
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
echo "  Val:" $(wc -l < ~/RakshakAI/v2/inputs/datasets/axolotl/val.jsonl)

echo "[3/5] Installing dependencies..."
pip install --break-system-packages torch==2.5.1 transformers==4.47.1 accelerate peft datasets bitsandbytes tensorboard sentencepiece axolotl==0.6.0 2>&1 | tail -5
python3 -c "import torch; print(f'  PyTorch {torch.__version__}, CUDA: {torch.cuda.is_available()}')"
python3 -c "from transformers import AutoModel; print('  transformers OK')"
python3 -c "from axolotl.cli import train; print('  axolotl OK')"

echo "[4/5] 14B SFT phase (~3.5h)..."
cd ~/RakshakAI
python -m axolotl.cli.train v2/configs/lightning_14b_sft.yaml 2>&1 | tee ~/train_sft.log
SFT_END=$SECONDS
echo "SFT done: $(( (SFT_END - START) / 60 )) min elapsed"

echo "[5/5] 14B DPO phase (~0.8h)..."
python -m axolotl.cli.train v2/configs/lightning_14b_dpo.yaml 2>&1 | tee ~/train_dpo.log
END=$SECONDS

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║   DONE! Total: $(( (END - START) / 60 )) min                  ║"
echo "║   SFT: v2/model/sft_14b    DPO: v2/model/dpo_14b            ║"
echo "║                                                              ║"
echo "║   Pushing models to HuggingFace...                           ║"
echo "╚══════════════════════════════════════════════════════════════╝"

if [ -n "$HF_TOKEN" ]; then
    echo "[6/6] Pushing SFT adapter..."
    python3 -c "
from huggingface_hub import HfApi
import os
api = HfApi()
api.upload_folder(
    folder_path='v2/model/sft_14b',
    path_in_repo='',
    repo_id='Muneerali199/rakshak-cwe-v3',
    token='$HF_TOKEN',
    ignore_patterns=['*.safetensors', 'optimizer.pt', 'training_args.bin'],
)
print('Pushed SFT adapter')
"
    echo "  Model pushed to https://huggingface.co/Muneerali199/rakshak-cwe-v3"
else
    echo "  [SKIP] HF_TOKEN not set. Push manually:"
    echo "    export HF_TOKEN=\"hf_...\""
    echo "    huggingface-cli upload Muneerali199/rakshak-cwe-v3 v2/model/sft_14b --repo-type model"
fi

END=$SECONDS
echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║   ALL DONE! Credits used: ~$(( (END - START) / 60 * 250 / 100 )) / $14 budget    ║"
echo "╚══════════════════════════════════════════════════════════════╝"
