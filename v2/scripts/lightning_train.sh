#!/bin/bash
set -e

HF_TOKEN="${HF_TOKEN:-}"
export HF_TOKEN

# Install dependencies
pip install -q axolotl==0.6.0 transformers==4.48.3 torchao==0.5.0 huggingface_hub safetensors

# Download checkpoint
huggingface-cli download Muneerali199/rakshak-cwe-14b-sft-step375 \
  --local-dir /cache/checkpoint --local-dir-use-symlinks False

# Remove incomplete optimizer
for f in optimizer.pt scheduler.pt; do
  p="/cache/checkpoint/$f"
  if [ -f "$p" ] && [ "$(stat -f%z "$p")" -lt 3000000000 ]; then
    rm "$p"
  fi
done

# Download dataset
huggingface-cli download --repo-type dataset Muneerali199/rakshak-sft-dataset \
  train_87k_with_reasoning.jsonl --local-dir /cache/dataset --local-dir-use-symlinks False

mkdir -p /cache/output /cache/prepared

cat > /cache/config.yml << 'CONFIG'
adapter: qlora
base_model: Qwen/Qwen2.5-Coder-14B-Instruct
bf16: true
fp16: false
dataloader_num_workers: 4
dataset_prepared_path: /cache/prepared

datasets:
  - type: chat_template
    chat_template: chatml
    field_messages: messages
    path: /cache/dataset/train_87k_with_reasoning.jsonl
    split: train

eval_strategy: "no"
learning_rate: 1.5e-4
num_epochs: 1
max_steps: 750
warmup_ratio: 0.03
lr_scheduler: cosine
optimizer: paged_adamw_8bit
micro_batch_size: 2
gradient_accumulation_steps: 8
load_in_4bit: true
bnb_4bit_compute_dtype: bfloat16
bnb_4bit_use_double_quant: true
bnb_4bit_quant_type: nf4
gradient_checkpointing: true
flash_attention: false
max_grad_norm: 1.0
lora_r: 32
lora_alpha: 32
lora_dropout: 0.05
lora_target_modules:
  - q_proj
  - k_proj
  - v_proj
  - o_proj
  - gate_proj
  - up_proj
  - down_proj
lora_modules_to_save:
  - embed_tokens
  - lm_head
sequence_len: 2048
sample_packing: true
group_by_length: true
train_on_inputs: false
resume_from_checkpoint: /cache/checkpoint
output_dir: /cache/output
save_strategy: steps
save_steps: 50
save_total_limit: 5
logging_steps: 10
report_to: none
special_tokens:
  pad_token: <|endoftext|>
seed: 42
rl_beta: null
CONFIG

# Upload watcher
uploaded=()
upload_watcher() {
  while true; do
    for d in /cache/output/checkpoint-*/; do
      [ -d "$d" ] || continue
      name=$(basename "$d")
      if [[ ! " ${uploaded[@]} " =~ " $name " ]]; then
        uploaded+=("$name")
        echo "[WATCHER] Uploading $name..."
        python3 -c "
from huggingface_hub import HfApi
api = HfApi()
api.upload_folder(folder_path='$d', repo_id='Muneerali199/rakshak-cwe-14b-sft-checkpoints', path_in_repo='$name', token='$HF_TOKEN')
" && echo "[WATCHER] Uploaded $name"
      fi
    done
    sleep 30
  done
}

upload_watcher &
WATCHER_PID=$!

# Train
python3 -m axolotl.cli.train /cache/config.yml || true

kill $WATCHER_PID 2>/dev/null

# Upload final
echo "Uploading final..."
python3 -c "
from huggingface_hub import HfApi
api = HfApi()
api.upload_folder(folder_path='/cache/output', repo_id='Muneerali199/rakshak-cwe-14b-sft-final', token='$HF_TOKEN')
print('Done!')
"

# Upload any remaining checkpoints
for d in /cache/output/checkpoint-*/; do
  [ -d "$d" ] || continue
  name=$(basename "$d")
  if [[ ! " ${uploaded[@]} " =~ " $name " ]]; then
    python3 -c "
from huggingface_hub import HfApi
api = HfApi()
api.upload_folder(folder_path='$d', repo_id='Muneerali199/rakshak-cwe-14b-sft-checkpoints', path_in_repo='$name', token='$HF_TOKEN')
"
  fi
done

echo "ALL DONE"
