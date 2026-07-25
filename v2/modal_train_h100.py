"""RakshakAI v2 — Train on Modal H100/B200.
Run AFTER uploading dataset with modal_upload.py.
Requires: payment method in Modal settings (credits cover costs).

Usage:
    python3 -m modal run v2/modal_train_h100.py
"""
import modal
import sys

app = modal.App("rakshakai-train")
volume = modal.Volume.from_name("rakshakai-data", create_if_missing=True)

image = (
    modal.Image.from_registry("pytorch/pytorch:2.5.1-cuda12.4-cudnn9-devel")
    .run_commands(
        "pip install --upgrade pip",
        "pip install transformers==4.47.1 datasets==3.2.0 accelerate==1.2.1 "
        "peft==0.14.0 trl==0.15.1 bitsandbytes==0.45.0 "
        "tensorboard==2.18.0 sentencepiece==0.2.0 protobuf==5.29.3 "
        "huggingface-hub==0.27.1 wandb==0.19.1",
        "pip install axolotl==0.6.0",
    )
    .env({"HF_HUB_ENABLE_HF_TRANSFER": "1"})
)


@app.function(
    image=image,
    gpu="H100",
    volumes={"/data": volume},
    timeout=86400,
)
def train():
    import subprocess

    config = """
base_model: Qwen/Qwen2.5-Coder-7B-Instruct

dataset:
  - path: /data/axolotl/train.jsonl
    type: jsonl
    split: train
    chat_template: chatml
    field_messages: messages

eval_dataset:
  - path: /data/axolotl/val.jsonl
    type: jsonl
    split: val
    chat_template: chatml
    field_messages: messages

val_set_size: 0
dataset_prepared_path: /data/prepared

lora_r: 0
lora_target_modules: []

optimizer: adamw_torch_fused
learning_rate: 1.5e-5
lr_scheduler: cosine
warmup_ratio: 0.03
weight_decay: 0.01
num_epochs: 2

eval_strategy: steps
eval_steps: 200
eval_sample_max_num: 500
metric_for_best_model: eval_loss
load_best_model_at_end: true
early_stopping_patience: 3

micro_batch_size: 24
gradient_accumulation_steps: 3
sequence_len: 4096
train_on_inputs: false

output_dir: /data/model
save_strategy: steps
save_steps: 500
save_total_limit: 2
save_only_model: true

bf16: true
tf32: true

gradient_checkpointing: true
gradient_checkpointing_kwargs:
  use_reentrant: false

sample_packing: true
group_by_length: true
dataloader_num_workers: 8
dataloader_pin_memory: true

logging_steps: 10
report_to: tensorboard
logging_dir: /data/logs

special_tokens:
  pad_token: "<|endoftext|>"

seed: 42
"""
    with open("/data/config.yaml", "w") as f:
        f.write(config)

    print("=" * 60)
    print("Training on H100 80GB")
    print("=" * 60)

    result = subprocess.run(
        ["python", "-m", "axolotl.cli.train", "/data/config.yaml"],
        capture_output=True, text=True
    )
    print(result.stdout)
    if result.returncode != 0:
        print("STDERR:", result.stderr[:2000])
        sys.exit(1)

    volume.commit()
    print("Model saved to /data/model/")


@app.local_entrypoint()
def main():
    train.remote()
