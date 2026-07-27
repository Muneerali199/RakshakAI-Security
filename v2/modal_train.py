"""
RakshakAI v2 — Modal Training Script
Target: Beat Mythos 5 & GPT-5.6 Terra on security benchmarks
Hardware: 1x H100 80GB ($3.95/hr) — 70 hours with $280 credits
Dataset: 383K samples, 631 CWEs, 30 languages

Usage:
    # 1. Upload dataset to Modal Volume (run locally once)
    modal run v2/modal_train.py --action upload

    # 2. Train (runs on H100)
    modal run v2/modal_train.py --action train

    # 3. Evaluate benchmarks (after training)
    modal run v2/modal_train.py --action evaluate

    # 4. All in one go
    modal run v2/modal_train.py
"""

from pathlib import Path
import modal
import sys
import os

# ── App & Volume ─────────────────────────────────────────────────────────
app = modal.App("rakshakai-v2")
volume = modal.Volume.from_name("rakshakai-data", create_if_missing=True)

# ── Custom Docker image ─────────────────────────────────────────────────
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

GPU_CONFIG = "H100"  # H100 80GB ($3.95/hr) — add payment method in Modal settings to use B200

# ── Upload dataset ──────────────────────────────────────────────────────
@app.function(volumes={"/data": volume}, timeout=600)
def upload_dataset():
    import shutil

    src = Path("v2/inputs/datasets/axolotl")
    dst = Path("/data/axolotl")
    dst.mkdir(parents=True, exist_ok=True)

    for f in ["train.jsonl", "val.jsonl", "test.jsonl"]:
        sp = src / f
        if sp.exists():
            shutil.copy2(str(sp), str(dst / f))
            print(f"  Uploaded {f} ({sp.stat().st_size / 1e6:.1f} MB)")
    volume.commit()
    print(f"Dataset uploaded to Modal Volume.")


# ── Train ───────────────────────────────────────────────────────────────
@app.function(
    image=image,
    gpu=GPU_CONFIG,
    volumes={"/data": volume},
    timeout=86400,  # 24h max
    secrets=[],
)
def train():
    import subprocess, json
    from pathlib import Path

    # Write training config
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

# Full fine-tune (no LoRA)
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

micro_batch_size: 24  # B200 192GB — can fit larger batches
gradient_accumulation_steps: 3  # effective batch = 72
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

    config_path = "/data/config.yaml"
    with open(config_path, "w") as f:
        f.write(config)

    print("=" * 60)
    print("Starting training on H100 80GB")
    print(f"Dataset: /data/axolotl/")
    print(f"Output: /data/model/")
    print("=" * 60)

    result = subprocess.run(
        ["python", "-m", "axolotl.cli.train", config_path],
        capture_output=True, text=True
    )
    print(result.stdout)
    if result.returncode != 0:
        print("STDERR:", result.stderr)
        sys.exit(1)

    volume.commit()
    print("Model saved to Modal Volume at /data/model/")


# ── Evaluate ────────────────────────────────────────────────────────────
@app.function(
    image=image,
    gpu=GPU_CONFIG,
    volumes={"/data": volume},
    timeout=7200,
)
def evaluate():
    """Run benchmark evaluation on trained model."""
    import subprocess, json

    model_path = "/data/model"
    if not (Path(model_path) / "config.json").exists():
        print("No trained model found at", model_path)
        return

    print("Running evaluation...")
    result = subprocess.run(
        ["python", "/root/v2/scripts/evaluate_phase_b.py",
         "--model", model_path, "--benchmarks", "all"],
        capture_output=True, text=True
    )
    print(result.stdout)
    if result.returncode != 0:
        print("STDERR:", result.stderr)


# ── Check status ────────────────────────────────────────────────────────
@app.function(volumes={"/data": volume})
def status():
    from pathlib import Path
    data = Path("/data")
    print("Modal Volume contents:")
    for p in sorted(data.rglob("*")):
        if p.is_file():
            print(f"  {p.relative_to(data)}  ({p.stat().st_size / 1e6:.1f} MB)")
    volume.commit()


# ── Local entrypoint ────────────────────────────────────────────────────
@app.local_entrypoint()
def main(action: str = "all"):
    """
    Actions: all | upload | train | evaluate | status
    """
    if action in ("all", "upload"):
        print("\n[1/4] Uploading dataset...")
        upload_dataset.remote()

    if action in ("all", "train"):
        print("\n[2/4] Training on H100...")
        train.remote()

    if action in ("all", "evaluate"):
        print("\n[3/4] Evaluating benchmarks...")
        evaluate.remote()

    if action in ("all", "status"):
        print("\n[4/4] Check status...")
        status.remote()

    print("\nDone!")
