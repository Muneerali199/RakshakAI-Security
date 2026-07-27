import modal, os, threading, time, json

HF_REPO_CHECKPOINTS = "Muneerali199/rakshak-cwe-14b-sft-checkpoints"
HF_REPO_FINAL = "Muneerali199/rakshak-cwe-14b-sft-final"
HF_TOKEN = os.environ.get("HF_TOKEN", "")

image = (
    modal.Image.debian_slim(python_version="3.11")
    .apt_install("git", "wget")
    .pip_install(
        "axolotl==0.6.0",
        "transformers==4.48.3",
        "torchao==0.5.0",
        "huggingface_hub",
        "safetensors",
    )
    .env({"HF_TOKEN": HF_TOKEN})
)

app = modal.App("rakshak-14b-sft")

@app.function(image=image, gpu="A10G", timeout=14400)
def train():
    import subprocess, os, sys
    from huggingface_hub import HfApi, create_repo

    api = HfApi()
    create_repo(HF_REPO_CHECKPOINTS, exist_ok=True, token=HF_TOKEN)
    create_repo(HF_REPO_FINAL, exist_ok=True, token=HF_TOKEN)

    # Download checkpoint
    subprocess.run([
        "huggingface-cli", "download",
        "Muneerali199/rakshak-cwe-14b-sft-step375",
        "--local-dir", "/cache/checkpoint",
        "--local-dir-use-symlinks", "False",
    ], check=True)

    for f in ["optimizer.pt", "scheduler.pt"]:
        p = f"/cache/checkpoint/{f}"
        if os.path.exists(p) and os.path.getsize(p) < 3_000_000_000:
            os.remove(p)

    # Download dataset
    subprocess.run([
        "huggingface-cli", "download",
        "--repo-type", "dataset",
        "Muneerali199/rakshak-sft-dataset",
        "train_87k_with_reasoning.jsonl",
        "--local-dir", "/cache/dataset",
        "--local-dir-use-symlinks", "False",
    ], check=True)

    os.environ["PYTORCH_CUDA_ALLOC_CONF"] = "expandable_segments:True"

    ckpt_path = "/cache/checkpoint"
    dataset_path = "/cache/dataset/train_87k_with_reasoning.jsonl"
    output_dir = "/cache/model/sft_14b"
    os.makedirs(output_dir, exist_ok=True)
    os.makedirs("/cache/prepared", exist_ok=True)

    config = f"""
adapter: qlora
base_model: Qwen/Qwen2.5-Coder-14B-Instruct
fp16: false
bf16: true
dataloader_num_workers: 2
dataset_prepared_path: /cache/prepared

datasets:
  - type: chat_template
    chat_template: chatml
    field_messages: messages
    path: {dataset_path}
    split: train

eval_strategy: "no"
learning_rate: 1.5e-4
num_epochs: 1
max_steps: 750
warmup_ratio: 0.03
lr_scheduler: cosine
optimizer: paged_adamw_8bit
micro_batch_size: 1
gradient_accumulation_steps: 16
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
resume_from_checkpoint: {ckpt_path}
output_dir: {output_dir}
save_strategy: steps
save_steps: 50
save_total_limit: 5
logging_steps: 10
report_to: none
special_tokens:
  pad_token: <|endoftext|>
seed: 42
rl_beta: null
"""

    with open("/cache/config.yml", "w") as f:
        f.write(config)

    # Watcher thread: upload checkpoints live
    uploaded = set()
    training_done = False

    def upload_watcher():
        while not training_done:
            try:
                for d in sorted(os.listdir(output_dir)):
                    if d.startswith("checkpoint-") and d not in uploaded:
                        uploaded.add(d)
                        path = os.path.join(output_dir, d)
                        print(f"[WATCHER] Uploading {d}...")
                        api.upload_folder(
                            folder_path=path,
                            repo_id=HF_REPO_CHECKPOINTS,
                            path_in_repo=d,
                            token=HF_TOKEN,
                        )
                        print(f"[WATCHER] Uploaded {d}")
            except Exception as e:
                print(f"[WATCHER] Error: {e}")
            time.sleep(30)

    watcher = threading.Thread(target=upload_watcher, daemon=True)
    watcher.start()

    # Run training
    result = subprocess.run(
        [sys.executable, "-m", "axolotl.cli.train", "/cache/config.yml"]
    )

    training_done = True
    watcher.join(timeout=60)

    if result.returncode != 0:
        print(f"Training failed with code {result.returncode}")
        # Still upload any checkpoints we have
        for d in sorted(os.listdir(output_dir)):
            if d.startswith("checkpoint-") and d not in uploaded:
                api.upload_folder(
                    folder_path=os.path.join(output_dir, d),
                    repo_id=HF_REPO_CHECKPOINTS,
                    path_in_repo=d,
                    token=HF_TOKEN,
                )

    # Upload everything
    print("Uploading final output dir...")
    api.upload_folder(
        folder_path=output_dir,
        repo_id=HF_REPO_FINAL,
        token=HF_TOKEN,
    )
    print(f"Uploaded to {HF_REPO_FINAL}")

@app.local_entrypoint()
def main():
    train.remote()
