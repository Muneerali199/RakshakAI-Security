# %% [markdown]
# # RakshakAI 14B SFT Training (Resume from step 375)
# Resume QLoRA SFT on Qwen2.5-Coder-14B-Instruct using axolotl

# %% [markdown]
# ## Setup — Install dependencies

# %%
import subprocess, sys, os, json, threading, time, shutil

def run(cmd):
    subprocess.run(cmd, shell=True, check=True)

run("pip install -q axolotl==0.6.0 transformers==4.48.3 torchao==0.5.0 huggingface_hub safetensors")

# %% [markdown]
# ## Download checkpoint and dataset from HuggingFace

# %%
HF_TOKEN = os.environ.get("HF_TOKEN", "")
HF_REPO_CHECKPOINTS = "Muneerali199/rakshak-cwe-14b-sft-checkpoints"
HF_REPO_FINAL = "Muneerali199/rakshak-cwe-14b-sft-final"

os.environ["HF_TOKEN"] = HF_TOKEN

# Download checkpoint
run(f"huggingface-cli download Muneerali199/rakshak-cwe-14b-sft-step375 --local-dir /kaggle/working/checkpoint --local-dir-use-symlinks False")

# Remove incomplete optimizer/scheduler
for f in ["optimizer.pt", "scheduler.pt"]:
    p = f"/kaggle/working/checkpoint/{f}"
    if os.path.exists(p) and os.path.getsize(p) < 3_000_000_000:
        os.remove(p)

# Download dataset
run(f"huggingface-cli download --repo-type dataset Muneerali199/rakshak-sft-dataset train_87k_with_reasoning.jsonl --local-dir /kaggle/working/dataset --local-dir-use-symlinks False")

# %% [markdown]
# ## Configure training

# %%
os.makedirs("/kaggle/working/output", exist_ok=True)
os.makedirs("/kaggle/working/prepared", exist_ok=True)

config = f"""
adapter: qlora
base_model: Qwen/Qwen2.5-Coder-14B-Instruct
fp16: true
bf16: false
dataloader_num_workers: 2
dataset_prepared_path: /kaggle/working/prepared

datasets:
  - type: chat_template
    chat_template: chatml
    field_messages: messages
    path: /kaggle/working/dataset/train_87k_with_reasoning.jsonl
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
bnb_4bit_compute_dtype: float16
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
sequence_len: 1024
sample_packing: true
group_by_length: true
train_on_inputs: false
resume_from_checkpoint: /kaggle/working/checkpoint
output_dir: /kaggle/working/output
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

with open("/kaggle/working/config.yml", "w") as f:
    f.write(config)

# %% [markdown]
# ## Start training with live HF uploads

# %%
from huggingface_hub import HfApi, create_repo

api = HfApi()
create_repo(HF_REPO_CHECKPOINTS, exist_ok=True, token=HF_TOKEN)
create_repo(HF_REPO_FINAL, exist_ok=True, token=HF_TOKEN)

uploaded = set()
training_done = False

def upload_watcher():
    while not training_done:
        try:
            for d in sorted(os.listdir("/kaggle/working/output")):
                if d.startswith("checkpoint-") and d not in uploaded:
                    uploaded.add(d)
                    path = os.path.join("/kaggle/working/output", d)
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
    [sys.executable, "-m", "axolotl.cli.train", "/kaggle/working/config.yml"],
    capture_output=False
)

training_done = True
watcher.join(timeout=60)

if result.returncode != 0:
    print(f"Training failed with code {result.returncode}")
    for d in sorted(os.listdir("/kaggle/working/output")):
        if d.startswith("checkpoint-") and d not in uploaded:
            api.upload_folder(
                folder_path=os.path.join("/kaggle/working/output", d),
                repo_id=HF_REPO_CHECKPOINTS,
                path_in_repo=d,
                token=HF_TOKEN,
            )

# Upload final
print("Uploading final output dir...")
api.upload_folder(
    folder_path="/kaggle/working/output",
    repo_id=HF_REPO_FINAL,
    token=HF_TOKEN,
)
print(f"Uploaded to {HF_REPO_FINAL}")
print("DONE")
