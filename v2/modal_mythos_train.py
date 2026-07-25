"""
RakshakAI v2 — Merge LoRA → SFT on Modal A10G
Target: Beat Claude Mythos 5 on security benchmarks

Usage:
    python3 -m modal run v2/modal_mythos_train.py --action merge    # Step 1: merge adapter → full model
    python3 -m modal run v2/modal_mythos_train.py --action train    # Step 2: SFT on A10G
    python3 -m modal run v2/modal_mythos_train.py --action all      # Both steps
"""
import modal
import os
from pathlib import Path

app = modal.App("rakshakai-v2-mythos")

HF_TOKEN = os.environ.get("HF_TOKEN", "")

image = (
    modal.Image.from_registry("pytorch/pytorch:2.5.1-cuda12.4-cudnn9-devel")
    .run_commands(
        "pip install --upgrade pip",
        "pip install transformers==4.47.1 datasets==3.2.0 accelerate==1.2.1 "
        "peft==0.14.0 trl==0.15.1 bitsandbytes==0.45.0 "
        "tensorboard==2.18.0 sentencepiece==0.2.0 protobuf==5.29.3 "
        "huggingface-hub==0.27.1 wandb==0.19.1 pyyaml",
        "pip install axolotl==0.6.0",
        "MAX_JOBS=4 pip install flash-attn --no-build-isolation",
    )
    .env({"HF_HUB_ENABLE_HF_TRANSFER": "1"})

)

volume = modal.Volume.from_name("rakshakai-data", create_if_missing=True)

MERGE_MODEL_NAME = "Muneerali199/RakshakAI-SecureCoder-7B-v1-merged"


@app.function(
    image=image,
    gpu="A10G",
    memory=32000,
    timeout=7200,
    secrets=[modal.Secret.from_dict({"HF_TOKEN": HF_TOKEN})],
    volumes={"/data": volume},
)
def merge_adapter():
    """Merge RakshakAI-v1 LoRA → full merged model on HF."""
    import torch
    from transformers import AutoModelForCausalLM, AutoTokenizer
    from peft import PeftModel
    from huggingface_hub import HfApi
    from pathlib import Path

    base_name = "Qwen/Qwen2.5-Coder-7B-Instruct"
    adapter_name = "Muneerali199/RakshakAI-SecureCoder-7B-v1"
    save_path = Path("/data/merged_model")

    print(f"[1/4] Loading base: {base_name}")
    base = AutoModelForCausalLM.from_pretrained(
        base_name,
        torch_dtype=torch.bfloat16,
        device_map="auto",
        token=os.environ["HF_TOKEN"],
    )

    print(f"[2/4] Loading LoRA: {adapter_name}")
    model = PeftModel.from_pretrained(base, adapter_name, token=os.environ["HF_TOKEN"])

    print("[3/4] Merging & unloading...")
    merged = model.merge_and_unload()

    print("[3b/4] Saving to volume...")
    merged.save_pretrained(str(save_path), safe_serialization=True, max_shard_size="4GB")
    tokenizer = AutoTokenizer.from_pretrained(base_name, token=os.environ["HF_TOKEN"])
    tokenizer.save_pretrained(str(save_path))
    volume.commit()
    print(f"  Saved to volume ({sum(f.stat().st_size for f in save_path.rglob('*')) / 1e9:.1f} GB)")

    print(f"[4/4] Uploading to HF: {MERGE_MODEL_NAME}")
    api = HfApi(token=os.environ["HF_TOKEN"])
    api.upload_folder(
        folder_id=str(save_path),
        repo_id=MERGE_MODEL_NAME,
        repo_type="model",
        ignore_patterns=[".gitattributes", "README.md"],
    )

    # Verify
    files = api.list_repo_files(MERGE_MODEL_NAME, repo_type="model")
    safetensors = [f for f in files if f.endswith(".safetensors")]
    for f in safetensors:
        info = api.get_paths_info(MERGE_MODEL_NAME, paths=[f], repo_type="model")[0]
        if info.size == 0:
            raise RuntimeError(f"File {f} is 0 bytes!")
        print(f"  ✓ {f}: {info.size/1e6:.1f} MB")

    print("✓ Merged model verified at:", MERGE_MODEL_NAME)
    return MERGE_MODEL_NAME


@app.function(
    image=image,
    gpu="L4",
    memory=64000,
    timeout=86400,
    secrets=[modal.Secret.from_dict({"HF_TOKEN": HF_TOKEN})],
    volumes={"/data": volume},
)
def train():
    """SFT on A10G with 303K samples — targets Mythos 5."""
    import subprocess, yaml, sys, requests
    import os
    from pathlib import Path
    os.environ["PYTORCH_CUDA_ALLOC_CONF"] = "expandable_segments:True"

    data_dir = Path("/data/axolotl")
    data_dir.mkdir(parents=True, exist_ok=True)

    hf_base = "https://huggingface.co/datasets/Muneerali199/RakshakAI-v3-dataset/resolve/main/axolotl"
    headers = {"Authorization": f"Bearer {os.environ['HF_TOKEN']}"}

    for fname in ["train.jsonl", "val.jsonl"]:
        local_path = data_dir / fname
        if not local_path.exists():
            url = f"{hf_base}/{fname}"
            print(f"Downloading {fname}...")
            r = requests.get(url, headers=headers, stream=True)
            r.raise_for_status()
            with open(local_path, "wb") as f:
                for chunk in r.iter_content(chunk_size=8192):
                    f.write(chunk)
            size_mb = local_path.stat().st_size / 1e6
            print(f"  Downloaded {fname} ({size_mb:.1f} MB)")
        else:
            print(f"  {fname} already cached ({local_path.stat().st_size / 1e6:.1f} MB)")

    import glob
    output_dir = Path("/data/model_sft")

    config = {
        "base_model": MERGE_MODEL_NAME,

        "datasets": [{
            "path": str(data_dir / "train.jsonl"),
            "type": "chat_template",
            "chat_template": "chatml",
            "field_messages": "messages",
        }],
        "dataset_prepared_path": "/data/prepared",

        "val_set_size": 0.01,
        "eval_steps": 500,
        "eval_strategy": "steps",
        "eval_sample_max_num": 100,

        "micro_batch_size": 2,
        "gradient_accumulation_steps": 16,
        "sequence_len": 2048,
        "sample_packing": True,
        "pad_to_sequence_len": True,
        "group_by_length": True,
        "train_on_inputs": False,
        "dataloader_num_workers": 2,
        "dataloader_pin_memory": True,

        "optimizer": "adamw_8bit",
        "learning_rate": 1e-4,
        "lr_scheduler": "cosine",
        "warmup_ratio": 0.03,
        "num_epochs": 1,

        "lora_r": 32,
        "lora_alpha": 32,
        "lora_dropout": 0.05,
        "lora_target_modules": [
            "q_proj", "k_proj", "v_proj", "o_proj",
            "gate_proj", "up_proj", "down_proj",
        ],
        "lora_modules_to_save": ["embed_tokens", "lm_head"],

        "adapter": "qlora",
        "load_in_4bit": True,
        "bf16": True,
        "tf32": True,
        "flash_attention": True,

        "gradient_checkpointing": True,
        "gradient_checkpointing_kwargs": {"use_reentrant": False},

        "output_dir": str(output_dir),
        "save_strategy": "steps",
        "save_steps": 100,
        "save_total_limit": 5,
        "save_safetensors": True,

        "logging_steps": 10,
        "report_to": "none",
        "logging_dir": "/data/logs",

        "special_tokens": {"pad_token": "<|endoftext|>"},
        "seed": 42,
    }

    config_path = "/data/config_sft.yaml"
    log_file = "/data/train_log.txt"

    # Check for existing checkpoints
    existing = sorted(glob.glob(str(output_dir / "checkpoint-*"))) if output_dir.exists() else []
    if existing:
        config["resume_from_checkpoint"] = existing[-1]
        print(f"Resuming from checkpoint: {existing[-1]}")
    else:
        print("Starting fresh training run")

    # Write config
    with open(config_path, "w") as f:
        yaml.dump(config, f, default_flow_style=False)

    import threading, time

    keep_going = True
    last_sync = time.time()

    last_sync = time.time()
    def heartbeat():
        nonlocal last_sync
        while keep_going:
            time.sleep(20)
            print(f"[heartbeat] training still running... ({time.strftime('%H:%M:%S')})")
            if time.time() - last_sync > 55:
                volume.commit()
                last_sync = time.time()
                print(f"[heartbeat] volume synced at {time.strftime('%H:%M:%S')}")

    hb = threading.Thread(target=heartbeat, daemon=True)
    hb.start()

    proc = subprocess.Popen(
        ["python", "-m", "axolotl.cli.train", config_path],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        bufsize=1, universal_newlines=True,
    )

    train_ok = False
    with open(log_file, "a") as lf:
        lf.write(f"=== RUN at {time.strftime('%H:%M:%S')} ===\n")
        for line in proc.stdout:
            lf.write(line)
            lf.flush()
            print(line, end="")
            if "train" in line.lower() and ("completed" in line.lower() or "saving" in line.lower()):
                pass  # just tracking
        lf.write("\n=== STDERR ===\n")
        for line in proc.stderr:
            lf.write(line)
            lf.flush()
            print("ERR:", line, end="")

    keep_going = False
    hb.join(timeout=5)
    ret = proc.wait()

    if ret == 0:
        print("✓ Training run completed!")
        train_ok = True
    else:
        # Check if we made progress (checkpoints were saved)
        checkpoints = sorted(glob.glob(str(output_dir / "checkpoint-*"))) if output_dir.exists() else []
        if checkpoints:
            last_step = checkpoints[-1].split("checkpoint-")[-1]
            print(f"✗ Training interrupted after step {last_step}. Checkpoint saved for resume.")
        else:
            print("✗ Training died before any checkpoint saved.")

    # Sync everything to volume
    volume.commit()

    return train_ok


@app.local_entrypoint()
def main(action: str = "all"):
    """
    Actions: all | merge | train
    """
    if action in ("all", "merge"):
        print("\n[Step 1] Merging LoRA adapter → full model...")
        merge_adapter.remote()
        print("✓ Merge done!")

    if action in ("all", "train"):
        print("\n[Step 2] SFT training on A10G (auto-retry on preemption)...")
        total_steps = 3255  # total optimizer steps for this run
        max_attempts = 99
        for at in range(max_attempts):
            print(f"\n{'='*60}")
            print(f"Training attempt {at+1}/{max_attempts}")
            print(f"{'='*60}")
            try:
                ok = train.remote()
            except Exception as e:
                print(f"  Remote error (likely preemption): {e}")
                ok = False
            if ok:
                print("\n✓ Training completed successfully!")
                break
            # Check how far we got by reading the latest checkpoint
            import subprocess as sp
            chk = sp.run(
                ["python3", "-m", "modal", "volume", "ls", "rakshakai-data", "model_sft"],
                capture_output=True, text=True, timeout=15
            )
            ckpts = [l.strip() for l in chk.stdout.split('\n') if 'checkpoint-' in l]
            if ckpts:
                last = ckpts[-1].split('checkpoint-')[-1].split()[0]
                print(f"  Last checkpoint: step {last}")
                # Check if we've reached total_steps
                try:
                    if int(last) >= total_steps:
                        print("✓ All steps completed! Finishing.")
                        break
                except ValueError:
                    pass
            print(f"  Restarting in 5s...")
            import time as _t
            _t.sleep(5)
        else:
            print("✗ Max attempts reached. Training incomplete.")

    print("\n✓ Done!")
