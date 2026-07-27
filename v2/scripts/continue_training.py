#!/usr/bin/env python3
"""Continue RakshakAI 14B training from step-375 → step-425.
Self-contained script for any GPU cloud notebook. Auto-pushes to HF."""
import os, sys, json, time, shutil
from pathlib import Path
from datetime import datetime

import torch
from transformers import (
    AutoModelForCausalLM, AutoTokenizer, TrainingArguments, Trainer,
    BitsAndBytesConfig
)
from peft import LoraConfig, PeftModel, prepare_model_for_kbit_training
from datasets import load_dataset
from huggingface_hub import HfApi, snapshot_download, create_repo

# ============================================================
# CONFIG — edit these if needed
# ============================================================
HF_TOKEN = os.environ.get("HF_TOKEN", "")
BASE_MODEL = "Qwen/Qwen2.5-Coder-14B-Instruct"
CKPT_375 = "Muneerali199/rakshak-cwe-14b-sft-step375"
OUTPUT_REPO = "Muneerali199/rakshak-cwe-14b-sft-checkpoints"
DATASET_FILE = "train_87k_with_reasoning.jsonl"
DATASET_REPO = "Muneerali199/rakshak-sft-dataset"

MAX_NEW_STEPS = 50        # train 50 more steps from 375 → 425
SEQ_LEN = 1024
MICRO_BS = 1
GRAD_ACCUM = 16           # effective BS = 16
LR = 1.5e-5               # 1/10 of original — continuation fine-tune
SAVE_EVERY = 25
LOG_EVERY = 5

WORKSPACE = "/workspace"
CKPT_DIR = f"{WORKSPACE}/checkpoint-step375"
OUTPUT_DIR = f"{WORKSPACE}/output"
ts = lambda: datetime.now().strftime("%H:%M:%S")

print(f"[{ts()}] {'=' * 55}")
print(f"[{ts()}]  RakshakAI — Resume step-375 → step-425 ({MAX_NEW_STEPS} steps)")
print(f"[{ts()}]  LR={LR}, constant, eff_bs={MICRO_BS * GRAD_ACCUM}")
print(f"[{ts()}]  HF_TOKEN={'SET' if HF_TOKEN else 'MISSING!'}")
print(f"[{ts()}] {'=' * 55}")

api = HfApi(token=HF_TOKEN) if HF_TOKEN else None

# ============================================================
# 1. Download dataset
# ============================================================
ds_file = f"{WORKSPACE}/dataset/{DATASET_FILE}"
if not os.path.exists(ds_file):
    print(f"[{ts()}] Downloading dataset...")
    os.makedirs(f"{WORKSPACE}/dataset", exist_ok=True)
    from huggingface_hub import hf_hub_download
    hf_hub_download(repo_id=DATASET_REPO, filename=DATASET_FILE,
                    repo_type="dataset", token=HF_TOKEN,
                    local_dir=f"{WORKSPACE}/dataset")

# ============================================================
# 2. Tokenizer + Dataset
# ============================================================
print(f"[{ts()}] Loading tokenizer...")
tok = AutoTokenizer.from_pretrained(BASE_MODEL, trust_remote_code=True, token=HF_TOKEN or None)
tok.pad_token = tok.eos_token
tok.padding_side = "right"
tok.chat_template = "{% for msg in messages %}{{'<|im_start|>' + msg['role'] + '\n' + msg['content'] + '<|im_end|>\n'}}{% endfor %}{% if add_generation_prompt %}<|im_start|>assistant\n{% endif %}"

def fmt_fn(ex):
    return {"text": tok.apply_chat_template(ex["messages"], tokenize=False, add_generation_prompt=False)}

def tok_fn(exs):
    r = tok(exs["text"], truncation=True, max_length=SEQ_LEN, padding="max_length")
    r["labels"] = r["input_ids"][:]
    return r

print(f"[{ts()}] Loading + tokenizing dataset...")
ds = load_dataset("json", data_files=ds_file, split="train")
ds = ds.map(fmt_fn, remove_columns=["messages"], num_proc=8)
ds = ds.map(tok_fn, remove_columns=["text"], batched=True, num_proc=8)
ds = ds.train_test_split(test_size=0.005, seed=42)
train_ds, val_ds = ds["train"], ds["test"]
print(f"[{ts()}] Train: {len(train_ds)}, Val: {len(val_ds)}")

# ============================================================
# 3. Load base model (4-bit) + LoRA adapter from step-375
# ============================================================
print(f"[{ts()}] Loading 4-bit base model...")
bnb = BitsAndBytesConfig(
    load_in_4bit=True, bnb_4bit_use_double_quant=True,
    bnb_4bit_quant_type="nf4", bnb_4bit_compute_dtype=torch.float16,
)
base = AutoModelForCausalLM.from_pretrained(
    BASE_MODEL, quantization_config=bnb, torch_dtype=torch.float16,
    trust_remote_code=True, device_map="auto", token=HF_TOKEN or None,
)
base = prepare_model_for_kbit_training(base)
base.config.use_cache = False

print(f"[{ts()}] Loading step-375 adapter...")
if not os.path.exists(f"{CKPT_DIR}/adapter_model.safetensors"):
    snapshot_download(repo_id=CKPT_375, local_dir=CKPT_DIR,
                      token=HF_TOKEN, ignore_patterns=["*.bin", "*.pt"])

model = PeftModel.from_pretrained(base, CKPT_DIR)
model.train()  # enable training mode
print(f"[{ts()}] Adapter loaded from step-375, training mode ON")
model.print_trainable_parameters()

# ============================================================
# 4. Training — run 50 fresh steps with loaded weights
# ============================================================
# max_steps = MAX_NEW_STEPS because Trainer starts from 0
# but model already has 375 steps of knowledge
args = TrainingArguments(
    output_dir=OUTPUT_DIR,
    per_device_train_batch_size=MICRO_BS,
    per_device_eval_batch_size=1,
    gradient_accumulation_steps=GRAD_ACCUM,
    learning_rate=LR,
    warmup_steps=0,
    lr_scheduler_type="constant",
    fp16=True,
    max_steps=MAX_NEW_STEPS,
    save_strategy="steps",
    save_steps=SAVE_EVERY,
    save_total_limit=2,
    save_only_model=True,
    logging_steps=LOG_EVERY,
    logging_first_step=True,
    eval_strategy="steps",
    eval_steps=25,
    dataloader_num_workers=2,
    dataloader_pin_memory=True,
    report_to="none",
    gradient_checkpointing=True,
    max_grad_norm=1.0,
    seed=42,
    remove_unused_columns=False,
    ddp_find_unused_parameters=False,
    prediction_loss_only=True,
)

print(f"\n[{ts()}] Starting {MAX_NEW_STEPS} fresh steps from loaded step-375 adapter...")
trainer = Trainer(model=model, args=args, train_dataset=train_ds,
                  eval_dataset=val_ds, processing_class=tok)

try:
    trainer.train()
    final_step = 375 + MAX_NEW_STEPS
    print(f"\n[{ts()}] ✅ Complete — effective step {final_step}")
except Exception as e:
    print(f"\n[{ts()}] ❌ {e}")
    import traceback; traceback.print_exc()
    try:
        trainer.save_model(f"{OUTPUT_DIR}/crash_recovery")
    except: pass
    sys.exit(1)

# ============================================================
# 5. Save final checkpoint + push to HF
# ============================================================
final_dir = f"{OUTPUT_DIR}/checkpoint-{final_step}"
os.makedirs(final_dir, exist_ok=True)
trainer.save_model(final_dir)

if api:
    # Push to checkpoint repo
    api.upload_folder(
        folder_path=final_dir, repo_id=OUTPUT_REPO,
        path_in_repo=f"checkpoint-{final_step}", token=HF_TOKEN,
        ignore_patterns=["optimizer.pt", "scheduler.pt", "rng_state*", "training_args.bin"],
    )
    print(f"[{ts()}] ✅ Pushed: hf.co/{OUTPUT_REPO}/tree/main/checkpoint-{final_step}")

    # Push as standalone named repo
    named = f"Muneerali199/rakshak-cwe-14b-sft-step{final_step}"
    create_repo(named, token=HF_TOKEN, exist_ok=True, repo_type="model")
    api.upload_folder(
        folder_path=final_dir, repo_id=named, token=HF_TOKEN,
        ignore_patterns=["optimizer.pt", "scheduler.pt", "rng_state*", "training_args.bin"],
    )
    print(f"[{ts()}] ✅ Pushed: hf.co/{named}")

print(f"[{ts()}] {'=' * 55}")
print(f"[{ts()}]  DONE — step-{final_step} ready")
print(f"[{ts()}] {'=' * 55}")
