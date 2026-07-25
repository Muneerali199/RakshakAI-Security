"""RakshakAI 14B QLoRA SFT for AMD ROCm (Radeon Cloud) - FIXED"""
import json, os, sys, time, threading, subprocess
from pathlib import Path

import torch
from transformers import (
    AutoModelForCausalLM, AutoTokenizer, TrainingArguments, Trainer,
    BitsAndBytesConfig
)
from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training
from datasets import load_dataset
from huggingface_hub import HfApi, create_repo

HF_TOKEN = os.environ.get("HF_TOKEN", "")
HF_CHECKPOINTS = "Muneerali199/rakshak-cwe-14b-sft-checkpoints"
HF_FINAL = "Muneerali199/rakshak-cwe-14b-sft-final"
BASE_MODEL = "Qwen/Qwen2.5-Coder-14B-Instruct"
SEQ_LEN = 2048
BATCH_SIZE = 2
GRAD_ACCUM = 8
LR = 1.5e-4
MAX_STEPS = 750
WARMUP_RATIO = 0.03
SAVE_STEPS = 50
LOGGING_STEPS = 10

api = HfApi()
create_repo(HF_CHECKPOINTS, exist_ok=True, token=HF_TOKEN)
create_repo(HF_FINAL, exist_ok=True, token=HF_TOKEN)

# === Download checkpoint-50 (not step-375, we continue from 50) ===
ckpt_dir = "/workspace/checkpoint"
os.makedirs(ckpt_dir, exist_ok=True)
print("[FIXED] Downloading checkpoint-50...")
subprocess.run(
    f"huggingface-cli download Muneerali199/rakshak-cwe-14b-sft-checkpoints "
    f"--local-dir {ckpt_dir} --local-dir-use-symlinks False "
    f"--include checkpoint-50/* 2>/dev/null",
    shell=True, check=False
)
for f in ["optimizer.pt", "scheduler.pt", "rng_state.pth", "training_args.bin"]:
    p = f"{ckpt_dir}/checkpoint-50/{f}"
    if os.path.exists(p):
        os.remove(p)

# === Download dataset ===
ds_dir = "/workspace/dataset"
os.makedirs(ds_dir, exist_ok=True)
print("[FIXED] Downloading dataset...")
subprocess.run(
    f"huggingface-cli download --repo-type dataset Muneerali199/rakshak-sft-dataset "
    f"train_87k_with_reasoning.jsonl --local-dir {ds_dir} "
    f"--local-dir-use-symlinks False 2>/dev/null",
    shell=True, check=False
)

# === Tokenizer ===
print("[FIXED] Loading tokenizer...")
tokenizer = AutoTokenizer.from_pretrained(BASE_MODEL, trust_remote_code=True)
tokenizer.pad_token = tokenizer.eos_token
tokenizer.padding_side = "right"
CHAT_TEMPLATE = "{% for msg in messages %}{{'<|im_start|>' + msg['role'] + '\n' + msg['content'] + '<|im_end|>\n'}}{% endfor %}{% if add_generation_prompt %}<|im_start|>assistant\n{% endif %}"
tokenizer.chat_template = CHAT_TEMPLATE

def format_chat(example):
    msgs = example["messages"]
    text = tokenizer.apply_chat_template(msgs, tokenize=False, add_generation_prompt=False)
    return {"text": text}

def tokenize_fn(examples):
    result = tokenizer(examples["text"], truncation=True, max_length=SEQ_LEN, padding="max_length")
    result["labels"] = result["input_ids"].copy()
    return result

# === Dataset ===
print("[FIXED] Loading dataset...")
dataset = load_dataset("json", data_files=f"{ds_dir}/train_87k_with_reasoning.jsonl", split="train")
dataset = dataset.map(format_chat, remove_columns=["messages"], num_proc=8)
dataset = dataset.map(tokenize_fn, remove_columns=["text"], batched=True, num_proc=8)
dataset = dataset.train_test_split(test_size=0.005, seed=42)
train_data = dataset["train"]
val_data = dataset["test"]
print(f"[FIXED] Train: {len(train_data)}, Val: {len(val_data)}")

# === Model (4-bit QLoRA) ===
print("[FIXED] Loading model with 4-bit quantization...")
bnb = BitsAndBytesConfig(
    load_in_4bit=True,
    bnb_4bit_use_double_quant=True,
    bnb_4bit_quant_type="nf4",
    bnb_4bit_compute_dtype=torch.bfloat16,
)
model = AutoModelForCausalLM.from_pretrained(
    BASE_MODEL,
    quantization_config=bnb,
    torch_dtype=torch.bfloat16,
    trust_remote_code=True,
    device_map="auto",
    attn_implementation="flash_attention_2",
)
model = prepare_model_for_kbit_training(model)
model.config.use_cache = False

lora_config = LoraConfig(
    r=32,
    lora_alpha=64,
    target_modules=["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"],
    modules_to_save=["embed_tokens", "lm_head"],
    lora_dropout=0.05,
    bias="none",
    task_type="CAUSAL_LM",
)
model = get_peft_model(model, lora_config)
model.print_trainable_parameters()

# === Training Args ===
args = TrainingArguments(
    output_dir="/workspace/output",
    per_device_train_batch_size=BATCH_SIZE,
    per_device_eval_batch_size=2,
    gradient_accumulation_steps=GRAD_ACCUM,
    learning_rate=LR,
    warmup_ratio=WARMUP_RATIO,
    lr_scheduler_type="cosine",
    bf16=True,
    max_steps=MAX_STEPS,
    save_strategy="steps",
    save_steps=SAVE_STEPS,
    save_total_limit=2,
    save_only_model=True,
    logging_steps=LOGGING_STEPS,
    evaluation_strategy="steps",
    eval_steps=100,
    dataloader_num_workers=2,
    report_to="none",
    remove_unused_columns=False,
    gradient_checkpointing=True,
    max_grad_norm=1.0,
    seed=42,
    ddp_find_unused_parameters=False,
)

# === Upload watcher ===
uploaded = set()
def upload_watcher():
    while True:
        try:
            for d in sorted(os.listdir("/workspace/output")):
                if d.startswith("checkpoint-") and d not in uploaded:
                    uploaded.add(d)
                    path = os.path.join("/workspace/output", d)
                    print(f"[WATCHER] Uploading {d}...")
                    api.upload_folder(
                        folder_path=path,
                        repo_id=HF_CHECKPOINTS,
                        path_in_repo=d,
                        token=HF_TOKEN,
                    )
                    print(f"[WATCHER] Uploaded {d}")
        except Exception as e:
            print(f"[WATCHER] Error: {e}")
        time.sleep(30)

watcher = threading.Thread(target=upload_watcher, daemon=True)
watcher.start()

# === Resume from checkpoint-50 ===
resume = f"{ckpt_dir}/checkpoint-50"
print(f"[FIXED] Resuming from: {resume}")

# Determine which kwarg to use for tokenizer (transformers 5.x vs 4.x)
import transformers
transformers_version = tuple(int(x) for x in transformers.__version__.split(".")[:2])
trainer_kwargs = {"model": model, "args": args, "train_dataset": train_data, "eval_dataset": val_data}
if transformers_version >= (5, 0):
    print(f"[FIXED] transformers {transformers.__version__} detected, using processing_class")
    trainer_kwargs["processing_class"] = tokenizer
else:
    trainer_kwargs["tokenizer"] = tokenizer

trainer = Trainer(**trainer_kwargs)
trainer.train(resume_from_checkpoint=resume)
print("[FIXED] Training done!")

# === Save & Upload final ===
print("[FIXED] Saving final model...")
trainer.save_model("/workspace/output/final")
api.upload_folder(
    folder_path="/workspace/output",
    repo_id=HF_FINAL,
    token=HF_TOKEN,
    ignore_patterns=["*.pt", "*.bin", "rng_state*"],
)
print(f"[FIXED] Uploaded to {HF_FINAL}")
