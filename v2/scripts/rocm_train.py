"""RakshakAI SFT training for AMD ROCm (Radeon Cloud)"""
import json, os, sys, time, threading
from pathlib import Path

import torch
from transformers import (
    AutoModelForCausalLM, AutoTokenizer, TrainingArguments, Trainer,
    DataCollatorForSeq2Seq
)
from peft import LoraConfig, get_peft_model
from datasets import load_dataset
from huggingface_hub import HfApi, create_repo

HF_TOKEN = os.environ.get("HF_TOKEN", "")
HF_CHECKPOINTS = "Muneerali199/rakshak-cwe-14b-sft-checkpoints"
HF_FINAL = "Muneerali199/rakshak-cwe-14b-sft-final"
HF_STEP375 = "Muneerali199/rakshak-cwe-14b-sft-step375"

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

# Download checkpoint from HF
print("[ROCm] Downloading checkpoint...")
os.system(f"huggingface-cli download {HF_STEP375} --local-dir /cache/checkpoint --local-dir-use-symlinks False 2>/dev/null")
for f in ["optimizer.pt", "scheduler.pt"]:
    p = f"/cache/checkpoint/{f}"
    if os.path.exists(p) and os.path.getsize(p) < 3_000_000_000:
        os.remove(p)

# Download dataset
print("[ROCm] Downloading dataset...")
os.system(f"huggingface-cli download --repo-type dataset Muneerali199/rakshak-sft-dataset train_87k_with_reasoning.jsonl --local-dir /cache/dataset --local-dir-use-symlinks False 2>/dev/null")

print("[ROCm] Loading tokenizer...")
tokenizer = AutoTokenizer.from_pretrained(BASE_MODEL, trust_remote_code=True)
tokenizer.pad_token = tokenizer.eos_token
CHAT_TEMPLATE = "{% for msg in messages %}{{'<|im_start|>' + msg['role'] + '\n' + msg['content'] + '<|im_end|>\n'}}{% endfor %}{% if add_generation_prompt %}<|im_start|>assistant\n{% endif %}"
tokenizer.chat_template = CHAT_TEMPLATE

def format_chat(example):
    msgs = example["messages"]
    text = tokenizer.apply_chat_template(msgs, tokenize=False, add_generation_prompt=False)
    return {"text": text}

def tokenize_fn(examples):
    return tokenizer(examples["text"], truncation=True, max_length=SEQ_LEN, padding=False)

print("[ROCm] Loading dataset...")
dataset = load_dataset("json", data_files="/cache/dataset/train_87k_with_reasoning.jsonl", split="train")
dataset = dataset.map(format_chat, remove_columns=["messages"], num_proc=8)
dataset = dataset.map(tokenize_fn, remove_columns=["text"], batched=True, num_proc=8)
dataset = dataset.filter(lambda x: len(x["input_ids"]) <= SEQ_LEN, num_proc=8)
dataset = dataset.train_test_split(test_size=0.005, seed=42)
train_data = dataset["train"]
val_data = dataset["test"]
print(f"[ROCm] Train: {len(train_data)}, Val: {len(val_data)}")

print("[ROCm] Loading model in bf16 (no quantization)...")
model = AutoModelForCausalLM.from_pretrained(
    BASE_MODEL,
    torch_dtype=torch.bfloat16,
    trust_remote_code=True,
    device_map="auto",
)

lora_config = LoraConfig(
    r=32,
    lora_alpha=32,
    target_modules=["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"],
    modules_to_save=["embed_tokens", "lm_head"],
    lora_dropout=0.05,
    bias="none",
    task_type="CAUSAL_LM",
)
model = get_peft_model(model, lora_config)
model.print_trainable_parameters()

args = TrainingArguments(
    output_dir="/cache/output",
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
    save_total_limit=3,
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

# Upload watcher
uploaded = set()
def upload_watcher():
    while True:
        try:
            for d in sorted(os.listdir("/cache/output")):
                if d.startswith("checkpoint-") and d not in uploaded:
                    uploaded.add(d)
                    path = os.path.join("/cache/output", d)
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

resume = "/cache/checkpoint" if os.path.exists("/cache/checkpoint/trainer_state.json") else None
print(f"[ROCm] Resume from: {resume}")

trainer = Trainer(
    model=model,
    args=args,
    train_dataset=train_data,
    eval_dataset=val_data,
    tokenizer=tokenizer,
)

trainer.train(resume_from_checkpoint=resume)
print("[ROCm] Training done!")

print("[ROCm] Saving final model...")
trainer.save_model("/cache/output/final")
api.upload_folder(
    folder_path="/cache/output",
    repo_id=HF_FINAL,
    token=HF_TOKEN,
)
print(f"[ROCm] Uploaded to {HF_FINAL}")
