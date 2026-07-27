#!/usr/bin/env python3
"""RakshakAI 14B — Resume checkpoint-375 → 750 (Final Run)"""
import os, sys, time, threading, subprocess, json
from datetime import datetime
import torch
from transformers import (
    AutoModelForCausalLM, AutoTokenizer, TrainingArguments, Trainer, BitsAndBytesConfig
)
from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training
from datasets import load_dataset
from huggingface_hub import HfApi, create_repo

HF_TOKEN = os.environ.get("HF_TOKEN", "")
HF_CHECKPOINTS = "Muneerali199/rakshak-cwe-14b-sft-checkpoints"
BASE_MODEL = "Qwen/Qwen2.5-Coder-14B-Instruct"
SEQ_LEN = 1024
BATCH_SIZE = 1
GRAD_ACCUM = 16
MAX_STEPS = 750
SAVE_STEPS = 25
LOG_STEPS = 5
RESUME_FROM = "checkpoint-375"

api = HfApi(token=HF_TOKEN)
try:
    create_repo(HF_CHECKPOINTS, exist_ok=True, token=HF_TOKEN)
except:
    pass

ts = lambda: datetime.now().strftime("%H:%M:%S")
print(f"[{ts()}] RakshakAI 14B — Resume {RESUME_FROM} → 750")

# ============ DOWNLOAD CHECKPOINT ============
ckpt_dir = "/workspace/checkpoint"
resume_path = f"{ckpt_dir}/{RESUME_FROM}"
os.makedirs(ckpt_dir, exist_ok=True)

if not os.path.exists(f"{resume_path}/trainer_state.json"):
    print(f"[{ts()}] Downloading {RESUME_FROM} from step375 repo...")
    subprocess.run(
        f"huggingface-cli download Muneerali199/rakshak-cwe-14b-sft-step375 "
        f"--local-dir {resume_path} --local-dir-use-symlinks False 2>/dev/null",
        shell=True, check=False, timeout=300,
    )

if not os.path.exists(f"{resume_path}/trainer_state.json"):
    print(f"[{ts()}] ERROR: checkpoint not found at {resume_path}"); sys.exit(1)

with open(f"{resume_path}/trainer_state.json") as f:
    start_step = json.load(f).get("global_step", 375)
print(f"[{ts()}] Checkpoint OK — resuming from step {start_step} → {MAX_STEPS} "
      f"(={MAX_STEPS - start_step} new steps)")

# ============ DATASET ============
ds_dir = "/workspace/dataset"
if not os.path.exists(f"{ds_dir}/train_87k_with_reasoning.jsonl"):
    print(f"[{ts()}] Downloading dataset...")
    os.makedirs(ds_dir, exist_ok=True)
    subprocess.run(
        f"huggingface-cli download --repo-type dataset Muneerali199/rakshak-sft-dataset "
        f"train_87k_with_reasoning.jsonl --local-dir {ds_dir} "
        f"--local-dir-use-symlinks False 2>/dev/null",
        shell=True, check=False, timeout=300,
    )

print(f"[{ts()}] Loading dataset...")
tokenizer = AutoTokenizer.from_pretrained(BASE_MODEL, trust_remote_code=True, token=HF_TOKEN)
tokenizer.pad_token = tokenizer.eos_token
tokenizer.padding_side = "right"
tokenizer.chat_template = "{% for msg in messages %}{{'<|im_start|>' + msg['role'] + '\n' + msg['content'] + '<|im_end|>\n'}}{% endfor %}{% if add_generation_prompt %}<|im_start|>assistant\n{% endif %}"

def fmt(ex):
    return {"text": tokenizer.apply_chat_template(ex["messages"], tokenize=False, add_generation_prompt=False)}

def tok_fn(examples):
    r = tokenizer(examples["text"], truncation=True, max_length=SEQ_LEN, padding="max_length")
    r["labels"] = r["input_ids"][:]
    return r

dataset = load_dataset("json", data_files=f"{ds_dir}/train_87k_with_reasoning.jsonl", split="train")
dataset = dataset.map(fmt, remove_columns=["messages"], num_proc=8)
dataset = dataset.map(tok_fn, remove_columns=["text"], batched=True, num_proc=8)
ds = dataset.train_test_split(test_size=0.005, seed=42)
train_ds, val_ds = ds["train"], ds["test"]
print(f"[{ts()}] Train: {len(train_ds)}, Val: {len(val_ds)}")

# ============ MODEL (4-bit QLoRA) ============
print(f"[{ts()}] Loading model (4-bit)...")
bnb = BitsAndBytesConfig(
    load_in_4bit=True, bnb_4bit_use_double_quant=True,
    bnb_4bit_quant_type="nf4", bnb_4bit_compute_dtype=torch.float16,
)
model = AutoModelForCausalLM.from_pretrained(
    BASE_MODEL, quantization_config=bnb, torch_dtype=torch.float16,
    trust_remote_code=True, device_map="auto", token=HF_TOKEN,
)
model = prepare_model_for_kbit_training(model)
model.config.use_cache = False

lora_config = LoraConfig(
    r=32, lora_alpha=64,
    target_modules=["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"],
    modules_to_save=["embed_tokens", "lm_head"],
    lora_dropout=0.05, bias="none", task_type="CAUSAL_LM",
)
model = get_peft_model(model, lora_config)
model.print_trainable_parameters()

# ============ TRAINING ARGS ============
args = TrainingArguments(
    output_dir="/workspace/output",
    per_device_train_batch_size=BATCH_SIZE,
    per_device_eval_batch_size=1,
    gradient_accumulation_steps=GRAD_ACCUM,
    learning_rate=1.5e-4,
    warmup_steps=20,
    lr_scheduler_type="cosine",
    fp16=True,
    max_steps=MAX_STEPS,
    save_strategy="steps",
    save_steps=SAVE_STEPS,
    save_total_limit=3,
    save_only_model=True,
    logging_steps=LOG_STEPS,
    logging_first_step=True,
    eval_strategy="steps",
    eval_steps=250,
    dataloader_num_workers=2,
    dataloader_pin_memory=True,
    report_to="none",
    gradient_checkpointing=True,
    max_grad_norm=1.0,
    seed=42,
    ddp_find_unused_parameters=False,
    remove_unused_columns=False,
)

# ============ UPLOAD WATCHER ============
uploaded = set()
def upload_watcher():
    while True:
        try:
            if not os.path.exists("/workspace/output"):
                time.sleep(30); continue
            for d in sorted(os.listdir("/workspace/output")):
                if not d.startswith("checkpoint-") or d in uploaded:
                    continue
                p = f"/workspace/output/{d}"
                if not os.path.exists(f"{p}/adapter_model.safetensors"):
                    continue
                print(f"\n[{ts()}] UPLOADING {d}...")
                try:
                    api.upload_folder(
                        folder_path=p, repo_id=HF_CHECKPOINTS,
                        path_in_repo=d, token=HF_TOKEN,
                        ignore_patterns=["optimizer.pt", "scheduler.pt", "rng_state*", "training_args.bin"],
                    )
                    uploaded.add(d)
                    print(f"[{ts()}] UPLOADED {d}")
                except Exception as e:
                    print(f"[{ts()}] Upload failed: {e}")
        except Exception as e:
            print(f"[{ts()}] Watcher error: {e}")
        time.sleep(30)

threading.Thread(target=upload_watcher, daemon=True).start()
print(f"[{ts()}] Upload watcher started")

# ============ TRAIN ============
remaining = MAX_STEPS - start_step
est_hours = remaining * 54 / 3600
print(f"\n[{ts()}] {'='*50}")
print(f"[{ts()}] TRAINING: step {start_step} → {MAX_STEPS} ({remaining} steps)")
print(f"[{ts()}] Est. time: {est_hours:.1f}h at ~54s/it")
print(f"[{ts()}] Checkpoints every {SAVE_STEPS} steps (every ~{SAVE_STEPS*54//60}m)")
print(f"[{ts()}] {'='*50}\n")

trainer = Trainer(
    model=model, args=args,
    train_dataset=train_ds, eval_dataset=val_ds,
    processing_class=tokenizer,
)

try:
    trainer.train(resume_from_checkpoint=resume_path)
    print(f"\n[{ts()}] {'='*50}")
    print(f"[{ts()}] ✅ TRAINING COMPLETE — {MAX_STEPS} steps reached!")
    print(f"[{ts()}] {'='*50}")

    final_path = "/workspace/output/final"
    trainer.save_model(final_path)
    print(f"[{ts()}] Uploading final...")
    api.upload_folder(
        folder_path=final_path, repo_id="Muneerali199/rakshak-cwe-14b-sft-final",
        token=HF_TOKEN, ignore_patterns=["*.pt", "*.bin", "rng_state*"],
    )
    print(f"[{ts()}] ✅ Uploaded final model")
except KeyboardInterrupt:
    print(f"\n[{ts()}] Interrupted — saving partial...")
    try:
        trainer.save_model("/workspace/output/interrupted")
    except: pass
    sys.exit(0)
except Exception as e:
    print(f"\n[{ts()}] ❌ ERROR: {e}")
    import traceback; traceback.print_exc()
    sys.exit(1)
