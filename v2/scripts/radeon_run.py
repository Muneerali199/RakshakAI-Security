#!/usr/bin/env python3
"""RakshakAI 14B — Final: Resume → Complete 750 steps"""
import os, sys, time, threading, subprocess, json, urllib.request
from datetime import datetime
import torch
from transformers import AutoModelForCausalLM, AutoTokenizer, TrainingArguments, Trainer, BitsAndBytesConfig
from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training
from datasets import load_dataset
from huggingface_hub import HfApi, create_repo

SCRIPT_URL = "https://raw.githubusercontent.com/Muneerali199/RakshakAI/main/v2/scripts/radeon_run.py"
HF_TOKEN = os.environ.get("HF_TOKEN", "")
HF_CHECKPOINTS = "Muneerali199/rakshak-cwe-14b-sft-checkpoints"
HF_STEP375 = "Muneerali199/rakshak-cwe-14b-sft-step375"
BASE_MODEL = "Qwen/Qwen2.5-Coder-14B-Instruct"
SEQ_LEN, BATCH_SIZE, GRAD_ACCUM = 1024, 1, 16
MAX_STEPS, SAVE_STEPS, LOG_STEPS = 750, 25, 5

ts = lambda: datetime.now().strftime("%H:%M:%S")

# Update self from GitHub if possible
try:
    req = urllib.request.Request(SCRIPT_URL, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=10) as r:
        new = r.read().decode()
    cur = open(__file__).read()
    if new != cur and len(new) > 100:
        open(__file__, "w").write(new)
        print(f"[{ts()}] Self-updated. Re-run...")
        os.execl(sys.executable, sys.executable, *sys.argv)
except Exception as e:
    print(f"[{ts()}] Self-update skipped ({e})")

print(f"[{ts()}] RakshakAI 14B — Final Run (step →750)")
if not HF_TOKEN:
    print(f"[{ts()}] WARNING: No HF_TOKEN set — will fail on uploads")

api = HfApi(token=HF_TOKEN) if HF_TOKEN else None

# === Find latest checkpoint ===
def find_checkpoint():
    for repo, local, name in [
        (HF_CHECKPOINTS, "/workspace/checkpoints_hf", "HF checkpoints"),
        (HF_STEP375, "/workspace/checkpoint-step375", "step375"),
    ]:
        state_file = f"{local}/trainer_state.json"
        if os.path.exists(state_file):
            with open(state_file) as f:
                step = json.load(f).get("global_step", 0)
            print(f"[{ts()}] Found {name}: step {step} at {local}")
            return local, step
        print(f"[{ts()}] Not found locally, trying HF: {repo}")
        os.makedirs(local, exist_ok=True)
        subprocess.run(
            f"huggingface-cli download {repo} --local-dir {local} --local-dir-use-symlinks False 2>/dev/null",
            shell=True, check=False, timeout=300,
        )
        if os.path.exists(state_file):
            with open(state_file) as f:
                step = json.load(f).get("global_step", 0)
            print(f"[{ts()}] Downloaded {name}: step {step}")
            return local, step
    print(f"[{ts()}] No checkpoint found — starting from scratch")
    return None, 0

ckpt_path, start_step = find_checkpoint()
print(f"[{ts()}] Starting from step {start_step} → {MAX_STEPS} "
      f"(={MAX_STEPS - start_step} new steps)")

# === Dataset ===
ds_file = "/workspace/dataset/train_87k_with_reasoning.jsonl"
if not os.path.exists(ds_file):
    print(f"[{ts()}] Downloading dataset...")
    os.makedirs("/workspace/dataset", exist_ok=True)
    subprocess.run(
        f"huggingface-cli download --repo-type dataset Muneerali199/rakshak-sft-dataset "
        f"train_87k_with_reasoning.jsonl --local-dir /workspace/dataset "
        f"--local-dir-use-symlinks False 2>/dev/null",
        shell=True, check=False, timeout=600,
    )

print(f"[{ts()}] Loading tokenizer + dataset...")
tok = AutoTokenizer.from_pretrained(BASE_MODEL, trust_remote_code=True, token=HF_TOKEN or None)
tok.pad_token = tok.eos_token
tok.padding_side = "right"
tok.chat_template = "{% for msg in messages %}{{'<|im_start|>' + msg['role'] + '\n' + msg['content'] + '<|im_end|>\n'}}{% endfor %}{% if add_generation_prompt %}<|im_start|>assistant\n{% endif %}"

def fmt(ex):
    return {"text": tok.apply_chat_template(ex["messages"], tokenize=False, add_generation_prompt=False)}

def tok_fn(exs):
    r = tok(exs["text"], truncation=True, max_length=SEQ_LEN, padding="max_length")
    r["labels"] = r["input_ids"][:]
    return r

ds = load_dataset("json", data_files=ds_file, split="train")
ds = ds.map(fmt, remove_columns=["messages"], num_proc=8)
ds = ds.map(tok_fn, remove_columns=["text"], batched=True, num_proc=8)
ds = ds.train_test_split(test_size=0.005, seed=42)
train_ds, val_ds = ds["train"], ds["test"]
print(f"[{ts()}] Train: {len(train_ds)}, Val: {len(val_ds)}")

# === Model ===
print(f"[{ts()}] Loading 4-bit model...")
bnb = BitsAndBytesConfig(
    load_in_4bit=True, bnb_4bit_use_double_quant=True,
    bnb_4bit_quant_type="nf4", bnb_4bit_compute_dtype=torch.float16,
)
model = AutoModelForCausalLM.from_pretrained(
    BASE_MODEL, quantization_config=bnb, torch_dtype=torch.float16,
    trust_remote_code=True, device_map="auto", token=HF_TOKEN or None,
)
model = prepare_model_for_kbit_training(model)
model.config.use_cache = False

lora = LoraConfig(
    r=32, lora_alpha=64,
    target_modules=["q_proj","k_proj","v_proj","o_proj","gate_proj","up_proj","down_proj"],
    modules_to_save=["embed_tokens","lm_head"],
    lora_dropout=0.05, bias="none", task_type="CAUSAL_LM",
)
model = get_peft_model(model, lora)
model.print_trainable_parameters()

# === Training ===
args = TrainingArguments(
    output_dir="/workspace/output",
    per_device_train_batch_size=BATCH_SIZE,
    per_device_eval_batch_size=1,
    gradient_accumulation_steps=GRAD_ACCUM,
    learning_rate=1.5e-4, warmup_steps=20,
    lr_scheduler_type="cosine", fp16=True,
    max_steps=MAX_STEPS,
    save_strategy="steps", save_steps=SAVE_STEPS,
    save_total_limit=3, save_only_model=True,
    logging_steps=LOG_STEPS, logging_first_step=True,
    eval_strategy="steps", eval_steps=250,
    dataloader_num_workers=2, dataloader_pin_memory=True,
    report_to="none", gradient_checkpointing=True,
    max_grad_norm=1.0, seed=42, remove_unused_columns=False,
)

# === Upload watcher ===
uploaded = set()
if api:
    def watcher():
        while True:
            try:
                if not os.path.exists("/workspace/output"):
                    time.sleep(30); continue
                for d in sorted(os.listdir("/workspace/output")):
                    if not d.startswith("checkpoint-") or d in uploaded: continue
                    p = f"/workspace/output/{d}"
                    if not os.path.exists(f"{p}/adapter_model.safetensors"): continue
                    print(f"[{ts()}] ⬆ Uploading {d}...")
                    try:
                        api.upload_folder(folder_path=p, repo_id=HF_CHECKPOINTS,
                            path_in_repo=d, token=HF_TOKEN,
                            ignore_patterns=["optimizer.pt","scheduler.pt","rng_state*","training_args.bin"])
                        uploaded.add(d)
                        print(f"[{ts()}] ✅ Uploaded {d}")
                    except Exception as e:
                        print(f"[{ts()}] Upload {d} failed: {e}")
            except: pass
            time.sleep(30)
    threading.Thread(target=watcher, daemon=True).start()

# === Train ===
remaining = MAX_STEPS - start_step
est_h = remaining * 54 / 3600
print(f"\n[{ts()}] {'='*50}")
print(f"[{ts()}] 🎯 Step {start_step} → {MAX_STEPS} ({remaining} steps, ~{est_h:.1f}h)")
print(f"[{ts()}] Save every {SAVE_STEPS} steps (~{SAVE_STEPS*54//60}m)")
print(f"[{ts()}] {'='*50}\n")

trainer = Trainer(model=model, args=args, train_dataset=train_ds,
                  eval_dataset=val_ds, processing_class=tok)

try:
    trainer.train(resume_from_checkpoint=ckpt_path)
    print(f"\n[{ts()}] ✅ 750 steps complete!")
    final = "/workspace/output/final"
    trainer.save_model(final)
    if api:
        api.upload_folder(folder_path=final, repo_id=HF_CHECKPOINTS,
            path_in_repo="final", token=HF_TOKEN,
            ignore_patterns=["*.pt","*.bin","rng_state*"])
        print(f"[{ts()}] ✅ Uploaded final to {HF_CHECKPOINTS}")
except KeyboardInterrupt:
    print(f"[{ts()}] Interrupted — partial save")
    trainer.save_model("/workspace/output/interrupted")
except Exception as e:
    print(f"[{ts()}] ❌ {e}")
    import traceback; traceback.print_exc()
