#!/usr/bin/env python3
"""RakshakAI — Continue training step-375 → step-425. Fully self-contained.
Upload to any GPU cloud notebook and run: python3 continue.py"""
import subprocess, sys, os, json, time, shutil, importlib, warnings
warnings.filterwarnings("ignore")

# ── 1. Auto-install dependencies ──
reqs = ["torch>=2.0", "transformers>=4.44", "peft>=0.12", "datasets>=2.14",
        "accelerate>=0.33", "huggingface_hub>=0.24", "safetensors>=0.4",
        "bitsandbytes>=0.43", "scipy", "sentencepiece"]
for pkg in reqs:
    name = pkg.split(">=")[0].split("==")[0].strip()
    try:
        importlib.import_module(name.replace("-", "_"))
    except ImportError:
        p = name if ">=" not in pkg else pkg
        print(f"[setup] Installing {p}...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-q", p])

# ── 2. Imports ──
import torch
from transformers import AutoModelForCausalLM, AutoTokenizer, TrainingArguments, Trainer, BitsAndBytesConfig
from peft import LoraConfig, PeftModel, prepare_model_for_kbit_training
from datasets import load_dataset
from huggingface_hub import HfApi, snapshot_download, create_repo, hf_hub_download

# ── 3. Config ──
HF_TOKEN = os.environ.get("HF_TOKEN", "")
os.environ["HF_TOKEN"] = HF_TOKEN

BASE       = "Qwen/Qwen2.5-Coder-14B-Instruct"
CKPT_375   = "Muneerali199/rakshak-cwe-14b-sft-step375"
DS_REPO    = "Muneerali199/rakshak-sft-dataset"
DS_FILE    = "train_87k_with_reasoning.jsonl"
WKDIR      = "/workspace"
CKPT_LOCAL = f"{WKDIR}/checkpoint-375"
DS_LOCAL   = f"{WKDIR}/dataset/{DS_FILE}"
OUTDIR     = f"{WKDIR}/output"

MAX_NEW    = 50           # train 50 steps → step 425
LR         = 1.5e-5       # 1/10 original — continuation
SEQ_LEN    = 1024
BS         = 1
GA         = 16           # eff BS = 16
SAVE_EVERY = 25

ts = lambda: f"[{time.strftime('%H:%M:%S')}]"

# ── 4. Download dataset ──
if not os.path.exists(DS_LOCAL):
    print(f"{ts()} Downloading dataset...")
    os.makedirs(f"{WKDIR}/dataset", exist_ok=True)
    hf_hub_download(repo_id=DS_REPO, filename=DS_FILE, repo_type="dataset",
                    token=HF_TOKEN, local_dir=f"{WKDIR}/dataset")

# ── 5. Tokenizer ──
tok = AutoTokenizer.from_pretrained(BASE, trust_remote_code=True, token=HF_TOKEN)
tok.pad_token = tok.eos_token; tok.padding_side = "right"
tok.chat_template = "{% for msg in messages %}{{'<|im_start|>' + msg['role'] + '\n' + msg['content'] + '<|im_end|>\n'}}{% endfor %}{% if add_generation_prompt %}<|im_start|>assistant\n{% endif %}"

# ── 6. Load & tokenize dataset ──
ds = load_dataset("json", data_files=DS_LOCAL, split="train")
def fmt(ex):
    return {"text": tok.apply_chat_template(ex["messages"], tokenize=False, add_generation_prompt=False)}
def tok_fn(exs):
    r = tok(exs["text"], truncation=True, max_length=SEQ_LEN, padding="max_length")
    r["labels"] = r["input_ids"][:]; return r
ds = ds.map(fmt, remove_columns=["messages"], num_proc=8)
ds = ds.map(tok_fn, remove_columns=["text"], batched=True, num_proc=8)
ds = ds.train_test_split(test_size=0.005, seed=42)
train_ds, val_ds = ds["train"], ds["test"]
print(f"{ts()} Train: {len(train_ds)}, Val: {len(val_ds)}")

# ── 7. Load 4-bit model + step-375 adapter ──
bnb = BitsAndBytesConfig(load_in_4bit=True, bnb_4bit_use_double_quant=True,
                          bnb_4bit_quant_type="nf4", bnb_4bit_compute_dtype=torch.float16)
base = AutoModelForCausalLM.from_pretrained(BASE, quantization_config=bnb,
    torch_dtype=torch.float16, trust_remote_code=True, device_map="auto", token=HF_TOKEN)
base = prepare_model_for_kbit_training(base)
base.config.use_cache = False

if not os.path.exists(f"{CKPT_LOCAL}/adapter_model.safetensors"):
    print(f"{ts()} Downloading step-375 checkpoint...")
    snapshot_download(repo_id=CKPT_375, local_dir=CKPT_LOCAL, token=HF_TOKEN,
                      ignore_patterns=["*.bin", "*.pt", "rng_state*"])

model = PeftModel.from_pretrained(base, CKPT_LOCAL)
model.train()
print(f"{ts()} Step-375 adapter loaded, training mode ON")
model.print_trainable_parameters()

# ── 8. Training args ──
args = TrainingArguments(
    output_dir=OUTDIR,
    per_device_train_batch_size=BS,
    per_device_eval_batch_size=1,
    gradient_accumulation_steps=GA,
    learning_rate=LR,
    warmup_steps=0,
    lr_scheduler_type="constant",
    fp16=True,
    max_steps=MAX_NEW,
    save_strategy="steps", save_steps=SAVE_EVERY,
    save_total_limit=2, save_only_model=True,
    logging_steps=5, logging_first_step=True,
    eval_strategy="steps", eval_steps=25,
    dataloader_num_workers=2, dataloader_pin_memory=True,
    report_to="none", gradient_checkpointing=True,
    max_grad_norm=1.0, seed=42, remove_unused_columns=False,
)

trainer = Trainer(model=model, args=args, train_dataset=train_ds,
                  eval_dataset=val_ds, processing_class=tok)

# ── 9. Train! ──
print(f"\n{ts()} Training: 0 → {MAX_NEW} steps (effective: 375 → {375+MAX_NEW})")
try:
    trainer.train()
except Exception as e:
    print(f"{ts()} FAILED: {e}")
    import traceback; traceback.print_exc()
    try: trainer.save_model(f"{OUTDIR}/crash_recovery")
    except: pass
    sys.exit(1)

final_step = 375 + MAX_NEW
final_dir = f"{OUTDIR}/checkpoint-{final_step}"
os.makedirs(final_dir, exist_ok=True)
trainer.save_model(final_dir)
print(f"{ts()} Model saved to {final_dir}")

# ── 10. Push to HF ──
api = HfApi(token=HF_TOKEN)
print(f"{ts()} Pushing step-{final_step} to HF...")

# Push to shared checkpoint repo
api.upload_folder(folder_path=final_dir,
    repo_id="Muneerali199/rakshak-cwe-14b-sft-checkpoints",
    path_in_repo=f"checkpoint-{final_step}", token=HF_TOKEN,
    ignore_patterns=["optimizer.pt","scheduler.pt","rng_state*","training_args.bin"])

# Push to standalone named repo
named = f"Muneerali199/rakshak-cwe-14b-sft-step{final_step}"
create_repo(named, token=HF_TOKEN, exist_ok=True, repo_type="model")
api.upload_folder(folder_path=final_dir, repo_id=named, token=HF_TOKEN,
    ignore_patterns=["optimizer.pt","scheduler.pt","rng_state*","training_args.bin"])

print(f"\n{'='*55}")
print(f"  ✅ DONE — step-{final_step} on HF")
print(f"     hf.co/Muneerali199/rakshak-cwe-14b-sft-step{final_step}")
print(f"     hf.co/Muneerali199/rakshak-cwe-14b-sft-checkpoints")
print(f"{'='*55}")
