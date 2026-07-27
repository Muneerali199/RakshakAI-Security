"""RakshakAI v2 — QLoRA Training Notebook
============================================
Trains Qwen2.5-Coder-7B on curated CWE vulnerability data.

Convert to .ipynb or run as a Kaggle script.

Usage on Kaggle:
1. Upload curated_80k_train.jsonl as a Dataset
2. Set HF_TOKEN secret in Kaggle Secrets
3. Run with GPU P100/T4 (free tier)
"""
# %% [markdown]
# # RakshakAI v2 — QLoRA Fine-Tune
#
# Base model: **Qwen2.5-Coder-7B-Instruct**
# Dataset: **Curated 80K CWE vulnerability analysis records**
# Method: **QLoRA** (4-bit NF4, LoRA rank 16)
#
# ## Setup

# %% Install dependencies
# !pip install -qU transformers peft accelerate bitsandbytes trl datasets huggingface_hub wandb

import os, json, gc, torch
import transformers
from datasets import load_dataset
from transformers import (
    AutoModelForCausalLM,
    AutoTokenizer,
    BitsAndBytesConfig,
    TrainingArguments,
)
from peft import LoraConfig, prepare_model_for_kbit_training, get_peft_model
from trl import SFTTrainer
from huggingface_hub import login as hf_login
import bitsandbytes as bnb

# %% [markdown]
# ## Configuration

# %% Config
MODEL_NAME = "Qwen/Qwen2.5-Coder-7B-Instruct"
DATASET_PATH = "/kaggle/input/curated-80k/curated_80k_train.jsonl"
OUTPUT_DIR = "/kaggle/working/rakshak-cwe-v3"
HF_REPO = "Muneerali199/rakshak-cwe-v3"

# LoRA hyperparams
LORA_R = 16
LORA_ALPHA = 32
LORA_DROPOUT = 0.05
TARGET_MODULES = ["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"]

# Training hyperparams
PER_DEVICE_BATCH_SIZE = 2  # Adjust for 16GB GPU
GRADIENT_ACCUMULATION = 4   # Effective batch size = 8
MAX_STEPS = 3000
LEARNING_RATE = 2e-4
SAVE_STEPS = 500
EVAL_STEPS = 500
LOGGING_STEPS = 25
WARMUP_STEPS = 100

MAX_SEQ_LENGTH = 2048
USE_FLASH_ATTN = False  # Set True on Ampere+ GPUs (A100, A10G)

# HF token (set as Kaggle secret)
HF_TOKEN = os.environ.get("HF_TOKEN", "")

# %% [markdown]
# ## Load Tokenizer & Model (4-bit QLoRA)

# %% Load model with 4-bit quantization
bnb_config = BitsAndBytesConfig(
    load_in_4bit=True,
    bnb_4bit_quant_type="nf4",
    bnb_4bit_compute_dtype=torch.float16,
    bnb_4bit_use_double_quant=True,
)

model = AutoModelForCausalLM.from_pretrained(
    MODEL_NAME,
    quantization_config=bnb_config,
    device_map="auto",
    trust_remote_code=True,
    use_flash_attention_2=USE_FLASH_ATTN,
    torch_dtype=torch.float16,
)

tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME, trust_remote_code=True)
tokenizer.pad_token = tokenizer.eos_token
tokenizer.padding_side = "right"

# %% Prepare model for k-bit training
model = prepare_model_for_kbit_training(model)

# %% Apply LoRA
lora_config = LoraConfig(
    r=LORA_R,
    lora_alpha=LORA_ALPHA,
    target_modules=TARGET_MODULES,
    lora_dropout=LORA_DROPOUT,
    bias="none",
    task_type="CAUSAL_LM",
)

model = get_peft_model(model, lora_config)
model.print_trainable_parameters()
# Should show ~0.5% trainable params (~40M of 7B)

# %% [markdown]
# ## Load Dataset

# %% Load and inspect dataset
dataset = load_dataset("json", data_files=DATASET_PATH, split="train")
dataset = dataset.shuffle(seed=42)

# Split into train/val
split = dataset.train_test_split(test_size=0.02, seed=42)
train_dataset = split["train"]
eval_dataset = split["test"]

print(f"Train: {len(train_dataset)} | Eval: {len(eval_dataset)}")

# Check record structure
print("Sample keys:", train_dataset[0].keys())
print("CWE distribution:")
from collections import Counter
cwes = Counter()
for i in range(min(len(train_dataset), 10000)):
    cwe = train_dataset[i].get("_meta", {}).get("cwe", "UNKNOWN")
    cwes[cwe] += 1
for cwe, count in cwes.most_common(10):
    print(f"  {cwe}: {count}")

# %% [markdown]
# ## Formatting Function
#
# The data uses OpenAI messages format. We convert it to the format
# expected by Qwen's chat template.

# %% Formatting function
def format_chat(example):
    """Format messages for SFTTrainer using the tokenizer's chat template."""
    messages = example["messages"]
    # Qwen expects standard messages format
    text = tokenizer.apply_chat_template(
        messages,
        tokenize=False,
        add_generation_prompt=False,
    )
    return {"text": text}

# Test formatting
sample = format_chat(train_dataset[0])
print("Formatted sample (first 500 chars):")
print(sample["text"][:500])

# %% [markdown]
# ## Training

# %% Training args
training_args = TrainingArguments(
    output_dir=OUTPUT_DIR,
    per_device_train_batch_size=PER_DEVICE_BATCH_SIZE,
    per_device_eval_batch_size=PER_DEVICE_BATCH_SIZE,
    gradient_accumulation_steps=GRADIENT_ACCUMULATION,
    gradient_checkpointing=True,
    max_steps=MAX_STEPS,
    learning_rate=LEARNING_RATE,
    bf16=torch.cuda.is_bf16_supported(),
    fp16=not torch.cuda.is_bf16_supported(),
    logging_steps=LOGGING_STEPS,
    save_steps=SAVE_STEPS,
    eval_steps=EVAL_STEPS,
    evaluation_strategy="steps",
    warmup_steps=WARMUP_STEPS,
    lr_scheduler_type="cosine",
    optim="paged_adamw_8bit",
    report_to="none",
    ddp_find_unused_parameters=False,
    remove_unused_columns=True,
    dataloader_num_workers=2,
    save_total_limit=2,
    load_best_model_at_end=True,
    metric_for_best_model="eval_loss",
    greater_is_better=False,
    push_to_hub=False,  # We'll push manually
)

# %% Trainer
trainer = SFTTrainer(
    model=model,
    tokenizer=tokenizer,
    args=training_args,
    train_dataset=train_dataset,
    eval_dataset=eval_dataset,
    formatting_func=format_chat,
    max_seq_length=MAX_SEQ_LENGTH,
    dataset_text_field=None,  # formatting_func handles this
    packing=False,
)

# %% Train
trainer.train()

# %% [markdown]
# ## Save & Push to Hub

# %% Save adapter
model.save_pretrained(OUTPUT_DIR)
tokenizer.save_pretrained(OUTPUT_DIR)
print(f"Model saved to {OUTPUT_DIR}")

# %% Push to HuggingFace Hub
if HF_TOKEN:
    hf_login(HF_TOKEN)
    model.push_to_hub(HF_REPO)
    tokenizer.push_to_hub(HF_REPO)
    print(f"Model pushed to {HF_REPO}")
else:
    print("No HF_TOKEN set. Download the model from Kaggle output.")

# %% [markdown]
# ## Evaluation on benchmark

# %% Quick eval on held-out samples
from transformers import pipeline

pipe = pipeline(
    "text-generation",
    model=model,
    tokenizer=tokenizer,
    device_map="auto",
    max_new_tokens=512,
    do_sample=False,
    temperature=0.1,
)

# Test on some known vulnerable patterns
test_cases = [
    ("C buffer overflow", "char buf[10]; gets(buf);"),
    ("SQL injection", 'cursor.execute("SELECT * FROM users WHERE id = " + user_id)'),
    ("XSS", '<div>' + user_input + '</div>'),
]

for label, code in test_cases:
    prompt = f"<|im_start|>system\nYou are a security expert. Analyze the following code for vulnerabilities.\n<|im_end|>\n<|im_start|>user\n```c\n{code}\n```\n<|im_end|>\n<|im_start|>assistant\n"
    result = pipe(prompt)[0]["generated_text"]
    print(f"\n=== {label} ===")
    print(result[len(prompt):300])

# %% Cleanup
gc.collect()
torch.cuda.empty_cache()
