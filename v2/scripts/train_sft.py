"""RakshakAI direct SFT training (no axolotl dependency)"""
import json, math, sys
from pathlib import Path

import torch
from transformers import (
    AutoModelForCausalLM, AutoTokenizer, TrainingArguments, Trainer,
    DataCollatorForSeq2Seq, BitsAndBytesConfig
)
from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training
from datasets import load_dataset

# Config
BASE = "Qwen/Qwen2.5-Coder-7B-Instruct"
DATA = "v2/inputs/datasets/axolotl/train_250k.jsonl"
VAL_DATA = "v2/inputs/datasets/axolotl/val.jsonl"
OUTPUT = "v2/model/sft"
SEQ_LEN = 4096
MICRO_BS = 32
GA_STEPS = 2
LR = 2e-4
EPOCHS = 1

tokenizer = AutoTokenizer.from_pretrained(BASE, trust_remote_code=True)
tokenizer.pad_token = tokenizer.eos_token
tokenizer.padding_side = "right"

# ChatML template
CHAT_TEMPLATE = "{% for msg in messages %}{{'<|im_start|>' + msg['role'] + '\n' + msg['content'] + '<|im_end|>\n'}}{% endfor %}{% if add_generation_prompt %}<|im_start|>assistant\n{% endif %}"
tokenizer.chat_template = CHAT_TEMPLATE

def format_chat(example):
    msgs = example["messages"]
    # Format with train on last (assistant) message
    user_text = tokenizer.apply_chat_template(msgs[:-1], tokenize=False, add_generation_prompt=True)
    full_text = tokenizer.apply_chat_template(msgs, tokenize=False, add_generation_prompt=False)
    return {"text": user_text + "<|im_start|>assistant\n", "labels": full_text}

def tokenize_fn(examples):
    texts = examples["text"]
    labels_texts = examples["labels"]
    model_inputs = tokenizer(texts, truncation=True, max_length=SEQ_LEN, padding=False)
    labels = tokenizer(labels_texts, truncation=True, max_length=SEQ_LEN, padding=False)
    model_inputs["labels"] = labels["input_ids"]
    return model_inputs

print("Loading dataset...")
dataset = load_dataset("json", data_files=DATA, split="train")
val_dataset = load_dataset("json", data_files=VAL_DATA, split="train")

print(f"Train: {len(dataset)}, Val: {len(val_dataset)}")

dataset = dataset.map(format_chat, remove_columns=["messages", "_meta"])
val_dataset = val_dataset.map(format_chat, remove_columns=["messages", "_meta"])

dataset = dataset.map(tokenize_fn, remove_columns=["text", "labels"], batched=True)
val_dataset = val_dataset.map(tokenize_fn, remove_columns=["text", "labels"], batched=True)

bnb = BitsAndBytesConfig(
    load_in_4bit=True,
    bnb_4bit_use_double_quant=True,
    bnb_4bit_quant_type="nf4",
    bnb_4bit_compute_dtype=torch.bfloat16,
)

print("Loading model...")
model = AutoModelForCausalLM.from_pretrained(
    BASE,
    quantization_config=bnb,
    device_map="auto",
    torch_dtype=torch.bfloat16,
    trust_remote_code=True,
    attn_implementation="flash_attention_2",
)
model = prepare_model_for_kbit_training(model)
model.config.use_cache = False

lora = LoraConfig(
    r=32,
    lora_alpha=64,
    target_modules=["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"],
    lora_dropout=0.05,
    bias="none",
    task_type="CAUSAL_LM",
    modules_to_save=["embed_tokens", "lm_head"],
)
model = get_peft_model(model, lora)
model.print_trainable_parameters()

args = TrainingArguments(
    output_dir=OUTPUT,
    per_device_train_batch_size=MICRO_BS,
    gradient_accumulation_steps=GA_STEPS,
    learning_rate=LR,
    warmup_ratio=0.03,
    lr_scheduler_type="cosine",
    num_train_epochs=EPOCHS,
    logging_steps=10,
    save_strategy="steps",
    save_steps=500,
    save_total_limit=1,
    bf16=True,
    tf32=True,
    gradient_checkpointing=True,
    dataloader_num_workers=4,
    report_to="none",
    ddp_find_unused_parameters=False,
    prediction_loss_only=True,
)

collator = DataCollatorForSeq2Seq(tokenizer, model=model, padding=True)

print("Starting training...")
trainer = Trainer(
    model=model,
    args=args,
    train_dataset=dataset,
    eval_dataset=val_dataset,
    data_collator=collator,
)
trainer.train()
trainer.save_model(OUTPUT)
tokenizer.save_pretrained(OUTPUT)
print(f"Model saved to {OUTPUT}")
