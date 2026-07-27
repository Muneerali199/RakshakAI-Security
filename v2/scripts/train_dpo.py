"""RakshakAI DPO training (loads SFT adapter)"""
import json
from pathlib import Path

import torch
from transformers import (
    AutoModelForCausalLM, AutoTokenizer, TrainingArguments,
    BitsAndBytesConfig
)
from peft import PeftModel
from datasets import load_dataset

BASE = "Qwen/Qwen2.5-Coder-7B-Instruct"
SFT_ADAPTER = "v2/model/sft"
DPO_DATA = "v2/inputs/datasets/axolotl/dpo_train.jsonl"
OUTPUT = "v2/model/dpo"
SEQ_LEN = 2048
MICRO_BS = 16
LR = 5e-6
EPOCHS = 1
BETA = 0.1

tokenizer = AutoTokenizer.from_pretrained(BASE, trust_remote_code=True)
tokenizer.pad_token = tokenizer.eos_token
tokenizer.padding_side = "left"

CHAT_TEMPLATE = "{% for msg in messages %}{{'<|im_start|>' + msg['role'] + '\n' + msg['content'] + '<|im_end|>\n'}}{% endfor %}{% if add_generation_prompt %}<|im_start|>assistant\n{% endif %}"
tokenizer.chat_template = CHAT_TEMPLATE

def tokenize_chat(msgs):
    text = tokenizer.apply_chat_template(msgs, tokenize=False, add_generation_prompt=False)
    return tokenizer(text, truncation=True, max_length=SEQ_LEN, padding=False)["input_ids"]

def load_dpo_data(path):
    chosen_ids, rejected_ids = [], []
    with open(path) as f:
        for line in f:
            d = json.loads(line)
            chosen_ids.append(tokenize_chat(d["chosen"]))
            rejected_ids.append(tokenize_chat(d["rejected"]))
    return chosen_ids, rejected_ids

print(f"Loading DPO data from {DPO_DATA}...")
chosen, rejected = load_dpo_data(DPO_DATA)
print(f"Loaded {len(chosen)} pairs")

bnb = BitsAndBytesConfig(load_in_4bit=True, bnb_4bit_use_double_quant=True,
    bnb_4bit_quant_type="nf4", bnb_4bit_compute_dtype=torch.bfloat16)

print("Loading base model + SFT adapter...")
model = AutoModelForCausalLM.from_pretrained(
    BASE, quantization_config=bnb, device_map="auto",
    torch_dtype=torch.bfloat16, trust_remote_code=True,
    attn_implementation="flash_attention_2",
)
model = PeftModel.from_pretrained(model, SFT_ADAPTER)
model.config.use_cache = False

# DPO needs reference model
ref_model = AutoModelForCausalLM.from_pretrained(
    BASE, quantization_config=bnb, device_map="auto",
    torch_dtype=torch.bfloat16, trust_remote_code=True,
    attn_implementation="flash_attention_2",
)
ref_model = PeftModel.from_pretrained(ref_model, SFT_ADAPTER)

# DPO loss
def dpo_loss(chosen_logps, rejected_logps):
    log_ratio = rejected_logps - chosen_logps
    return -torch.nn.functional.logsigmoid(BETA * log_ratio).mean()

def compute_logps(model, input_ids):
    with torch.no_grad():
        outputs = model(input_ids=input_ids)
        logits = outputs.logits[:, :-1, :]
        labels = input_ids[:, 1:]
        log_probs = torch.nn.functional.log_softmax(logits, dim=-1)
        per_token_logps = log_probs.gather(-1, labels.unsqueeze(-1)).squeeze(-1)
        return per_token_logps.sum(dim=-1)

print("Starting DPO training (simple loop)...")
model.train()
opt = torch.optim.AdamW(model.parameters(), lr=LR)

n = len(chosen)
batch_size = MICRO_BS
for epoch in range(EPOCHS):
    for i in range(0, n, batch_size):
        end = min(i + batch_size, n)
        ch = torch.nn.utils.rnn.pad_sequence(
            [torch.tensor(c) for c in chosen[i:end]], 
            batch_first=True, padding_value=tokenizer.pad_token_id
        ).to(model.device)
        re = torch.nn.utils.rnn.pad_sequence(
            [torch.tensor(c) for c in rejected[i:end]],
            batch_first=True, padding_value=tokenizer.pad_token_id
        ).to(model.device)

        ch_logps = compute_logps(model, ch)
        re_logps = compute_logps(ref_model, re)

        loss = dpo_loss(ch_logps, re_logps)
        loss.backward()
        opt.step()
        opt.zero_grad()

        if (i // batch_size) % 10 == 0:
            print(f"Epoch {epoch+1}, batch {i//batch_size}/{n//batch_size}, loss: {loss.item():.4f}")

adapter_path = Path(OUTPUT)
model.save_pretrained(adapter_path)
tokenizer.save_pretrained(adapter_path)
print(f"DPO adapter saved to {OUTPUT}")
