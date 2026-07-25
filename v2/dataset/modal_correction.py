"""Quick LoRA correction to fix CWE-119 bias. Trains on balanced 2000-record set with weighted loss."""
import json, os, math, random
import modal

app = modal.App("rakshak-correction")

image = (
    modal.Image.debian_slim(python_version="3.11")
    .apt_install("git")
    .pip_install("torch", "accelerate", "peft", "huggingface_hub", "openai", "bitsandbytes", "transformers", "datasets")
    .pip_install("git+https://github.com/huggingface/transformers.git")
)

@app.function(image=image, gpu="T4", timeout=1800)
def run_correction(records):
    import torch
    from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig, Trainer, TrainingArguments
    from peft import PeftModel
    from datasets import Dataset

    print("Loading model...", flush=True)
    bnb = BitsAndBytesConfig(load_in_4bit=True, bnb_4bit_use_double_quant=True, bnb_4bit_quant_type="nf4")
    base = AutoModelForCausalLM.from_pretrained(
        "Qwen/Qwen3.5-9B", quantization_config=bnb, device_map="auto",
        torch_dtype=torch.bfloat16,
    )
    tokenizer = AutoTokenizer.from_pretrained("Qwen/Qwen3.5-9B")
    tokenizer.pad_token = tokenizer.eos_token

    # Load existing LoRA adapter as trainable
    model = PeftModel.from_pretrained(base, "Muneerali199/rakshak-cwe-v2", is_trainable=True)
    model.gradient_checkpointing_enable()
    model.enable_input_require_grads()
    print(f"Loaded base + LoRA. Trainable params: {sum(p.numel() for p in model.parameters() if p.requires_grad)}", flush=True)

    # Tokenize dataset
    print(f"Tokenizing {len(records)} records...", flush=True)
    texts = []
    cwe_weights = []
    for rec in records:
        msgs = rec["messages"]
        text = tokenizer.apply_chat_template(msgs, tokenize=False)
        texts.append(text)
        cwe = rec["_meta"]["cwe"]
        # Weight: penalize CWE-119 predictions on non-CWE-119 ground truth
        weight = 5.0 if cwe != "CWE-119" else 1.0
        cwe_weights.append(weight)

    # Tokenize
    enc = tokenizer(texts, truncation=True, padding=False, max_length=1024, return_tensors=None)
    ds = Dataset.from_dict({"input_ids": enc["input_ids"], "attention_mask": enc["attention_mask"], "weight": cwe_weights})

    # Data collator with labels = input_ids (autoregressive)
    def collator(batch):
        batch = {k: [d[k] for d in batch] for k in batch[0].keys()}
        batch["labels"] = batch["input_ids"].copy()
        batch = tokenizer.pad(batch, padding=True, return_tensors="pt")
        return batch

    args = TrainingArguments(
        output_dir="/tmp/correction",
        per_device_train_batch_size=1,
        gradient_accumulation_steps=8,
        num_train_epochs=3,
        learning_rate=5e-5,
        warmup_ratio=0.1,
        logging_steps=5,
        save_strategy="no",
        report_to="none",
        fp16=True,
        dataloader_num_workers=0,
        remove_unused_columns=False,
    )

    class WeightedTrainer(Trainer):
        def compute_loss(self, model, inputs, return_outputs=False, num_items_in_batch=None):
            labels = inputs.pop("labels")
            weights = inputs.pop("weight", None)
            outputs = model(**inputs)
            logits = outputs.logits
            loss_fn = torch.nn.CrossEntropyLoss(reduction="none", ignore_index=-100)
            shift_logits = logits[..., :-1, :].contiguous()
            shift_labels = labels[..., 1:].contiguous()
            token_loss = loss_fn(shift_logits.view(-1, shift_logits.size(-1)), shift_labels.view(-1))
            token_loss = token_loss.view(shift_labels.shape)
            loss_per_seq = token_loss.sum(dim=1) / (shift_labels != -100).sum(dim=1).float().clamp(min=1)
            if weights is not None:
                loss_per_seq = loss_per_seq * weights.to(loss_per_seq.device)
            loss = loss_per_seq.mean()
            return (loss, outputs) if return_outputs else loss

        def prediction_step(self, model, inputs, prediction_loss_only, ignore_keys=None):
            return None, None, None  # skip eval

    trainer = WeightedTrainer(
        model=model,
        args=args,
        train_dataset=ds,
        data_collator=collator,
    )

    print("Starting training...", flush=True)
    trainer.train()

    # Save adapter locally
    model.save_pretrained("/tmp/adapter_fixed")
    tokenizer.save_pretrained("/tmp/adapter_fixed")
    print("Training done. Adapter saved to /tmp/adapter_fixed", flush=True)

    # Push to HuggingFace
    from huggingface_hub import HfApi
    api = HfApi()
    api.upload_folder(
        folder_path="/tmp/adapter_fixed",
        repo_id="Muneerali199/rakshak-cwe-v2-fixed",
        repo_type="model",
    )
    print("Pushed to Muneerali199/rakshak-cwe-v2-fixed", flush=True)
    return True

@app.local_entrypoint()
def main():
    random.seed(42)

    # Load training data
    with open("v2/inputs/datasets/train_merged.jsonl") as f:
        all_records = [json.loads(line) for line in f if line.strip()]

    from collections import Counter
    by_cwe = {}
    for r in all_records:
        by_cwe.setdefault(r["_meta"]["cwe"], []).append(r)

    # Sample 100 per CWE class (9 non-119 + CWE-119 = 1000 records)
    target_classes = ["CWE-119", "CWE-79", "CWE-89", "CWE-22", "CWE-78", "CWE-502", "CWE-20", "CWE-125", "CWE-787", "CWE-416"]
    records = []
    for cwe in target_classes:
        pool = by_cwe.get(cwe, [])
        sampled = random.sample(pool, min(100, len(pool)))
        records.extend(sampled)

    print(f"Correction dataset: {len(records)} records")
    for cwe in target_classes:
        cnt = sum(1 for r in records if r["_meta"]["cwe"] == cwe)
        print(f"  {cwe}: {cnt}")
    print(f"  Non-CWE-119 count: {sum(1 for r in records if r['_meta']['cwe'] != 'CWE-119')}", flush=True)

    run_correction.remote(records)
