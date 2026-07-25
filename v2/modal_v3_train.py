"""
RakshakAI v3 — Modal QLoRA Training (7B on A10G / 14B on A100)

Modes:
  modal run v2/modal_v3_train.py::train           # 7B → A10G (fast, $2/hr)
  modal run v2/modal_v3_train.py::train_14b        # 14B → A100 (strong, $4/hr)

Dataset: Muneerali199/rakshak-cwe-v3-data (500K CWE samples, 13 languages)
Output: Muneerali199/rakshak-cwe-v3 (LoRA adapter)
"""
import os
from pathlib import Path
import modal

HF_TOKEN = os.environ.get("HF_TOKEN", "")
HF_DATASET = os.environ.get("HF_DATASET", "Muneerali199/rakshak-cwe-v3-data")
HF_REPO = os.environ.get("HF_REPO", "Muneerali199/rakshak-cwe-v3")

app = modal.App("rakshakai-v3")

base_image = (
    modal.Image.from_registry("pytorch/pytorch:2.5.1-cuda12.4-cudnn9-devel")
    .run_commands(
        "pip install --upgrade pip",
        "pip install transformers==4.47.1 datasets==3.2.0 accelerate==1.2.1 "
        "peft==0.14.0 trl==0.15.1 bitsandbytes==0.45.0 "
        "huggingface-hub==0.27.1 hf_transfer sentencepiece==0.2.0 protobuf==5.29.3",
    )
    .env({"HF_HUB_ENABLE_HF_TRANSFER": "1", "HF_HUB_DISABLE_SYMLINKS_WARNING": "1"})
)


def build_train_fn(model_name: str, batch_size: int, grad_accum: int,
                   max_steps: int, lr: float, max_seq: int, gpu: str):
    """Factory: returns a Modal function that runs QLoRA training."""

    @modal.App()
    def inner_app():
        pass

    @inner_app.function(
        image=base_image,
        gpu=gpu,
        timeout=86400,
        secrets=[],
    )
    def train():
        import os, torch, gc
        from transformers import (
            AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig, TrainingArguments,
        )
        from peft import LoraConfig, prepare_model_for_kbit_training, get_peft_model
        from trl import SFTTrainer
        from datasets import load_dataset
        from huggingface_hub import login as hf_login

        os.environ["HF_TOKEN"] = HF_TOKEN
        os.environ["PYTORCH_CUDA_ALLOC_CONF"] = "expandable_segments:True"
        hf_login(HF_TOKEN)

        MODEL_NAME = model_name
        PER_DEVICE_BATCH_SIZE = batch_size
        GRADIENT_ACCUMULATION = grad_accum
        MAX_STEPS = max_steps
        LEARNING_RATE = lr
        MAX_SEQ_LENGTH = max_seq

        # ── Load model 4-bit ──
        print(f"Loading {MODEL_NAME} ...")
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
            torch_dtype=torch.float16,
        )
        tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME, trust_remote_code=True)
        tokenizer.pad_token = tokenizer.eos_token
        tokenizer.padding_side = "right"
        tokenizer.model_max_length = MAX_SEQ_LENGTH
        print(f"Model loaded ({sum(p.numel() for p in model.parameters())/1e9:.1f}B params)")

        # ── LoRA ──
        model = prepare_model_for_kbit_training(model)
        lora_config = LoraConfig(
            r=16, lora_alpha=32, target_modules=[
                "q_proj", "k_proj", "v_proj", "o_proj",
                "gate_proj", "up_proj", "down_proj",
            ],
            lora_dropout=0.05, bias="none", task_type="CAUSAL_LM",
        )
        model = get_peft_model(model, lora_config)
        trainable = sum(p.numel() for p in model.parameters() if p.requires_grad)
        total = sum(p.numel() for p in model.parameters())
        print(f"Trainable: {trainable:,} / {total:,} ({100*trainable/total:.2f}%)")

        # ── Dataset ──
        print(f"Loading dataset from {HF_DATASET}...")
        dataset = load_dataset(HF_DATASET, split="train")
        dataset = dataset.shuffle(seed=42)
        split_size = 20000 if len(dataset) > 50000 else int(len(dataset) * 0.02)
        dataset = dataset.select(range(min(len(dataset), 500000)))
        split = dataset.train_test_split(test_size=split_size, seed=42)
        train_dataset = split["train"]
        eval_dataset = split["test"]
        print(f"Train: {len(train_dataset)} | Eval: {len(eval_dataset)}")

        def format_chat(example):
            messages = example["messages"]
            text = tokenizer.apply_chat_template(
                messages, tokenize=False, add_generation_prompt=False,
            )
            return {"text": text}

        # ── Training ──
        training_args = TrainingArguments(
            output_dir="/root/model",
            per_device_train_batch_size=PER_DEVICE_BATCH_SIZE,
            per_device_eval_batch_size=PER_DEVICE_BATCH_SIZE,
            gradient_accumulation_steps=GRADIENT_ACCUMULATION,
            gradient_checkpointing=True,
            gradient_checkpointing_kwargs={"use_reentrant": False},
            max_steps=MAX_STEPS,
            learning_rate=LEARNING_RATE,
            fp16=True,
            logging_steps=25,
            save_steps=500,
            warmup_steps=100,
            lr_scheduler_type="cosine",
            optim="paged_adamw_8bit",
            report_to="none",
            remove_unused_columns=True,
            save_total_limit=2,
            push_to_hub=False,
            ddp_find_unused_parameters=False,
        )

        trainer = SFTTrainer(
            model=model,
            processing_class=tokenizer,
            args=training_args,
            train_dataset=train_dataset,
            formatting_func=format_chat,
        )

        print("Starting training...")
        trainer.train()
        print("Training complete")

        # ── Save & Push ──
        print("Saving adapter...")
        model.save_pretrained("/root/model")
        tokenizer.save_pretrained("/root/model")

        print(f"Pushing to {HF_REPO}...")
        model.push_to_hub(HF_REPO, token=HF_TOKEN)
        tokenizer.push_to_hub(HF_REPO, token=HF_TOKEN)
        print(f"Pushed to https://huggingface.co/{HF_REPO}")

        gc.collect()
        torch.cuda.empty_cache()
        print("Done!")

    return train


train = build_train_fn(
    model_name="Qwen/Qwen2.5-Coder-7B-Instruct",
    batch_size=1, grad_accum=8, max_steps=2000,
    lr=2e-4, max_seq=2048, gpu="A10G",
)
train_14b = build_train_fn(
    model_name="Qwen/Qwen2.5-Coder-14B-Instruct",
    batch_size=1, grad_accum=8, max_steps=2000,
    lr=1.5e-4, max_seq=2048, gpu="A100",
)
train_14b_long = build_train_fn(
    model_name="Qwen/Qwen2.5-Coder-14B-Instruct",
    batch_size=1, grad_accum=8, max_steps=4000,
    lr=1.5e-4, max_seq=4096, gpu="H100",
)
