#!/usr/bin/env python3
"""RakshakAI 14B - Ultra-Fast Training (6hr optimized)"""
import os, sys, time, threading, subprocess
from datetime import datetime
import torch
from transformers import AutoModelForCausalLM, AutoTokenizer, TrainingArguments, Trainer, BitsAndBytesConfig
from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training
from datasets import load_dataset
from huggingface_hub import HfApi, create_repo

# ============ CONFIG ============
HF_TOKEN = os.environ.get("HF_TOKEN", "")
HF_CHECKPOINTS = 'Muneerali199/rakshak-cwe-14b-sft-checkpoints'
HF_FINAL = 'Muneerali199/rakshak-cwe-14b-sft-final'
BASE_MODEL = 'Qwen/Qwen2.5-Coder-14B-Instruct'

# Optimized for speed + memory
SEQ_LEN = 1024  # Reduced from 2048 for 2x speed
BATCH_SIZE = 1
GRAD_ACCUM = 16
MAX_STEPS = 750
SAVE_STEPS = 50
LOG_STEPS = 5

print(f"[{datetime.now().strftime('%H:%M:%S')}] 🚀 Starting optimized training...")

# ============ SETUP HF ============
api = HfApi(token=HF_TOKEN)
try:
    create_repo(HF_CHECKPOINTS, exist_ok=True, token=HF_TOKEN)
    create_repo(HF_FINAL, exist_ok=True, token=HF_TOKEN)
except: pass

# ============ TOKENIZER ============
print(f"[{datetime.now().strftime('%H:%M:%S')}] 📝 Loading tokenizer...")
tokenizer = AutoTokenizer.from_pretrained(BASE_MODEL, trust_remote_code=True, token=HF_TOKEN)
tokenizer.pad_token = tokenizer.eos_token
tokenizer.padding_side = "right"
tokenizer.chat_template = "{% for msg in messages %}{{'<|im_start|>' + msg['role'] + '\n' + msg['content'] + '<|im_end|>\n'}}{% endfor %}{% if add_generation_prompt %}<|im_start|>assistant\n{% endif %}"

def format_chat(ex):
    return {'text': tokenizer.apply_chat_template(ex['messages'], tokenize=False, add_generation_prompt=False)}

def tokenize_fn(examples):
    result = tokenizer(examples['text'], truncation=True, max_length=SEQ_LEN, padding='max_length')
    result['labels'] = result['input_ids'][:]
    return result

# ============ DATASET ============
print(f"[{datetime.now().strftime('%H:%M:%S')}] 📦 Loading dataset...")
dataset = load_dataset('json', data_files='/workspace/dataset/train_87k_with_reasoning.jsonl', split='train')
dataset = dataset.map(format_chat, remove_columns=['messages'], num_proc=8)
dataset = dataset.map(tokenize_fn, remove_columns=['text'], batched=True, num_proc=8)
dataset = dataset.train_test_split(test_size=0.005, seed=42)
train_ds, val_ds = dataset['train'], dataset['test']
print(f"[{datetime.now().strftime('%H:%M:%S')}] ✅ Train: {len(train_ds)}, Val: {len(val_ds)}")

# ============ MODEL ============
print(f"[{datetime.now().strftime('%H:%M:%S')}] 🔧 Loading model (4-bit)...")
bnb_config = BitsAndBytesConfig(
    load_in_4bit=True,
    bnb_4bit_use_double_quant=True,
    bnb_4bit_quant_type='nf4',
    bnb_4bit_compute_dtype=torch.float16
)

model = AutoModelForCausalLM.from_pretrained(
    BASE_MODEL,
    quantization_config=bnb_config,
    torch_dtype=torch.float16,
    trust_remote_code=True,
    device_map='auto',
    token=HF_TOKEN
)
model = prepare_model_for_kbit_training(model)
model.config.use_cache = False

# ============ LORA ============
lora_config = LoraConfig(
    r=32,
    lora_alpha=64,
    target_modules=['q_proj', 'k_proj', 'v_proj', 'o_proj', 'gate_proj', 'up_proj', 'down_proj'],
    modules_to_save=['embed_tokens', 'lm_head'],
    lora_dropout=0.05,
    bias='none',
    task_type='CAUSAL_LM'
)
model = get_peft_model(model, lora_config)

model.print_trainable_parameters()

# ============ TRAINING ARGS ============
training_args = TrainingArguments(
    output_dir='/workspace/output',
    per_device_train_batch_size=BATCH_SIZE,
    per_device_eval_batch_size=BATCH_SIZE,
    gradient_accumulation_steps=GRAD_ACCUM,
    learning_rate=1.5e-4,
    warmup_steps=20,
    lr_scheduler_type='cosine',
    fp16=True,
    max_steps=MAX_STEPS,
    save_strategy='steps',
    save_steps=SAVE_STEPS,
    save_total_limit=2,
    save_only_model=True,
    logging_steps=LOG_STEPS,
    logging_first_step=True,
    eval_strategy='steps',
    eval_steps=250,
    dataloader_num_workers=2,
    dataloader_pin_memory=True,
    report_to='none',
    gradient_checkpointing=True,
    max_grad_norm=1.0,
    seed=42
)

# ============ AUTO-UPLOAD WATCHER ============
uploaded_checkpoints = set()

def upload_watcher():
    """Background thread to upload checkpoints"""
    global uploaded_checkpoints
    while True:
        try:
            if not os.path.exists('/workspace/output'):
                time.sleep(30)
                continue
                
            checkpoints = [d for d in os.listdir('/workspace/output') if d.startswith('checkpoint-')]
            for ckpt_name in sorted(checkpoints):
                if ckpt_name in uploaded_checkpoints:
                    continue
                    
                ckpt_path = f'/workspace/output/{ckpt_name}'
                
                # Check if checkpoint is complete (has adapter_model.safetensors)
                if not os.path.exists(f'{ckpt_path}/adapter_model.safetensors'):
                    continue
                
                print(f"\n[{datetime.now().strftime('%H:%M:%S')}] ⬆️  Uploading {ckpt_name}...")
                try:
                    api.upload_folder(
                        folder_path=ckpt_path,
                        repo_id=HF_CHECKPOINTS,
                        path_in_repo=ckpt_name,
                        token=HF_TOKEN,
                        ignore_patterns=['optimizer.pt', 'scheduler.pt', 'rng_state*', 'training_args.bin']
                    )
                    uploaded_checkpoints.add(ckpt_name)
                    print(f"[{datetime.now().strftime('%H:%M:%S')}] ✅ Uploaded {ckpt_name}")
                except Exception as e:
                    print(f"[{datetime.now().strftime('%H:%M:%S')}] ❌ Upload failed: {e}")
                    
        except Exception as e:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] ⚠️  Watcher error: {e}")
        
        time.sleep(30)

# Start upload watcher
watcher_thread = threading.Thread(target=upload_watcher, daemon=True)
watcher_thread.start()
print(f"[{datetime.now().strftime('%H:%M:%S')}] 👀 Upload watcher started")

# ============ DOWNLOAD CHECKPOINT FOR RESUME ============
ckpt_dir = '/workspace/checkpoint'
resume_ckpt = None
if os.path.exists(f'{ckpt_dir}/checkpoint-100/trainer_state.json'):
    resume_ckpt = f'{ckpt_dir}/checkpoint-100'
    print(f"[{datetime.now().strftime('%H:%M:%S')}] ✅ Found checkpoint-100 locally")
else:
    print(f"[{datetime.now().strftime('%H:%M:%S')}] 🔄 Downloading checkpoint-100...")
    os.makedirs(ckpt_dir, exist_ok=True)
    subprocess.run(
        f'huggingface-cli download Muneerali199/rakshak-cwe-14b-sft-checkpoints '
        f'--local-dir {ckpt_dir} --local-dir-use-symlinks False '
        f'--include checkpoint-100/* 2>/dev/null',
        shell=True, check=False
    )
    if os.path.exists(f'{ckpt_dir}/checkpoint-100/trainer_state.json'):
        resume_ckpt = f'{ckpt_dir}/checkpoint-100'
        print(f"[{datetime.now().strftime('%H:%M:%S')}] ✅ Downloaded checkpoint-100")
    else:
        print(f"[{datetime.now().strftime('%H:%M:%S')}] ⚠️  checkpoint-100 not found, trying checkpoint-50...")
        subprocess.run(
            f'huggingface-cli download Muneerali199/rakshak-cwe-14b-sft-checkpoints '
            f'--local-dir {ckpt_dir} --local-dir-use-symlinks False '
            f'--include checkpoint-50/* 2>/dev/null',
            shell=True, check=False
        )
        if os.path.exists(f'{ckpt_dir}/checkpoint-50/trainer_state.json'):
            resume_ckpt = f'{ckpt_dir}/checkpoint-50'
            print(f"[{datetime.now().strftime('%H:%M:%S')}] ✅ Downloaded checkpoint-50")

# ============ TRAINING ============
print(f"\n[{datetime.now().strftime('%H:%M:%S')}] 🎯 TRAINING STARTED")
print(f"[{datetime.now().strftime('%H:%M:%S')}] {'Resuming from ' + resume_ckpt if resume_ckpt else 'Starting from scratch'}")
print(f"[{datetime.now().strftime('%H:%M:%S')}] Expected: ~20-30s/it\n")

trainer = Trainer(
    model=model,
    args=training_args,
    train_dataset=train_ds,
    eval_dataset=val_ds,
    processing_class=tokenizer
)

try:
    trainer.train(resume_from_checkpoint=resume_ckpt)
    
    print(f"\n[{datetime.now().strftime('%H:%M:%S')}] ✅ TRAINING COMPLETE!")
    
    # ============ SAVE FINAL MODEL ============
    print(f"[{datetime.now().strftime('%H:%M:%S')}] 💾 Saving final model...")
    final_path = '/workspace/output/final'
    trainer.save_model(final_path)
    
    print(f"[{datetime.now().strftime('%H:%M:%S')}] ⬆️  Uploading final model...")
    api.upload_folder(
        folder_path=final_path,
        repo_id=HF_FINAL,
        token=HF_TOKEN,
        ignore_patterns=['*.pt', '*.bin', 'rng_state*']
    )
    
    print(f"\n{'='*60}")
    print(f"[{datetime.now().strftime('%H:%M:%S')}] 🎉 ALL DONE!")
    print(f"{'='*60}")
    print(f"✅ Final model: https://huggingface.co/{HF_FINAL}")
    print(f"✅ Checkpoints: https://huggingface.co/{HF_CHECKPOINTS}")
    
except KeyboardInterrupt:
    print(f"\n[{datetime.now().strftime('%H:%M:%S')}] ⚠️  Training interrupted by user")
    sys.exit(0)
except Exception as e:
    print(f"\n[{datetime.now().strftime('%H:%M:%S')}] ❌ ERROR: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
