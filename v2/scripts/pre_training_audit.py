#!/usr/bin/env python3
"""
Comprehensive pre-training audit to catch ALL issues before spending $13 on training.
Run this BEFORE launching Lightning training.
"""
import json
import os
import sys
from pathlib import Path
import hashlib

RESET = "\033[0m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
BOLD = "\033[1m"

errors = []
warnings = []
info = []

def error(msg):
    errors.append(msg)
    print(f"{RED}✗ ERROR: {msg}{RESET}")

def warn(msg):
    warnings.append(msg)
    print(f"{YELLOW}⚠ WARNING: {msg}{RESET}")

def success(msg):
    info.append(msg)
    print(f"{GREEN}✓ {msg}{RESET}")

def section(title):
    print(f"\n{BLUE}{BOLD}{'='*70}{RESET}")
    print(f"{BLUE}{BOLD}{title}{RESET}")
    print(f"{BLUE}{BOLD}{'='*70}{RESET}\n")

# ============================================================================
# 1. DATASET VALIDATION
# ============================================================================
section("1. DATASET FILES")

datasets = {
    "train_250k.jsonl": {"expected_lines": 250000, "type": "old_sft", "use": False},
    "train_87k_with_reasoning.jsonl": {"expected_lines": 259000, "type": "sft_with_reasoning", "use": True},
    "train_250k_with_reasoning.jsonl": {"expected_lines": 9269, "type": "reasoning_only", "use": False},
    "val_cleaned.jsonl": {"expected_lines": 5000, "type": "validation", "use": True},
    "dpo_train.jsonl": {"expected_lines": 6979, "type": "dpo", "use": True},
}

base_path = "v2/inputs/datasets/axolotl"

for filename, meta in datasets.items():
    filepath = os.path.join(base_path, filename)
    
    if not os.path.exists(filepath):
        if meta["use"]:
            error(f"Missing REQUIRED file: {filename}")
        else:
            warn(f"Missing optional file: {filename}")
        continue
    
    # Check line count
    with open(filepath, 'r') as f:
        actual_lines = sum(1 for _ in f)
    
    expected = meta["expected_lines"]
    tolerance = 0.02  # 2% tolerance
    
    if abs(actual_lines - expected) > expected * tolerance:
        warn(f"{filename}: Expected ~{expected:,} lines, got {actual_lines:,}")
    else:
        success(f"{filename}: {actual_lines:,} lines ✓")
    
    # Check JSON validity (first 10 lines)
    try:
        with open(filepath, 'r') as f:
            for i in range(min(10, actual_lines)):
                line = f.readline()
                data = json.loads(line)
                
                # Validate structure
                if meta["type"] in ["old_sft", "sft_with_reasoning", "validation"]:
                    if "messages" not in data:
                        error(f"{filename} line {i+1}: Missing 'messages' field")
                        break
                    if not isinstance(data["messages"], list):
                        error(f"{filename} line {i+1}: 'messages' must be a list")
                        break
                    if len(data["messages"]) < 2:
                        error(f"{filename} line {i+1}: Need at least 2 messages")
                        break
                    if data["messages"][-1]["role"] != "assistant":
                        error(f"{filename} line {i+1}: Last message must be 'assistant'")
                        break
                
                elif meta["type"] == "dpo":
                    if "chosen" not in data or "rejected" not in data:
                        error(f"{filename} line {i+1}: Missing 'chosen'/'rejected'")
                        break
        
        success(f"{filename}: JSON format valid ✓")
        
    except json.JSONDecodeError as e:
        error(f"{filename}: Invalid JSON at line ~{i+1}: {e}")
    except Exception as e:
        error(f"{filename}: Validation error: {e}")

# ============================================================================
# 2. CONFIG VALIDATION
# ============================================================================
section("2. TRAINING CONFIGS")

try:
    import yaml
    
    configs_to_check = {
        "v2/configs/lightning_14b_sft_PRODUCTION.yaml": {
            "expected_train": "train_87k_with_reasoning.jsonl",
            "expected_val": "val_cleaned.jsonl",
            "expected_lr": 1.5e-4,
            "expected_batch": 8,
        },
        "v2/configs/lightning_14b_dpo_PRODUCTION.yaml": {
            "expected_train": "dpo_train_processed.jsonl",
            "expected_lr": 1e-5,
            "expected_seq_len": 4096,
        }
    }
    
    for config_file, expectations in configs_to_check.items():
        if not os.path.exists(config_file):
            error(f"Missing config: {config_file}")
            continue
        
        with open(config_file) as f:
            cfg = yaml.safe_load(f)
        
        print(f"\n{BOLD}Checking {config_file}:{RESET}")
        
        # Check dataset paths
        if "datasets" in cfg:
            ds = cfg["datasets"][0]
            train_path = ds.get("path", ds.get("data_files", [None])[0] if ds.get("data_files") else None) or ""
            actual_file = os.path.basename(train_path)
            expected_file = expectations.get("expected_train")
            
            if expected_file and actual_file != expected_file:
                error(f"  Using WRONG dataset: {actual_file} (should be {expected_file})")
            else:
                success(f"  Dataset: {actual_file}")
            
            # Check if file exists
            if train_path and not os.path.exists(train_path):
                error(f"  Dataset file doesn't exist: {train_path}")
        
        # Check validation dataset
        if "eval_datasets" in cfg:
            val_path = cfg["eval_datasets"][0].get("path", "")
            actual_val = os.path.basename(val_path)
            expected_val = expectations.get("expected_val")
            
            if expected_val and actual_val != expected_val:
                error(f"  Using WRONG validation: {actual_val} (should be {expected_val})")
            else:
                success(f"  Validation: {actual_val}")
        
        # Check learning rate
        actual_lr = cfg.get("learning_rate")
        expected_lr = expectations.get("expected_lr")
        if expected_lr and actual_lr != expected_lr:
            warn(f"  Learning rate: {actual_lr} (expected {expected_lr})")
        else:
            success(f"  Learning rate: {actual_lr}")
        
        # Check sequence length
        if "expected_seq_len" in expectations:
            actual_seq = cfg.get("sequence_len")
            expected_seq = expectations["expected_seq_len"]
            if actual_seq != expected_seq:
                error(f"  Sequence length: {actual_seq} (should be {expected_seq})")
            else:
                success(f"  Sequence length: {actual_seq}")
        
        # Check critical settings
        if cfg.get("load_in_4bit") != True:
            warn(f"  4-bit quantization disabled (may OOM)")
        else:
            success(f"  4-bit quantization: enabled")
        
        if cfg.get("gradient_checkpointing") != True:
            warn(f"  Gradient checkpointing disabled (may OOM)")
        else:
            success(f"  Gradient checkpointing: enabled")
        
        if "max_grad_norm" not in cfg:
            warn(f"  No gradient clipping (may cause NaN)")
        else:
            success(f"  Gradient clipping: {cfg['max_grad_norm']}")

except ImportError:
    error("PyYAML not installed. Run: pip install pyyaml")
except Exception as e:
    error(f"Config validation failed: {e}")

# ============================================================================
# 3. DEPENDENCY CHECK
# ============================================================================
section("3. PYTHON DEPENDENCIES")

required_packages = {
    "torch": "2.5.0",
    "transformers": "4.47.0",
    "axolotl": "0.6.0",
    "peft": None,
    "datasets": None,
    "bitsandbytes": None,
    "accelerate": None,
}

for package, min_version in required_packages.items():
    try:
        if package == "torch":
            import torch
            version = torch.__version__
            has_cuda = torch.cuda.is_available()
            success(f"{package}: {version} (CUDA: {has_cuda})")
            if not has_cuda:
                warn("CUDA not available - training will be VERY slow")
        
        elif package == "transformers":
            import transformers
            version = transformers.__version__
            success(f"{package}: {version}")
        
        elif package == "axolotl":
            try:
                import axolotl
                success(f"{package}: installed")
            except:
                error(f"{package}: not found (pip install axolotl==0.6.0)")
        
        else:
            exec(f"import {package}")
            success(f"{package}: installed")
    
    except ImportError:
        error(f"{package}: NOT INSTALLED")

# ============================================================================
# 4. DISK SPACE CHECK
# ============================================================================
section("4. DISK SPACE")

import shutil

def get_size(path):
    if os.path.isfile(path):
        return os.path.getsize(path)
    total = 0
    for dirpath, dirnames, filenames in os.walk(path):
        for f in filenames:
            fp = os.path.join(dirpath, f)
            if os.path.exists(fp):
                total += os.path.getsize(fp)
    return total

# Check available space
stat = shutil.disk_usage(".")
available_gb = stat.free / (1024**3)

# Estimate required space
dataset_size = get_size("v2/inputs/datasets/axolotl") / (1024**3)
estimated_model_size = 30  # GB (14B model + adapters + checkpoints)
estimated_cache = 50  # GB (HF cache, prepared datasets)
total_required = dataset_size + estimated_model_size + estimated_cache

print(f"Available space: {available_gb:.1f} GB")
print(f"Required space: {total_required:.1f} GB")
print(f"  - Datasets: {dataset_size:.1f} GB")
print(f"  - Model outputs: {estimated_model_size:.1f} GB")
print(f"  - Cache: {estimated_cache:.1f} GB")

if available_gb < total_required:
    error(f"Insufficient disk space! Need {total_required:.1f}GB, have {available_gb:.1f}GB")
else:
    success(f"Sufficient disk space ({available_gb:.1f}GB available)")

# ============================================================================
# 5. HUGGINGFACE SETUP
# ============================================================================
section("5. HUGGINGFACE SETUP")

hf_token = os.environ.get("HF_TOKEN")
if not hf_token:
    warn("HF_TOKEN not set - model won't auto-upload after training")
    print("  Set with: export HF_TOKEN='hf_your_token_here'")
else:
    success(f"HF_TOKEN set ({hf_token[:10]}...)")

# Check if model repo exists
try:
    from huggingface_hub import HfApi
    api = HfApi()
    repo_info = api.repo_info("Muneerali199/rakshak-cwe-v3", repo_type="model", token=hf_token)
    success("HF model repo exists: Muneerali199/rakshak-cwe-v3")
except Exception as e:
    warn(f"Cannot access HF repo: {e}")

# ============================================================================
# 6. REASONING DATA CHECK
# ============================================================================
section("6. REASONING TRACES")

reasoning_file = "v2/inputs/datasets/axolotl/train_87k_with_reasoning.jsonl"
if os.path.exists(reasoning_file):
    # Check how many have reasoning
    reasoning_count = 0
    total_checked = 0
    
    with open(reasoning_file, 'r') as f:
        for i, line in enumerate(f):
            if i >= 10000:  # Sample first 10K
                break
            total_checked += 1
            data = json.loads(line)
            
            # Check if it's a reasoning trace
            source = data.get("_meta", {}).get("source", "")
            if "reasoning" in source or "trajectory" in source:
                reasoning_count += 1
            
            # Check assistant response length (reasoning traces are longer)
            if "messages" in data:
                for msg in data["messages"]:
                    if msg["role"] == "assistant" and len(msg["content"]) > 800:
                        reasoning_count += 1
                        break
    
    reasoning_pct = (reasoning_count / total_checked) * 100
    print(f"Sampled {total_checked:,} lines:")
    print(f"  - Reasoning traces: ~{reasoning_count:,} ({reasoning_pct:.1f}%)")
    print(f"  - Regular samples: ~{total_checked - reasoning_count:,} ({100-reasoning_pct:.1f}%)")
    
    if reasoning_pct < 2:
        warn(f"Only {reasoning_pct:.1f}% reasoning traces - expected ~3-4%")
    elif reasoning_pct > 10:
        warn(f"Too many reasoning traces ({reasoning_pct:.1f}%) - might be imbalanced")
    else:
        success(f"Reasoning ratio looks good ({reasoning_pct:.1f}%)")

# ============================================================================
# FINAL SUMMARY
# ============================================================================
section("FINAL SUMMARY")

print(f"{GREEN}✓ Passed: {len(info)}{RESET}")
print(f"{YELLOW}⚠ Warnings: {len(warnings)}{RESET}")
print(f"{RED}✗ Errors: {len(errors)}{RESET}")

if errors:
    print(f"\n{RED}{BOLD}❌ CRITICAL ERRORS FOUND - DO NOT START TRAINING{RESET}")
    print(f"{RED}Fix these issues first:{RESET}")
    for i, err in enumerate(errors, 1):
        print(f"{RED}  {i}. {err}{RESET}")
    sys.exit(1)

if warnings:
    print(f"\n{YELLOW}⚠️  WARNINGS (review before training):{RESET}")
    for i, warn_msg in enumerate(warnings, 1):
        print(f"{YELLOW}  {i}. {warn_msg}{RESET}")

print(f"\n{GREEN}{BOLD}{'='*70}{RESET}")
if errors == 0 and len(warnings) <= 2:
    print(f"{GREEN}{BOLD}✅ READY FOR TRAINING!{RESET}")
    print(f"\n{BLUE}Next steps:{RESET}")
    print(f"  1. Review any warnings above")
    print(f"  2. Run: bash v2/scripts/lightning_shot.sh user@ssh.lightning.ai 14b")
    print(f"  3. Monitor training logs for loss curves")
else:
    print(f"{YELLOW}{BOLD}⚠️  PROCEED WITH CAUTION{RESET}")
    print(f"\n{YELLOW}Review warnings carefully before training.{RESET}")

print(f"{GREEN}{BOLD}{'='*70}{RESET}\n")
sys.exit(0 if len(errors) == 0 else 1)
