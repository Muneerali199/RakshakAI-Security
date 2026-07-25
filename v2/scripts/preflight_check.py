#!/usr/bin/env python3
"""
Pre-flight check for RakshakAI training.
Run this BEFORE launching Lightning to catch issues early.
"""
import json
import os
import sys
from pathlib import Path

RESET = "\033[0m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"

errors = []
warnings = []
info = []

def check(condition, error_msg, warning_msg=None):
    if not condition:
        if warning_msg:
            warnings.append(warning_msg)
        else:
            errors.append(error_msg)
    return condition

def check_dataset_file(path, expected_format):
    """Validate dataset file exists and has correct format"""
    if not os.path.exists(path):
        errors.append(f"Missing: {path}")
        return False
    
    # Check file size
    size_mb = os.path.getsize(path) / 1024 / 1024
    if size_mb < 1:
        errors.append(f"{path} is too small ({size_mb:.1f}MB)")
        return False
    
    # Check format
    try:
        with open(path, 'r') as f:
            first_line = f.readline()
            data = json.loads(first_line)
            
            if expected_format == 'sft':
                if 'messages' not in data:
                    errors.append(f"{path} missing 'messages' field")
                    return False
                msgs = data['messages']
                if not isinstance(msgs, list) or len(msgs) < 2:
                    errors.append(f"{path} messages should be list with 2+ items")
                    return False
                if msgs[0].get('role') != 'system':
                    warnings.append(f"{path} first message should be 'system' role")
                if msgs[-1].get('role') != 'assistant':
                    errors.append(f"{path} last message must be 'assistant' role")
                    return False
                    
            elif expected_format == 'dpo':
                if 'chosen' not in data or 'rejected' not in data:
                    errors.append(f"{path} missing 'chosen'/'rejected' fields")
                    return False
                if not isinstance(data['chosen'], list) or not isinstance(data['rejected'], list):
                    errors.append(f"{path} chosen/rejected must be lists")
                    return False
        
        # Count lines
        line_count = sum(1 for _ in open(path))
        info.append(f"✓ {path.split('/')[-1]}: {line_count:,} samples, {size_mb:.0f}MB")
        return True
        
    except json.JSONDecodeError as e:
        errors.append(f"{path} invalid JSON: {e}")
        return False
    except Exception as e:
        errors.append(f"{path} error: {e}")
        return False

print(f"{BLUE}╔═══════════════════════════════════════════════════╗{RESET}")
print(f"{BLUE}║  RakshakAI Pre-Flight Check                      ║{RESET}")
print(f"{BLUE}╚═══════════════════════════════════════════════════╝{RESET}\n")

# Check 1: Dataset files
print(f"{BLUE}[1/6] Checking dataset files...{RESET}")
base_path = "v2/inputs/datasets/axolotl"
check_dataset_file(f"{base_path}/train_250k.jsonl", 'sft')
check_dataset_file(f"{base_path}/val.jsonl", 'sft')
check_dataset_file(f"{base_path}/dpo_train.jsonl", 'dpo')

# Check 2: Config files
print(f"\n{BLUE}[2/6] Validating configs...{RESET}")
try:
    import yaml
    
    for config_file in ['v2/configs/lightning_14b_sft.yaml', 'v2/configs/lightning_14b_dpo.yaml']:
        if not os.path.exists(config_file):
            errors.append(f"Missing config: {config_file}")
            continue
            
        with open(config_file) as f:
            cfg = yaml.safe_load(f)
        
        # Check critical fields
        if 'base_model' not in cfg:
            errors.append(f"{config_file} missing base_model")
        elif cfg['base_model'] != 'Qwen/Qwen2.5-Coder-14B-Instruct':
            warnings.append(f"{config_file} using non-standard base model: {cfg['base_model']}")
        
        if 'datasets' not in cfg or not cfg['datasets']:
            errors.append(f"{config_file} missing datasets")
        
        if cfg.get('load_in_4bit') != True:
            warnings.append(f"{config_file} not using 4-bit quantization (may OOM)")
        
        if cfg.get('gradient_checkpointing') != True:
            warnings.append(f"{config_file} gradient checkpointing disabled (may OOM)")
        
        # Check batch sizes
        batch_size = cfg.get('micro_batch_size', 8)
        if batch_size > 8:
            warnings.append(f"{config_file} micro_batch_size={batch_size} may OOM on A100")
        
        info.append(f"✓ {config_file.split('/')[-1]}: batch_size={batch_size}, lr={cfg.get('learning_rate')}")
        
except ImportError:
    errors.append("PyYAML not installed. Run: pip install pyyaml")
except Exception as e:
    errors.append(f"Config validation failed: {e}")

# Check 3: Dataset paths in configs match actual files
print(f"\n{BLUE}[3/6] Checking config → dataset path mappings...{RESET}")
try:
    with open('v2/configs/lightning_14b_sft.yaml') as f:
        sft_cfg = yaml.safe_load(f)
    
    sft_train_path = sft_cfg['datasets'][0]['path']
    if not os.path.exists(sft_train_path):
        errors.append(f"SFT config points to missing file: {sft_train_path}")
    else:
        info.append(f"✓ SFT training path: {sft_train_path}")
    
    with open('v2/configs/lightning_14b_dpo.yaml') as f:
        dpo_cfg = yaml.safe_load(f)
    
    dpo_train_path = dpo_cfg['datasets'][0]['path']
    if not os.path.exists(dpo_train_path):
        errors.append(f"DPO config points to missing file: {dpo_train_path}")
    else:
        info.append(f"✓ DPO training path: {dpo_train_path}")
        
except Exception as e:
    errors.append(f"Path mapping check failed: {e}")

# Check 4: Output directories
print(f"\n{BLUE}[4/6] Checking output directories...{RESET}")
for dir_path in ['v2/model', 'v2/prepared']:
    if not os.path.exists(dir_path):
        warnings.append(f"Directory doesn't exist (will be created): {dir_path}")
    else:
        info.append(f"✓ {dir_path} exists")

# Check 5: DPO adapter path
print(f"\n{BLUE}[5/6] Validating DPO stage dependencies...{RESET}")
try:
    with open('v2/configs/lightning_14b_dpo.yaml') as f:
        dpo_cfg = yaml.safe_load(f)
    
    adapter_path = dpo_cfg.get('adapter')
    if adapter_path != 'v2/model/sft_14b':
        errors.append(f"DPO adapter path should be 'v2/model/sft_14b', got '{adapter_path}'")
    else:
        info.append(f"✓ DPO will load adapter from: {adapter_path}")
        
    # Warn about training order
    warnings.append("⚠️  DPO MUST run AFTER SFT completes (adapter dependency)")
    
except Exception as e:
    errors.append(f"DPO validation failed: {e}")

# Check 6: Data quality warnings
print(f"\n{BLUE}[6/6] Data quality checks...{RESET}")

# Check train/val ratio
try:
    train_lines = sum(1 for _ in open('v2/inputs/datasets/axolotl/train_250k.jsonl'))
    val_lines = sum(1 for _ in open('v2/inputs/datasets/axolotl/val.jsonl'))
    
    if val_lines > train_lines * 0.2:
        warnings.append(f"Val set is {val_lines/train_lines*100:.0f}% of train set (typically 5-10%)")
    
    # Check DPO size
    dpo_lines = sum(1 for _ in open('v2/inputs/datasets/axolotl/dpo_train.jsonl'))
    if dpo_lines < 1000:
        warnings.append(f"DPO dataset only has {dpo_lines} pairs (recommend 5K+)")
    elif dpo_lines < 5000:
        warnings.append(f"DPO dataset has {dpo_lines} pairs (good, but 10K+ is better)")
    
    info.append(f"✓ Train: {train_lines:,}, Val: {val_lines:,}, DPO: {dpo_lines:,}")
    
except Exception as e:
    errors.append(f"Line count check failed: {e}")

# Print summary
print(f"\n{BLUE}╔═══════════════════════════════════════════════════╗{RESET}")
print(f"{BLUE}║  Summary                                         ║{RESET}")
print(f"{BLUE}╚═══════════════════════════════════════════════════╝{RESET}\n")

for msg in info:
    print(f"{GREEN}{msg}{RESET}")

if warnings:
    print(f"\n{YELLOW}Warnings ({len(warnings)}):{RESET}")
    for w in warnings:
        print(f"{YELLOW}  ⚠ {w}{RESET}")

if errors:
    print(f"\n{RED}Errors ({len(errors)}):{RESET}")
    for e in errors:
        print(f"{RED}  ✗ {e}{RESET}")
    print(f"\n{RED}❌ Pre-flight check FAILED. Fix errors before training.{RESET}")
    sys.exit(1)
else:
    print(f"\n{GREEN}✅ All checks passed! Ready to train.{RESET}")
    print(f"\n{BLUE}Estimated training time on A100 80GB:{RESET}")
    print(f"  • SFT (250K samples): ~3.5 hours")
    print(f"  • DPO (7K pairs): ~0.8 hours")
    print(f"  • Total: ~4.3 hours = ~$10.75 @ $2.50/hr")
    sys.exit(0)
