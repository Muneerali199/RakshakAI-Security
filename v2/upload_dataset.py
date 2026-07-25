#!/usr/bin/env python3
"""Upload the curated dataset to HuggingFace Datasets.

Usage:
  HF_TOKEN=hf_your_token python3 -m v2.cli.upload_dataset
  
Requires: datasets (pip install datasets)
"""
from __future__ import annotations
import os, sys, json
from pathlib import Path

_project_root = str(Path(__file__).resolve().parent.parent.parent)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

HF_TOKEN = os.environ.get("HF_TOKEN")
DATASET_PATH = "v2/inputs/datasets/curated_80k_train.jsonl"
HF_DATASET_REPO = "Muneerali199/rakshak-cwe-v3-data"

def upload():
    if not HF_TOKEN:
        print("Error: Set HF_TOKEN environment variable")
        sys.exit(1)

    from huggingface_hub import login, HfApi
    from datasets import load_dataset

    login(HF_TOKEN)
    
    path = Path(_project_root) / DATASET_PATH
    if not path.exists():
        print(f"Error: Dataset not found at {path}")
        sys.exit(1)

    print(f"Loading dataset from {path}...")
    dataset = load_dataset("json", data_files=str(path), split="train")
    print(f"Loaded {len(dataset)} records")
    
    # Push to Hub
    print(f"Pushing to {HF_DATASET_REPO}...")
    dataset.push_to_hub(HF_DATASET_REPO, private=False, token=HF_TOKEN)
    print(f"Done: https://huggingface.co/datasets/{HF_DATASET_REPO}")

    # Also push 80/20 train/val split
    split = dataset.train_test_split(test_size=0.02, seed=42)
    split.push_to_hub(HF_DATASET_REPO, private=False, token=HF_TOKEN)
    print(f"Train/Eval split pushed to {HF_DATASET_REPO}")

if __name__ == "__main__":
    upload()
