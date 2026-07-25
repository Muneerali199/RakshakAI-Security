#!/usr/bin/env python3
"""Upload RakshakAI Phase B dataset to Hugging Face Hub."""

import json, os, sys
from pathlib import Path
from huggingface_hub import HfApi, create_repo
from datasets import Dataset, DatasetDict

REPO = "Muneerali199/RakshakAI-phase-b"
META_DIR = Path("v2/inputs/datasets/phase_b/meta")

TOKEN = os.environ.get("HF_TOKEN")
if not TOKEN:
    print("ERROR: HF_TOKEN environment variable not set")
    sys.exit(1)


def load_split(path: Path) -> Dataset:
    rows = []
    with path.open("r") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    print(f"  Loaded {len(rows)} samples from {path.name}")
    return Dataset.from_list(rows)


def main():
    api = HfApi(token=TOKEN)

    print(f"Creating/verifying repo: {REPO}")
    create_repo(REPO, repo_type="dataset", exist_ok=True, private=False, token=TOKEN)

    print("Loading splits...")
    train = load_split(META_DIR / "train.jsonl")
    val = load_split(META_DIR / "val.jsonl")
    test = load_split(META_DIR / "test.jsonl")

    dataset = DatasetDict({
        "train": train,
        "val": val,
        "test": test,
    })

    print(f"Pushing to Hub ({REPO})...")
    dataset.push_to_hub(REPO, token=TOKEN, private=False)
    print("Done!")


if __name__ == "__main__":
    main()
