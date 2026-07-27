"""Finalize: merge original + augmented, add splits, run instruct, count."""
import json, random, hashlib
from pathlib import Path

rng = random.Random(42)

ORIG = Path("v2/inputs/datasets/consolidated/clean_all.jsonl")
AUG = Path("v2/inputs/datasets/consolidated/clean_all_augmented.jsonl")
OUT = Path("v2/inputs/datasets/final_balanced")
OUT.mkdir(exist_ok=True)

# Read original samples
samples = []
with open(ORIG) as f:
    for line in f:
        d = json.loads(line)
        samples.append(d)

# Read augmented samples  
with open(AUG) as f:
    for line in f:
        d = json.loads(line)
        samples.append(d)

print(f"Total raw: {len(samples)}")

# Stratified split: 90% train, 5% val, 5% test
by_cwe = {}
for s in samples:
    cwe = s.get("cwe", "CWE-UNKNOWN")
    by_cwe.setdefault(cwe, []).append(s)

train, val, test = [], [], []
for cwe, ss in by_cwe.items():
    rng.shuffle(ss)
    n = len(ss)
    n_test = max(1, int(n * 0.05))
    n_val = max(1, int(n * 0.05))
    for i, s in enumerate(ss):
        s["split"] = "test" if i < n_test else ("val" if i < n_test + n_val else "train")

train = [s for s in samples if s["split"] == "train"]
val = [s for s in samples if s["split"] == "val"]
test = [s for s in samples if s["split"] == "test"]

print(f"train: {len(train)}, val: {len(val)}, test: {len(test)}")

# Write split files for to_instruct
for split_name, split_samples in [("train", train), ("val", val), ("test", test)]:
    with open(OUT / f"{split_name}.jsonl", "w") as f:
        for s in split_samples:
            f.write(json.dumps(s) + "\n")

# Write all combined
with open(OUT / "_all.jsonl", "w") as f:
    for s in samples:
        f.write(json.dumps(s) + "\n")

print(f"Written to {OUT}")
print(f"All samples: {len(samples)}")

# Also write as single file for fast instruct processing
with open(OUT / "all.jsonl", "w") as f:
    for s in samples:
        f.write(json.dumps(s) + "\n")
