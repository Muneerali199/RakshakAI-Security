#!/usr/bin/env python3
"""
Merge generated rare CWE samples into meta, rebuild instruct & pack.
"""
import json
import time
import sys
from pathlib import Path
from collections import Counter

META_DIR = Path("v2/inputs/datasets/phase_b/meta")
GEN_FILE = Path("v2/inputs/datasets/phase_b/rare_cwe_generated/generated_samples.jsonl")
INSTRUCT_DIR = Path("v2/inputs/datasets/instruct")
PACK_DIR = Path("v2/inputs/datasets/pack")

def main():
    print(f"[merge] Reading generated samples from {GEN_FILE}")
    samples = []
    for line in open(GEN_FILE):
        s = json.loads(line)
        samples.append(s)
    print(f"[merge] Loaded {len(samples):,} generated samples")

    cwe_counts = Counter(s["cwe"] for s in samples)
    print(f"[merge] CWEs covered: {len(cwe_counts)}")
    still_rare = sum(1 for c, n in cwe_counts.items() if n < 10)
    print(f"[merge] CWEs with <10: {still_rare}")

    lang_counts = Counter(s["language"] for s in samples)
    print(f"[merge] Language breakdown: {dict(lang_counts.most_common(10))}")

    by_split = {"train": [], "val": [], "test": []}
    for s in samples:
        split = s.get("split", "train")
        by_split.setdefault(split, []).append(s)

    print(f"[merge] By split: " + ", ".join(f"{k}={len(v)}" for k, v in by_split.items()))

    for split, new_samples in by_split.items():
        if not new_samples:
            continue
        meta_path = META_DIR / f"{split}.jsonl"
        old_count = sum(1 for _ in open(meta_path))
        with open(meta_path, "a") as f:
            for s in new_samples:
                s["split"] = split
                s["added_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                f.write(json.dumps(s, ensure_ascii=False) + "\n")
        new_count = old_count + len(new_samples)
        print(f"[merge] {split}: {old_count:,} + {len(new_samples):,} = {new_count:,}")

    print("[merge] Done. Rebuild instruct from meta:")
    print(f"  python v2/dataset/to_instruct.py --in_dir {META_DIR} --out_dir {INSTRUCT_DIR}")
    print(f"  python v2/dataset/pack.py")

if __name__ == "__main__":
    main()
