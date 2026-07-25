#!/usr/bin/env python3
"""Merge generated patches into meta train.jsonl."""
import json, time
from pathlib import Path
from collections import Counter

META_DIR = Path("v2/inputs/datasets/phase_b/meta")
PATCH_DIR = Path("v2/inputs/datasets/phase_b/patches")

def load_patches():
    patches = {}
    for f in sorted(PATCH_DIR.glob("patches*.jsonl")):
        for line in open(f):
            s = json.loads(line)
            key = s.get("fingerprint", "") or s.get("id", "")
            if key and s.get("patched_code"):
                patches[key] = s["patched_code"]
    return patches

def main():
    print("=" * 60)
    print("Merge Patches into Meta")
    print("=" * 60)

    print("\n1. Loading patches...")
    patches = load_patches()
    print(f"   {len(patches):,} patch records")

    print("\n2. Patching meta files...")
    total_patched = 0
    for f in sorted(META_DIR.glob("*.jsonl")):
        lines = open(f).readlines()
        patched_lines = []
        for line in lines:
            s = json.loads(line)
            key = s.get("fingerprint", "") or s.get("id", "")
            if key in patches and s.get("is_vulnerable", True) and not s.get("patched_code"):
                s["patched_code"] = patches[key]
                s["_patched_by"] = "asi1-mini"
                total_patched += 1
            patched_lines.append(s)
        # Rewrite file
        with open(f, "w") as out:
            for s in patched_lines:
                out.write(json.dumps(s, ensure_ascii=False) + "\n")
        patched_in_file = sum(1 for s in patched_lines if s.get('_patched_by') == 'asi1-mini')
        print(f"   {f.name}: patched {patched_in_file} samples")

    print(f"\n3. Total patched: {total_patched:,}")

    # Recalculate stats
    total = 0
    patched = 0
    for f in sorted(META_DIR.glob("*.jsonl")):
        for line in open(f):
            s = json.loads(line)
            total += 1
            if s.get("patched_code"):
                patched += 1

    print(f"\n4. Post-patch stats:")
    print(f"   Total samples: {total:,}")
    print(f"   With patches:  {patched:,} ({100*patched/total:.1f}%)")
    print(f"\n5. To complete:")
    print(f"   python3 v2/dataset/to_instruct.py")
    print(f"   python3 v2/dataset/pack.py --phases phase_b")
    print(f"   python3 v2/dataset/rating_current.py")

if __name__ == "__main__":
    main()
