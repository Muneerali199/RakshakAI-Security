#!/usr/bin/env python3
"""
Merge existing real CVE data (OSV + GitHub with code) into meta pipeline.
Then calculate new rating projection.

Run: python3 v2/dataset/merge_real_cves.py
"""
import json
import hashlib
import sys
import time
from pathlib import Path
from collections import Counter

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

META_DIR = Path("v2/inputs/datasets/phase_b/meta")
OUT_DIR = Path("v2/inputs/datasets/phase_b/real_cve_generated")
INSTRUCT_DIR = Path("v2/inputs/datasets/instruct")

def load_meta():
    """Load all samples from meta."""
    samples = {"train": [], "val": [], "test": []}
    for split in ["train", "val", "test"]:
        path = META_DIR / f"{split}.jsonl"
        for line in open(path):
            s = json.loads(line)
            samples[split].append(s)
    return samples

def load_code_data():
    """Load github_advisories_with_code (has real vulnerable→patched code pairs)."""
    path = Path("v2/inputs/datasets/raw/github_advisories_with_code.jsonl")
    samples = []
    for line in open(path):
        s = json.loads(line)
        if s.get("vulnerable_code") and len(s.get("vulnerable_code", "")) > 20:
            samples.append(s)
    return samples

def deduplicate(new_samples, existing):
    """Filter out samples already in meta (by id or fingerprint)."""
    existing_ids = set()
    existing_fps = set()
    for s in existing:
        existing_ids.add(s.get("id", ""))
        existing_fps.add(s.get("fingerprint", ""))
    
    deduped = []
    for s in new_samples:
        sid = s.get("id", "")
        fp = s.get("fingerprint", "")
        # Check from the with_code file format
        # May not have fingerprint, use content hash
        code = s.get("vulnerable_code", "")
        fp = fp or hashlib.md5(code.encode()).hexdigest()[:12]
        if sid in existing_ids or fp in existing_fps:
            continue
        # Ensure fields
        s["fingerprint"] = fp
        s["added_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        s["split"] = "train"
        deduped.append(s)
    return deduped

def main():
    print("=" * 60)
    print("Real CVE Merge Pipeline")
    print("=" * 60)
    
    print("\n1. Loading meta...")
    meta = load_meta()
    existing = meta["train"] + meta["val"] + meta["test"]
    print(f"   Meta: {len(existing):,} total samples")
    print(f"     train: {len(meta['train']):,}")
    print(f"     val:   {len(meta['val']):,}")
    print(f"     test:  {len(meta['test']):,}")
    
    print("\n2. Loading GitHub advisories with real code...")
    code_samples = load_code_data()
    print(f"   {len(code_samples):,} samples with real code")
    
    # Stats
    code_langs = Counter(s.get("language", "?") for s in code_samples)
    code_cwes = Counter(s.get("cwe", "CWE-000") for s in code_samples if s.get("cwe"))
    code_with_patch = sum(1 for s in code_samples if s.get("patched_code"))
    print(f"   Languages: {dict(code_langs.most_common(10))}")
    print(f"   CWEs: {len(code_cwes)} unique")
    print(f"   With patch: {code_with_patch}/{len(code_samples)}")
    
    print("\n3. Deduplicating against meta...")
    import hashlib
    new_samples = deduplicate(code_samples, existing)
    print(f"   New samples to add: {len(new_samples):,}")
    
    print("\n4. Merging into meta/train.jsonl...")
    with open(META_DIR / "train.jsonl", "a") as f:
        for s in new_samples:
            f.write(json.dumps(s, ensure_ascii=False) + "\n")
    
    new_total = len(existing) + len(new_samples)
    print(f"   New meta total: {new_total:,}")
    print(f"   train: {len(meta['train']) + len(new_samples):,}")
    
    print("\n5. Projecting new rating...")
    
    # Calculate stats
    updated = {"train": meta["train"] + new_samples, "val": meta["val"], "test": meta["test"]}
    all_samples = updated["train"] + updated["val"] + updated["test"]
    
    total = len(all_samples)
    with_patch = sum(1 for s in all_samples if s.get("patched_code"))
    cwes = Counter(s.get("cwe", "CWE-000") for s in all_samples if s.get("cwe"))
    langs = Counter(s.get("language", "?") for s in all_samples if s.get("language"))
    real_sources = sum(1 for s in all_samples if "osv" in s.get("source", "").lower() or "github_advisory" in s.get("source", "").lower() or "cve" in s.get("source", "").lower())
    c_count = langs.get("c", 0) + langs.get("cpp", 0)
    c_pct = c_count / total * 100 if total > 0 else 0
    
    print(f"\n   {'Metric':<25} {'Before':<12} {'After':<12}")
    print(f"   {'─'*49}")
    print(f"   {'Total samples':<25} {261988:<12,} {total:<12,}")
    print(f"   {'Unique CWEs':<25} {511:<12} {len(cwes):<12}")
    print(f"   {'Languages':<25} {9:<12} {len(langs):<12}")
    print(f"   {'Patch coverage':<25} {'30%':<12} {100*with_patch/total:.1f}%")
    print(f"   {'C dominance':<25} {'65.8%':<12} {c_pct:.1f}%")
    print(f"   {'Real CVE sources':<25} {'0':<12} {real_sources:<12,}")
    
    # Rating projection
    old_rating = {
        "size_scale": 9.0,
        "data_quality": 9.5,
        "balance_diversity": 8.5,
        "patch_coverage": 6.0,
        "hard_negatives": 7.0,
        "explanations": 7.0,
        "source_diversity": 8.0,
        "benchmark_quality": 9.5,
        "training_readiness": 8.5,
    }
    
    # New rating projection
    new_rating = {
        "size_scale": 9.5 if total >= 270000 else 9.0,
        "data_quality": 9.5,
        "balance_diversity": 9.0 if len(langs) >= 10 else 8.5,
        "patch_coverage": min(9.0, 6.0 + (with_patch/total - 0.30) * 8),
        "hard_negatives": 7.0,
        "explanations": 7.5 if real_sources > 0 else 7.0,
        "source_diversity": 9.0 if real_sources > 5000 else 8.5,
        "benchmark_quality": 9.5,
        "training_readiness": 8.5,
    }
    
    print(f"\n   {'Category':<25} {'Old':<10} {'New':<10}")
    print(f"   {'─'*45}")
    old_avg = sum(old_rating.values()) / len(old_rating)
    new_avg = sum(new_rating.values()) / len(new_rating)
    for k, v in new_rating.items():
        label = k.replace("_", " ").title()
        old_v = old_rating[k]
        arrow = "↑" if v > old_v else "→"
        print(f"   {label:<25} {old_v:<10.1f} {v:<.1f} {arrow}")
    
    print(f"   {'─'*45}")
    print(f"   {'OVERALL':<25} {old_avg:<10.1f} {new_avg:<.1f} {'↑' if new_avg > old_avg else '→'}")
    
    print(f"\n6. Next steps:")
    print(f"   python3 v2/dataset/to_instruct.py --in_dir {META_DIR} --out_dir {INSTRUCT_DIR}")
    print(f"   python3 v2/dataset/pack.py --phases phase_b")

if __name__ == "__main__":
    main()
