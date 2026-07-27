#!/usr/bin/env python3
"""Quick boost patch coverage by better utilizing existing patched samples."""
import json
import sys
from pathlib import Path
from collections import defaultdict

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from dataset.schema import SecuritySample, write_jsonl

def analyze_current_patches():
    """Analyze patch coverage by source."""
    clean_dir = Path("v2/inputs/datasets/clean")
    
    by_source = defaultdict(lambda: {"total": 0, "patched": 0})
    
    for jsonl_file in clean_dir.rglob("*.jsonl"):
        with open(jsonl_file) as f:
            for line in f:
                try:
                    sample = json.loads(line)
                    if not sample.get("is_vulnerable"):
                        continue
                    
                    source = sample.get("source", "unknown")
                    by_source[source]["total"] += 1
                    
                    if sample.get("patched_code") and len(sample.get("patched_code", "").strip()) > 50:
                        by_source[source]["patched"] += 1
                except:
                    continue
    
    print("Patch coverage by source:")
    print(f"{'Source':<25} {'Total':>10} {'Patched':>10} {'Coverage':>10}")
    print("-" * 60)
    
    for source, stats in sorted(by_source.items(), key=lambda x: -x[1]["patched"]):
        total = stats["total"]
        patched = stats["patched"]
        pct = (patched / total * 100) if total > 0 else 0
        print(f"{source:<25} {total:>10,} {patched:>10,} {pct:>9.1f}%")
    
    return by_source

def prioritize_patched_samples():
    """Create a high-quality subset with maximum patches."""
    clean_dir = Path("v2/inputs/datasets/clean")
    output_file = Path("v2/inputs/datasets/clean/high_patch_priority.jsonl")
    
    # Collect all patched samples
    patched_samples = []
    unpatched_samples = []
    
    for jsonl_file in clean_dir.rglob("*.jsonl"):
        if jsonl_file.name == "high_patch_priority.jsonl":
            continue
            
        with open(jsonl_file) as f:
            for line in f:
                try:
                    sample = json.loads(line)
                    
                    if not sample.get("is_vulnerable"):
                        continue
                    
                    if sample.get("patched_code") and len(sample.get("patched_code", "").strip()) > 50:
                        patched_samples.append(sample)
                    else:
                        unpatched_samples.append(sample)
                except:
                    continue
    
    print(f"\nTotal vulnerable samples:")
    print(f"  With patches: {len(patched_samples):,}")
    print(f"  Without patches: {len(unpatched_samples):,}")
    print(f"  Coverage: {len(patched_samples) / (len(patched_samples) + len(unpatched_samples)) * 100:.1f}%")
    
    # Write prioritized file
    with open(output_file, "w") as f:
        for sample in patched_samples:
            f.write(json.dumps(sample) + "\n")
    
    print(f"\n✅ Created high-priority patched samples file: {output_file}")
    return len(patched_samples)

if __name__ == "__main__":
    print("Analyzing patch coverage...\n")
    by_source = analyze_current_patches()
    
    print("\n" + "="*60)
    prioritize_patched_samples()
