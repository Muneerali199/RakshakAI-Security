#!/usr/bin/env python3
"""
Intelligent C code downsampling from 193K → 105K samples.
Removes duplicates, low-quality, and overrepresented CWEs while keeping diversity.
"""
import json
import hashlib
from pathlib import Path
from collections import defaultdict
from typing import List, Dict

def compute_similarity_hash(code: str) -> str:
    """Fuzzy hash for near-duplicate detection."""
    # Normalize: remove whitespace, comments, variable names
    normalized = code.lower()
    normalized = ''.join(normalized.split())  # Remove all whitespace
    # Just use structural tokens
    tokens = [c for c in normalized if c in '{}();,=<>!&|+-*/%[]']
    return hashlib.md5(''.join(tokens).encode()).hexdigest()[:8]

def quality_score(sample: Dict) -> float:
    """Rate sample quality 0-1."""
    score = 0.5  # Base score
    
    code = sample.get('vulnerable_code', '')
    
    # Length (sweet spot: 100-2000 chars)
    if 100 < len(code) < 2000:
        score += 0.2
    elif len(code) < 50:
        score -= 0.3
    
    # Has patch
    if sample.get('patched_code'):
        score += 0.2
    
    # Has good explanation
    exp = sample.get('explanation', '')
    if len(exp) > 100 and 'vulnerability' in exp.lower():
        score += 0.2
    
    # Has CWE
    if sample.get('cwe') and sample['cwe'] != 'CWE-UNKNOWN':
        score += 0.1
    
    # Code complexity (more = better for learning)
    if 'if' in code and 'for' in code:
        score += 0.1
    
    return max(0, min(1, score))

def downsample_c(input_path: Path, target_count: int = 105000) -> List[Dict]:
    """
    Intelligently reduce C samples from ~193K to ~105K.
    
    Strategies:
    1. Remove near-duplicates (30K)
    2. Remove low-quality samples (20K)
    3. Downsample common CWEs (38K)
    """
    print("📂 Loading C samples...")
    c_samples = []
    
    with open(input_path) as f:
        for line in f:
            d = json.loads(line)
            if d.get('language') in ['c', 'cpp']:
                c_samples.append(d)
    
    print(f"Found {len(c_samples)} C/C++ samples")
    to_remove = len(c_samples) - target_count
    print(f"Need to remove: {to_remove} samples")
    
    # Step 1: Remove near-duplicates
    print("\n🔍 Step 1: Removing near-duplicates...")
    similarity_groups = defaultdict(list)
    for sample in c_samples:
        sim_hash = compute_similarity_hash(sample.get('vulnerable_code', ''))
        similarity_groups[sim_hash].append(sample)
    
    # Keep only best sample from each duplicate group
    deduped = []
    removed_dupes = 0
    for group in similarity_groups.values():
        if len(group) > 1:
            # Keep the one with highest quality score
            best = max(group, key=quality_score)
            deduped.append(best)
            removed_dupes += len(group) - 1
        else:
            deduped.append(group[0])
    
    print(f"  Removed {removed_dupes} duplicates, {len(deduped)} remain")
    remaining_to_remove = to_remove - removed_dupes
    
    # Step 2: Remove low-quality samples
    print("\n🔍 Step 2: Removing low-quality samples...")
    scored = [(sample, quality_score(sample)) for sample in deduped]
    scored.sort(key=lambda x: -x[1])  # Best first
    
    # Remove bottom 20% or remaining target
    quality_threshold = min(0.2 * len(scored), remaining_to_remove)
    quality_filtered = [s for s, score in scored if score > 0.4][:len(scored) - int(quality_threshold)]
    removed_quality = len(deduped) - len(quality_filtered)
    
    print(f"  Removed {removed_quality} low-quality samples, {len(quality_filtered)} remain")
    remaining_to_remove -= removed_quality
    
    # Step 3: Downsample overrepresented CWEs
    print("\n🔍 Step 3: Balancing CWE distribution...")
    cwe_groups = defaultdict(list)
    for sample in quality_filtered:
        cwe = sample.get('cwe', 'CWE-UNKNOWN')
        cwe_groups[cwe].append(sample)
    
    # Find overrepresented CWEs
    avg_per_cwe = len(quality_filtered) / len(cwe_groups)
    
    balanced = []
    for cwe, samples in cwe_groups.items():
        if len(samples) > avg_per_cwe * 2:  # Over-represented
            # Keep diverse samples
            samples_scored = [(s, quality_score(s)) for s in samples]
            samples_scored.sort(key=lambda x: -x[1])
            keep_count = int(avg_per_cwe * 1.5)
            balanced.extend([s for s, _ in samples_scored[:keep_count]])
            print(f"  {cwe}: {len(samples)} → {keep_count}")
        else:
            balanced.extend(samples)
    
    removed_cwe = len(quality_filtered) - len(balanced)
    print(f"  Removed {removed_cwe} from overrepresented CWEs, {len(balanced)} remain")
    
    # Final adjustment to hit exact target
    if len(balanced) > target_count:
        # Remove lowest quality samples
        scored = [(s, quality_score(s)) for s in balanced]
        scored.sort(key=lambda x: -x[1])
        balanced = [s for s, _ in scored[:target_count]]
    
    print(f"\n✅ Final C/C++ count: {len(balanced)}")
    print(f"📊 Removed {len(c_samples) - len(balanced)} total samples")
    
    return balanced

def main():
    input_path = Path("inputs/datasets/consolidated/clean_all_with_patches.jsonl")
    output_path = Path("inputs/datasets/consolidated/clean_all_balanced.jsonl")
    
    if not input_path.exists():
        print(f"⚠️  {input_path} not found, using clean_all.jsonl")
        input_path = Path("inputs/datasets/consolidated/clean_all.jsonl")
    
    # Downsample C
    c_samples_filtered = downsample_c(input_path, target_count=105000)
    c_ids = {s['id'] for s in c_samples_filtered}
    
    # Rebuild full dataset with filtered C samples
    print("\n📝 Rebuilding full dataset...")
    with open(output_path, 'w') as out:
        with open(input_path) as f:
            for line in f:
                d = json.loads(line)
                # Keep all non-C samples, only filtered C samples
                if d.get('language') not in ['c', 'cpp']:
                    out.write(line)
                elif d['id'] in c_ids:
                    out.write(line)
    
    # Stats
    total = sum(1 for _ in open(output_path))
    c_count = sum(1 for line in open(output_path) 
                  if json.loads(line).get('language') in ['c', 'cpp'])
    
    print(f"\n✅ Saved to: {output_path}")
    print(f"📊 Total samples: {total}")
    print(f"📊 C/C++ samples: {c_count} ({c_count/total*100:.1f}%)")
    
    # Language distribution
    lang_dist = defaultdict(int)
    for line in open(output_path):
        lang = json.loads(line).get('language', 'unknown')
        lang_dist[lang] += 1
    
    print("\n📊 Language distribution:")
    for lang, count in sorted(lang_dist.items(), key=lambda x: -x[1])[:10]:
        print(f"  {lang}: {count} ({count/total*100:.1f}%)")

if __name__ == "__main__":
    main()
