"""
RakshakAI v2 — Global Deduplication (Pre-Split).

Critical fix: Deduplicate BEFORE splitting into train/val/test to prevent leakage.

Current problem: clean.py deduplicates within each source, then build_phase_b.py
splits. This allows same code to appear in train AND val/test if from different sources.

New approach:
1. Load ALL samples from clean/ directory
2. Deduplicate globally (exact + fuzzy)
3. Group by repository to prevent repo-level leakage
4. THEN split into train/val/test with CWE stratification

Output: v2/inputs/datasets/deduped_global/
"""
from __future__ import annotations

import hashlib
import json
import random
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from v2.dataset.schema import SecuritySample, write_jsonl  # noqa: E402

try:
    from datasketch import MinHash, MinHashLSH
    HAVE_DATASKETCH = True
except ImportError:
    HAVE_DATASKETCH = False
    print("⚠️  datasketch not installed. Run: pip install datasketch")
    print("   Falling back to exact dedup only")

random.seed(42)

# Paths
CLEAN_DIR = Path("v2/inputs/datasets/clean")
OUT_DIR = Path("v2/inputs/datasets/deduped_global")
OUT_DIR.mkdir(parents=True, exist_ok=True)

# Dedup config
JACCARD_THRESHOLD = 0.85  # 85% similarity = duplicate
NUM_PERM = 128  # MinHash permutations

stats = {
    "total_loaded": 0,
    "exact_duplicates": 0,
    "fuzzy_duplicates": 0,
    "repo_conflicts": 0,
    "final_kept": 0,
}


def get_code_from_sample(sample: SecuritySample) -> str:
    """Extract code from sample, handling different attribute names."""
    if hasattr(sample, 'vulnerable_code') and sample.vulnerable_code:
        return sample.vulnerable_code
    if hasattr(sample, 'code') and sample.code:
        return sample.code
    return ""


def normalize_code(code: str) -> str:
    """Normalize code for fuzzy comparison."""
    if not code:
        return ""
    # Remove comments
    code = re.sub(r"//.*?$|/\*.*?\*/|#.*?$|<!--.*?-->", "", code, flags=re.MULTILINE)
    # Collapse whitespace
    code = re.sub(r"\s+", " ", code)
    # Normalize variable names (identifier → ID)
    code = re.sub(r"\b[a-z_][a-z0-9_]{2,}\b", "ID", code, flags=re.IGNORECASE)
    # Remove string literals
    code = re.sub(r'"[^"]*"', '""', code)
    code = re.sub(r"'[^']*'", "''", code)
    return code.strip().lower()


def get_fingerprint(code: str) -> str:
    """Get exact fingerprint (SHA256) of normalized code."""
    normalized = normalize_code(code)
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:16]


def get_minhash(code: str) -> MinHash:
    """Get MinHash for fuzzy deduplication."""
    if not HAVE_DATASKETCH:
        return None
    
    normalized = normalize_code(code)
    tokens = normalized.split()
    
    # Create shingles (5-grams)
    shingles = set()
    for i in range(len(tokens) - 4):
        shingle = " ".join(tokens[i:i+5])
        shingles.add(shingle)
    
    if not shingles:
        shingles = {normalized}
    
    # Create MinHash
    m = MinHash(num_perm=NUM_PERM)
    for s in shingles:
        m.update(s.encode("utf-8"))
    
    return m


def extract_repo_from_source(source: str, metadata: dict | None) -> str | None:
    """Extract repository identifier from source/metadata."""
    if metadata and "repository" in metadata:
        return metadata["repository"]
    
    if metadata and "repo" in metadata:
        return metadata["repo"]
    
    # Extract from source string (e.g., "bigvul_chromium" -> "chromium")
    if "_" in source:
        parts = source.split("_")
        if len(parts) > 1:
            return parts[-1]
    
    return source


def load_all_samples() -> list[SecuritySample]:
    """Load all samples from clean directory."""
    print("\n[1/5] Loading all samples...")
    
    samples = []
    for p in sorted(CLEAN_DIR.rglob("*.jsonl")):
        with p.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                
                try:
                    data = json.loads(line)
                    sample = SecuritySample.from_dict(data)
                    samples.append(sample)
                except Exception as e:
                    continue
    
    stats["total_loaded"] = len(samples)
    print(f"   Loaded: {len(samples):,} samples")
    return samples


def dedup_exact(samples: list[SecuritySample]) -> list[SecuritySample]:
    """Remove exact duplicates by fingerprint."""
    print("\n[2/5] Removing exact duplicates...")
    
    seen_fingerprints = {}
    unique = []
    
    for sample in samples:
        code = get_code_from_sample(sample)
        if not code:
            continue
            
        fp = get_fingerprint(code)
        
        if fp in seen_fingerprints:
            stats["exact_duplicates"] += 1
            # Keep the one with more metadata
            existing = seen_fingerprints[fp]
            if sample.patched_code and not existing.patched_code:
                # New sample has patch, keep it
                seen_fingerprints[fp] = sample
                unique.remove(existing)
                unique.append(sample)
        else:
            seen_fingerprints[fp] = sample
            unique.append(sample)
    
    print(f"   Removed: {stats['exact_duplicates']:,} exact duplicates")
    print(f"   Remaining: {len(unique):,}")
    return unique


def dedup_fuzzy(samples: list[SecuritySample]) -> list[SecuritySample]:
    """Remove fuzzy duplicates using MinHash LSH."""
    if not HAVE_DATASKETCH:
        print("\n[3/5] Skipping fuzzy dedup (datasketch not installed)")
        return samples
    
    print("\n[3/5] Removing fuzzy duplicates (Jaccard >= 0.85)...")
    
    # Build LSH index
    lsh = MinHashLSH(threshold=JACCARD_THRESHOLD, num_perm=NUM_PERM)
    sample_by_id = {}
    
    for i, sample in enumerate(samples):
        code = get_code_from_sample(sample)
        if not code:
            continue
        mh = get_minhash(code)
        if mh:
            sample_id = f"sample_{i}"
            lsh.insert(sample_id, mh)
            sample_by_id[sample_id] = sample
    
    # Find duplicates
    duplicate_groups = []
    processed = set()
    
    for sample_id, sample in sample_by_id.items():
        if sample_id in processed:
            continue
        
        code = get_code_from_sample(sample)
        if not code:
            continue
        mh = get_minhash(code)
        if not mh:
            continue
        
        # Find similar samples
        similar = lsh.query(mh)
        
        if len(similar) > 1:
            duplicate_groups.append(similar)
            processed.update(similar)
    
    # Keep one from each group (prefer with patch)
    to_remove = set()
    for group in duplicate_groups:
        group_samples = [sample_by_id[sid] for sid in group]
        
        # Sort by: has patch > has explanation > random
        group_samples.sort(key=lambda s: (
            bool(s.patched_code),
            bool(s.explanation),
            random.random(),
        ), reverse=True)
        
        # Keep first, remove rest
        for sid in group[1:]:
            to_remove.add(sid)
    
    # Filter samples
    unique = []
    for i, sample in enumerate(samples):
        sample_id = f"sample_{i}"
        if sample_id not in to_remove:
            unique.append(sample)
    
    stats["fuzzy_duplicates"] = len(to_remove)
    print(f"   Removed: {stats['fuzzy_duplicates']:,} fuzzy duplicates")
    print(f"   Remaining: {len(unique):,}")
    return unique


def group_by_repo(samples: list[SecuritySample]) -> dict[str, list[SecuritySample]]:
    """Group samples by repository."""
    print("\n[4/5] Grouping by repository...")
    
    by_repo = defaultdict(list)
    
    for sample in samples:
        repo = extract_repo_from_source(sample.source, sample.metadata)
        by_repo[repo or "unknown"].append(sample)
    
    print(f"   Found {len(by_repo)} unique repositories")
    
    # Show top repos
    top_repos = sorted(by_repo.items(), key=lambda x: len(x[1]), reverse=True)[:10]
    for repo, samples_list in top_repos:
        print(f"     {repo}: {len(samples_list):,} samples")
    
    return by_repo


def verify_no_leakage(train: list[SecuritySample], val: list[SecuritySample], test: list[SecuritySample]):
    """Verify no fingerprint overlap between splits."""
    print("\n[5/5] Verifying no leakage...")
    
    train_fps = {get_fingerprint(get_code_from_sample(s)) for s in train if get_code_from_sample(s)}
    val_fps = {get_fingerprint(get_code_from_sample(s)) for s in val if get_code_from_sample(s)}
    test_fps = {get_fingerprint(get_code_from_sample(s)) for s in test if get_code_from_sample(s)}
    
    train_val_overlap = train_fps & val_fps
    train_test_overlap = train_fps & test_fps
    val_test_overlap = val_fps & test_fps
    
    if train_val_overlap:
        print(f"   ❌ LEAKAGE: {len(train_val_overlap)} samples in train AND val")
    else:
        print("   ✅ No train/val overlap")
    
    if train_test_overlap:
        print(f"   ❌ LEAKAGE: {len(train_test_overlap)} samples in train AND test")
    else:
        print("   ✅ No train/test overlap")
    
    if val_test_overlap:
        print(f"   ❌ LEAKAGE: {len(val_test_overlap)} samples in val AND test")
    else:
        print("   ✅ No val/test overlap")
    
    return len(train_val_overlap) == 0 and len(train_test_overlap) == 0 and len(val_test_overlap) == 0


def main():
    print("=" * 80)
    print("🔍 RakshakAI v2 - Global Deduplication (Pre-Split)")
    print("=" * 80)
    
    # 1. Load all samples
    samples = load_all_samples()
    
    # 2. Exact dedup
    samples = dedup_exact(samples)
    
    # 3. Fuzzy dedup
    samples = dedup_fuzzy(samples)
    
    # 4. Group by repo
    by_repo = group_by_repo(samples)
    
    stats["final_kept"] = len(samples)
    
    # Write output (single file for now, build_phase_b_v2.py will split)
    output_file = OUT_DIR / "all_deduped.jsonl"
    write_jsonl(output_file, [s.to_dict() for s in samples])
    
    # Summary
    print("\n" + "=" * 80)
    print("📊 Deduplication Summary")
    print("=" * 80)
    print(f"Total loaded: {stats['total_loaded']:,}")
    print(f"Exact duplicates: {stats['exact_duplicates']:,}")
    print(f"Fuzzy duplicates: {stats['fuzzy_duplicates']:,}")
    print(f"Final kept: {stats['final_kept']:,}")
    print(f"Dedup rate: {(1 - stats['final_kept'] / stats['total_loaded']) * 100:.1f}%")
    print(f"\nOutput: {output_file}")
    print("=" * 80 + "\n")
    
    print("Next step: python v2/dataset/rebuild_phase_b_v2.py")


if __name__ == "__main__":
    main()
