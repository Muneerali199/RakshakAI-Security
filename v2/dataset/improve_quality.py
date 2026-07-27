"""Improve dataset quality: balance languages, ensure CWE diversity, remove noise."""
import json
import os
from pathlib import Path
from collections import Counter, defaultdict
import random

DATA_DIR = Path("v2/inputs/datasets/instruct_cleaned")
OUT_DIR = Path("v2/inputs/datasets/instruct_quality")
FILES = ["train.jsonl", "val.jsonl", "test.jsonl"]

random.seed(42)

# Target caps per language
LANGUAGE_CAPS = {
    "c": 100000,
    "cpp": 80000,
    "javascript": 100000,
    "java": 100000,
    "php": 80000,
    "python": 100000,
    "go": 50000,
    "rust": 30000,
    "csharp": 30000,
    "ruby": 20000,
    "swift": 15000,
    "kotlin": 8000,
    "typescript": 8000,
}

# Val/test get proportional caps (train is 15-16% per top lang)
VAL_CAP_RATIO = 0.035   # val is ~3.5% of train
TEST_CAP_RATIO = 0.07   # test is ~7% of train

# Sources to deprioritize (synthetic/auto-generated)
LOW_QUALITY_SOURCES = {"v1-augmented"}

def process_file(inpath, outpath, split):
    records = []
    total = 0
    
    with open(inpath) as f:
        for line in f:
            d = json.loads(line)
            meta = d.get("_meta", {})
            total += 1
            
            lang = meta.get("language", "unknown").lower()
            cwe = meta.get("cwe", "CWE-UNKNOWN")
            source = meta.get("source", "unknown")
            
            records.append({
                "data": d,
                "lang": lang,
                "cwe": cwe,
                "source": source,
            })
    
    print(f"\n{split}: {total} input records")
    
    lang_before = Counter(r["lang"] for r in records)
    print(f"  Lang before: {dict(lang_before.most_common(8))}")
    
    # Group records by (language, CWE) for stratified sampling
    buckets = defaultdict(list)
    for r in records:
        buckets[(r["lang"], r["cwe"])].append(r)
    
    selected = []
    lang_counts = Counter()
    
    # Adjust caps for val/test based on ratio
    caps = LANGUAGE_CAPS.copy()
    if split != "train":
        ratio = VAL_CAP_RATIO if split == "val" else TEST_CAP_RATIO
        caps = {k: max(int(v * ratio), 500) for k, v in caps.items() if v != float("inf")}
        # Also keep all languages present in the split
        present_langs = set(r["lang"] for r in records)
        for lang in present_langs:
            if lang not in caps:
                caps[lang] = 500
    
    # Sample from each bucket, respecting language caps
    for (lang, cwe), bucket in sorted(buckets.items()):
        cap = caps.get(lang, float("inf"))
        remaining = cap - lang_counts[lang]
        
        if remaining <= 0:
            continue
        
        # Prioritize non-low-quality sources
        high_quality = [r for r in bucket if r["source"] not in LOW_QUALITY_SOURCES]
        low_quality = [r for r in bucket if r["source"] in LOW_QUALITY_SOURCES]
        
        # Take high quality first, then fill with low quality if needed
        take = min(len(bucket), remaining)
        selected_bucket = high_quality[:take]
        if len(selected_bucket) < take:
            needed = take - len(selected_bucket)
            selected_bucket += low_quality[:needed]
        
        selected.extend(selected_bucket)
        lang_counts[lang] += len(selected_bucket)
    
    # Shuffle to mix languages
    random.shuffle(selected)
    
    lang_after = Counter(r["lang"] for r in selected)
    cwe_after = Counter(r["cwe"] for r in selected)
    
    print(f"  Lang after:  {dict(lang_after.most_common(8))}")
    print(f"  CWEs: {len(cwe_after)} classes")
    
    with open(outpath, "w") as f:
        for r in selected:
            f.write(json.dumps(r["data"], ensure_ascii=False) + "\n")
    
    print(f"  Output: {len(selected)} records")
    
    return len(selected)

def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    
    total_out = 0
    for fname in FILES:
        inpath = DATA_DIR / fname
        outpath = OUT_DIR / fname
        if not inpath.exists():
            print(f"Skipping {fname}")
            continue
        n = process_file(inpath, outpath, fname.replace(".jsonl", ""))
        total_out += n
    
    print(f"\n{'='*50}")
    print(f"Total output: {total_out} records")
    print(f"Output dir: {OUT_DIR.resolve()}")
    print(f"{'='*50}")

if __name__ == "__main__":
    main()
