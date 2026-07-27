"""Clean the instruct_final dataset: dedup, fix null CWEs, normalize sources, validate."""
import json
import hashlib
import os
import sys
from pathlib import Path
from collections import Counter

DATA_DIR = Path("v2/inputs/datasets/instruct_final")
OUT_DIR = Path("v2/inputs/datasets/instruct_cleaned")
FILES = ["train.jsonl", "val.jsonl", "test.jsonl"]

def content_fingerprint(d):
    msgs = d.get("messages", [])
    meta = d.get("_meta", {})
    key = json.dumps(msgs, sort_keys=True) + json.dumps({k: meta.get(k) for k in ["id", "task"]}, sort_keys=True)
    return hashlib.sha256(key.encode()).hexdigest()

def normalize_source(src):
    if not src:
        return "unknown"
    parts = src.split(":")
    if len(parts) >= 3 and parts[0] == "bigvul":
        return "bigvul"
    if len(parts) >= 3 and parts[0] == "ayshajavd":
        return parts[1] if len(parts) > 1 else parts[0]
    return src

def clean_file(inpath, outpath):
    total = 0
    kept = 0
    dup_removed = 0
    null_cwe_fixed = 0
    cwe_before = Counter()
    cwe_after = Counter()
    lang_counter = Counter()
    source_counter = Counter()

    seen_fps = set()

    with open(outpath, "w") as out:
        with open(inpath) as f:
            for line in f:
                total += 1
                d = json.loads(line)
                meta = d.setdefault("_meta", {})

                fp = content_fingerprint(d)
                if fp in seen_fps:
                    dup_removed += 1
                    continue
                seen_fps.add(fp)

                cwe_before[meta.get("cwe", "MISSING") or "MISSING"] += 1

                if not meta.get("cwe"):
                    meta["cwe"] = "CWE-UNKNOWN"
                    null_cwe_fixed += 1

                if meta.get("source"):
                    meta["source"] = normalize_source(meta["source"])

                cwe_after[meta.get("cwe", "MISSING") or "MISSING"] += 1
                lang_counter[meta.get("language", "unknown")] += 1
                source_counter[meta.get("source", "unknown")] += 1

                out.write(json.dumps(d, ensure_ascii=False) + "\n")
                kept += 1

    print(f"\n{inpath.name}:")
    print(f"  Total: {total}, Kept: {kept}, Dups removed: {dup_removed}, Null CWE fixed: {null_cwe_fixed}")
    print(f"  Top CWEs (before): {dict(cwe_before.most_common(5))}")
    print(f"  Top CWEs (after):  {dict(cwe_after.most_common(5))}")
    print(f"  Top langs: {dict(lang_counter.most_common(5))}")
    print(f"  Top sources: {dict(source_counter.most_common(5))}")

    return total, kept, dup_removed, null_cwe_fixed

def main():
    os.makedirs(OUT_DIR, exist_ok=True)

    totals = {"total": 0, "kept": 0, "dups": 0, "null_cwe_fixed": 0}
    for fname in FILES:
        inpath = DATA_DIR / fname
        outpath = OUT_DIR / fname
        if not inpath.exists():
            print(f"Skipping {fname} (not found)")
            continue
        t, k, d, n = clean_file(inpath, outpath)
        totals["total"] += t
        totals["kept"] += k
        totals["dups"] += d
        totals["null_cwe_fixed"] += n

    print(f"\n{'='*50}")
    print(f"TOTAL: {totals['total']} -> {totals['kept']} kept")
    print(f"  Duplicates removed: {totals['dups']}")
    print(f"  Null CWEs fixed:    {totals['null_cwe_fixed']}")
    print(f"Output: {OUT_DIR.resolve()}")
    print(f"{'='*50}")

if __name__ == "__main__":
    main()
