#!/usr/bin/env python3
"""
Merge extracted OSV commit data + GitHub advisory code into meta.
"""
import json
import hashlib
import time
from pathlib import Path
from collections import Counter

META_DIR = Path("v2/inputs/datasets/phase_b/meta")
REAL_DIR = Path("v2/inputs/datasets/phase_b/real_cve_generated")

def load_meta():
    samples = []
    for f in sorted(META_DIR.glob("*.jsonl")):
        for line in open(f):
            samples.append(json.loads(line))
    return samples

def load_real():
    samples = []
    for f in sorted(REAL_DIR.glob("*.jsonl")):
        if f.name == "all_real_cves.jsonl":
            continue
        for line in open(f):
            s = json.loads(line)
            if s.get("vulnerable_code") and len(s["vulnerable_code"]) > 20:
                samples.append(s)
    return samples

def deduplicate(new_samples, existing):
    existing_keys = set()
    for s in existing:
        existing_keys.add(s.get("id", ""))
        existing_keys.add("fp:" + (s.get("fingerprint", "") or ""))
    deduped = []
    for s in new_samples:
        key = s.get("id", "")
        fp = s.get("fingerprint", "") or hashlib.md5((s.get("vulnerable_code", "") or "").encode()).hexdigest()[:12]
        if key and key in existing_keys:
            continue
        if ("fp:" + fp) in existing_keys:
            continue
        s["fingerprint"] = fp
        s["added_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        s["split"] = "train"
        deduped.append(s)
    return deduped

def main():
    print("=" * 60)
    print("Merge Real CVE Data into Meta")
    print("=" * 60)

    print("\n1. Loading meta...")
    existing = load_meta()
    print(f"   Existing meta: {len(existing):,}")

    print("\n2. Loading real CVE extracted data...")
    real = load_real()
    print(f"   Real CVE samples: {len(real):,}")

    cwes = Counter(s.get("cwe", "CWE-000") for s in real)
    langs = Counter(s.get("language", "?") for s in real)
    with_patch = sum(1 for s in real if s.get("patched_code"))
    print(f"   CWEs: {len(cwes)} unique")
    print(f"   Languages: {len(langs)} — {dict(langs.most_common(10))}")
    print(f"   With patch: {with_patch}/{len(real)} ({100*with_patch/len(real):.1f}%)")

    print("\n3. Deduplicating against meta...")
    new_samples = deduplicate(real, existing)
    print(f"   New unique samples to add: {len(new_samples):,}")

    if not new_samples:
        print("   Nothing to add!")
        return

    print("\n4. Appending to meta/train.jsonl...")
    with open(META_DIR / "train.jsonl", "a") as f:
        for s in new_samples:
            f.write(json.dumps(s, ensure_ascii=False) + "\n")

    new_total = len(existing) + len(new_samples)
    print(f"   New meta total: {new_total:,}")

    print("\n5. Post-merge stats:")
    all_new = existing + new_samples
    total_cwes = Counter(s.get("cwe", "CWE-000") for s in all_new)
    total_langs = Counter(s.get("language", "?") for s in all_new)
    total_patch = sum(1 for s in all_new if s.get("patched_code"))
    real_sources = sum(1 for s in all_new if "osv" in str(s.get("source", "")).lower() or "github" in str(s.get("source", "")).lower())
    c_count = total_langs.get("c", 0) + total_langs.get("cpp", 0)
    c_pct = c_count / new_total * 100
    print(f"   {'Metric':<25} {'Value':<12}")
    print(f"   {'─'*37}")
    print(f"   {'Total':<25} {new_total:<12,}")
    print(f"   {'CWEs':<25} {len(total_cwes):<12}")
    print(f"   {'Languages':<25} {len(total_langs):<12}")
    print(f"   {'Patch coverage':<25} {100*total_patch/new_total:.1f}%")
    print(f"   {'C dominance':<25} {c_pct:.1f}%")
    print(f"   {'Real CVE sources':<25} {real_sources:<12,}")

    print(f"\n6. To complete:")
    print(f"   python3 v2/dataset/to_instruct.py")
    print(f"   python3 v2/dataset/pack.py --phases phase_b")
    print(f"   python3 v2/dataset/audit_quality_v2.py")

if __name__ == "__main__":
    main()
