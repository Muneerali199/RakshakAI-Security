#!/usr/bin/env python3
"""Download CVEfixes focusing on high-patch-coverage languages."""
import json
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from v2.dataset.schema import SecuritySample, write_jsonl

print("Downloading CVEfixes (streaming, will take time)...")
try:
    from datasets import load_dataset
    ds = load_dataset("hitoshura25/cvefixes", split="train", streaming=True)
    samples = []
    target_langs = {"python", "javascript", "java", "go", "rust", "php"}
    for i, row in enumerate(ds):
        if len(samples) >= 25000:
            break
        lang = row.get("language", "").lower()
        if lang not in target_langs:
            continue
        if not row.get("diff") and not row.get("fixed_code"):
            continue
        vuln_code = row.get("vulnerable_code", row.get("before", ""))
        patch_code = row.get("fixed_code", row.get("after", ""))
        if len(vuln_code) < 50:
            continue
        sample = SecuritySample(
            id=f"cvefixes_{row.get('cve_id', i)}",
            vulnerable_code=vuln_code,
            patched_code=patch_code if len(patch_code) > 50 else None,
            language=lang,
            is_vulnerable=True,
            cwe=row.get("cwe_id"),
            severity=str(row.get("severity", "medium")).lower(),
            explanation=row.get("description", "CVEfixes vulnerability"),
            attack_scenario="",
            secure_fix=f"Patch available: {bool(patch_code)}",
            source="cvefixes",
            source_license="MIT",
            cve=row.get("cve_id"),
        )
        samples.append(sample)
        if len(samples) % 500 == 0:
            print(f"  Downloaded {len(samples)} (target: 25K...", flush=True)
    write_jsonl(Path("v2/inputs/datasets/raw/cvefixes.jsonl"), samples)
    print(f"\nDownloaded {len(samples)} CVEfixes samples")
    patched = sum(1 for s in samples if s.patched_code)
    print(f"With patches: {patched} ({100*patched/max(len(samples),1):.1f}%)")
except ImportError:
    print("datasets library not installed: pip install datasets")
    sys.exit(1)