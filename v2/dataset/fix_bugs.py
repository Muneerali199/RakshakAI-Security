#!/usr/bin/env python3
"""Fix 3 critical dataset bugs found in live audit."""

import json, sys
from pathlib import Path

META_DIR = Path("v2/inputs/datasets/phase_b/meta")
OUT_DIR = Path("v2/inputs/datasets/phase_b/cleaned")
OUT_DIR.mkdir(parents=True, exist_ok=True)

TEXT_SIGNALS = [
    "is vulnerable to",
    "This advisory",
    "A vulnerability",
    "was addressed with",
    "Duplicate Advisory",
    "This issue is fixed in",
    "An app may be able to",
    "If successfully exploited",
    "prior to and including",
    "Upgrade ",
]

CODE_SIGNALS = [
    "{", "}", "(", ")", ";",
    "def ", "void ", "int ", "class ",
    "function ", "func ", "fn ", "pub ",
    "return ", "if ", "for ", "while ",
]


def is_actual_code(code: str) -> bool:
    """Bug 1: detect NVD/OSV advisory text masquerading as code."""
    head = code[:300]
    has_text = any(sig in head for sig in TEXT_SIGNALS)
    if not has_text:
        return True
    has_code = any(s in code for s in CODE_SIGNALS)
    return has_code


def fix_bug2(sample: dict) -> dict:
    """Bug 2: OWASP false positives should be is_vulnerable=False."""
    src = sample.get("source", "")
    if "owasp-benchmark" in src:
        expl = (sample.get("explanation") or "").lower()
        if "false positive" in expl:
            sample["is_vulnerable"] = False
            sample["severity"] = "clean"
            sample["cwe"] = None
            sample["attack_scenario"] = None
    return sample


def fix_bug3(sample: dict) -> dict:
    """Bug 3: Null patched_code when identical to vulnerable_code."""
    vuln = sample.get("vulnerable_code") or ""
    patch = sample.get("patched_code")
    if patch is not None and vuln.strip() == patch.strip():
        sample["patched_code"] = None
    return sample


stats = {"total": 0, "bug1_removed": 0, "bug1_nvd": 0, "bug1_osv": 0,
         "bug2_fixed": 0, "bug3_nulled": 0}

for split in ["train", "val", "test"]:
    in_path = META_DIR / f"{split}.jsonl"
    out_path = OUT_DIR / f"{split}.jsonl"
    kept = 0
    dropped = 0

    with in_path.open() as f_in, out_path.open("w") as f_out:
        for line in f_in:
            sample = json.loads(line)
            stats["total"] += 1

            # Bug 1 — remove text-as-code
            code = sample.get("vulnerable_code", "") or ""
            src = sample.get("source", "")
            is_nvd_osv = src.startswith("nvd:") or src.startswith("osv:")
            if is_nvd_osv and not is_actual_code(code):
                stats["bug1_removed"] += 1
                if src.startswith("nvd:"):
                    stats["bug1_nvd"] += 1
                else:
                    stats["bug1_osv"] += 1
                dropped += 1
                continue

            # Bug 2 — fix OWASP labels
            sample = fix_bug2(sample)
            if "false positive" in (sample.get("explanation") or "").lower() and not sample.get("is_vulnerable"):
                stats["bug2_fixed"] += 1

            # Bug 3 — null identical patches
            sample = fix_bug3(sample)
            if sample.get("patched_code") is None and sample.get("is_vulnerable"):
                stats["bug3_nulled"] += 1

            f_out.write(json.dumps(sample) + "\n")
            kept += 1

    print(f"  {split}: {kept} kept, {dropped} dropped")

print(f"\n🔴 Bug 1 — Removed text-as-code: {stats['bug1_removed']} (NVD={stats['bug1_nvd']}, OSV={stats['bug1_osv']})")
print(f"🔴 Bug 2 — OWASP false positives fixed: {stats['bug2_fixed']}")
print(f"🔴 Bug 3 — Null identical patches: {stats['bug3_nulled']}")
print(f"\nTotal: {stats['total']} → {stats['total'] - stats['bug1_removed']} ({100*(stats['total']-stats['bug1_removed'])/stats['total']:.1f}%)")
print(f"\nCleaned files → {OUT_DIR}/")