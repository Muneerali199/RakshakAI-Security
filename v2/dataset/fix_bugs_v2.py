#!/usr/bin/env python3
"""Fix 3 dataset bugs — v2 with corrected logic."""

import json
from pathlib import Path

META_DIR = Path("v2/inputs/datasets/phase_b/meta")
OUT_DIR = Path("v2/inputs/datasets/phase_b/cleaned")
OUT_DIR.mkdir(parents=True, exist_ok=True)

FUNC_KEYWORDS = [
    "def ", "void ", "int ", "function ", "class ",
    "func ", "fn ", "static ", "public ", "private ",
    "return ", "for ", "while ", "if (",
]


def is_actual_code(sample: dict) -> bool:
    """Bug 1: source-based filter for NVD/OSV advisory text."""
    code = (sample.get("vulnerable_code") or "").strip()
    source = sample.get("source") or ""

    # Source-based: only filter nvd: and osv: rows
    if not (source.startswith("nvd:") or source.startswith("osv:")):
        return True

    # Count code-like characters
    code_chars = sum(1 for c in code if c in "{}();=<>[]")

    # Must have function/method definition
    has_func = any(kw in code for kw in FUNC_KEYWORDS)

    # Remove only when BOTH are bad (advisory text lacks both)
    if code_chars < 5 and not has_func:
        return False

    return True


def fix_bug2(sample: dict) -> dict:
    """Bug 2: OWASP false positives → is_vulnerable=False."""
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
    """Bug 3: null patched_code only for VULN samples where vuln==patch."""
    vuln = (sample.get("vulnerable_code") or "").strip()
    patch = (sample.get("patched_code") or "").strip()
    is_vuln = sample.get("is_vulnerable", False)

    if is_vuln and patch and vuln == patch:
        sample["patched_code"] = None
        sample["secure_fix"] = f"Patch unavailable — see CVE: {sample.get('cve', 'unknown')}"

    return sample


def fix_bug4(sample: dict) -> dict:
    """Bug 4: null partial patches (snippet vs full function)."""
    vuln = (sample.get("vulnerable_code") or "").strip()
    patch = (sample.get("patched_code") or "").strip()
    is_vuln = sample.get("is_vulnerable", False)

    if is_vuln and patch and vuln != patch:
        vuln_lines = vuln.count("\n") + 1
        patch_lines = patch.count("\n") + 1
        if vuln_lines > 5 and patch_lines < vuln_lines * 0.5:
            sample["patched_code"] = None
            sample["secure_fix"] = "Partial fix snippet — not a complete before/after pair"

    return sample


stats = {"total": 0, "bug1_removed": 0, "bug1_nvd": 0, "bug1_osv": 0,
         "bug2_fixed": 0, "bug3_nulled": 0, "bug4_nulled": 0}

for split in ["train", "val", "test"]:
    in_path = META_DIR / f"{split}.jsonl"
    out_path = OUT_DIR / f"{split}.jsonl"
    kept = 0
    dropped = 0

    with in_path.open() as f_in, out_path.open("w") as f_out:
        for line in f_in:
            sample = json.loads(line)
            stats["total"] += 1

            # Bug 1 — remove text-as-code (source-based filter)
            if not is_actual_code(sample):
                stats["bug1_removed"] += 1
                src = sample.get("source", "")
                if src.startswith("nvd:"):
                    stats["bug1_nvd"] += 1
                else:
                    stats["bug1_osv"] += 1
                dropped += 1
                continue

            # Bug 2 — fix OWASP labels
            old_vuln = sample.get("is_vulnerable")
            sample = fix_bug2(sample)
            if old_vuln and not sample.get("is_vulnerable"):
                stats["bug2_fixed"] += 1

            # Bug 3 — null identical patches (vuln only)
            old_patch3 = sample.get("patched_code")
            sample = fix_bug3(sample)
            if old_patch3 is not None and sample.get("patched_code") is None and sample.get("is_vulnerable"):
                stats["bug3_nulled"] += 1

            # Bug 4 — null partial patches (snippet vs full function)
            old_patch4 = sample.get("patched_code")
            sample = fix_bug4(sample)
            if old_patch4 is not None and sample.get("patched_code") is None and sample.get("is_vulnerable"):
                stats["bug4_nulled"] += 1

            f_out.write(json.dumps(sample) + "\n")
            kept += 1

    print(f"  {split}: {kept} kept, {dropped} dropped")

print(f"\n🔴 Bug 1 — Removed text-as-code: {stats['bug1_removed']} (NVD={stats['bug1_nvd']}, OSV={stats['bug1_osv']})")
print(f"🔴 Bug 2 — OWASP false positives fixed: {stats['bug2_fixed']}")
print(f"🔴 Bug 3 — Null identical patches (vuln only): {stats['bug3_nulled']}")
print(f"🔴 Bug 4 — Null partial patches (snippet vs full): {stats['bug4_nulled']}")
print(f"\nTotal: {stats['total']} → {stats['total'] - stats['bug1_removed']}")