#!/usr/bin/env python3
"""
Reduce C dominance from 66.5% → ~50% by pruning low-quality C samples.
Keeps ALL non-C samples. Targets 200K total at 50/50 balance.
"""
import json
from pathlib import Path

META_DIR = Path("v2/inputs/datasets/phase_b/meta")
OUT_DIR = Path("v2/inputs/datasets/phase_b/meta_reduced")
BACKUP_DIR = Path("v2/inputs/datasets/phase_b/meta_before_c_reduction")

SPLIT_TARGETS = {
    "train": {"total": 187_000, "vuln_nc_keep": "all", "nonvuln_nc_keep": "all"},
    "test":  {"total": 22_000,  "vuln_nc_keep": "all", "nonvuln_nc_keep": "all"},
    "val":   {"total": 11_000,  "vuln_nc_keep": "all", "nonvuln_nc_keep": "all"},
}

def quality_score(s):
    score = 0
    if s.get("patched_code"): score += 10
    if len(s.get("explanation", "")) > 100: score += 2
    if len(s.get("vulnerable_code", "")) > 200: score += 1
    if s.get("cwe") and s["cwe"] != "CWE-UNKNOWN": score += 1
    if s.get("severity") in ("high", "critical"): score += 1
    if s.get("explanation_source") in ("groq", "mistral", "nvidia"): score += 2
    return score

def process_split(f_path, out_path, target_total):
    rows = {"vuln_c": [], "vuln_nc": [], "nonvuln_c": [], "nonvuln_nc": []}
    for line in open(f_path):
        s = json.loads(line)
        is_c = s.get("language") in ("c", "cpp")
        is_vuln = s.get("is_vulnerable", False)
        key = f"{'vuln' if is_vuln else 'nonvuln'}_{'c' if is_c else 'nc'}"
        rows[key].append(s)

    half = target_total // 2

    # Keep ALL non-C
    vuln_nc = rows["vuln_nc"]
    nonvuln_nc = rows["nonvuln_nc"]

    # If non-C already exceeds half, we need to trim non-C too (shouldn't happen)
    if len(vuln_nc) > half:
        vuln_nc.sort(key=quality_score, reverse=True)
        vuln_nc = vuln_nc[:half]
    if len(nonvuln_nc) > half:
        nonvuln_nc.sort(key=quality_score, reverse=True)
        nonvuln_nc = nonvuln_nc[:half]

    # How many C to keep per side
    vuln_c_keep = half - len(vuln_nc)
    nonvuln_c_keep = half - len(nonvuln_nc)

    # Score and pick best C
    rows["vuln_c"].sort(key=quality_score, reverse=True)
    rows["nonvuln_c"].sort(key=quality_score, reverse=True)

    vuln_c = rows["vuln_c"][:vuln_c_keep]
    nonvuln_c = rows["nonvuln_c"][:nonvuln_c_keep]

    # Write
    out = vuln_c + vuln_nc + nonvuln_c + nonvuln_nc
    with open(out_path, "w") as f:
        for s in out:
            f.write(json.dumps(s, ensure_ascii=False) + "\n")

    c_count = sum(1 for s in out if s.get("language") in ("c", "cpp"))
    total = len(out)
    balance = sum(1 for s in out if s.get("is_vulnerable"))
    return total, c_count, balance

def main():
    OUT_DIR.mkdir(exist_ok=True)

    total_samples = 0
    total_c = 0
    total_vuln = 0

    for meta_file in sorted(META_DIR.glob("*.jsonl")):
        split = meta_file.stem
        target = SPLIT_TARGETS[split]["total"]
        out_path = OUT_DIR / meta_file.name
        t, c, v = process_split(meta_file, out_path, target)
        total_samples += t
        total_c += c
        total_vuln += v
        print(f"{split:10s}: {t:>6,} total, {c:>6,} C ({c/t*100:.1f}%), {v:>6,} vuln ({v/t*100:.0f}%)")

    print(f"\n{'TOTAL':10s}: {total_samples:>6,} total, {total_c:>6,} C ({total_c/total_samples*100:.1f}%), {total_vuln:>6,} vuln ({total_vuln/total_samples*100:.0f}%)")

    # Backup and replace
    if BACKUP_DIR.exists():
        import shutil
        shutil.rmtree(BACKUP_DIR)
    META_DIR.rename(BACKUP_DIR)
    OUT_DIR.rename(META_DIR)
    print(f"\n✅ Backup: {BACKUP_DIR}")
    print(f"✅ New meta: {META_DIR}")

if __name__ == "__main__":
    main()
