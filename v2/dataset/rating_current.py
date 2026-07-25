#!/usr/bin/env python3
"""Quick dataset rating calculator for current meta state."""
import json
from pathlib import Path
from collections import Counter

META = Path("v2/inputs/datasets/phase_b/meta")

def main():
    samples = []
    for f in sorted(META.glob("*.jsonl")):
        for line in open(f):
            samples.append(json.loads(line))

    total = len(samples)
    cwes = Counter(s.get("cwe", "CWE-000") for s in samples if s.get("cwe"))
    langs = Counter(s.get("language", "?") for s in samples if s.get("language"))
    patch = sum(1 for s in samples if s.get("patched_code"))
    vuln = sum(1 for s in samples if s.get("is_vulnerable", True))
    clean = total - vuln
    expl = sum(1 for s in samples if s.get("explanation") and len(s.get("explanation", "")) > 50)
    hard_neg = sum(1 for s in samples if not s.get("is_vulnerable", True))

    c_count = langs.get("c", 0) + langs.get("cpp", 0)
    c_pct = c_count / total * 100
    lang_top = langs.most_common(1)[0][1] / total * 100 if langs else 0

    real_sources = sum(1 for s in samples
                       if "osv" in str(s.get("source", "")).lower()
                       or "github" in str(s.get("source", "")).lower()
                       or "cve" in str(s.get("source", "")).lower()
                       or "nvd" in str(s.get("source", "")).lower())

    print("=" * 60)
    print("RakshakAI Dataset Quality Rating")
    print("=" * 60)

    print(f"\n{'Metric':<30} {'Value':<12} {'Score':<8}")
    print("-" * 52)

    # 1. Size & Scale (0-10)
    if total >= 300000: size_s = 10.0
    elif total >= 250000: size_s = 9.5
    elif total >= 200000: size_s = 9.0
    elif total >= 150000: size_s = 8.0
    elif total >= 100000: size_s = 7.0
    else: size_s = 5.0
    print(f"{'Size & Scale':<30} {total:<12,} {size_s:<.1f}")

    # 2. CWE Coverage (0-10)
    n = len(cwes)
    if n >= 500: cwe_s = 10.0
    elif n >= 400: cwe_s = 9.5
    elif n >= 300: cwe_s = 9.0
    elif n >= 200: cwe_s = 8.0
    elif n >= 100: cwe_s = 7.0
    else: cwe_s = 5.0
    print(f"{'CWE Coverage':<30} {n:<12} {cwe_s:<.1f}")

    # 3. Language Balance (0-10) - lower C dominance = better
    if c_pct <= 30: lang_s = 10.0
    elif c_pct <= 40: lang_s = 9.0
    elif c_pct <= 50: lang_s = 8.0
    elif c_pct <= 60: lang_s = 7.0
    elif c_pct <= 70: lang_s = 6.0
    else: lang_s = 5.0
    nlangs = len(langs)
    print(f"{'Languages':<30} {nlangs:<12} {lang_s:<.1f} ({c_pct:.0f}% C)")

    # 4. Patch Coverage (0-10)
    pct = patch / total * 100
    if pct >= 80: patch_s = 10.0
    elif pct >= 60: patch_s = 8.0
    elif pct >= 40: patch_s = 6.0
    elif pct >= 30: patch_s = 5.0
    elif pct >= 20: patch_s = 4.0
    else: patch_s = 3.0
    print(f"{'Patch Coverage':<30} {patch:<12,} {patch_s:<.1f} ({pct:.1f}%)")

    # 5. Explanation Quality (0-10)
    expct = expl / vuln * 100 if vuln else 0
    if expct >= 90: exp_s = 9.5
    elif expct >= 80: exp_s = 8.5
    elif expct >= 70: exp_s = 7.5
    elif expct >= 60: exp_s = 6.5
    else: exp_s = 5.0
    print(f"{'Explanation Quality':<30} {expl:<12,} {exp_s:<.1f} ({expct:.0f}%)")

    # 6. Hard Negatives (0-10)
    if hard_neg >= 50000: hn_s = 10.0
    elif hard_neg >= 10000: hn_s = 8.0
    elif hard_neg >= 5000: hn_s = 7.0
    elif hard_neg >= 1000: hn_s = 6.0
    elif hard_neg >= 100: hn_s = 5.0
    else: hn_s = 4.0
    print(f"{'Hard Negatives':<30} {hard_neg:<12,} {hn_s:<.1f}")

    # 7. Source Diversity (0-10)
    nsources = len(set(s.get("source", "?") for s in samples if s.get("source")))
    # Real CVE sources bonus
    real_bonus = min(1.0, real_sources / 50000)
    src_s = min(10.0, 7.0 + (nsources / 20) + real_bonus)
    print(f"{'Source Diversity':<30} {nsources:<12} {src_s:<.1f}")

    # 8. Data Quality / Realism (0-10)
    real_pct = real_sources / total * 100
    dq = min(10.0, 8.0 + (real_pct / 20))
    print(f"{'Real-world Data':<30} {real_sources:<12,} {dq:<.1f} ({real_pct:.1f}%)")

    # 9. Vulnerability Rate (0-10)
    vuln_pct = vuln / total * 100
    vrate = min(10.0, max(5.0, 10.0 - abs(vuln_pct - 60) / 10))
    print(f"{'Vulnerability Rate':<30} {vuln_pct:<.1f}%{'':>7} {vrate:<.1f}")

    scores = [size_s, cwe_s, lang_s, patch_s, exp_s, hn_s, src_s, dq, vrate]
    overall = sum(scores) / len(scores)

    print("-" * 52)
    print(f"{'OVERALL':<30} {'':<12} {overall:<.1f}")

    print(f"\n{'─' * 40}")
    print(f"  Total: {total:,} samples")
    print(f"  CWEs:  {n} unique")
    print(f"  Langs: {nlangs} ({', '.join(l[0] for l in langs.most_common(5))})")
    print(f"  Patch: {pct:.1f}%")
    print(f"  Real:  {real_sources:,} ({real_pct:.1f}%)")
    print(f"{'─' * 40}")

    print(f"\n  Next: to_instruct.py → pack.py → audit_quality_v2.py")

if __name__ == "__main__":
    main()
