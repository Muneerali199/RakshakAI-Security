"""
RakshakAI v2 — Final dataset build (v2.2).

Loads enriched vuln samples (meta_enriched/), hard negatives (nonvuln/),
rebalances with language weights, and builds instruct/pack/axolotl formats.

Usage:
    python v2/dataset/build_final.py
"""
from __future__ import annotations

import json
import random
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from v2.dataset.schema import SecuritySample

random.seed(42)

META_ENRICHED = Path("inputs/datasets/phase_b/meta_enriched")
NONVULN_DIR = Path("inputs/datasets/nonvuln")
EXTRA_VULN_DIR = Path("inputs/datasets/extra_vuln")
OUT_DIR = Path("inputs/datasets/phase_b")
OUT_META = OUT_DIR / "meta"
OUT_INSTRUCT = OUT_DIR / "instruct"
OUT_PACK = OUT_DIR / "pack"
OUT_AXOLOTL = Path("inputs/datasets/axolotl")
CONFIGS = Path("configs")

SYSTEM_PROMPT = """You are RakshakAI v2, a security-specialized code analysis model. Analyze the code snippet for security vulnerabilities.

Think through your analysis step by step, then respond with a JSON object containing:
{
  "is_vulnerable": true/false,
  "vulnerability_type": "<CWE-XXX or null if not vulnerable>",
  "severity": "<critical|high|medium|low|clean>",
  "explanation": "<root cause explanation>",
  "patched_code": "<fixed code or null if already secure>",
  "secure_fix_recommendation": "<how to fix it>"
}
If the code is secure, set is_vulnerable=false, severity="clean", and all other fields to appropriate null/clean values."""


def load_enriched_vuln() -> list[dict]:
    """Load enriched vulnerable samples from meta_enriched/."""
    samples = []
    for split in ["train", "val", "test"]:
        path = META_ENRICHED / f"{split}.jsonl"
        if not path.exists():
            continue
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    d = json.loads(line)
                    if not d.get("is_vulnerable", True):
                        continue
                    d["split"] = split
                    samples.append(d)
                except json.JSONDecodeError:
                    continue
    # Also load from extra_vuln (CrossVul, synthetic, CVEfixes, exploits, trajectories, DPO)
    if EXTRA_VULN_DIR.exists():
        for p in sorted(EXTRA_VULN_DIR.rglob("*.jsonl")):
            # Skip exploit_bench_exploits (has patched_code == vcode, used only as exploit pairs)
            if "exploit_bench_exploits" in p.name:
                continue
            with open(p) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        d = json.loads(line)
                        if not d.get("is_vulnerable", True):
                            continue
                        d["split"] = "train"
                        samples.append(d)
                    except json.JSONDecodeError:
                        continue
    print(f"[load] {len(samples)} enriched vuln samples from meta_enriched/ + extra_vuln/")
    return samples


def load_hard_negatives() -> list[dict]:
    """Load hard negatives and other non-vuln samples."""
    samples = []
    if not NONVULN_DIR.exists():
        print(f"[load] {NONVULN_DIR} not found")
        return samples
    for p in sorted(NONVULN_DIR.rglob("*.jsonl")):
        with open(p) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    d = json.loads(line)
                    if not d.get("is_vulnerable", True):
                        d["split"] = "train"
                        samples.append(d)
                except json.JSONDecodeError:
                    continue
    print(f"[load] {len(samples)} non-vuln samples from nonvuln/")
    return samples


def compute_quality(d):
    """Compute quality score 0-1 for a sample."""
    score = 0.5
    code = d.get("vulnerable_code", "")
    expl = d.get("explanation", "")
    patch = d.get("patched_code")
    if 100 < len(code) < 5000:
        score += 0.15
    if patch and len(patch) > 30:
        score += 0.2
    if len(expl) > 100:
        score += 0.15
    cwe = d.get("cwe", "")
    if cwe and cwe not in ("CWE-UNKNOWN", "CWE-CLEAN", "CWE-NVD-CWE-Other", "CWE-NVD-CWE-noinfo"):
        score += 0.1
    if "def " in code or "function " in code or "public " in code:
        score += 0.05
    if "import " in code or "#include" in code or "require(" in code:
        score += 0.05
    return min(1.0, max(0.0, score))


def build_final():
    rng = random.Random(42)

    # 1. Load data
    print("=" * 60)
    print("STEP 1: Load data")
    print("=" * 60)
    vuln = load_enriched_vuln()
    nonvuln = load_hard_negatives()
    print(f"  Vuln: {len(vuln)}, Non-vuln: {len(nonvuln)}")

    # 2. Deduplicate globally
    print("\n" + "=" * 60)
    print("STEP 2: Global dedup")
    print("=" * 60)
    seen_fps: set[str] = set()
    deduped_vuln = []
    deduped_nonvuln = []
    for s in vuln:
        fp = s.get("fingerprint", "") or SecuritySample.fingerprint_of(s.get("vulnerable_code", ""))
        if fp in seen_fps:
            continue
        seen_fps.add(fp)
        deduped_vuln.append(s)
    for s in nonvuln:
        fp = s.get("fingerprint", "") or SecuritySample.fingerprint_of(s.get("vulnerable_code", ""))
        if fp in seen_fps:
            continue
        seen_fps.add(fp)
        deduped_nonvuln.append(s)
    print(f"  After dedup: {len(deduped_vuln)} vuln, {len(deduped_nonvuln)} non-vuln")

    # Clean CWE edge cases
    CWE_BAD = {"CWE-NVD-CWE-Other", "CWE-NVD-CWE-noinfo"}
    for s in deduped_vuln:
        if s.get("cwe", "") in CWE_BAD:
            s["cwe"] = "CWE-UNKNOWN"
    for s in deduped_nonvuln:
        if s.get("cwe", "") == "CWE-CLEAN":
            s["cwe"] = "CWE-UNKNOWN"

    # 3. Balance with language weights
    print("\n" + "=" * 60)
    print("STEP 3: Balance")
    print("=" * 60)

    lang_weights = {}
    lw_path = CONFIGS / "language_balance.json"
    if lw_path.exists():
        cfg = json.loads(lw_path.read_text())
        lang_weights = cfg.get("language_weights", {})
    print(f"  Using language weights: {lang_weights}")

    # Assign quality scores, sort by language
    for s in deduped_vuln:
        s["_quality"] = compute_quality(s)
    for s in deduped_nonvuln:
        s["_quality"] = compute_quality(s)

    deduped_vuln.sort(key=lambda s: -s["_quality"])
    deduped_nonvuln.sort(key=lambda s: -s["_quality"])

    def weighted_downsample(items, target):
        by_lang = defaultdict(list)
        for s in items:
            lang = s.get("language", "text")
            by_lang[lang].append(s)

        # Soft cap on C/C++ to control dominance
        hard_cap = {"c": int(target * 0.50), "cpp": int(target * 0.10)}

        total_weight = sum(lang_weights.get(lang, 1.0) for lang in by_lang) or len(by_lang)

        allocations = {}
        for lang, group in by_lang.items():
            raw = int(target * lang_weights.get(lang, 1.0) / total_weight)
            cap = hard_cap.get(lang, len(group))
            allocations[lang] = max(0, min(raw, len(group), cap))

        allocated = sum(allocations.values())
        if allocated < target:
            remaining = target - allocated
            for _ in range(remaining):
                best_lang = None
                best_ratio = float('inf')
                for lang in by_lang:
                    cap = hard_cap.get(lang, len(by_lang[lang]))
                    if allocations[lang] < min(len(by_lang[lang]), cap):
                        expect = target * lang_weights.get(lang, 1.0) / total_weight
                        ratio = (allocations[lang] + 1) / max(expect, 0.001)
                        if ratio < best_ratio:
                            best_ratio = ratio
                            best_lang = lang
                if best_lang:
                    allocations[best_lang] += 1

        selected = []
        for lang, n_take in allocations.items():
            selected.extend(by_lang[lang][:n_take])
        return selected

    n = min(len(deduped_vuln), len(deduped_nonvuln))
    # Target 400K @ 60/40 vuln/non-vuln split
    target_vuln = min(240_000, len(deduped_vuln))
    target_nonvuln = min(int(target_vuln * 0.667), len(deduped_nonvuln))
    total_target = target_vuln + target_nonvuln

    vuln_balanced = weighted_downsample(deduped_vuln, target_vuln)
    nonvuln_balanced = weighted_downsample(deduped_nonvuln, target_nonvuln)

    print(f"  Balanced: {len(vuln_balanced)} vuln + {len(nonvuln_balanced)} non-vuln = {len(vuln_balanced) + len(nonvuln_balanced)}")

    # Language distribution report
    all_balanced = vuln_balanced + nonvuln_balanced
    lang_dist = Counter(s.get("language", "?") for s in all_balanced)
    print("\n  Language distribution:")
    for lang, cnt in sorted(lang_dist.items(), key=lambda x: -x[1]):
        print(f"    {lang:<12} {cnt:>6,} ({100*cnt/len(all_balanced):.1f}%)")

    # 4. Split
    print("\n" + "=" * 60)
    print("STEP 4: Train/Val/Test split")
    print("=" * 60)
    rng.shuffle(vuln_balanced)
    rng.shuffle(nonvuln_balanced)

    n_vuln = len(vuln_balanced)
    n_v_train = int(n_vuln * 0.85)
    n_v_val = int(n_vuln * 0.05)
    
    n_non = len(nonvuln_balanced)
    n_n_train = int(n_non * 0.85)
    n_n_val = int(n_non * 0.05)

    splits = {
        "train": vuln_balanced[:n_v_train] + nonvuln_balanced[:n_n_train],
        "val": vuln_balanced[n_v_train:n_v_train + n_v_val] + nonvuln_balanced[n_n_train:n_n_train + n_n_val],
        "test": vuln_balanced[n_v_train + n_v_val:] + nonvuln_balanced[n_n_train + n_n_val:],
    }
    for name in splits:
        rng.shuffle(splits[name])
    for name, items in splits.items():
        print(f"  {name}: {len(items)}")

    # 5. Write meta
    print("\n" + "=" * 60)
    print("STEP 5: Write meta")
    print("=" * 60)
    OUT_META.mkdir(parents=True, exist_ok=True)
    for split_name, split_samples in splits.items():
        path = OUT_META / f"{split_name}.jsonl"
        with open(path, "w") as f:
            for s in split_samples:
                f.write(json.dumps(s, ensure_ascii=False) + "\n")
        print(f"  {split_name}: {len(split_samples)} -> {path}")

    # 6. Build instruct (chat format)
    print("\n" + "=" * 60)
    print("STEP 6: Build instruct (chat format)")
    print("=" * 60)
    OUT_INSTRUCT.mkdir(parents=True, exist_ok=True)

    def make_user_content(s) -> str:
        lang = s.get("language", "code")
        code = s.get("vulnerable_code", "")
        return f"Analyze the following {lang} code for security vulnerabilities:\n\n```{lang}\n{code}\n```"

    def make_assistant_content(s) -> str:
        if s.get("is_vulnerable", True):
            cwe = s.get("cwe") or "CWE-UNKNOWN"
            severity = s.get("severity") or "high"
            explanation = (s.get("explanation") or "").strip() or "Vulnerability detected."
            attack = (s.get("attack_scenario") or "").strip()
            fix_text = (s.get("secure_fix") or "").strip() or "Apply standard security fixes."
            patched = (s.get("patched_code") or "").strip()

            cot_parts = [
                f"1. Vulnerability analysis: {cwe} — {explanation}",
            ]
            if attack:
                cot_parts.append(f"2. Attack scenario: {attack}")
            cot_parts.append(f"3. Severity assessment: {severity}")
            if patched:
                cot_parts.append("4. Code fix: The vulnerable code should be rewritten to address the security issue.")
            cot_parts.append(f"5. Secure fix recommendation: {fix_text}")
            cot = "\n".join(cot_parts)

            result = {
                "is_vulnerable": True,
                "vulnerability_type": cwe,
                "severity": severity,
                "explanation": explanation,
                "patched_code": patched if patched else None,
                "secure_fix_recommendation": fix_text,
            }
        else:
            cot = ("1. Vulnerability analysis: No vulnerability detected.\n"
                   "2. Attack scenario: None — code is secure.\n"
                   "3. Severity assessment: clean\n"
                   "4. Code fix: Not needed.\n"
                   "5. Secure fix recommendation: Code is already secure.")
            result = {
                "is_vulnerable": False,
                "vulnerability_type": None,
                "severity": "clean",
                "explanation": "Code appears to be secure with no detected vulnerabilities.",
                "patched_code": None,
                "secure_fix_recommendation": "No fix needed — code is secure.",
            }
        return f"Let me analyze this code step by step.\n\n{cot}\n\n{json.dumps(result, indent=2)}"

    def to_chat(s) -> dict:
        return {
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": make_user_content(s)},
                {"role": "assistant", "content": make_assistant_content(s)},
            ],
            "_meta": {
                "id": s.get("id", ""),
                "cwe": s.get("cwe"),
                "severity": s.get("severity"),
                "language": s.get("language"),
                "source": s.get("source"),
                "split": s.get("split", "train"),
                "is_vulnerable": s.get("is_vulnerable", True),
            },
        }

    for split_name, split_samples in splits.items():
        path = OUT_INSTRUCT / f"{split_name}.jsonl"
        with open(path, "w") as f:
            for s in split_samples:
                f.write(json.dumps(to_chat(s), ensure_ascii=False) + "\n")
        print(f"  {split_name}: written to {path}")

    # Combined all
    all_path = OUT_INSTRUCT / "all.jsonl"
    with open(all_path, "w") as f:
        for s in all_balanced:
            f.write(json.dumps(to_chat(s), ensure_ascii=False) + "\n")
    print(f"  all: {len(all_balanced)} -> {all_path}")

    # 7. Build pack format
    print("\n" + "=" * 60)
    print("STEP 7: Build pack format")
    print("=" * 60)
    OUT_PACK.mkdir(parents=True, exist_ok=True)
    for split_name, split_samples in splits.items():
        path = OUT_PACK / f"{split_name}.jsonl"
        with open(path, "w") as f:
            for s in split_samples:
                p = {
                    "id": s.get("id", ""),
                    "language": s.get("language", "text"),
                    "vulnerable_code": s.get("vulnerable_code", ""),
                    "patched_code": s.get("patched_code"),
                    "cwe": s.get("cwe"),
                    "severity": s.get("severity"),
                    "explanation": s.get("explanation", ""),
                    "is_vulnerable": s.get("is_vulnerable", True),
                    "source": s.get("source", ""),
                    "split": s.get("split", "train"),
                }
                f.write(json.dumps(p, ensure_ascii=False) + "\n")
        print(f"  {split_name}: {len(split_samples)} -> {path}")
    all_path = OUT_PACK / "all.jsonl"
    with open(all_path, "w") as f:
        for s in all_balanced:
            p = {
                "id": s.get("id", ""),
                "language": s.get("language", "text"),
                "vulnerable_code": s.get("vulnerable_code", ""),
                "patched_code": s.get("patched_code"),
                "cwe": s.get("cwe"),
                "severity": s.get("severity"),
                "explanation": s.get("explanation", ""),
                "is_vulnerable": s.get("is_vulnerable", True),
                "source": s.get("source", ""),
                "split": s.get("split", "train"),
            }
            f.write(json.dumps(p, ensure_ascii=False) + "\n")
    print(f"  all: {len(all_balanced)} -> {all_path}")

    # 8. Build axolotl format
    print("\n" + "=" * 60)
    print("STEP 8: Build axolotl format")
    print("=" * 60)
    OUT_AXOLOTL.mkdir(parents=True, exist_ok=True)
    for split_name, split_samples in splits.items():
        path = OUT_AXOLOTL / f"{split_name}.jsonl"
        with open(path, "w") as f:
            for s in split_samples:
                chat = to_chat(s)
                f.write(json.dumps(chat, ensure_ascii=False) + "\n")
        print(f"  {split_name}: written to {path}")

    # 9. Summary
    print("\n" + "=" * 60)
    print("FINAL DATASET SUMMARY")
    print("=" * 60)
    vuln_count = sum(1 for s in all_balanced if s.get("is_vulnerable", True))
    clean_count = len(all_balanced) - vuln_count
    patch_count = sum(1 for s in all_balanced if s.get("is_vulnerable", True) and s.get("patched_code"))
    expl_count = sum(1 for s in all_balanced if len(s.get("explanation", "")) > 50)
    c_count = lang_dist.get("c", 0) + lang_dist.get("cpp", 0)
    c_pct = 100 * c_count / len(all_balanced) if all_balanced else 0
    cwe_set = set(s.get("cwe") for s in all_balanced if s.get("is_vulnerable", True) and s.get("cwe") and s["cwe"] != "CWE-UNKNOWN" and s["cwe"] != "CWE-CLEAN")

    print(f"  Total samples:    {len(all_balanced):,}")
    print(f"  Vulnerable:       {vuln_count:,} ({100*vuln_count/len(all_balanced):.1f}%)")
    print(f"  Non-vulnerable:   {clean_count:,} ({100*clean_count/len(all_balanced):.1f}%)")
    print(f"  With patches:     {patch_count:,} ({100*patch_count/max(vuln_count,1):.1f}% of vuln)")
    print(f"  With explanations:{expl_count:,} ({100*expl_count/len(all_balanced):.1f}%)")
    print(f"  C dominance:      {c_count:,} ({c_pct:.1f}%)")
    print(f"  Unique CWEs:      {len(cwe_set)}")
    print(f"  Languages:        {len(lang_dist)}")

    summary = {
        "total": len(all_balanced),
        "vulnerable": vuln_count,
        "non_vulnerable": clean_count,
        "patch_count": patch_count,
        "patch_pct_vuln": round(100 * patch_count / max(vuln_count, 1), 1),
        "explanation_count": expl_count,
        "explanation_pct": round(100 * expl_count / len(all_balanced), 1),
        "c_dominance_pct": round(c_pct, 1),
        "unique_cwes": len(cwe_set),
        "unique_languages": len(lang_dist),
        "language_distribution": dict(lang_dist.most_common(20)),
    }
    (OUT_DIR / "final_summary.json").write_text(json.dumps(summary, indent=2))
    print(f"\n  Summary saved to {OUT_DIR / 'final_summary.json'}")

    return all_balanced, splits


if __name__ == "__main__":
    build_final()
