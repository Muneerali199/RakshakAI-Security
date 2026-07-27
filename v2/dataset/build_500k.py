"""
RakshakAI v2 — 500K Final Dataset Build.

Loads enriched vuln samples (meta_enriched/), extra_vuln/ sources, and nonvuln/
hard negatives. Fixes UNKNOWN CWE → inferred CWE from explanation text.
Deduplicates globally. Balances with language weights. Builds all output formats.

Usage:
    python v2/dataset/build_500k.py
"""
from __future__ import annotations

import json
import random
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

random.seed(42)

BASE = Path("inputs/datasets")
META_ENRICHED = BASE / "phase_b/meta_enriched"
NONVULN_DIR = BASE / "nonvuln"
EXTRA_VULN_DIR = BASE / "extra_vuln"
OUT_DIR = Path("inputs/datasets/phase_b")
OUT_META = OUT_DIR / "meta"
OUT_INSTRUCT = OUT_DIR / "instruct"
OUT_PACK = OUT_DIR / "pack"
OUT_AXOLOTL = BASE / "axolotl"
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

# CWE inference mapping from vulnerability type names mentioned in explanations
CWE_INFERENCE_MAP: dict[str, str] = {
    "sql injection": "CWE-89",
    "sqli": "CWE-89",
    "cross-site scripting": "CWE-79",
    "xss": "CWE-79",
    "path traversal": "CWE-22",
    "directory traversal": "CWE-22",
    "os command injection": "CWE-78",
    "command injection": "CWE-78",
    "remote code execution": "CWE-94",
    "rce": "CWE-94",
    "code injection": "CWE-94",
    "eval injection": "CWE-94",
    "deserialization": "CWE-502",
    "insecure deserialization": "CWE-502",
    "server-side request forgery": "CWE-918",
    "ssrf": "CWE-918",
    "information disclosure": "CWE-200",
    "information exposure": "CWE-200",
    "buffer overflow": "CWE-119",
    "buffer over-read": "CWE-125",
    "out-of-bounds read": "CWE-125",
    "out-of-bounds write": "CWE-787",
    "heap overflow": "CWE-122",
    "stack overflow": "CWE-121",
    "use after free": "CWE-416",
    "uaf": "CWE-416",
    "double free": "CWE-415",
    "null pointer dereference": "CWE-476",
    "format string": "CWE-134",
    "integer overflow": "CWE-190",
    "integer underflow": "CWE-191",
    "race condition": "CWE-362",
    "time-of-check time-of-use": "CWE-367",
    "toctou": "CWE-367",
    "open redirect": "CWE-601",
    "cross-site request forgery": "CWE-352",
    "csrf": "CWE-352",
    "broken access control": "CWE-284",
    "improper access control": "CWE-284",
    "authentication bypass": "CWE-287",
    "improper authentication": "CWE-287",
    "hardcoded credentials": "CWE-798",
    "hardcoded password": "CWE-798",
    "cryptographic weakness": "CWE-327",
    "weak cryptography": "CWE-327",
    "insufficient entropy": "CWE-331",
    "insecure randomness": "CWE-330",
    "xxe": "CWE-611",
    "xml external entity": "CWE-611",
    "prototype pollution": "CWE-1321",
    "denial of service": "CWE-400",
    "dos": "CWE-400",
    "resource exhaustion": "CWE-400",
    "unrestricted upload": "CWE-434",
    "file upload": "CWE-434",
    "clickjacking": "CWE-1021",
    "log injection": "CWE-117",
    "http response splitting": "CWE-113",
    "open redirect": "CWE-601",
    "mass assignment": "CWE-915",
    "insecure direct object reference": "CWE-639",
    "idor": "CWE-639",
    "security misconfiguration": "CWE-200",
    "cors misconfiguration": "CWE-942",
    "x-forwarded-for": "CWE-290",
    "host header injection": "CWE-644",
    "missing encryption": "CWE-311",
    "cleartext transmission": "CWE-319",
    "cleartext storage": "CWE-312",
    "improper input validation": "CWE-20",
    "input validation": "CWE-20",
    "unvalidated input": "CWE-20",
    "loop with unreachable exit": "CWE-835",
    "deadlock": "CWE-833",
    "memory leak": "CWE-401",
    "type confusion": "CWE-843",
    "out-of-bounds": "CWE-119",
    "buffer overflow": "CWE-119",
}

# Severity normalization
SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "moderate": "medium",
    "low": "low",
    "info": "info",
    "none": "clean",
    "clean": "clean",
    "unknown": "high",
}


def normalize_cwe(cwe: str | None) -> str | None:
    if not cwe:
        return None
    cwe = str(cwe).strip()
    if cwe in ("CWE-NVD-CWE-Other", "CWE-NVD-CWE-noinfo", "CWE-CLEAN", "CWE-000", "CWE-0"):
        return "CWE-UNKNOWN"
    if cwe.upper() == "UNKNOWN":
        return "CWE-UNKNOWN"
    if cwe.upper() == "NONE" or cwe.upper() == "NULL":
        return None
    m = re.search(r"CWE-(\d+)", cwe, re.IGNORECASE)
    if m:
        return f"CWE-{m.group(1)}"
    return cwe


def infer_cwe_from_explanation(explanation: str) -> str | None:
    """Try to extract CWE from explanation text."""
    # Direct CWE reference
    m = re.search(r"CWE-(\d+)", explanation)
    if m:
        return f"CWE-{m.group(1)}"
    # Pattern like "CWE-UNKNOWN (XSS)" or "CWE-UNKNOWN (SQL Injection)"
    m = re.search(r"CWE-UNKNOWN\s*\(([^)]+)\)", explanation, re.IGNORECASE)
    if m:
        vuln_name = m.group(1).strip().lower()
        for pattern, cwe in CWE_INFERENCE_MAP.items():
            if pattern in vuln_name:
                return cwe
    # Pattern like "**CWE-UNKNOWN (Open Redirect in PHP):**"
    m = re.search(r"\*\*CWE-UNKNOWN\s*\(([^)]+)\)\*\*", explanation)
    if m:
        vuln_name = m.group(1).strip().lower()
        for pattern, cwe in CWE_INFERENCE_MAP.items():
            if pattern in vuln_name:
                return cwe
    # Search explanation for vulnerability type keywords
    expl_lower = explanation.lower()
    # Check for CWE-79 (XSS)
    if any(p in expl_lower for p in ["cross-site", "xss", "script injection"]):
        return "CWE-79"
    # Check for CWE-89 (SQL injection)
    if any(p in expl_lower for p in ["sql injection", "sqli", "sql"]):
        return "CWE-89"
    # Check for CWE-22 (path traversal)
    if any(p in expl_lower for p in ["path traversal", "directory traversal"]):
        return "CWE-22"
    # Check for CWE-78 (command injection)
    if any(p in expl_lower for p in ["command injection", "os injection", "shell injection"]):
        return "CWE-78"
    # Check for CWE-94 (code injection)
    if any(p in expl_lower for p in ["code injection", "remote code execution", "rce"]):
        return "CWE-94"
    # Check for CWE-502 (deserialization)
    if any(p in expl_lower for p in ["deserialization", "unserialize"]):
        return "CWE-502"
    # Check for CWE-918 (SSRF)
    if any(p in expl_lower for p in ["ssrf", "server-side request forgery"]):
        return "CWE-918"
    # Check for CWE-200 (information disclosure)
    if any(p in expl_lower for p in ["information disclosure", "information exposure"]):
        return "CWE-200"
    # Check for CWE-119 (buffer overflow)
    if any(p in expl_lower for p in ["buffer overflow", "buffer overrun"]):
        return "CWE-119"
    # Check for CWE-125 (out-of-bounds read)
    if any(p in expl_lower for p in ["out-of-bounds read", "buffer over-read"]):
        return "CWE-125"
    # Check for CWE-787 (out-of-bounds write)
    if any(p in expl_lower for p in ["out-of-bounds write", "heap overflow"]):
        return "CWE-787"
    # Check for CWE-416 (use after free)
    if any(p in expl_lower for p in ["use after free", "uaf"]):
        return "CWE-416"
    # Check for CWE-362 (race condition)
    if any(p in expl_lower for p in ["race condition"]):
        return "CWE-362"
    # Check for CWE-352 (CSRF)
    if any(p in expl_lower for p in ["csrf", "cross-site request forgery"]):
        return "CWE-352"
    # Check for CWE-287 (auth bypass)
    if any(p in expl_lower for p in ["authentication bypass", "improper authentication"]):
        return "CWE-287"
    # Check for CWE-284 (access control)
    if any(p in expl_lower for p in ["access control", "authorization bypass"]):
        return "CWE-284"
    # Check for CWE-601 (open redirect)
    if any(p in expl_lower for p in ["open redirect", "url redirection"]):
        return "CWE-601"
    # Check for CWE-611 (XXE)
    if any(p in expl_lower for p in ["xxe", "xml external entity"]):
        return "CWE-611"
    # Check for CWE-400 (DoS)
    if any(p in expl_lower for p in ["denial of service", "resource exhaustion"]):
        return "CWE-400"
    # Check for CWE-1321 (prototype pollution)
    if any(p in expl_lower for p in ["prototype pollution"]):
        return "CWE-1321"
    # Check for CWE-20 (input validation)
    if any(p in expl_lower for p in ["input validation", "unvalidated input"]):
        return "CWE-20"
    # Check for CWE-190 (integer overflow)
    if any(p in expl_lower for p in ["integer overflow", "integer underflow"]):
        return "CWE-190"
    # Check for CWE-434 (file upload)
    if any(p in expl_lower for p in ["file upload", "unrestricted upload"]):
        return "CWE-434"
    return None


def fix_cwe(sample: dict) -> dict:
    """Fix CWE-UNKNOWN for vulnerable samples by parsing explanations."""
    if not sample.get("is_vulnerable", True):
        return sample
    cwe = sample.get("cwe")
    if cwe and cwe not in ("CWE-UNKNOWN", "UNKNOWN", None, ""):
        sample["cwe"] = normalize_cwe(cwe)
        return sample
    explanation = sample.get("explanation", "")
    if not explanation:
        return sample
    inferred = infer_cwe_from_explanation(explanation)
    if inferred:
        sample["cwe"] = inferred
    return sample


def fix_severity(sample: dict) -> dict:
    sev = sample.get("severity")
    if sev:
        sample["severity"] = SEVERITY_MAP.get(sev.lower(), sev)
    return sample


def compute_quality(d: dict) -> float:
    """Compute quality score 0-1 for a sample."""
    score = 0.5
    code = d.get("vulnerable_code", "") or ""
    expl = d.get("explanation", "") or ""
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
    if any(p in code for p in ("def ", "function ", "public ", "class ")):
        score += 0.05
    if any(p in code for p in ("import ", "#include", "require(", "from ")):
        score += 0.05
    return min(1.0, max(0.0, score))


def load_jsonl(path: Path) -> list[dict]:
    samples = []
    if not path.exists():
        return samples
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
                samples.append(d)
            except json.JSONDecodeError:
                continue
    return samples


def get_fingerprint(d: dict) -> str:
    fp = d.get("fingerprint", "")
    if fp:
        return fp
    import hashlib
    code = d.get("vulnerable_code", "") or ""
    return hashlib.sha1(code.encode()).hexdigest()


def load_vuln() -> list[dict]:
    """Load all vulnerable samples from enriched + extra vuln sources."""
    samples = []
    # Primary: meta_enriched
    for split in ["train", "val", "test"]:
        path = META_ENRICHED / f"{split}.jsonl"
        if not path.exists():
            continue
        loaded = load_jsonl(path)
        for s in loaded:
            if s.get("is_vulnerable", True):
                s["split"] = split
                samples.append(s)
    # Supplementary: extra_vuln
    if EXTRA_VULN_DIR.exists():
        for p in sorted(EXTRA_VULN_DIR.rglob("*.jsonl")):
            if "exploit_bench_exploits" in p.name:
                continue
            loaded = load_jsonl(p)
            for s in loaded:
                if s.get("is_vulnerable", True):
                    s["split"] = "train"
                    samples.append(s)
    return samples


def load_nonvuln() -> list[dict]:
    """Load hard negatives and clean samples."""
    samples = []
    if not NONVULN_DIR.exists():
        return samples
    for p in sorted(NONVULN_DIR.rglob("*.jsonl")):
        loaded = load_jsonl(p)
        for s in loaded:
            if not s.get("is_vulnerable", True):
                s["split"] = "train"
                samples.append(s)
    return samples


def weighted_downsample(items: list[dict], target: int, lang_weights: dict) -> list[dict]:
    """Balanced downsampling with language-weighted allocation."""
    by_lang: dict[str, list[dict]] = defaultdict(list)
    for s in items:
        lang = s.get("language", "text") or "text"
        by_lang[lang].append(s)

    hard_cap = {"c": int(target * 0.10), "cpp": int(target * 0.03)}
    total_weight = sum(lang_weights.get(lang, 1.0) for lang in by_lang) or len(by_lang)
    allocations: dict[str, int] = {}
    for lang, group in by_lang.items():
        raw = int(target * lang_weights.get(lang, 1.0) / total_weight)
        cap = hard_cap.get(lang, len(group))
        allocations[lang] = max(0, min(raw, len(group), cap))

    allocated = sum(allocations.values())
    if allocated < target:
        remaining = target - allocated
        for _ in range(remaining):
            best_lang: str | None = None
            best_ratio = float("inf")
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

    selected: list[dict] = []
    for lang in sorted(allocations):
        n_take = allocations[lang]
        group = by_lang[lang]
        group.sort(key=lambda s: -s.get("_quality", 0))
        selected.extend(group[:n_take])
    return selected


def make_user_content(s: dict) -> str:
    lang = s.get("language", "code") or "code"
    code = s.get("vulnerable_code", "") or ""
    return f"Analyze the following {lang} code for security vulnerabilities:\n\n```{lang}\n{code}\n```"


def make_assistant_content(s: dict) -> str:
    if s.get("is_vulnerable", True):
        cwe = s.get("cwe") or "CWE-UNKNOWN"
        severity = s.get("severity") or "high"
        explanation = (s.get("explanation") or "").strip() or "Vulnerability detected."
        attack = (s.get("attack_scenario") or "").strip()
        fix_text = (s.get("secure_fix") or "").strip() or "Apply standard security fixes."
        patched = s.get("patched_code") or ""

        cot_parts = [
            f"1. Vulnerability analysis: {cwe} — {explanation}",
        ]
        if attack:
            cot_parts.append(f"2. Attack scenario: {attack}")
        cot_parts.append(f"3. Severity assessment: {severity}")
        if patched:
            if len(patched) > 20:
                cot_parts.append(f"4. Code fix:\n```{s.get('language', 'code')}\n{patched}\n```")
            else:
                cot_parts.append("4. Code fix: The vulnerable code should be rewritten to address the security issue.")
        cot_parts.append(f"5. Secure fix recommendation: {fix_text}")
        cot = "\n".join(cot_parts)

        result = {
            "is_vulnerable": True,
            "vulnerability_type": cwe,
            "severity": severity,
            "explanation": explanation,
            "patched_code": patched if len(patched) > 20 else None,
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


def to_chat(s: dict) -> dict:
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


def main():
    rng = random.Random(42)

    print("=" * 60)
    print("RAKSHAKAI v2 — 500K DATASET BUILD")
    print("=" * 60)

    # 1. Load all data
    print("\n[1/8] Loading data...")
    vuln_raw = load_vuln()
    nonvuln_raw = load_nonvuln()
    print(f"  Loaded: {len(vuln_raw):,} vulnerable, {len(nonvuln_raw):,} non-vulnerable")

    # 2. Fix CWE + severity
    print("\n[2/8] Fixing CWE UNKNOWN and severity...")
    cwe_fixed_vuln = 0
    cwe_fixed_total = 0
    for s in vuln_raw:
        old_cwe = s.get("cwe")
        fix_cwe(s)
        fix_severity(s)
        if old_cwe != s.get("cwe") and old_cwe in ("CWE-UNKNOWN", "UNKNOWN", None, ""):
            cwe_fixed_vuln += 1
        cwe_fixed_total += 1
    for s in nonvuln_raw:
        if not s.get("cwe") or s["cwe"] in ("CWE-UNKNOWN", "UNKNOWN", ""):
            s["cwe"] = "CWE-CLEAN"
        fix_severity(s)
    print(f"  CWE-UNKNOWN fixed: {cwe_fixed_vuln:,} vulnerable samples")

    # 3. Global dedup
    print("\n[3/8] Global deduplication...")
    seen_fps: set[str] = set()
    deduped_vuln: list[dict] = []
    deduped_nonvuln: list[dict] = []
    for s in vuln_raw:
        fp = get_fingerprint(s)
        if fp in seen_fps:
            continue
        seen_fps.add(fp)
        deduped_vuln.append(s)
    for s in nonvuln_raw:
        fp = get_fingerprint(s)
        if fp in seen_fps:
            continue
        seen_fps.add(fp)
        deduped_nonvuln.append(s)
    print(f"  After dedup: {len(deduped_vuln):,} vuln, {len(deduped_nonvuln):,} non-vuln")

    # 4. Compute quality scores
    print("\n[4/8] Computing quality scores...")
    for s in deduped_vuln:
        s["_quality"] = compute_quality(s)
    for s in deduped_nonvuln:
        s["_quality"] = compute_quality(s)

    # 5. Balance with language weights
    print("\n[5/8] Balancing with language weights...")
    lang_weights: dict[str, float] = {}
    lw_path = CONFIGS / "language_balance.json"
    if lw_path.exists():
        cfg = json.loads(lw_path.read_text())
        lang_weights = cfg.get("language_weights", {})
    print(f"  Using language weights for {len(lang_weights)} languages")

    # Sort by quality within each language group before downsampling
    target_vuln = min(300_000, len(deduped_vuln))
    target_nonvuln = min(200_000, len(deduped_nonvuln))
    total_target = target_vuln + target_nonvuln
    print(f"  Target: {target_vuln:,} vuln + {target_nonvuln:,} non-vuln = {total_target:,}")

    vuln_balanced = weighted_downsample(deduped_vuln, target_vuln, lang_weights)
    nonvuln_balanced = weighted_downsample(deduped_nonvuln, target_nonvuln, lang_weights)

    all_balanced = vuln_balanced + nonvuln_balanced
    lang_dist = Counter(s.get("language", "?") or "?" for s in all_balanced)
    print(f"\n  Language distribution:")
    for lang, cnt in sorted(lang_dist.items(), key=lambda x: -x[1]):
        print(f"    {lang:<12} {cnt:>6,} ({100*cnt/len(all_balanced):.1f}%)")

    # 6. Train/Val/Test split
    print("\n[6/8] Train/Val/Test split...")
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
        print(f"  {name}: {len(items):,}")

    # 7. Write meta
    print("\n[7/8] Writing outputs...")
    OUT_META.mkdir(parents=True, exist_ok=True)
    for split_name, split_samples in splits.items():
        path = OUT_META / f"{split_name}.jsonl"
        with open(path, "w") as f:
            for s in split_samples:
                d = {k: v for k, v in s.items() if not k.startswith("_")}
                f.write(json.dumps(d, ensure_ascii=False) + "\n")
        print(f"  meta/{split_name}: {len(split_samples):,}")

    # 8. Build instruct + axolotl formats
    OUT_INSTRUCT.mkdir(parents=True, exist_ok=True)
    OUT_AXOLOTL.mkdir(parents=True, exist_ok=True)

    for split_name, split_samples in splits.items():
        instruct_path = OUT_INSTRUCT / f"{split_name}.jsonl"
        axolotl_path = OUT_AXOLOTL / f"{split_name}.jsonl"
        with open(instruct_path, "w") as fi, open(axolotl_path, "w") as fa:
            for s in split_samples:
                chat = to_chat(s)
                line = json.dumps(chat, ensure_ascii=False) + "\n"
                fi.write(line)
                fa.write(line)
        print(f"  instruct/{split_name}: {len(split_samples):,}")
        print(f"  axolotl/{split_name}: {len(split_samples):,}")

    # Combined all
    all_instruct = OUT_INSTRUCT / "all.jsonl"
    all_axolotl = OUT_AXOLOTL / "all.jsonl"
    with open(all_instruct, "w") as fi, open(all_axolotl, "w") as fa:
        for s in all_balanced:
            chat = to_chat(s)
            line = json.dumps(chat, ensure_ascii=False) + "\n"
            fi.write(line)
            fa.write(line)
    print(f"  instruct/all: {len(all_balanced):,}")
    print(f"  axolotl/all: {len(all_balanced):,}")

    # 9. Summary
    print("\n" + "=" * 60)
    print("FINAL DATASET SUMMARY")
    print("=" * 60)
    vuln_count = sum(1 for s in all_balanced if s.get("is_vulnerable", True))
    clean_count = len(all_balanced) - vuln_count
    patch_count = sum(1 for s in all_balanced if s.get("is_vulnerable", True) and s.get("patched_code") and len(s.get("patched_code", "")) > 20)
    expl_count = sum(1 for s in all_balanced if len(s.get("explanation", "") or "") > 50)
    c_count = lang_dist.get("c", 0) + lang_dist.get("cpp", 0)
    c_pct = 100 * c_count / len(all_balanced) if all_balanced else 0
    unknown_cwe = sum(1 for s in all_balanced if s.get("is_vulnerable", True) and s.get("cwe") in ("CWE-UNKNOWN", "UNKNOWN", None, ""))
    cwe_set = set()
    for s in all_balanced:
        c = s.get("cwe")
        if c and c not in ("CWE-UNKNOWN", "CWE-CLEAN", "CWE-NVD-CWE-Other", "CWE-NVD-CWE-noinfo", None, ""):
            cwe_set.add(c)

    print(f"  Total samples:      {len(all_balanced):,}")
    print(f"  Vulnerable:         {vuln_count:,} ({100*vuln_count/len(all_balanced):.1f}%)")
    print(f"  Non-vulnerable:     {clean_count:,} ({100*clean_count/len(all_balanced):.1f}%)")
    print(f"  With patches:       {patch_count:,} ({100*patch_count/max(vuln_count,1):.1f}% of vuln)")
    print(f"  With explanations:  {expl_count:,} ({100*expl_count/len(all_balanced):.1f}%)")
    print(f"  C/C++ dominance:    {c_count:,} ({c_pct:.1f}%)")
    print(f"  UNKNOWN CWEs:       {unknown_cwe:,} ({100*unknown_cwe/max(vuln_count,1):.1f}% of vuln)")
    print(f"  Unique CWEs:        {len(cwe_set)}")
    print(f"  Languages:          {len(lang_dist)}")

    summary = {
        "total": len(all_balanced),
        "vulnerable": vuln_count,
        "non_vulnerable": clean_count,
        "patch_count": patch_count,
        "patch_pct_vuln": round(100 * patch_count / max(vuln_count, 1), 1),
        "explanation_count": expl_count,
        "explanation_pct": round(100 * expl_count / len(all_balanced), 1),
        "unknown_cwe_vuln": unknown_cwe,
        "unknown_cwe_pct_vuln": round(100 * unknown_cwe / max(vuln_count, 1), 1),
        "c_dominance_pct": round(c_pct, 1),
        "unique_cwes": len(cwe_set),
        "unique_languages": len(lang_dist),
        "language_distribution": dict(lang_dist.most_common(20)),
    }
    summary_path = OUT_DIR / "final_summary.json"
    summary_path.write_text(json.dumps(summary, indent=2))
    print(f"\n  Summary saved to {summary_path}")

    # Also write 250K variant for comparison
    print("\n  All done! Ready for training.")


if __name__ == "__main__":
    main()
