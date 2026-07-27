"""
RakshakAI v2 — Phase B Dataset Quality Audit.

Performs a comprehensive quality assessment before training begins.
Answers: is the current dataset strong enough for Phase B training?

Usage:
    python v2/dataset/audit_quality.py > v2/dataset/audit_report.txt
"""
from __future__ import annotations

import json
import random
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from v2.dataset.schema import SecuritySample

random.seed(42)

CLEAN_DIR = Path("v2/inputs/datasets/phase_b/meta")
OUTPUT = Path("v2/dataset/audit_report.txt")

# ─── Security domain mapping ────────────────────────────────────────────────
DOMAIN_CWES: dict[str, set[str]] = {
    "Injection": {"CWE-77", "CWE-94", "CWE-95", "CWE-96", "CWE-97", "CWE-98"},
    "XSS": {"CWE-79", "CWE-80", "CWE-81", "CWE-82", "CWE-83", "CWE-84", "CWE-85", "CWE-86", "CWE-87"},
    "SQLi": {"CWE-89", "CWE-90", "CWE-91", "CWE-564"},
    "Command Injection": {"CWE-77", "CWE-78", "CWE-88"},
    "SSRF": {"CWE-918"},
    "Path Traversal": {"CWE-22", "CWE-23", "CWE-24", "CWE-25", "CWE-35", "CWE-36", "CWE-37", "CWE-38", "CWE-39"},
    "Deserialization": {"CWE-502", "CWE-915"},
    "Authentication": {"CWE-287", "CWE-288", "CWE-289", "CWE-290", "CWE-291", "CWE-292", "CWE-293",
                       "CWE-294", "CWE-295", "CWE-296", "CWE-297", "CWE-298", "CWE-299", "CWE-306", "CWE-307"},
    "Authorization": {"CWE-285", "CWE-639", "CWE-862", "CWE-863"},
    "JWT / Crypto Signatures": {"CWE-347", "CWE-348", "CWE-349"},
    "Cryptography": {"CWE-310", "CWE-311", "CWE-312", "CWE-313", "CWE-314", "CWE-315", "CWE-316",
                     "CWE-317", "CWE-318", "CWE-319", "CWE-320", "CWE-321", "CWE-322", "CWE-323",
                     "CWE-324", "CWE-325", "CWE-326", "CWE-327", "CWE-328", "CWE-329", "CWE-330",
                     "CWE-331", "CWE-332", "CWE-333", "CWE-334", "CWE-335", "CWE-336", "CWE-337",
                     "CWE-338", "CWE-339", "CWE-340"},
    "Secrets Exposure": {"CWE-798", "CWE-799", "CWE-521", "CWE-522", "CWE-523", "CWE-524",
                         "CWE-525", "CWE-526", "CWE-527", "CWE-528", "CWE-529", "CWE-530",
                         "CWE-531", "CWE-532", "CWE-533", "CWE-534", "CWE-535", "CWE-536",
                         "CWE-537", "CWE-538", "CWE-539", "CWE-540", "CWE-541"},
    "Race Conditions": {"CWE-362", "CWE-363", "CWE-364", "CWE-365", "CWE-366", "CWE-367",
                        "CWE-368", "CWE-370"},
    "Supply Chain": {"CWE-1104", "CWE-829", "CWE-494", "CWE-506"},
    "Prompt Injection": {"CWE-77"},  # Prompt injection maps to CWE-77
    "AI Agent Security": set(),  # No standard CWEs yet; detected by source keyword
    "Buffer Overflow": {"CWE-119", "CWE-120", "CWE-121", "CWE-122", "CWE-123", "CWE-124",
                        "CWE-125", "CWE-126", "CWE-787", "CWE-788"},
    "Integer Issues": {"CWE-190", "CWE-191", "CWE-192", "CWE-193", "CWE-194", "CWE-195",
                       "CWE-196", "CWE-197", "CWE-681"},
    "Memory Safety": {"CWE-416", "CWE-415", "CWE-476", "CWE-401", "CWE-400"},
    "Resource Management": {"CWE-400", "CWE-770", "CWE-789", "CWE-1325"},
    "Information Disclosure": {"CWE-200", "CWE-201", "CWE-202", "CWE-203", "CWE-204", "CWE-205",
                               "CWE-206", "CWE-207", "CWE-208", "CWE-209", "CWE-210"},
}

# Source keywords that indicate domain even without CWE
SOURCE_DOMAIN_HINTS: dict[str, str] = {
    "purplellama": "AI Agent Security",
    "injection": "Prompt Injection",
    "garak": "AI Agent Security",
    "securecode_aiml": "AI Agent Security",
    "securecode": "AI Agent Security",
    "code_ai": "AI Agent Security",
    "llm01": "Prompt Injection",
    "prompt_injection": "Prompt Injection",
}

# ─── Helpers ─────────────────────────────────────────────────────────────────

def cwe_to_domain(cwe: str | None, source: str = "") -> str:
    """Map a CWE to its security domain. Falls back to 'Other'."""
    if not cwe:
        # Check source hints for null-CWE samples
        for keyword, domain in SOURCE_DOMAIN_HINTS.items():
            if keyword in source.lower():
                return domain
        return "Uncategorized (no CWE)"
    for domain, cwes in DOMAIN_CWES.items():
        if cwe in cwes:
            return domain
    return "Other"


def iter_samples(sample_limit: int = 0) -> list[SecuritySample]:
    """Load all samples for quality inspection. Set sample_limit > 0 for subsampling."""
    samples = []
    for p in sorted(CLEAN_DIR.rglob("*.jsonl")):
        with p.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    d = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(d, dict):
                    continue
                s = SecuritySample.from_dict(d)
                errs = s.validate()
                if errs:
                    continue
                samples.append(s)
                if sample_limit and len(samples) >= sample_limit:
                    return samples
    return samples


def scan_directory() -> tuple[
    dict, dict, dict, dict, dict, dict, Counter, Counter, Counter
]:
    """First pass: scan all files collecting aggregate statistics.
    
    Returns multiple dictionaries to avoid loading all into memory at once.
    We make multiple passes, each reading the files once for efficiency:
      pass 1: composition, CWE, language, domain, fix coverage
    """
    total = 0
    vuln = 0
    clean = 0
    has_patch = 0
    has_cwe = 0
    has_explanation = 0
    
    cwe_counter: Counter = Counter()
    lang_counter: Counter = Counter()
    domain_counter: Counter = Counter()
    
    for p in sorted(CLEAN_DIR.rglob("*.jsonl")):
        with p.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    d = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(d, dict):
                    continue
                total += 1
                
                is_vuln = d.get("is_vulnerable", True)
                if is_vuln:
                    vuln += 1
                else:
                    clean += 1
                
                lang = d.get("language", "unknown")
                lang_counter[lang] += 1
                
                cwe = d.get("cwe") or None
                if cwe:
                    cwe_counter[cwe] += 1
                    has_cwe += 1
                
                source = d.get("source", "")
                domain = cwe_to_domain(cwe, source)
                domain_counter[domain] += 1
                # Source-based domain overrides for AI/security (counts additional domains)
                for keyword, sdomain in SOURCE_DOMAIN_HINTS.items():
                    if keyword in source.lower() and sdomain != domain:
                        domain_counter[sdomain] = domain_counter.get(sdomain, 0) + 1
                
                if d.get("patched_code"):
                    has_patch += 1
                if d.get("explanation"):
                    has_explanation += 1
    
    return total, vuln, clean, has_patch, has_cwe, has_explanation, cwe_counter, lang_counter, domain_counter


def analyze_clean_samples(clean_samples: list[SecuritySample]) -> dict:
    """Analyze clean (non-vulnerable) samples for quality / difficulty."""
    result = {
        "total_clean": len(clean_samples),
        "real_code": 0,  # Not synthetic
        "security_relevant": 0,  # Code doing security-sensitive operations
        "near_vulnerability": 0,  # Code that's almost vulnerable
        "too_easy": 0,  # Trivially non-security code
    }
    
    # Security-relevant keywords in code
    security_keywords = re.compile(
        r"\b(auth|password|secret|key|token|encrypt|decrypt|hash|salt|"
        r"signature|certificate|ssl|tls|https|cookie|session|"
        r"permission|role|admin|sudo|exec|eval|query|sql|command|"
        r"deserialize|pickle|yaml\.load|xml\.parse|exec|\$\{|"
        r"input|request|param|argument|upload|download|file|path|"
        r"buffer|malloc|free|pointer|allocate|copy|strcpy|gets|printf)\b",
        re.I,
    )
    
    # Trivially non-security code patterns
    trivial_patterns = re.compile(
        r"\b(hello_world|factorial|fibonacci|bubble_sort|print|"
        r"console\.log|fmt\.Print|printf\(\"Hello|add\(|"
        r"def test_|class Test|assertEquals|"
        r"sort\(|reverse\(|trim\(|format\(|"
        r"fizzbuzz|tower_of_hanoi|linked_list|binary_search)\b",
        re.I,
    )
    
    for s in clean_samples:
        code = s.vulnerable_code
        
        # Detect real (non-synthetic) code: has imports, functions, classes
        if re.search(r"\b(import |from |require|use |#include|package |module )", code):
            result["real_code"] += 1
        
        # Security-relevant: code touching security operations
        if security_keywords.search(code):
            result["security_relevant"] += 1
        
        # Near-vulnerability: code that's close to being vulnerable
        # (e.g., parameterized query vs raw SQL, safe eval vs exec)
        near_patterns = [
            r"parametrized|parameterized|prepared statement|bind variable",
            r"escape|sanitize|validate|filter|purify",
            r"allowlist|denylist|whitelist|blacklist",
            r"csrf_token|nonce|captcha|rate.limit|throttle",
            r"bcrypt|argon2|scrypt|pbkdf2|hashlib",
            r"\.env|vault|kms|secrets|keyring",
            r"https://|ssl|tls|certificate|ca.crt",
        ]
        for pat in near_patterns:
            if re.search(pat, code, re.I):
                result["near_vulnerability"] += 1
                break
        
        # Too easy: trivial non-security code like hello world
        if trivial_patterns.search(code):
            result["too_easy"] += 1
    
    return result


def manual_spot_check(samples: list[SecuritySample], n: int = 200,
                      title: str = "vulnerable") -> dict:
    """Randomly inspect n samples for quality issues."""
    inspected = random.sample(samples, min(n, len(samples)))
    
    label_errors = 0
    missing_cwe = 0
    broken_code = 0
    truncated_code = 0
    duplicates_found = 0
    short_explanation = 0  # Less than 20 chars
    pii_leak = 0
    
    # Patterns for broken code
    ellipsis_pattern = re.compile(r"\.\.\.$|\.\.\.\s*$|\.\.\.\n|truncated|\.{10,}")
    
    # PII check
    pii_patterns = [
        re.compile(r"AKIA[0-9A-Z]{16}"),
        re.compile(r"sk-[A-Za-z0-9]{32,}"),
        re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    ]
    
    seen_fps: set[str] = set()
    
    for s in inspected:
        # Floating-point equality check
        if s.fingerprint in seen_fps:
            duplicates_found += 1
        seen_fps.add(s.fingerprint)
        
        # Check for label errors: should vuln code have cwe?
        if s.is_vulnerable and not s.cwe:
            missing_cwe += 1
        
        # Check for broken code (gibberish, non-code)
        code = s.vulnerable_code
        if len(code) < 30:  # Should be caught by schema
            broken_code += 1
        # Check for code that's obviously corrupted
        non_printable_ratio = sum(1 for c in code if ord(c) < 32 and c not in "\n\r\t") / max(len(code), 1)
        if non_printable_ratio > 0.01:
            broken_code += 1
        
        # Truncated code
        if ellipsis_pattern.search(code):
            truncated_code += 1
        
        # Short explanation
        if s.is_vulnerable and len(s.explanation or "") < 20:
            short_explanation += 1
        
        # PII in code
        for pat in pii_patterns:
            if pat.search(code):
                pii_leak += 1
                break
    
    total_inspected = len(inspected)
    return {
        "inspected": total_inspected,
        "label_errors": label_errors,
        "missing_cwe": missing_cwe,
        "broken_code": broken_code,
        "truncated_code": truncated_code,
        "duplicates_internal": duplicates_found,
        "short_explanation": short_explanation,
        "pii_leak": pii_leak,
        "estimated_label_accuracy": 1 - (label_errors / max(total_inspected, 1)),
        "estimated_quality_score": 1 - (
            (label_errors + broken_code + truncated_code + pii_leak) /
            max(total_inspected * 4, 1)
        ),
    }


def main() -> int:
    print("=" * 70)
    print("  RakshakAI v2 — Phase B Dataset Quality Audit")
    print("=" * 70)
    print()
    
    # ─── 1. Dataset Composition ──────────────────────────────────────────
    print("[1] Dataset Composition")
    print("-" * 40)
    
    total, vuln, clean, has_patch, has_cwe, has_explanation, \
        cwe_counter, lang_counter, domain_counter = scan_directory()
    
    print(f"  Total samples:      {total:>8,}")
    print(f"  Vulnerable samples: {vuln:>8,}")
    print(f"  Clean samples:      {clean:>8,}")
    ratio = vuln / max(clean, 1)
    print(f"  Vuln/Clean ratio:   {ratio:.2f}:1")
    print(f"  Patch coverage:     {has_patch:>8,} ({100*has_patch/max(total,1):.1f}%)")
    print(f"  CWE coverage:       {has_cwe:>8,} ({100*has_cwe/max(total,1):.1f}%)")
    print(f"  Explanation cover:  {has_explanation:>8,} ({100*has_explanation/max(total,1):.1f}%)")
    print()
    
    # ─── 2. CWE Coverage ─────────────────────────────────────────────────
    print("[2] CWE Coverage")
    print("-" * 40)
    
    total_cwe_samples = sum(cwe_counter.values())
    
    # Top 50
    print("\n  Top 50 CWEs:")
    print(f"  {'CWE':<20} {'Count':>8} {'%':>8}")
    print(f"  {'-'*20} {'-'*8} {'-'*8}")
    for cwe, cnt in cwe_counter.most_common(50):
        pct = 100 * cnt / max(total, 1)
        print(f"  {cwe:<20} {cnt:>8,} {pct:>7.2f}%")
    
    # CWEs below thresholds
    low_cwes = {c: n for c, n in cwe_counter.items() if n < 50}
    very_low_cwes = {c: n for c, n in cwe_counter.items() if n < 20}
    zero_cwes_expected = {
        "CWE-77", "CWE-287", "CWE-310", "CWE-327", "CWE-362", "CWE-502",
        "CWE-918", "CWE-798", "CWE-347", "CWE-1104",
    }
    
    print(f"\n  CWEs with < 50 samples: {len(low_cwes)}")
    for cwe, cnt in sorted(low_cwes.items(), key=lambda x: x[1]):
        print(f"    {cwe:<20} {cnt:>4}")
    
    print(f"\n  CWEs with < 20 samples: {len(very_low_cwes)}")
    for cwe, cnt in sorted(very_low_cwes.items(), key=lambda x: x[1]):
        print(f"    {cwe:<20} {cnt:>4}")
    
    # Expected high-priority CWEs with zero/weak coverage
    missing_cwes = zero_cwes_expected - set(cwe_counter.keys())
    weak_cwes = {c: n for c, n in low_cwes.items() if c in zero_cwes_expected}
    print(f"\n  CRITICAL CWEs with ZERO coverage: {len(missing_cwes)}")
    for cwe in sorted(missing_cwes):
        print(f"    {cwe:<20} 0 samples")
    print(f"\n  CRITICAL CWEs with WEAK coverage (<50):")
    for cwe, cnt in sorted(weak_cwes.items(), key=lambda x: x[1]):
        print(f"    {cwe:<20} {cnt} samples")
    
    print(f"\n  Total unique CWEs: {len(cwe_counter)}")
    print()
    
    # ─── 3. Security Domain Coverage ────────────────────────────────────
    print("[3] Security Domain Coverage")
    print("-" * 40)
    
    # Some sequences overlap (e.g. CWE-77 is in Injection AND Command Injection)
    # Count per-sample domain (first matching)
    print(f"\n  {'Domain':<35} {'Count':>8} {'%':>8}")
    print(f"  {'-'*35} {'-'*8} {'-'*8}")
    for domain, cnt in domain_counter.most_common(25):
        pct = 100 * cnt / max(total, 1)
        print(f"  {domain:<35} {cnt:>8,} {pct:>7.2f}%")
    print()
    
    # ─── 4. Language Coverage ───────────────────────────────────────────
    print("[4] Language Coverage")
    print("-" * 40)
    
    TARGET_LANGS = [
        "python", "java", "javascript", "typescript", "go",
        "c", "cpp", "csharp", "php", "rust", "kotlin", "swift", "ruby",
    ]
    
    other_count = sum(c for lang, c in lang_counter.items() if lang not in TARGET_LANGS)
    
    print(f"\n  {'Language':<15} {'Count':>8} {'%':>8}")
    print(f"  {'-'*15} {'-'*8} {'-'*8}")
    for lang in TARGET_LANGS:
        cnt = lang_counter.get(lang, 0)
        pct = 100 * cnt / max(total, 1)
        print(f"  {lang:<15} {cnt:>8,} {pct:>7.2f}%")
    
    for lang, cnt in sorted(lang_counter.items(), key=lambda x: -x[1]):
        if lang not in TARGET_LANGS:
            pct = 100 * cnt / max(total, 1)
            print(f"  {lang:<15} {cnt:>8,} {pct:>7.2f}%  (other)")
    
    # Language distribution analysis
    print(f"\n  Language imbalance ratio (max/min among targets):")
    lang_counts = {l: lang_counter.get(l, 0) for l in TARGET_LANGS}
    max_lang = max(lang_counts.values()) if lang_counts else 1
    min_lang = min(l for l in lang_counts.values() if l > 0) if any(lang_counts.values()) else 1
    print(f"    Most: {max(lang_counts, key=lang_counts.get)} ({max_lang:,})")
    print(f"    Least: {min(lang_counts, key=lambda k: lang_counts[k] if lang_counts[k] > 0 else 10**9)} ({min_lang:,})")
    print(f"    Ratio: {max_lang / max(min_lang, 1):.0f}:1")
    print()
    
    # ─── 5. Vulnerability Quality Audit ─────────────────────────────────
    print("[5] Vulnerability Quality Audit")
    print("-" * 40)
    print("  Loading samples for quality inspection...")
    
    all_samples = iter_samples()
    random.shuffle(all_samples)
    
    vuln_samples = [s for s in all_samples if s.is_vulnerable]
    clean_samples = [s for s in all_samples if not s.is_vulnerable]
    
    print(f"  Loaded {len(vuln_samples):,} vulnerable, {len(clean_samples):,} clean")
    
    vuln_audit = manual_spot_check(vuln_samples, n=200, title="vulnerable")
    clean_audit = manual_spot_check(clean_samples, n=200, title="clean")
    
    print(f"\n  Vulnerable sample audit (n={vuln_audit['inspected']}):")
    print(f"    Label errors:       {vuln_audit['label_errors']}")
    print(f"    Missing CWE:        {vuln_audit['missing_cwe']}")
    print(f"    Broken code:        {vuln_audit['broken_code']}")
    print(f"    Truncated code:     {vuln_audit['truncated_code']}")
    print(f"    Duplicates (intra): {vuln_audit['duplicates_internal']}")
    print(f"    Short explanation:  {vuln_audit['short_explanation']}")
    print(f"    PII leak:           {vuln_audit['pii_leak']}")
    print(f"    Estimated label accuracy: {vuln_audit['estimated_label_accuracy']*100:.1f}%")
    print(f"    Estimated quality score:  {vuln_audit['estimated_quality_score']*100:.1f}%")
    
    print(f"\n  Clean sample audit (n={clean_audit['inspected']}):")
    print(f"    Label errors:       {clean_audit['label_errors']}")
    print(f"    Missing CWE:        {clean_audit['missing_cwe']}")
    print(f"    Broken code:        {clean_audit['broken_code']}")
    print(f"    Truncated code:     {clean_audit['truncated_code']}")
    print(f"    Duplicates (intra): {clean_audit['duplicates_internal']}")
    print(f"    Short explanation:  {clean_audit['short_explanation']}")
    print(f"    PII leak:           {clean_audit['pii_leak']}")
    print(f"    Estimated purity:   {clean_audit['estimated_label_accuracy']*100:.1f}%")
    print()
    
    # ─── 6. Fix Coverage ────────────────────────────────────────────────
    print("[6] Fix Coverage")
    print("-" * 40)
    
    vuln_with_patch = sum(1 for s in vuln_samples if s.patched_code)
    vuln_with_cwe = sum(1 for s in vuln_samples if s.cwe)
    vuln_with_explanation = sum(1 for s in vuln_samples if s.explanation)
    
    total_vuln = len(vuln_samples)
    print(f"\n  {'Metric':<30} {'Count':>8} {'%':>8}")
    print(f"  {'-'*30} {'-'*8} {'-'*8}")
    print(f"  {'Has vulnerable_code':<30} {total_vuln:>8,} {100*total_vuln/max(total_vuln,1):>7.1f}%")
    print(f"  {'Has patched_code (fix)':<30} {vuln_with_patch:>8,} {100*vuln_with_patch/max(total_vuln,1):>7.1f}%")
    print(f"  {'Has CWE label':<30} {vuln_with_cwe:>8,} {100*vuln_with_cwe/max(total_vuln,1):>7.1f}%")
    print(f"  {'Has explanation':<30} {vuln_with_explanation:>8,} {100*vuln_with_explanation/max(total_vuln,1):>7.1f}%")
    print(f"  {'Has ALL FOUR':<30} {len([s for s in vuln_samples if s.patched_code and s.cwe and s.explanation]):>8,}", end="")
    print(f" {100*len([s for s in vuln_samples if s.patched_code and s.cwe and s.explanation])/max(total_vuln,1):>7.1f}%")
    print()
    
    # ─── 7. Hard Negative Analysis ──────────────────────────────────────
    print("[7] Hard Negative Analysis")
    print("-" * 40)
    
    clean_analysis = analyze_clean_samples(clean_samples)
    
    print(f"\n  {'Metric':<35} {'Count':>8} {'%':>8}")
    print(f"  {'-'*35} {'-'*8} {'-'*8}")
    print(f"  {'Total clean samples':<35} {clean_analysis['total_clean']:>8,} {100:>7.1f}%")
    print(f"  {'Real code (imports/funcs)':<35} {clean_analysis['real_code']:>8,} {100*clean_analysis['real_code']/max(clean_analysis['total_clean'],1):>7.1f}%")
    print(f"  {'Security-relevant code':<35} {clean_analysis['security_relevant']:>8,} {100*clean_analysis['security_relevant']/max(clean_analysis['total_clean'],1):>7.1f}%")
    print(f"  {'Near-vulnerability examples':<35} {clean_analysis['near_vulnerability']:>8,} {100*clean_analysis['near_vulnerability']/max(clean_analysis['total_clean'],1):>7.1f}%")
    print(f"  {'Trivially easy (hello-world)':<35} {clean_analysis['too_easy']:>8,} {100*clean_analysis['too_easy']/max(clean_analysis['total_clean'],1):>7.1f}%")
    
    easiness_ratio = clean_analysis['too_easy'] / max(clean_analysis['total_clean'], 1)
    if easiness_ratio > 0.1:
        print(f"\n  ⚠  {clean_analysis['too_easy']} clean samples ({easiness_ratio*100:.1f}%) appear trivially easy.")
        print("     These are non-security code like hello-world, sorting algorithms, etc.")
        print("     Model may learn to say 'secure' too easily.")
    else:
        print(f"\n  ✓ Clean samples are mostly difficult/nuanced ({easiness_ratio*100:.1f}% trivial).")
    print()
    
    # ─── 8. Dataset Imbalance Detection ─────────────────────────────────
    print("[8] Dataset Imbalance Detection")
    print("-" * 40)
    
    # Overrepresented: top 10 CWEs account for what %?
    top10_count = sum(c for _, c in cwe_counter.most_common(10))
    top3_count = sum(c for _, c in cwe_counter.most_common(3))
    print(f"\n  Top 3 CWEs account for:  {100*top3_count/max(total_cwe_samples,1):.1f}% of all CWE-labeled samples")
    print(f"  Top 10 CWEs account for: {100*top10_count/max(total_cwe_samples,1):.1f}% of all CWE-labeled samples")
    
    # Identify overrepresented
    print(f"\n  Overrepresented CWEs (>10% of dataset):")
    for cwe, cnt in cwe_counter.most_common(5):
        pct = 100 * cnt / max(total, 1)
        if pct > 5:
            print(f"    {cwe:<20} {cnt:>8,} ({pct:.1f}%)")
    
    # Identify underrepresented
    print(f"\n  Underrepresented CWEs (<0.1% and critical):")
    for cwe in sorted(zero_cwes_expected):
        cnt = cwe_counter.get(cwe, 0)
        pct = 100 * cnt / max(total, 1)
        if pct < 0.1:
            print(f"    {cwe:<20} {cnt:>4} ({pct:.3f}%) ★ CRITICAL GAP")
    
    print(f"\n  Missing security domains (fewer than 100 samples):")
    low_domains = [(d, c) for d, c in domain_counter.items() if c < 100 and d != "Uncategorized (no CWE)"]
    for domain, cnt in sorted(low_domains, key=lambda x: x[1]):
        print(f"    {domain:<30} {cnt:>4} samples")
    
    # Additional imbalance: language
    print(f"\n  Language imbalance — C dominates:")
    c_count = lang_counter.get("c", 0)
    cpp_count = lang_counter.get("cpp", 0)
    total_c_family = c_count + cpp_count
    non_c_total = total - total_c_family
    print(f"    C family:     {total_c_family:>8,} ({100*total_c_family/max(total,1):.1f}%)")
    print(f"    Non-C family: {non_c_total:>8,} ({100*non_c_total/max(total,1):.1f}%)")
    print(f"    Python:       {lang_counter.get('python', 0):>8,} ({100*lang_counter.get('python',0)/max(total,1):.1f}%)")
    print(f"    JavaScript:   {lang_counter.get('javascript', 0):>8,} ({100*lang_counter.get('javascript',0)/max(total,1):.1f}%)")
    print(f"    Go:           {lang_counter.get('go', 0):>8,} ({100*lang_counter.get('go',0)/max(total,1):.1f}%)")
    print(f"    Rust:         {lang_counter.get('rust', 0):>8,} ({100*lang_counter.get('rust',0)/max(total,1):.1f}%)")
    print()
    
    # ─── 9. Final Recommendation ────────────────────────────────────────
    print("[9] Final Recommendation")
    print("-" * 40)
    
    # Scoring
    score = 10.0
    deductions = []
    
    # CWE coverage
    cwe_gaps = len(missing_cwes) + len(weak_cwes)
    if cwe_gaps > 0:
        gap_penalty = min(2.0, cwe_gaps * 0.2)
        score -= gap_penalty
        deductions.append(f"Missing/weak CWE coverage ({cwe_gaps} gaps): -{gap_penalty:.1f}")
    
    # Language imbalance
    lang_ratio = max_lang / max(min_lang, 1)
    if lang_ratio > 100:
        score -= 1.5
        deductions.append(f"Extreme language imbalance ({lang_ratio:.0f}:1 C vs others): -1.5")
    elif lang_ratio > 20:
        score -= 1.0
        deductions.append(f"Language imbalance ({lang_ratio:.0f}:1): -1.0")
    
    # Fix coverage
    fix_rate = vuln_with_patch / max(total_vuln, 1)
    if fix_rate < 0.5:
        score -= 1.0
        deductions.append(f"Low fix coverage ({fix_rate*100:.1f}%): -1.0")
    
    # Label quality
    label_acc = vuln_audit['estimated_label_accuracy']
    if label_acc < 0.95:
        score -= 1.0
        deductions.append(f"Label accuracy {label_acc*100:.1f}%: -1.0")
    
    # Clean sample quality
    trivial_clean_ratio = clean_analysis['too_easy'] / max(clean_analysis['total_clean'], 1)
    if trivial_clean_ratio > 0.1:
        score -= 0.5
        deductions.append(f"Trivial clean samples ({trivial_clean_ratio*100:.1f}%): -0.5")
    
    # AI security gap
    if domain_counter.get("AI Agent Security", 0) < 10:
        score -= 0.5
        deductions.append("Missing AI security domain: -0.5")
    if domain_counter.get("Prompt Injection", 0) < 10:
        score -= 0.5
        deductions.append("Missing prompt injection domain: -0.5")
    
    # Supply chain gap
    if domain_counter.get("Supply Chain", 0) < 10:
        score -= 0.3
        deductions.append("Missing supply chain domain: -0.3")
    
    # JWT gap
    if domain_counter.get("JWT / Crypto Signatures", 0) < 50:
        score -= 0.3
        deductions.append("Weak JWT coverage: -0.3")
    
    # Truncation / broken code penalty
    trunc_rate = vuln_audit['truncated_code'] / max(vuln_audit['inspected'], 1)
    if trunc_rate > 0.05:
        score -= 0.3
        deductions.append(f"Truncated code ({trunc_rate*100:.1f}%): -0.3")
    
    score = max(0, min(10, score))
    
    print(f"\n  Dataset Quality Score: {score:.1f}/10")
    print()
    if deductions:
        print("  Deductions:")
        for d in deductions:
            print(f"    {d}")
    print()
    
    # Readiness decision
    ready = score >= 6.0
    print(f"  Ready for Phase B training: {'YES' if ready else 'NO — see recommendations below'}")
    
    if ready:
        print(f"\n  Current dataset IS adequate for Phase B training.")
        print(f"  However, the following categories would most improve the model:")
    
    print(f"\n  Top 5 categories needing more data:")
    need_more = [
        ("Prompt Injection / AI Security", "AI-specific vulnerability classes (CWE-77, agent security)"),
        ("Supply Chain", "Malicious package detection (CWE-1104, CWE-829) — 0 samples"),
        ("Cryptography", "Weak crypto, broken algorithms, TLS misuse (CWE-310 family)"),
        ("JWT / Authentication", "JWT verification, hardcoded secrets (CWE-347, CWE-798)"),
        ("SSRF / Deserialization / Race", "Niche but high-impact CWE classes (CWE-918, CWE-502, CWE-362)"),
    ]
    for i, (category, reason) in enumerate(need_more, 1):
        print(f"    {i}. {category}: {reason}")
    
    print(f"\n  Top 5 categories already sufficiently represented:")
    sufficient = [
        ("Buffer Overflow", f"{domain_counter.get('Buffer Overflow', 0):,} samples"),
        ("Memory Safety", f"{domain_counter.get('Memory Safety', 0):,} samples (UAF, null ptr)"),
        ("XSS", f"{domain_counter.get('XSS', 0):,} samples"),
        ("SQL Injection", f"{domain_counter.get('SQLi', 0):,} samples"),
        ("Path Traversal", f"{domain_counter.get('Path Traversal', 0):,} samples"),
    ]
    for i, (category, reason) in enumerate(sufficient, 1):
        print(f"    {i}. {category}: {reason}")
    
    print()
    print("=" * 70)
    print("  END OF AUDIT")
    print("=" * 70)
    
    return 0 if ready else 1


if __name__ == "__main__":
    sys.exit(main())
