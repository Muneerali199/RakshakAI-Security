"""
RakshakAI v2 — Extract hard negative samples.

Hard negatives are crucial for teaching the model precision (reduce false positives).
These are code samples that LOOK suspicious but are actually secure.

Sources:
1. Patched versions of vulnerable code (apply fix → clean code)
2. OWASP Benchmark false positive cases
3. Juliet Test Suite "GOOD" variants
4. Code near vulnerabilities but not vulnerable (same file, different function)
5. SAST tool false positives from real repositories

Output: v2/inputs/datasets/nonvuln/hard_negatives.jsonl
"""
from __future__ import annotations

import hashlib
import json
import random
import re
import subprocess
import sys
from collections import defaultdict
from pathlib import Path
from typing import Iterator

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from v2.dataset.schema import SecuritySample, write_jsonl  # noqa: E402

random.seed(42)

# Paths
CLEAN_DIR = Path("v2/inputs/datasets/clean")
OUT_DIR = Path("v2/inputs/datasets/nonvuln")
OWASP_DIR = Path("v2/inputs/datasets/raw/owasp-benchmark")
JULIET_DIR = Path("v2/inputs/datasets/raw/juliet")

OUT_DIR.mkdir(parents=True, exist_ok=True)

# Stats
stats = {
    "patched_code": 0,
    "owasp_false_positives": 0,
    "juliet_good": 0,
    "nearby_clean": 0,
    "sast_false_positives": 0,
}


# ─── Strategy 1: Extract patched code ───────────────────────────────────────

def extract_patched_versions() -> Iterator[SecuritySample]:
    """
    For samples with patches, the patched code is a hard negative.
    It's similar to the vuln code but secure.
    """
    print("\n[1/5] Extracting patched versions as hard negatives...")
    
    for p in sorted(CLEAN_DIR.rglob("*.jsonl")):
        with p.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                
                try:
                    data = json.loads(line)
                    sample = SecuritySample.from_dict(data)
                    
                    # Only process vulnerable samples with patches
                    if not sample.is_vulnerable or not sample.patched_code:
                        continue
                    
                    # Create hard negative from patched code
                    hard_neg = SecuritySample(
                        id=f"{sample.id}_patched",
                        code=sample.patched_code,
                        language=sample.language,
                        is_vulnerable=False,
                        vulnerability_type=None,
                        cwe_id=None,
                        severity="clean",
                        explanation=f"This is the patched version of vulnerable code with {sample.cwe_id}. "
                                    f"The fix prevents the vulnerability by: {sample.secure_fix_recommendation or 'applying proper mitigation'}",
                        patched_code=None,
                        secure_fix_recommendation=None,
                        source=f"{sample.source}_patched",
                        metadata={
                            "hard_negative": True,
                            "similar_to_cwe": sample.cwe_id,
                            "original_vuln_id": sample.id,
                            "reason": "patched_version",
                        },
                    )
                    
                    stats["patched_code"] += 1
                    yield hard_neg
                    
                except Exception as e:
                    continue


# ─── Strategy 2: OWASP Benchmark false positives ────────────────────────────

def extract_owasp_false_positives() -> Iterator[SecuritySample]:
    """
    OWASP Benchmark contains true/false labels for each test case.
    Extract the FALSE cases (secure code that might trigger SAST tools).
    """
    print("\n[2/5] Extracting OWASP Benchmark false positive cases...")
    
    if not OWASP_DIR.exists():
        print("   ⚠️  OWASP Benchmark not found, skipping...")
        return
    
    # Look for expectedresults*.csv files
    result_files = list(OWASP_DIR.rglob("expectedresults*.csv"))
    if not result_files:
        print("   ⚠️  No OWASP result files found, skipping...")
        return
    
    # Parse expected results
    false_positive_cases = set()
    for rf in result_files:
        with rf.open("r") as f:
            for line in f:
                parts = line.strip().split(",")
                if len(parts) >= 2 and parts[1].lower() == "false":
                    false_positive_cases.add(parts[0])
    
    print(f"   Found {len(false_positive_cases)} false positive test cases")
    
    # Find corresponding code files
    for test_id in false_positive_cases:
        # OWASP Benchmark uses BenchmarkTestXXXXX naming
        java_file = OWASP_DIR / "src" / "main" / "java" / "org" / "owasp" / "benchmark" / "testcode" / f"{test_id}.java"
        if not java_file.exists():
            continue
        
        code = java_file.read_text(encoding="utf-8")
        
        # Extract CWE from test case name (e.g., BenchmarkTest00001 -> map to CWE)
        cwe_match = re.search(r"CWE[_-]?(\d+)", code)
        cwe = f"CWE-{cwe_match.group(1)}" if cwe_match else None
        
        hard_neg = SecuritySample(
            id=f"owasp_fp_{test_id}",
            code=code,
            language="Java",
            is_vulnerable=False,
            vulnerability_type=None,
            cwe_id=None,
            severity="clean",
            explanation=f"OWASP Benchmark false positive case. This code is secure but may trigger SAST tools for {cwe}.",
            source="owasp_benchmark_fp",
            metadata={
                "hard_negative": True,
                "similar_to_cwe": cwe,
                "reason": "owasp_false_positive",
                "test_case_id": test_id,
            },
        )
        
        stats["owasp_false_positives"] += 1
        yield hard_neg


# ─── Strategy 3: Juliet Test Suite GOOD variants ────────────────────────────

def extract_juliet_good() -> Iterator[SecuritySample]:
    """
    Juliet Test Suite has BAD (vulnerable) and GOOD (secure) variants for each CWE.
    Extract the GOOD variants as hard negatives.
    """
    print("\n[3/5] Extracting Juliet Test Suite GOOD variants...")
    
    if not JULIET_DIR.exists():
        print("   ⚠️  Juliet Test Suite not found, skipping...")
        print("   Download: https://samate.nist.gov/SARD/testsuite.php")
        return
    
    # Juliet uses naming: CWE###_XXX/CWE###_XXX__good.c
    good_files = list(JULIET_DIR.rglob("*good*.c")) + list(JULIET_DIR.rglob("*good*.cpp")) + list(JULIET_DIR.rglob("*good*.java"))
    
    print(f"   Found {len(good_files)} GOOD variant files")
    
    for good_file in good_files:
        try:
            code = good_file.read_text(encoding="utf-8")
            
            # Extract CWE from path
            cwe_match = re.search(r"CWE[_-]?(\d+)", str(good_file))
            cwe = f"CWE-{cwe_match.group(1)}" if cwe_match else None
            
            # Determine language
            lang = "Java" if good_file.suffix == ".java" else "C" if good_file.suffix == ".c" else "C++"
            
            hard_neg = SecuritySample(
                id=f"juliet_good_{good_file.stem}",
                code=code,
                language=lang,
                is_vulnerable=False,
                vulnerability_type=None,
                cwe_id=None,
                severity="clean",
                explanation=f"Juliet Test Suite GOOD variant for {cwe}. This code demonstrates proper mitigation.",
                source="juliet_good",
                metadata={
                    "hard_negative": True,
                    "similar_to_cwe": cwe,
                    "reason": "juliet_good_variant",
                    "test_case": good_file.stem,
                },
            )
            
            stats["juliet_good"] += 1
            yield hard_neg
            
        except Exception as e:
            continue


# ─── Strategy 4: Code near vulnerabilities (same file) ──────────────────────

def extract_nearby_clean_code() -> Iterator[SecuritySample]:
    """
    For samples with file-level context, extract OTHER functions in the same file
    that are NOT vulnerable. These share patterns with vuln code but are secure.
    """
    print("\n[4/5] Extracting clean code near vulnerabilities...")
    
    # This requires file-level context in metadata
    # Skip for now if not available in current dataset
    print("   ⚠️  Requires file-level context, skipping for now...")
    print("   Will implement after CVEfixes integration (has full file context)")
    
    # Placeholder for future implementation
    return
    yield  # Make it a generator


# ─── Strategy 5: SAST tool false positives from real repos ──────────────────

def extract_sast_false_positives() -> Iterator[SecuritySample]:
    """
    Run SAST tools (semgrep, bandit) on popular repos, then manually verify
    false positives. Extract those as hard negatives.
    
    This is resource-intensive, so we'll extract from a curated list.
    """
    print("\n[5/5] Extracting SAST false positives from real repositories...")
    
    # Curated list of false positive patterns
    false_positive_patterns = [
        {
            "code": """
def process_user_input(user_data: str) -> str:
    # semgrep flags this as SQL injection, but it's using parameterized query
    query = "SELECT * FROM users WHERE id = %s"
    cursor.execute(query, (user_data,))  # SAFE: parameterized
    return cursor.fetchone()
""",
            "language": "Python",
            "cwe": "CWE-89",
            "reason": "Uses parameterized query, not string concatenation",
        },
        {
            "code": """
function sanitize_html(input) {
    // eslint flags this as XSS, but DOMPurify sanitizes
    const clean = DOMPurify.sanitize(input);
    document.getElementById('output').innerHTML = clean;  // SAFE: sanitized
}
""",
            "language": "JavaScript",
            "cwe": "CWE-79",
            "reason": "Input is sanitized with DOMPurify before rendering",
        },
        {
            "code": """
import subprocess

def run_safe_command(filename: str) -> None:
    # bandit flags this as command injection, but using safe subprocess.run
    if not filename.replace('_', '').replace('.', '').isalnum():
        raise ValueError("Invalid filename")
    subprocess.run(['cat', filename], check=True)  # SAFE: no shell, validated input
""",
            "language": "Python",
            "cwe": "CWE-78",
            "reason": "Uses subprocess list form (no shell) + input validation",
        },
        {
            "code": """
public void readFile(String filename) throws IOException {
    // SpotBugs flags this as path traversal, but we validate first
    Path basePath = Paths.get("/safe/directory");
    Path requestedPath = basePath.resolve(filename).normalize();
    
    if (!requestedPath.startsWith(basePath)) {
        throw new SecurityException("Path traversal attempt");
    }
    
    Files.readString(requestedPath);  // SAFE: validated within base path
}
""",
            "language": "Java",
            "cwe": "CWE-22",
            "reason": "Path is normalized and validated against base directory",
        },
    ]
    
    for i, pattern in enumerate(false_positive_patterns):
        hard_neg = SecuritySample(
            id=f"sast_fp_{i}",
            vulnerable_code=pattern["code"],
            patched_code=None,
            language=pattern["language"],
            is_vulnerable=False,
            cwe=None,
            severity="clean",
            explanation=f"SAST tools may flag this for {pattern['cwe']}, but it's secure because: {pattern['reason']}. Hard negative for training precision.",
            attack_scenario="",
            secure_fix="No fix needed - code is already secure.",
            source="sast_false_positive",
            source_license="MIT",
        )
        
        stats["sast_false_positives"] += 1
        yield hard_neg
    
    print(f"   Added {len(false_positive_patterns)} curated SAST false positives")


# ─── Main ────────────────────────────────────────────────────────────────────

def main():
    print("=" * 80)
    print("🔍 RakshakAI v2 - Hard Negative Extraction")
    print("=" * 80)
    
    all_hard_negatives = []
    
    # Strategy 1: Patched versions
    all_hard_negatives.extend(list(extract_patched_versions()))
    
    # Strategy 2: OWASP false positives
    all_hard_negatives.extend(list(extract_owasp_false_positives()))
    
    # Strategy 3: Juliet GOOD variants
    all_hard_negatives.extend(list(extract_juliet_good()))
    
    # Strategy 4: Nearby clean code
    all_hard_negatives.extend(list(extract_nearby_clean_code()))
    
    # Strategy 5: SAST false positives
    all_hard_negatives.extend(list(extract_sast_false_positives()))
    
    # Write output
    output_file = OUT_DIR / "hard_negatives.jsonl"
    write_jsonl(output_file, all_hard_negatives)
    
    # Summary
    print("\n" + "=" * 80)
    print("📊 Hard Negative Extraction Summary")
    print("=" * 80)
    for key, count in stats.items():
        print(f"  {key}: {count:,}")
    print(f"\n  Total hard negatives: {len(all_hard_negatives):,}")
    print(f"  Output: {output_file}")
    print("=" * 80 + "\n")


if __name__ == "__main__":
    main()
