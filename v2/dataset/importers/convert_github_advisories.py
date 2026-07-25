#!/usr/bin/env python3
"""Convert GitHub Security Advisories to SecuritySample format.

Reads the local advisory-database clone and produces:
  v2/inputs/datasets/raw/github_advisories.jsonl

Only includes advisories for ecosystems we care about
(npm→javascript, pip→python, maven→java, nuget→csharp, rubygems→ruby).

Each advisory becomes a SecuritySample with:
  - is_vulnerable = True
  - vulnerable_code = placeholder text (advisories have metadata, not code)
  - cwe from database_specific.cwe_ids
  - cve from aliases (if present)
"""
import json
import sys
from pathlib import Path
from collections import Counter

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from v2.dataset.schema import SecuritySample, write_jsonl

ADVISORY_DIR = Path("v2/inputs/datasets/raw/github-advisories/advisories/github-reviewed")

LANG_MAP = {
    "npm": "javascript",
    "pip": "python",
    "PyPI": "python",
    "maven": "java",
    "Maven": "java",
    "nuget": "csharp",
    "NuGet": "csharp",
    "rubygems": "ruby",
    "RubyGems": "ruby",
    "go": "go",
    "Go": "go",
    "packagist": "php",
    "Packagist": "php",
    "rust": "rust",
    "crates.io": "rust",
    "Crates.io": "rust",
    "hex": "elixir",
    "Hex": "elixir",
}

samples = []
skipped = 0

json_files = list(ADVISORY_DIR.rglob("*.json"))
total_files = len(json_files)
print(f"Scanning {total_files} advisory files...")

for i, json_file in enumerate(json_files):
    try:
        with open(json_file) as f:
            adv = json.load(f)
    except Exception:
        skipped += 1
        continue

    # Extract ecosystem from affected[0].package.ecosystem
    affected = adv.get("affected") or adv.get("vulnerabilities") or []
    ecosystem = ""
    found_eco_raw = ""
    for aff in affected:
        pkg = aff.get("package", {})
        eco = pkg.get("ecosystem", "")
        if eco:
            found_eco_raw = eco
            ecosystem = eco.lower()
            break

    # Try exact match first, then case-insensitive lookup
    lang = LANG_MAP.get(found_eco_raw) or LANG_MAP.get(ecosystem)
    if not lang:
        for key, val in LANG_MAP.items():
            if key.lower() == ecosystem:
                lang = val
                break

    if not lang:
        skipped += 1
        if i % 5000 == 0:
            print(f"  [{i}/{total_files}] found {len(samples)} so far (skipped {skipped})", flush=True)
        continue

    language = lang
    aliases = adv.get("aliases", [])
    cve = next((a for a in aliases if a and a.startswith("CVE-")), None) or (aliases[0] if aliases else None)

    # CWE
    db_specific = adv.get("database_specific", {})
    cwe_ids = db_specific.get("cwe_ids") or adv.get("cwes") or []
    cwe = cwe_ids[0] if cwe_ids else None
    if cwe and isinstance(cwe, str) and cwe.upper().startswith("CWE-"):
        cwe = cwe.upper()
    elif cwe:
        cwe = f"CWE-{cwe}" if isinstance(cwe, str) and cwe.replace("-","").isdigit() else None

    # Severity
    severity_map = {"CRITICAL": "critical", "HIGH": "high", "MODERATE": "medium", "LOW": "low"}
    severity_val = adv.get("severity", "medium")
    if isinstance(severity_val, list):
        severity_val = severity_val[0].get("score", "medium") if severity_val else "medium"
        if isinstance(severity_val, (int, float)):
            severity = "critical" if severity_val >= 9 else "high" if severity_val >= 7 else "medium" if severity_val >= 4 else "low"
        else:
            severity = "medium"
    else:
        severity_raw = str(severity_val).upper()
        severity = severity_map.get(severity_raw, "medium")

    # Explanation
    summary = (adv.get("summary") or adv.get("details") or "").strip()
    description = (adv.get("description") or "").strip()
    if description and len(description) > len(summary):
        explanation = description[:5000]
    else:
        explanation = summary[:5000] or f"GitHub Advisory {adv.get('id', 'unknown')}"

    # References
    refs = adv.get("references", [])
    ref_urls = [r.get("url", "") for r in refs if isinstance(r, dict) and r.get("url")]

    # Sample: mark as vulnerable, placeholder code (no actual code in advisories)
    sample = SecuritySample(
        id=adv.get("id", f"ghsa_{i}").replace("GHSA-", "ghsa_"),
        vulnerable_code=f"// GitHub Advisory {adv.get('id', '')}\n// Ecosystem: {ecosystem}\n// {summary[:200]}\n// See advisory for affected versions and patches",
        patched_code=None,
        language=language,
        is_vulnerable=True,
        cwe=cwe,
        severity=severity,
        explanation=explanation,
        attack_scenario=summary[:500] if summary else "",
        secure_fix="Apply patches referenced in the advisory",
        source="github_advisory",
        source_license="CC-BY-4.0",
        cve=cve if cve and "CVE-" in str(cve) else None,
        references=ref_urls,
    )
    samples.append(sample)

    if i % 5000 == 0:
        print(f"  [{i}/{total_files}] found {len(samples)} ({skipped} skipped)", flush=True)

# Write output
out_path = Path("v2/inputs/datasets/raw/github_advisories.jsonl")
write_jsonl(out_path, samples)
print(f"\nConverted {len(samples)} GitHub advisories to {out_path}")

# Language breakdown
lang_counts = Counter(s.language for s in samples)
print("\nBy language:")
for lang, count in lang_counts.most_common():
    print(f"  {lang}: {count:,}")

# CVE count
cve_count = sum(1 for s in samples if s.cve)
print(f"\nWith CVE ID: {cve_count} ({100*cve_count/max(len(samples),1):.1f}%)")