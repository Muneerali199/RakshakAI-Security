"""RakshakAI v2 — MoreFixes importer.

Source:  https://huggingface.co/datasets/JafarAkhondali/morefixes (HF)
Format:  Parquet with CVE→fix mappings, 26,617 CVEs, 31,883 commits.

MoreFixes (2026) is the largest dataset of CVEs paired with their fixing commits.
Crucially, it avoids overlap with BigVul/Devign/PrimeVul (different CVE selection)
and adds language diversity beyond C/C++.

Output: v2/inputs/datasets/raw/morefixes.jsonl
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Iterator

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from v2.dataset.importers.common import ImportStats, write_samples, run_importer
from v2.dataset.schema import SecuritySample

SOURCE = "morefixes"
MAX_SAMPLES = 200_000

LANG_MAP = {
    "c": "c", "cpp": "cpp", "c++": "cpp", "c#": "csharp",
    "java": "java", "javascript": "javascript", "python": "python",
    "php": "php", "go": "go", "rust": "rust", "ruby": "ruby",
    "swift": "swift", "kotlin": "kotlin", "typescript": "typescript",
    "scala": "scala", "csharp": "csharp",
}


def generate(stats: ImportStats) -> Iterator[SecuritySample]:
    try:
        from datasets import load_dataset
    except ImportError:
        stats.error = "datasets not installed; run: pip install datasets"
        return

    print(f"[{SOURCE}] Loading from HuggingFace...")
    try:
        ds = load_dataset("jafarja/MoreFixes", split="train", trust_remote_code=True)
    except Exception as e:
        stats.error = f"HF load failed: {e}"
        return

    print(f"[{SOURCE}] Loaded {len(ds)} rows")

    for i, row in enumerate(ds):
        if stats.built >= MAX_SAMPLES:
            break
        stats.requested += 1

        cve_id = (row.get("cve_id") or row.get("cve") or "").strip()
        lang_raw = (row.get("language") or row.get("lang") or "").strip().lower()
        language = LANG_MAP.get(lang_raw, "text")
        if language == "text":
            stats.skipped_no_code += 1
            continue

        before = (row.get("code_before") or row.get("vuln_code") or row.get("before") or "").strip()
        after = (row.get("code_after") or row.get("patch_code") or row.get("after") or "").strip()

        if len(before) < 30:
            stats.skipped_too_short += 1
            continue
        if len(before) > 100_000:
            stats.skipped_too_short += 1
            continue

        cwe_raw = row.get("cwe") or row.get("cwe_id") or ""
        cwe = None
        if cwe_raw:
            m = re.search(r"CWE-(\d+)", str(cwe_raw), re.I)
            if m:
                cwe = f"CWE-{int(m.group(1))}"

        desc = (row.get("description") or row.get("cve_description") or f"CVE: {cve_id}").strip()
        explanation = desc[:5000] if desc else f"MoreFixes record: {cve_id}"
        attack = desc[:5000] if desc else ""
        fix_guide = (row.get("fix_text") or row.get("fix_guidance") or "").strip()
        secure_fix = fix_guide[:5000] if fix_guide else f"Apply patch from commit fixing {cve_id}."

        cvss_val = row.get("cvss") or row.get("cvss_score") or None
        try:
            cvss_val = float(cvss_val) if cvss_val is not None else None
        except (ValueError, TypeError):
            cvss_val = None

        sev = "high"
        if cvss_val is not None:
            if cvss_val >= 9.0:
                sev = "critical"
            elif cvss_val >= 7.0:
                sev = "high"
            elif cvss_val >= 4.0:
                sev = "medium"
            else:
                sev = "low"

        refs = row.get("references") or row.get("urls") or []
        if isinstance(refs, str):
            refs = [refs]

        yield SecuritySample.build(
            language=language,
            vulnerable_code=before[:8000],
            patched_code=after[:8000] if after else None,
            cwe=cwe,
            severity=sev,
            explanation=explanation,
            attack_scenario=attack,
            secure_fix=secure_fix,
            source=f"morefixes:{cve_id}" if cve_id else f"morefixes:{i}",
            source_license="MIT",
            cve=cve_id or None,
            cvss=cvss_val,
            references=list(refs or []),
            is_vulnerable=True,
            split="train",
        )


def main() -> int:
    path, stats = run_importer(SOURCE, generate)
    print(f"[{SOURCE}] done: {stats.built} samples -> {path}")
    if stats.error:
        print(f"[{SOURCE}] ERROR: {stats.error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
