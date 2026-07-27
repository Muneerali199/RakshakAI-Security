"""
RakshakAI v2 — CVEfixes importer.

Source:  https://huggingface.co/datasets/securelab-ttu/CVEfixes  (HF dataset)
Format:  Parquet with rows representing CVE records.

CVEfixes provides paired before/after code for every CVE — this is the
canonical source for patched_code training.  Records also include language
detection (multi-language), CWE, CVSS, and references.

Output: v2/inputs/datasets/raw/cvefixes.jsonl
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Iterator

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from v2.dataset.importers.common import ImportStats, write_samples
from v2.dataset.schema import SecuritySample

SOURCE = "cvefixes"
MAX_SAMPLES = 120_000


def main() -> int:
    stats = ImportStats(source=SOURCE)
    samples: list[SecuritySample] = []

    try:
        import pyarrow.parquet as pq
        import pyarrow.dataset as ds
    except ImportError:
        print("[cvefixes] ERROR: pyarrow not installed. Run: pip install pyarrow")
        stats.error = "pyarrow not installed"
        write_samples(SOURCE, samples, stats)
        print(json.dumps(stats.to_dict(), indent=2))
        return 1

    data_path = Path("v2/inputs/datasets/raw/cvefixes")
    if not data_path.exists():
        print(f"[cvefixes] Data not found at {data_path}. Run download.py first.")
        stats.error = "data not downloaded"
        write_samples(SOURCE, samples, stats)
        print(json.dumps(stats.to_dict(), indent=2))
        return 1

    try:
        dataset = pq.read_table(str(data_path))
        rows = dataset.to_pylist()
    except Exception as e:
        print(f"[cvefixes] Failed to read parquet: {e}")
        stats.error = str(e)
        write_samples(SOURCE, samples, stats)
        print(json.dumps(stats.to_dict(), indent=2))
        return 1

    lang_map = {
        "c": "c", "c++": "cpp", "cpp": "cpp", "c#": "csharp",
        "java": "java", "javascript": "javascript", "python": "python",
        "php": "php", "go": "go", "rust": "rust", "ruby": "ruby",
        "swift": "swift", "kotlin": "kotlin", "typescript": "typescript",
        "scala": "scala", "perl": "perl", "shell": "shell",
        "sql": "text", "html": "text",
    }

    for i, row in enumerate(rows):
        if i >= MAX_SAMPLES:
            break
        stats.requested += 1

        cve_id = row.get("cve_id") or ""
        cwe_str = row.get("cwe") or row.get("cwe_id") or ""
        lang_raw = (row.get("language") or "").strip().lower()
        language = lang_map.get(lang_raw, "text")

        # Skip non-code languages
        if language not in ("c", "cpp", "java", "javascript", "python",
                            "php", "go", "rust", "ruby", "swift", "kotlin",
                            "typescript", "scala", "csharp"):
            stats.skipped_no_code += 1
            continue

        before = row.get("code_before") or row.get("vulnerable_code") or ""
        after = row.get("code_after") or row.get("patched_code") or ""

        if len(before) < 30:
            stats.skipped_too_short += 1
            continue
        if len(before) > 100_000:
            stats.skipped_too_short += 1
            continue

        desc = row.get("description") or row.get("cve_description") or ""
        explanation = desc[:1500] if desc else f"CVEfixes record: {cve_id}"
        attack = desc[:1500] if desc else ""
        fix_guide = row.get("fix") or row.get("fix_text") or ""
        secure_fix = fix_guide[:1500] if fix_guide else f"Apply patch described in {cve_id}."

        cvss_val = row.get("cvss_score") or row.get("cvss") or None
        try:
            cvss_val = float(cvss_val) if cvss_val is not None else None
        except (ValueError, TypeError):
            cvss_val = None

        sev = row.get("severity") or ""
        if sev not in ("critical", "high", "medium", "low", "info", "clean"):
            if cvss_val is not None:
                if cvss_val >= 9.0:
                    sev = "critical"
                elif cvss_val >= 7.0:
                    sev = "high"
                elif cvss_val >= 4.0:
                    sev = "medium"
                else:
                    sev = "low"
            else:
                sev = "high"

        cwe = None
        if cwe_str:
            import re
            m = re.search(r"CWE-(\d+)", cwe_str, re.I)
            if m:
                cwe = f"CWE-{int(m.group(1))}"

        refs = row.get("references") or row.get("urls") or []
        if isinstance(refs, str):
            refs = [refs]
        elif hasattr(refs, "to_pylist"):
            refs = refs.to_pylist()

        try:
            s = SecuritySample.build(
                language=language,
                vulnerable_code=before[:8000],
                patched_code=after[:8000] if after else None,
                cwe=cwe,
                severity=sev,
                explanation=explanation,
                attack_scenario=attack,
                secure_fix=secure_fix,
                source=f"cvefixes:{cve_id}" if cve_id else f"cvefixes:{i}",
                source_license="MIT",
                cve=cve_id or None,
                cvss=cvss_val,
                references=list(refs or []),
                split="train",
            )
        except Exception:
            stats.skipped_no_code += 1
            continue

        errs = s.validate()
        if errs:
            stats.skipped_no_code += 1
            continue

        samples.append(s)
        stats.built += 1

    write_samples(SOURCE, samples, stats)
    print(f"[cvefixes] built {len(samples)} samples from {stats.requested} rows")
    print(json.dumps(stats.to_dict(), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
