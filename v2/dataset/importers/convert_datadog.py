"""RakshakAI v2 — DataDog Malicious Software Packages importer.

Source:  https://github.com/DataDog/malicious-software-packages-dataset (GitHub)
Format:  CSV/JSON with real malicious package samples.

This dataset contains 28,000+ real-world supply chain attack examples across
PyPI, npm, RubyGems, and other ecosystems.  Each record includes the malicious
code and a description of the attack.

These samples are essential for training the model to detect AI supply-chain
attacks (Tier 3 vulnerability coverage).

Output: v2/inputs/datasets/raw/datadog.jsonl
"""
from __future__ import annotations

import csv
import json
import re
import sys
from io import StringIO
from pathlib import Path
from typing import Iterator

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from v2.dataset.importers.common import (
    ImportStats, write_samples, run_importer, fetch_text,
)
from v2.dataset.schema import SecuritySample

SOURCE = "datadog"
MAX_SAMPLES = 50_000

LANG_MAP = {
    "pypi": "python",
    "npm": "javascript",
    "rubygems": "ruby",
    "cratesio": "rust",
    "packagist": "php",
    "nuget": "csharp",
}

ECOSYSTEM_CWE = {
    "pypi": "CWE-1104",  # Use of Unmaintained Third-Party Components
    "npm": "CWE-1104",
    "rubygems": "CWE-1104",
    "cratesio": "CWE-1104",
    "packagist": "CWE-1104",
    "nuget": "CWE-1104",
}


def _load_csv(data_dir: Path) -> list[dict]:
    """Load from CSV or JSON files in the DataDog dataset."""
    records = []

    csv_files = list(data_dir.rglob("*.csv"))
    json_files = list(data_dir.rglob("*.json"))

    for csv_path in csv_files:
        try:
            with csv_path.open("r", encoding="utf-8", errors="replace") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    records.append(dict(row))
        except Exception as e:
            print(f"  [datadog] Error reading {csv_path}: {e}")

    for json_path in json_files:
        try:
            with json_path.open("r", encoding="utf-8", errors="replace") as f:
                data = json.load(f)
            if isinstance(data, list):
                records.extend(data)
            elif isinstance(data, dict):
                records.append(data)
        except Exception as e:
            print(f"  [datadog] Error reading {json_path}: {e}")

    return records


def generate(stats: ImportStats) -> Iterator[SecuritySample]:
    data_dir = Path("v2/inputs/datasets/raw/datadog")
    if not data_dir.exists():
        stats.error = f"Data not found at {data_dir}. Run download.py first."
        return

    records = _load_csv(data_dir)
    print(f"[{SOURCE}] Loaded {len(records)} records from {data_dir}")

    for i, rec in enumerate(records):
        if stats.built >= MAX_SAMPLES:
            break
        stats.requested += 1

        ecosystem = (rec.get("ecosystem") or rec.get("source") or "").strip().lower()
        language = LANG_MAP.get(ecosystem, "python")

        code = (rec.get("code") or rec.get("malicious_code") or rec.get("payload") or "").strip()
        if not code:
            code = (rec.get("content") or rec.get("script") or "").strip()
        if not code and "diff" in rec:
            code = rec["diff"]

        if len(code) < 30:
            stats.skipped_too_short += 1
            continue
        if len(code) > 100_000:
            stats.skipped_too_short += 1
            continue

        cve_id = rec.get("cve") or rec.get("cve_id") or ""
        cwe = rec.get("cwe") or ECOSYSTEM_CWE.get(ecosystem, "CWE-1104")
        desc = (rec.get("description") or rec.get("summary") or "").strip()
        package = rec.get("package") or rec.get("package_name") or "unknown"

        explanation = desc[:5000] if desc else f"Malicious {ecosystem} package: {package}"
        attack = f"Supply chain attack via {ecosystem} package '{package}'. {desc[:3000]}"
        fix_guide = rec.get("remediation") or rec.get("fix") or ""
        secure_fix = fix_guide[:5000] if fix_guide else f"Remove malicious package '{package}', audit dependencies."

        yield SecuritySample.build(
            language=language,
            vulnerable_code=code[:8000],
            patched_code=None,
            cwe=cwe,
            severity="high",
            explanation=explanation,
            attack_scenario=attack,
            secure_fix=secure_fix,
            source=f"datadog:{package}:{ecosystem}" if package else f"datadog:{i}",
            source_license="MIT",
            cve=cve_id or None,
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
