"""RakshakAI v2 — SecurityEval2 importer.

Source:  https://github.com/fsoft-ai-hub/SecurityEval2 (GitHub)
Format:  JSON files with vulnerable/buggy code and fix.

SecurityEval2 provides 1,809 Python vulnerability samples across 75+ CWEs,
with paired vulnerable/fixed code. Extends the original SecurityEval (130 samples)
with 15x more coverage, specifically for Python.

Output: v2/inputs/datasets/raw/securityeval2.jsonl
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

SOURCE = "securityeval2"
MAX_SAMPLES = 10_000

LANG_MAP = {
    "py": "python", "python": "python",
    "js": "javascript", "javascript": "javascript",
    "ts": "typescript", "typescript": "typescript",
    "java": "java",
    "go": "go",
    "rs": "rust", "rust": "rust",
    "c": "c", "cpp": "cpp",
}


def _load_data(data_dir: Path) -> list[dict]:
    """Recursively load all JSON files from SecurityEval2 data directory."""
    records = []
    for p in sorted(data_dir.rglob("*.json")):
        try:
            with p.open("r", encoding="utf-8") as f:
                data = json.load(f)
        except (json.JSONDecodeError, Exception):
            continue
        if isinstance(data, dict):
            records.append(data)
        elif isinstance(data, list):
            records.extend(data)
    return records


def generate(stats: ImportStats) -> Iterator[SecuritySample]:
    data_dir = Path("v2/inputs/datasets/raw/securityeval2")
    if not data_dir.exists():
        stats.error = f"Data not found at {data_dir}. Run download.py first."
        return

    records = _load_data(data_dir)
    print(f"[{SOURCE}] Loaded {len(records)} records from {data_dir}")

    for i, rec in enumerate(records):
        if stats.built >= MAX_SAMPLES:
            break
        stats.requested += 1

        code = (rec.get("vulnerable_code") or rec.get("buggy_code") or rec.get("code") or "").strip()
        fix = (rec.get("fixed_code") or rec.get("patched_code") or rec.get("fix") or "").strip()
        cwe_raw = rec.get("cwe") or rec.get("cwe_id") or ""
        cve_id = rec.get("cve") or rec.get("cve_id") or ""

        if len(code) < 30:
            stats.skipped_too_short += 1
            continue

        lang = "python"
        file_path = rec.get("file") or rec.get("file_path") or ""
        ext = Path(file_path).suffix.lower()
        if ext:
            lang = LANG_MAP.get(ext.lstrip("."), "python")

        cwe = None
        if cwe_raw:
            m = re.search(r"CWE-(\d+)", str(cwe_raw), re.I)
            if m:
                cwe = f"CWE-{int(m.group(1))}"

        desc = (rec.get("description") or rec.get("explanation") or "").strip()
        explanation = desc[:5000] if desc else f"SecurityEval2 sample: {cwe or cve_id or 'vulnerability'}"
        attack = desc[:5000] if desc else ""
        fix_text = (rec.get("fix_guidance") or rec.get("mitigation") or "").strip()
        secure_fix = fix_text[:5000] if fix_text else f"Apply fix for {cwe or cve_id or 'vulnerability'}."

        sev = rec.get("severity") or "high"
        if sev not in ("critical", "high", "medium", "low", "info", "clean"):
            sev = "high"

        yield SecuritySample.build(
            language=lang,
            vulnerable_code=code[:8000],
            patched_code=fix[:8000] if fix else None,
            cwe=cwe,
            severity=sev,
            explanation=explanation,
            attack_scenario=attack,
            secure_fix=secure_fix,
            source=f"securityeval2:{cve_id}" if cve_id else f"securityeval2:{i}",
            source_license="MIT",
            cve=cve_id or None,
            references=rec.get("references") or [],
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
