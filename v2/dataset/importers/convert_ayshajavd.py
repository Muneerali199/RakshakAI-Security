"""RakshakAI v2 — ayshajavd/code-security-vulnerability-dataset importer.

Source:  https://huggingface.co/datasets/ayshajavd/code-security-vulnerability-dataset
Format:  HF dataset, parquet, 140K rows, 16 languages, CWE labels.
         ~5% of vulnerable samples have code_fixed (fix code pairs).

Output:  v2/inputs/datasets/raw/ayshajavd.jsonl
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Iterator

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from v2.dataset.importers.common import ImportStats, run_importer
from v2.dataset.schema import SecuritySample

SOURCE = "ayshajavd"
MAX_SAMPLES = 500_000

LANG_MAP = {
    "c": "c", "c++": "cpp", "cpp": "cpp", "c#": "csharp", "csharp": "csharp",
    "java": "java", "python": "python", "javascript": "javascript", "js": "javascript",
    "php": "php", "go": "go", "golang": "go", "rust": "rust", "rs": "rust",
    "ruby": "ruby", "rb": "ruby", "swift": "swift", "kotlin": "kotlin", "kt": "kotlin",
    "typescript": "typescript", "ts": "typescript", "scala": "scala",
    "fortran": "text", "unknown": "text",
}

CWE_RE = re.compile(r"CWE-(\d+)", re.I)

LANG_ORDER = {
    "python": 0, "javascript": 1, "typescript": 2, "java": 3,
    "go": 4, "rust": 5, "ruby": 6, "kotlin": 7, "swift": 8,
    "php": 9, "csharp": 10, "c": 11, "cpp": 12,
}


def generate(stats: ImportStats) -> Iterator[SecuritySample]:
    try:
        from datasets import load_dataset
    except ImportError:
        stats.error = "datasets not installed; run: pip install datasets"
        return

    print(f"[{SOURCE}] Loading from HuggingFace...")
    try:
        ds = load_dataset("ayshajavd/code-security-vulnerability-dataset", split="train",
                          streaming=True, trust_remote_code=True)
    except Exception as e:
        stats.error = f"HF load failed: {e}"
        return

    for row in ds:
        if stats.built >= MAX_SAMPLES:
            break
        stats.requested += 1

        lang_raw = (row.get("language") or "").strip().lower()
        language = LANG_MAP.get(lang_raw, "text")
        if language == "text":
            stats.skipped_no_code += 1
            continue

        code = (row.get("code") or "").strip()
        if len(code) < 30:
            stats.skipped_too_short += 1
            continue
        if len(code) > 100_000:
            stats.skipped_no_code += 1
            continue

        is_vuln = bool(row.get("is_vulnerable", False))

        cwe_str = (row.get("cwe_id") or "").strip()
        cwe = None
        if cwe_str and cwe_str.lower() != "safe":
            m = CWE_RE.search(cwe_str)
            if m:
                cwe = f"CWE-{int(m.group(1))}"

        code_fixed_str = (row.get("code_fixed") or "").strip()
        patched = code_fixed_str if code_fixed_str else None

        source_raw = (row.get("source") or "ayshajavd").strip().lower()
        source = f"ayshajavd:{source_raw}"

        sev = "high" if is_vuln else "clean"
        explanation = (f"Vulnerable {language} code ({cwe or 'unknown'})"
                       if is_vuln else f"Secure {language} code")

        yield SecuritySample.build(
            language=language,
            vulnerable_code=code[:8000],
            patched_code=patched[:8000] if patched else None,
            cwe=cwe if is_vuln else None,
            severity=sev,
            explanation=explanation[:5000],
            attack_scenario=explanation[:3000] if is_vuln else "",
            secure_fix=(f"Fix {cwe}" if is_vuln and cwe else "No fix needed."),
            source=source,
            source_license="MIT",
            is_vulnerable=is_vuln,
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
