"""RakshakAI v2 — hitoshura25/crossvul importer.

Source:  https://huggingface.co/datasets/hitoshura25/crossvul
Format:  HF dataset, parquet, 9,314 samples, 19 languages, fix pairs.
Fields:  cwe_id, vulnerable_code, fixed_code, language, file_pair_id, source

Output:  v2/inputs/datasets/raw/hitoshura25_crossvul.jsonl
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Iterator

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from v2.dataset.importers.common import ImportStats, run_importer
from v2.dataset.schema import SecuritySample

SOURCE = "hitoshura25_crossvul"

LANG_MAP = {
    "c": "c", "c++": "cpp", "cpp": "cpp", "c#": "csharp", "csharp": "csharp",
    "java": "java", "python": "python", "javascript": "javascript", "js": "javascript",
    "php": "php", "go": "go", "golang": "go", "rust": "rust", "rs": "rust",
    "ruby": "ruby", "rb": "ruby", "swift": "swift", "kotlin": "kotlin",
    "typescript": "typescript", "ts": "typescript", "scala": "scala",
    "erlang": "erlang", "haskell": "haskell", "elixir": "elixir",
    "perl": "perl", "r": "r", "lua": "lua",
    "shell": "shell", "bash": "shell", "sh": "shell",
    "sql": "sql", "html": "html", "xml": "xml", "json": "json",
}

CWE_RE = re.compile(r"CWE-(\d+)", re.I)


def generate(stats: ImportStats) -> Iterator[SecuritySample]:
    try:
        from datasets import load_dataset
    except ImportError:
        stats.error = "datasets not installed; run: pip install datasets"
        return

    print(f"[{SOURCE}] Loading from HuggingFace (this may take a minute)...")
    try:
        ds = load_dataset("hitoshura25/crossvul", split="train",
                          streaming=True, trust_remote_code=True)
    except Exception as e:
        stats.error = f"HF load failed: {e}"
        return

    for row in ds:
        stats.requested += 1

        lang_raw = (row.get("language") or "").strip().lower()
        language = LANG_MAP.get(lang_raw)
        if not language:
            stats.skipped_no_code += 1
            continue

        code = (row.get("vulnerable_code") or "").strip()
        if len(code) < 30:
            stats.skipped_too_short += 1
            continue
        if len(code) > 100_000:
            stats.skipped_no_code += 1
            continue

        fixed = (row.get("fixed_code") or "").strip()
        patched = fixed if fixed and len(fixed) >= 10 else None

        cwe_str = (row.get("cwe_id") or "").strip()
        cwe = None
        if cwe_str:
            m = CWE_RE.search(cwe_str)
            if m:
                cwe = f"CWE-{int(m.group(1))}"

        src_raw = (row.get("source") or "crossvul").strip()
        source = f"hitoshura25:crossvul:{src_raw}"

        explanation = (f"Vulnerable {language} code ({cwe or 'unknown'})"
                       if cwe else f"Vulnerable {language} code")

        yield SecuritySample.build(
            language=language,
            vulnerable_code=code[:8000],
            patched_code=patched[:8000] if patched else None,
            cwe=cwe or "CWE-UNKNOWN",
            severity="high",
            explanation=explanation[:5000],
            attack_scenario=explanation[:3000],
            secure_fix=(f"Fix {cwe}" if patched and cwe else "No fix provided."),
            source=source,
            source_license="MIT",
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
