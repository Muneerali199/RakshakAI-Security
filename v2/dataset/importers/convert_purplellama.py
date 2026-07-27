"""RakshakAI v2 — PurpleLlama / CyberSecEval importer.

Source:  https://huggingface.co/datasets/meta-llama/PurpleLlama_CyberSecEval (HF)
Format:  Parquet with security-related prompts and completions.

PurpleLlama provides three evaluation sets:
  1. Prompt Injection — tests for prompt injection robustness
  2. CyberSecEval — tests for cyber security competency (vulnerable code detection)
  3. Safe Coding — tests for safe coding practices

We extract the vulnerable-code-detection samples to add AI-security and
secure-coding training data. All code is competency-based (Python/JS/etc).

Output: v2/inputs/datasets/raw/purplellama.jsonl
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

SOURCE = "purplellama"
MAX_SAMPLES = 30_000

LANG_MAP = {
    "python": "python", "py": "python",
    "javascript": "javascript", "js": "javascript",
    "typescript": "typescript", "ts": "typescript",
    "java": "java",
    "go": "go",
    "rust": "rust", "rs": "rust",
    "cpp": "cpp", "c++": "cpp", "c": "c",
    "ruby": "ruby", "rb": "ruby",
    "php": "php",
    "csharp": "csharp", "c#": "csharp",
    "kotlin": "kotlin", "kt": "kotlin",
    "swift": "swift",
}

# Prompt injection CWEs — mapping injection categories to our schema
INJECTION_CWES = {
    "direct": "CWE-77",
    "indirect": "CWE-77",
    "jailbreak": "CWE-77",
    "prompt_leak": "CWE-200",
    "tool_abuse": "CWE-77",
    "role_play": "CWE-77",
    "encoding_attack": "CWE-77",
    "few_shot": "CWE-77",
}


def _detect_language(code: str) -> str:
    """Simple language detection from code snippet patterns."""
    patterns = [
        (r"\bimport\s+\w+|def \w+\(|class \w+:|print\(|if __name__", "python"),
        (r"\bfunction\s+\w+|const\s+\w+|let\s+\w+|var\s+\w+|=>|console\.log", "javascript"),
        (r"\binterface\s+\w+|type\s+\w+|:\s*(string|number|boolean)\b", "typescript"),
        (r"\bpublic\s+(class|static)|System\.out\.|import\s+java\.", "java"),
        (r"\bfunc\s+\w+|package\s+main|import\s+\(", "go"),
        (r"\bfn\s+\w+|impl\s+\w+|let mut|use\s+\w+::", "rust"),
        (r"\b#include|int main|printf\(|scanf\(", "c"),
        (r"\b#include\s*<iostream>|std::|cout\s*<<|cin\s*>>", "cpp"),
        (r"\bdef\s+\w+|end\b|require|puts ", "ruby"),
        (r"\b<?php|echo\s+|function\s+\w+\(|namespace\s+", "php"),
        (r"\busing\s+System|Console\.WriteLine|class\s+\w+\s*:\s*[A-Z]", "csharp"),
    ]
    for pat, lang in patterns:
        if re.search(pat, code, re.MULTILINE):
            return lang
    return "python"


def generate(stats: ImportStats) -> Iterator[SecuritySample]:
    try:
        from datasets import load_dataset
    except ImportError:
        stats.error = "datasets not installed; run: pip install datasets"
        return

    print(f"[{SOURCE}] Loading PurpleLlama CyberSecEval...")
    try:
        ds = load_dataset(
            "meta-llama/PurpleLlama_CyberSecEval",
            split="train",
            trust_remote_code=True,
        )
    except Exception as e:
        print(f"[{SOURCE}] CyberSecEval failed, trying raw repo: {e}")
        stats.error = f"HF load failed: {e}"
        return

    print(f"[{SOURCE}] Loaded {len(ds)} rows from CyberSecEval")

    for i, row in enumerate(ds):
        if stats.built >= MAX_SAMPLES:
            break
        stats.requested += 1

        code = (row.get("code") or row.get("vulnerable_code") or row.get("prompt") or "").strip()
        context = (row.get("context") or row.get("instruction") or "").strip()
        label = row.get("label") or row.get("is_vulnerable") or row.get("safe") or ""
        category = (row.get("category") or row.get("type") or "").lower()

        if not code and not context:
            stats.skipped_no_code += 1
            continue

        # Use context as code if no code present
        if not code:
            code = context

        if len(code) < 30:
            stats.skipped_too_short += 1
            continue
        if len(code) > 100_000:
            stats.skipped_too_short += 1
            continue

        lang_hint = row.get("language") or ""
        language = LANG_MAP.get(lang_hint.lower(), _detect_language(code))
        if language == "python":
            pass

        is_vuln = True
        if isinstance(label, int) and label == 0:
            is_vuln = False
        elif isinstance(label, str) and label.lower() in ("0", "false", "safe", "benign"):
            is_vuln = False

        cwe = INJECTION_CWES.get(category, None)
        if not is_vuln:
            cwe = "CWE-UNKNOWN"

        explanation = (row.get("explanation") or row.get("description") or "").strip()
        if not explanation:
            if is_vuln:
                explanation = f"PurpleLlama {category} sample: potentially {category} vulnerability."
            else:
                explanation = "Benign code sample from PurpleLlama benchmark."

        fix_guide = (row.get("fix") or row.get("remediation") or "").strip()

        yield SecuritySample.build(
            language=language,
            vulnerable_code=code[:8000],
            patched_code=fix_guide[:8000] if fix_guide else None,
            cwe=cwe,
            severity="high" if is_vuln else "clean",
            explanation=explanation[:5000],
            attack_scenario=explanation[:5000] if is_vuln else "",
            secure_fix=fix_guide[:5000] if fix_guide else "Follow security best practices.",
            source=f"purplellama:{row.get('id', i)}",
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
