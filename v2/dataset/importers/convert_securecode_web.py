"""RakshakAI v2 — scthornton/securecode-web importer (web security dataset).

Source:  https://huggingface.co/datasets/scthornton/securecode-web
Format:  HF dataset (parquet), 1378 samples across 3 splits.
         OWASP Top 10 2021 web security with vulnerable + secure code blocks.

Output:  v2/inputs/datasets/raw/securecode_web.jsonl
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Iterator

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from v2.dataset.importers.common import ImportStats, run_importer
from v2.dataset.schema import SecuritySample

SOURCE = "securecode_web"

LANG_MAP = {
    "python": "python", "py": "python",
    "javascript": "javascript", "js": "javascript",
    "typescript": "typescript", "ts": "typescript",
    "java": "java", "go": "go", "golang": "go",
    "rust": "rust", "rs": "rust",
    "ruby": "ruby", "rb": "ruby",
    "php": "php", "csharp": "csharp", "kotlin": "kotlin",
    "swift": "swift", "dart": "text",
    "bash": "shell", "sh": "shell", "yaml": "text",
    "html": "html", "xml": "xml", "sql": "sql",
}

CWE_RE = re.compile(r"CWE-(\d+)", re.I)
CODE_BLOCK_RE = re.compile(r"```(\w+)\n(.*?)```", re.DOTALL)


def generate(stats: ImportStats) -> Iterator[SecuritySample]:
    try:
        from datasets import load_dataset
    except ImportError:
        stats.error = "datasets not installed"
        return

    print(f"[{SOURCE}] Loading from HuggingFace...")
    try:
        ds = load_dataset("scthornton/securecode-web", split="train",
                          streaming=True, trust_remote_code=True)
    except Exception as e:
        stats.error = f"HF load failed: {e}"
        return

    for row in ds:
        stats.requested += 1
        try:
            meta = row.get("metadata", {})
            if isinstance(meta, dict):
                lang_raw = (meta.get("lang") or "").strip().lower()
            else:
                lang_raw = ""
            language = LANG_MAP.get(lang_raw, "python")

            cat = ""
            if isinstance(meta, dict):
                cat = (meta.get("category") or "").lower()
            is_vuln = True

            cwe_str = ""
            if isinstance(meta, dict):
                cwe_str = (meta.get("cwe") or "").strip()
            cwe = None
            if cwe_str:
                m = CWE_RE.search(cwe_str)
                if m:
                    cwe = f"CWE-{int(m.group(1))}"

            all_blocks = []
            for conv in row.get("conversations", []):
                sender = conv.get("from", conv.get("role", "")).strip().lower()
                if sender not in ("gpt", "assistant", "ai", "bot"):
                    continue
                content = conv.get("value", conv.get("content", ""))
                blocks = CODE_BLOCK_RE.findall(content)
                for blang, bcode in blocks:
                    lang_norm = LANG_MAP.get(blang.strip().lower(), "text")
                    if lang_norm == "text":
                        continue
                    code = bcode.strip()
                    if len(code) >= 30:
                        all_blocks.append((lang_norm, code))

            if not all_blocks:
                stats.skipped_no_code += 1
                continue

            first_lang, first_code = all_blocks[0]
            last_lang, last_code = all_blocks[-1]

            vuln_code = first_code[:8000]
            patched = last_code[:8000] if (last_code != first_code and is_vuln) else None

            context = row.get("context", {})
            desc = (context.get("description") or "").strip()[:2000]
            impact = (context.get("impact") or context.get("business_impact") or "").strip()[:1000]

            explanation = f"Web Security: {desc}" + (f" (Impact: {impact})" if impact else "")
            attack_scenario = f"OWASP category: {cat}. {desc}" if is_vuln else ""
            fix_desc = f"Secure implementation for {cwe or 'web'} vulnerability."

            source = f"securecode_web:{row.get('id', 'unknown')}"

            yield SecuritySample.build(
                language=language,
                vulnerable_code=vuln_code,
                patched_code=patched,
                cwe=cwe if is_vuln else None,
                severity="high" if is_vuln else "clean",
                explanation=explanation[:5000],
                attack_scenario=attack_scenario[:3000],
                secure_fix=fix_desc[:3000],
                source=source,
                source_license="CC-BY-4.0",
                is_vulnerable=is_vuln,
                split="train",
            )
        except Exception:
            stats.skipped_no_code += 1
            continue


def main() -> int:
    path, stats = run_importer(SOURCE, generate)
    print(f"[{SOURCE}] done: {stats.built} samples -> {path}")
    if stats.error:
        print(f"[{SOURCE}] ERROR: {stats.error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
