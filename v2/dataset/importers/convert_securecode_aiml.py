"""RakshakAI v2 — scthornton/securecode-aiml importer.

Source:  https://huggingface.co/datasets/scthornton/securecode-aiml
Format:  HF dataset (JSONL), 750 samples, OWASP LLM Top 10 categories.
Fields:  conversations (human/assistant), metadata (CWE, lang, category)
         Each assistant response contains vulnerable + secure code blocks.

Output:  v2/inputs/datasets/raw/securecode_aiml.jsonl
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Iterator
from collections import Counter
from urllib.request import urlopen

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from v2.dataset.importers.common import ImportStats, run_importer
from v2.dataset.schema import SecuritySample

SOURCE = "securecode_aiml"

LANG_MAP = {
    "python": "python", "py": "python",
    "javascript": "javascript", "js": "javascript",
    "typescript": "typescript", "ts": "typescript",
    "java": "java", "go": "go", "rust": "rust", "ruby": "ruby",
    "php": "php", "csharp": "csharp", "kotlin": "kotlin",
    "swift": "swift", "dart": "text", "bash": "shell", "sh": "shell",
}

CATEGORY_IS_VULN = {
    "prompt injection": True,
    "sensitive information disclosure": True,
    "supply chain": True,
    "data and model poisoning": True,
    "improper output handling": True,
    "excessive agency": True,
    "system prompt leakage": True,
    "vector and embedding weaknesses": True,
    "misinformation": True,
    "unbounded consumption": True,
}

CWE_RE = re.compile(r"CWE-(\d+)", re.I)
CODE_BLOCK_RE = re.compile(r"```(\w+)\n(.*?)```", re.DOTALL)

URL = "https://huggingface.co/datasets/scthornton/securecode-aiml/resolve/main/train.jsonl"


def generate(stats: ImportStats) -> Iterator[SecuritySample]:
    print(f"[{SOURCE}] Fetching from HuggingFace...")
    try:
        resp = urlopen(URL, timeout=60)
        raw = resp.read().decode("utf-8")
    except Exception as e:
        stats.error = f"fetch failed: {e}"
        return

    lines = [l.strip() for l in raw.split("\n") if l.strip()]
    print(f"[{SOURCE}] Fetched {len(lines)} samples")

    for line in lines:
        stats.requested += 1
        try:
            d = json.loads(line)
        except json.JSONDecodeError:
            stats.skipped_no_code += 1
            continue

        meta = d.get("metadata", {})
        lang_raw = (meta.get("lang") or "").strip().lower()
        language = LANG_MAP.get(lang_raw)
        if not language or language == "text":
            language = "python"

        cat = (meta.get("category") or "").lower()
        is_vuln = any(k in cat for k in CATEGORY_IS_VULN)

        cwe_str = (meta.get("cwe") or "").strip()
        cwe = None
        if cwe_str:
            m = CWE_RE.search(cwe_str)
            if m:
                cwe = f"CWE-{int(m.group(1))}"

        # Extract code blocks from all assistant responses
        all_blocks = []
        for conv in d.get("conversations", []):
            if conv.get("role") == "assistant":
                content = conv.get("content", "")
                blocks = CODE_BLOCK_RE.findall(content)
                for blang, bcode in blocks:
                    lang_norm = LANG_MAP.get(blang.strip().lower(), "text")
                    if lang_norm == "text":
                        continue
                    code = bcode.strip()
                    if len(code) >= 30:
                        all_blocks.append((lang_norm, code))

        if not all_blocks and is_vuln:
            stats.skipped_no_code += 1
            continue
        if not all_blocks:
            stats.skipped_no_code += 1
            continue

        # First code block = vulnerable, last = fixed (if different)
        first_lang, first_code = all_blocks[0]
        last_lang, last_code = all_blocks[-1]

        vuln_code = first_code[:8000]
        patched = last_code[:8000] if (last_code != first_code and is_vuln) else None

        context = d.get("context", {})
        desc = (context.get("description") or d.get("id", "")).strip()[:2000]
        impact = (context.get("impact") or "").strip()[:1000]

        explanation = f"AI Security: {desc} (Impact: {impact})" if impact else f"AI Security: {desc}"
        attack_scenario = f"OWASP category: {cat}. {desc}" if is_vuln else ""
        fix_desc = f"Secure implementation for {cwe or 'AI safety'} vulnerability." if is_vuln else "Secure AI implementation."

        source = f"securecode_aiml:{d.get('id', 'unknown')}"
        sev = "critical" if is_vuln else "clean"

        try:
            yield SecuritySample.build(
                language=language if language != "text" else first_lang,
                vulnerable_code=vuln_code,
                patched_code=patched,
                cwe=cwe if is_vuln else None,
                severity=sev,
                explanation=explanation[:5000],
                attack_scenario=attack_scenario[:3000],
                secure_fix=fix_desc[:3000],
                source=source,
                source_license="MIT",
                is_vulnerable=is_vuln,
                split="train",
            )
        except Exception as e:
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
