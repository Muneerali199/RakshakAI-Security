"""
RakshakAI v2 — BigVul converter.

Reads raw BigVul JSONL from HuggingFace and converts to SecuritySample JSONL.

BigVul schema:
  - CVE ID, CWE ID, func_before (vulnerable), func_after (patched)
  - lang, vul (label), project, commit_id, codeLink

Output: v2/inputs/datasets/raw/bigvul_converted.jsonl
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from v2.dataset.schema import SecuritySample  # noqa: E402

LANG_MAP = {
    "C": "c",
    "C++": "cpp",
    "Java": "java",
    "Python": "python",
    "JavaScript": "javascript",
    "PHP": "php",
    "Ruby": "ruby",
    "Go": "go",
    "Rust": "rust",
    "C#": "csharp",
    "Kotlin": "kotlin",
    "TypeScript": "typescript",
    "Swift": "swift",
}

def main():
    in_path = Path("v2/inputs/datasets/raw/bigvul.jsonl")
    out_path = Path("v2/inputs/datasets/raw/bigvul_converted.jsonl")

    samples = []
    stats = {"read": 0, "converted": 0, "skipped_no_cwe": 0, "skipped_no_code": 0, "skipped_too_short": 0}

    with in_path.open("r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            stats["read"] += 1
            row = json.loads(line)

            cwe_raw = row.get("CWE ID") or ""
            func_before = row.get("func_before") or ""
            func_after = row.get("func_after")
            lang_raw = row.get("lang") or "C"
            vul = row.get("vul")
            cve_id = row.get("CVE ID") or ""

            cwe = cwe_raw.strip()
            if not cwe:
                stats["skipped_no_cwe"] += 1
                continue

            code = func_before.strip()
            if len(code) < 30:
                stats["skipped_too_short"] += 1
                continue

            lang = LANG_MAP.get(lang_raw, "c")

            patched = func_after.strip() if func_after and func_after.strip() else None

            explanation = row.get("commit_message", "")[:1500] if row.get("commit_message") else f"BigVul entry for {cve_id}"

            try:
                s = SecuritySample.build(
                    language=lang,
                    vulnerable_code=code[:8000],
                    patched_code=patched[:8000] if patched else None,
                    cwe=cwe,
                    severity="high",
                    explanation=explanation,
                    attack_scenario=f"CVE {cve_id} vulnerability in {row.get('project', 'unknown')}: {explanation}",
                    secure_fix=patched or "Review and apply standard security fixes for this CWE.",
                    source=f"bigvul:{cve_id}",
                    source_license="MIT",
                    split="train",
                )
                samples.append(s)
                stats["converted"] += 1
            except Exception:
                stats["skipped_no_code"] += 1

    with out_path.open("w") as f:
        for s in samples:
            f.write(json.dumps(s.to_dict(), ensure_ascii=False) + "\n")

    print(f"[bigvul] converted {stats['converted']}/{stats['read']} samples -> {out_path}")
    for k, v in stats.items():
        if k != "converted":
            print(f"  {k}: {v}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
