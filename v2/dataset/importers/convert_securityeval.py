"""
RakshakAI v2 — SecurityEval converter (updated for s2e-lab/SecurityEval on HF).

Reads raw SecurityEval JSONL and converts to SecuritySample JSONL.

Schema:
  - ID (format: CWE-XXX_author_N.py), Prompt, Insecure_code
  - No patched code in v2.1

Output: v2/inputs/datasets/raw/securityeval_converted.jsonl
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from v2.dataset.schema import SecuritySample  # noqa: E402


CWE_PATTERN = re.compile(r"CWE-(\d+)")


def extract_cwe(sample_id: str) -> str | None:
    m = CWE_PATTERN.search(sample_id)
    if m:
        return f"CWE-{m.group(1)}"
    return None


def main():
    in_path = Path("v2/inputs/datasets/raw/securityeval.jsonl")
    out_path = Path("v2/inputs/datasets/raw/securityeval_converted.jsonl")

    samples = []
    stats = {"read": 0, "converted": 0, "skipped_no_cwe": 0, "skipped_too_short": 0}

    with in_path.open("r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            stats["read"] += 1
            row = json.loads(line)

            sid = row.get("ID", "")
            prompt = row.get("Prompt", "")
            code = (row.get("Insecure_code") or "").strip()

            if len(code) < 30:
                stats["skipped_too_short"] += 1
                continue

            cwe = extract_cwe(sid)
            if not cwe:
                stats["skipped_no_cwe"] += 1
                continue

            try:
                s = SecuritySample.build(
                    language="python",
                    vulnerable_code=code[:8000],
                    patched_code=None,
                    cwe=cwe,
                    severity="high",
                    explanation=prompt[:1500] or f"SecurityEval test case {sid}",
                    attack_scenario=f"Standard CWE-{cwe.split('-')[-1]} attack using the vulnerable code pattern.",
                    secure_fix="Review input handling and apply context-appropriate neutralization.",
                    source=f"securityeval:{sid}",
                    source_license="MIT",
                    split="train",
                )
                samples.append(s)
                stats["converted"] += 1
            except Exception:
                continue

    with out_path.open("w") as f:
        for s in samples:
            f.write(json.dumps(s.to_dict(), ensure_ascii=False) + "\n")

    print(f"[securityeval] converted {stats['converted']}/{stats['read']} samples -> {out_path}")
    for k, v in stats.items():
        if k != "converted":
            print(f"  {k}: {v}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
