"""
RakshakAI v2 — Devign converter.

Reads raw Devign JSONL from HuggingFace and converts to SecuritySample JSONL.

Devign schema:
  - func, target (0=clean, 1=vulnerable), project, commit_id
  - No CWE IDs available — we mark clean code as CWE-UNKNOWN
    and vulnerable code as CWE-119 (generic buffer/input issue).

Output: v2/inputs/datasets/raw/devign_converted.jsonl
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from v2.dataset.schema import SecuritySample  # noqa: E402


def main():
    in_path = Path("v2/inputs/datasets/raw/devign.jsonl")
    out_path = Path("v2/inputs/datasets/raw/devign_converted.jsonl")

    samples = []
    stats = {"read": 0, "converted": 0, "skipped_too_short": 0}

    with in_path.open("r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            stats["read"] += 1
            row = json.loads(line)

            func = (row.get("func") or "").strip()
            if len(func) < 30:
                stats["skipped_too_short"] += 1
                continue

            target = row.get("target", 0)
            project = row.get("project", "")
            commit_id = row.get("commit_id", "")

            is_vuln = target == 1

            cwe = "CWE-119" if is_vuln else "CWE-UNKNOWN"
            severity = "high" if is_vuln else "clean"

            try:
                s = SecuritySample.build(
                    language="c",
                    vulnerable_code=func[:8000],
                    patched_code=None,
                    cwe=cwe,
                    severity=severity,
                    explanation=(
                        f"Devign sample from {project} (commit {commit_id[:8]}). "
                        f"{'Vulnerable code' if is_vuln else 'Secure code'}."
                    )[:1500],
                    attack_scenario=(
                        f"Real-world CVE in {project}. "
                        "Exploitation depends on the specific memory safety issue."
                    ) if is_vuln else "No attack scenario — code is clean.",
                    secure_fix="Apply standard memory safety practices (bounds checks, safe functions)." if is_vuln else "No fix needed.",
                    source=f"devign:{project}:{commit_id[:12] if commit_id else 'unknown'}",
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

    print(f"[devign] converted {stats['converted']}/{stats['read']} samples -> {out_path}")
    for k, v in stats.items():
        if k != "converted":
            print(f"  {k}: {v}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
