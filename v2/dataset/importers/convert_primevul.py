"""
RakshakAI v2 — PrimeVul converter (from HuggingFace).

Reads raw PrimeVul JSONL and converts to SecuritySample JSONL.

PrimeVul schema (colin/PrimeVul):
  - func (code), target (0=benign, 1=vulnerable)
  - cwes (list), cve, cve_desc, project, commit_url

Output: v2/inputs/datasets/raw/primevul_converted.jsonl
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from v2.dataset.schema import SecuritySample  # noqa: E402


def main():
    in_path = Path("v2/inputs/datasets/raw/primevul.jsonl")
    out_path = Path("v2/inputs/datasets/raw/primevul_converted.jsonl")

    if not in_path.exists():
        print("[primevul] no input file found, skipping")
        return 1

    samples = []
    stats = {"read": 0, "converted": 0, "skipped_no_cwe": 0, "skipped_too_short": 0}

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
            cwes = row.get("cwes") or []
            cve = row.get("cve") or ""
            cve_desc = row.get("cve_desc") or ""
            project = row.get("project") or ""

            # PrimeVul: target=1 is vulnerable, target=0 is benign
            is_vuln = target == 1

            if is_vuln and not cwes:
                stats["skipped_no_cwe"] += 1
                continue

            cwe = cwes[0] if cwes else "CWE-UNKNOWN"
            severity = "high" if is_vuln else "clean"

            explanation_parts = [cve_desc] if cve_desc else []
            if cve:
                explanation_parts.append(f"CVE: {cve}")
            explanation = " | ".join(explanation_parts)[:1500] or f"PrimeVul sample from {project}"

            try:
                s = SecuritySample.build(
                    language="c",
                    vulnerable_code=func[:8000],
                    patched_code=None,
                    cwe=cwe,
                    severity=severity,
                    explanation=explanation,
                    attack_scenario=cve_desc[:1500] if cve_desc else f"Vulnerability in {project} (CVE: {cve})",
                    secure_fix="Apply standard security fixes for this CWE type." if is_vuln else "No fix needed.",
                    source=f"primevul:{cve}" if cve else f"primevul:{project}",
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

    print(f"[primevul] converted {stats['converted']}/{stats['read']} samples -> {out_path}")
    for k, v in stats.items():
        if k != "converted":
            print(f"  {k}: {v}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
