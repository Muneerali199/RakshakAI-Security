"""
RakshakAI v2 — Extract non-vulnerable samples from raw Devign, PrimeVul, BigVul.

These raw datasets contain both vulnerable (target=1/vul=1) and non-vulnerable
(target=0/vul=0) code. The existing pipeline only converts the vulnerable side;
this script extracts the non-vulnerable half as SecuritySample records.

Output: v2/inputs/datasets/nonvuln/<source>.jsonl
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from v2.dataset.schema import SecuritySample  # noqa: E402

RAW = Path("v2/inputs/datasets/raw")
OUT = Path("v2/inputs/datasets/nonvuln")


def _extract_devign():
    """Extract target=0 (non-vulnerable) from Devign."""
    in_path = RAW / "devign.jsonl"
    out_path = OUT / "devign.jsonl"
    out_path.parent.mkdir(parents=True, exist_ok=True)

    samples = []
    with in_path.open() as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            if row.get("target", 0) != 0:
                continue
            func = (row.get("func") or "").strip()
            if len(func) < 30:
                continue
            project = row.get("project", "")
            commit = row.get("commit_id", "")
            s = SecuritySample.build(
                language="c",
                vulnerable_code=func[:8000],
                patched_code=None,
                cwe=None,
                severity="clean",
                explanation="Non-vulnerable code sample from Devign.",
                attack_scenario="No attack scenario — code is not vulnerable.",
                secure_fix="Not applicable — code is secure.",
                source=f"devign:{project}:{commit[:12] if commit else 'unknown'}",
                source_license="MIT",
                is_vulnerable=False,
                split="train",
            )
            samples.append(s)

    with out_path.open("w") as f:
        for s in samples:
            f.write(json.dumps(s.to_dict(), ensure_ascii=False) + "\n")
    print(f"[devign] extracted {len(samples)} non-vuln samples -> {out_path}")
    return len(samples)


def _extract_primevul(max_samples: int = 50000):
    """Extract target=0 (benign) from PrimeVul, up to max_samples."""
    in_path = RAW / "primevul.jsonl"
    out_path = OUT / "primevul.jsonl"

    samples = []
    with in_path.open() as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            if len(samples) >= max_samples:
                break
            row = json.loads(line)
            if row.get("target", 0) != 0:
                continue
            func = (row.get("func") or "").strip()
            if len(func) < 30:
                continue
            cwes = row.get("cwes") or []
            cve = row.get("cve") or ""
            project = row.get("project") or ""
            cve_desc = row.get("cve_desc") or ""
            s = SecuritySample.build(
                language="c",
                vulnerable_code=func[:8000],
                patched_code=None,
                cwe=None,
                severity="clean",
                explanation="Non-vulnerable code sample from PrimeVul.",
                attack_scenario="No attack scenario — code is not vulnerable.",
                secure_fix="Not applicable — code is secure.",
                source=f"primevul:{cve}" if cve else f"primevul:{project}",
                source_license="MIT",
                is_vulnerable=False,
                split="train",
            )
            samples.append(s)

    with out_path.open("w") as f:
        for s in samples:
            f.write(json.dumps(s.to_dict(), ensure_ascii=False) + "\n")
    print(f"[primevul] extracted {len(samples)} non-vuln samples -> {out_path}")
    return len(samples)


def _extract_bigvul(max_samples: int = 50000):
    """Extract vul=0 from BigVul, up to max_samples."""
    in_path = RAW / "bigvul.jsonl"
    out_path = OUT / "bigvul.jsonl"

    samples = []
    with in_path.open() as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            if len(samples) >= max_samples:
                break
            row = json.loads(line)
            if row.get("vul", 0) != 0:
                continue
            func = (row.get("func_before") or "").strip()
            if len(func) < 30:
                continue
            lang_raw = row.get("lang", "").strip().lower()
            lang_map = {"c": "c", "c++": "cpp", "cpp": "cpp"}
            language = lang_map.get(lang_raw, lang_raw) if lang_raw else "c"
            cwe_id = row.get("CWE ID") or ""
            project = row.get("project", "")
            cve = row.get("CVE ID", "")
            s = SecuritySample.build(
                language=language,
                vulnerable_code=func[:8000],
                patched_code=None,
                cwe=None,
                severity="clean",
                explanation="Non-vulnerable code sample from BigVul.",
                attack_scenario="No attack scenario — code is not vulnerable.",
                secure_fix="Not applicable — code is secure.",
                source=f"bigvul:{cve}" if cve else f"bigvul:{project}",
                source_license="MIT",
                is_vulnerable=False,
                split="train",
            )
            samples.append(s)

    with out_path.open("w") as f:
        for s in samples:
            f.write(json.dumps(s.to_dict(), ensure_ascii=False) + "\n")
    print(f"[bigvul] extracted {len(samples)} non-vuln samples -> {out_path}")
    return len(samples)


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    total = 0
    total += _extract_devign()
    total += _extract_primevul(max_samples=100000)
    total += _extract_bigvul(max_samples=80000)
    print(f"\nTotal non-vuln samples extracted: {total}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
