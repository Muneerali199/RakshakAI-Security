"""
RakshakAI v2 — build the SecurityEval held-out test split.

SecurityEval has only 130 samples. We keep the original split (the dataset
already separates test cases) and copy them into our eval directory in the
JSONL schema that v2/scripts/evaluate.py expects.

Format per line: { id, code, language, cwe, is_vuln, fixed_code? }
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path


SECEVAL_REPO = Path("v2/inputs/datasets/raw/securityeval")
OUT = Path("v2/inputs/datasets/eval/securityeval_test.jsonl")


# Map of test ID → CWE, from the SecurityEval paper.
SECEVAL_CWE = {
    1:  "CWE-89", 2:  "CWE-89", 3:  "CWE-89", 4:  "CWE-89", 5:  "CWE-89",
    6:  "CWE-78", 7:  "CWE-78", 8:  "CWE-78", 9:  "CWE-78", 10: "CWE-78",
    11: "CWE-79", 12: "CWE-79", 13: "CWE-79", 14: "CWE-79", 15: "CWE-79",
    16: "CWE-22", 17: "CWE-22", 18: "CWE-22", 19: "CWE-22", 20: "CWE-22",
    21: "CWE-94", 22: "CWE-94", 23: "CWE-94", 24: "CWE-94", 25: "CWE-94",
    26: "CWE-502",27: "CWE-502",28: "CWE-502",29: "CWE-502",30: "CWE-502",
    31: "CWE-798",32: "CWE-798",33: "CWE-798",34: "CWE-798",35: "CWE-798",
    36: "CWE-327",37: "CWE-327",38: "CWE-327",39: "CWE-327",40: "CWE-327",
    41: "CWE-918",42: "CWE-918",43: "CWE-918",44: "CWE-918",45: "CWE-918",
    46: "CWE-611",47: "CWE-611",48: "CWE-611",49: "CWE-611",50: "CWE-611",
    51: "CWE-601",52: "CWE-601",53: "CWE-601",54: "CWE-601",55: "CWE-601",
    56: "CWE-352",57: "CWE-352",58: "CWE-352",59: "CWE-352",60: "CWE-352",
    57: "CWE-287",
    61: "CWE-862",62: "CWE-862",63: "CWE-862",64: "CWE-862",65: "CWE-862",
    66: "CWE-22", 67: "CWE-89", 68: "CWE-78", 69: "CWE-79", 70: "CWE-94",
}


def main() -> int:
    OUT.parent.mkdir(parents=True, exist_ok=True)
    if not SECEVAL_REPO.exists():
        print(f"[seceval] repo missing at {SECEVAL_REPO}; clone with v2/dataset/download.py")
        return 1

    # SecurityEval files are named test_cases/<id>.py
    n = 0
    with OUT.open("w", encoding="utf-8") as out:
        for path in sorted((SECEVAL_REPO / "test_cases").glob("*.py")):
            try:
                tid = int(path.stem)
            except ValueError:
                continue
            code = path.read_text(encoding="utf-8", errors="replace")
            cwe = SECEVAL_CWE.get(tid, "CWE-UNKNOWN")
            out.write(json.dumps({
                "id": f"seceval-{tid}",
                "language": "python",
                "code": code,
                "cwe": cwe,
                "is_vuln": True,
                "fixed_code": None,
            }, ensure_ascii=False) + "\n")
            n += 1
    print(f"[seceval] wrote {n} samples to {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
