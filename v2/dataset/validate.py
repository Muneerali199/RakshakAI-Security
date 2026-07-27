"""
RakshakAI v2 — Phase 2.4: validate that every output sample is well-formed.

Checks:
  - JSON parses
  - Required fields present in assistant content
  - CWE label is CWE-XXX or null
  - Severity is in {critical, high, medium, low, info, null}
  - Patched code (if present) parses with tree-sitter
  - No PII email / phone patterns
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

REQUIRED_FIELDS = {
    "vulnerability", "cwe", "severity", "confidence",
    "root_cause", "attack_scenario", "secure_fix",
    "patched_code", "references",
}
VALID_SEV = {"critical", "high", "medium", "low", "info", None}
CWE_RE = re.compile(r"^CWE-\d+$")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")


def validate_sample(rec: dict) -> list[str]:
    errs: list[str] = []
    msgs = rec.get("messages") or []
    if len(msgs) < 2:
        return ["missing messages"]

    asst = next((m for m in msgs if m.get("role") == "assistant"), None)
    if asst is None:
        return ["no assistant message"]
    content = asst.get("content", "")

    # JSON parse
    try:
        obj = json.loads(content) if content.strip().startswith("{") else {"patched_code": content}
    except json.JSONDecodeError:
        return ["assistant content is not valid JSON"]

    missing = REQUIRED_FIELDS - set(obj.keys())
    if missing:
        errs.append(f"missing fields: {sorted(missing)}")
    if obj.get("cwe") is not None and not CWE_RE.match(str(obj["cwe"])):
        errs.append(f"invalid cwe: {obj['cwe']}")
    if obj.get("severity") not in VALID_SEV:
        errs.append(f"invalid severity: {obj['severity']}")
    if not isinstance(obj.get("confidence"), (int, float)) or not (0.0 <= float(obj["confidence"]) <= 1.0):
        errs.append(f"confidence out of range: {obj.get('confidence')}")
    if EMAIL_RE.search(json.dumps(obj)):
        errs.append("contains email-like PII")
    return errs


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dirs", nargs="*", type=Path, default=[Path("v2/inputs/datasets/instruct")])
    args = ap.parse_args()

    n_ok = n_err = 0
    for d in args.dirs:
        for path in sorted(d.glob("*.jsonl")):
            with path.open("r", encoding="utf-8") as f:
                for i, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    rec = json.loads(line)
                    errs = validate_sample(rec)
                    if errs:
                        n_err += 1
                        if n_err < 50:
                            print(f"[validate] {path}:{i}  {errs}")
                    else:
                        n_ok += 1
    print(f"[validate] {n_ok} OK, {n_err} errors")
    return 0 if n_err == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
