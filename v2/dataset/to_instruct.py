"""
RakshakAI v2 — Instruction-format converter (Task 5).

Converts every SecuritySample into a chat-template ``messages`` record
suitable for Axolotl SFT.  The output schema is::

    {
      "messages": [
        {"role": "system", "content": <system_prompt>},
        {"role": "user",   "content": <user_request>},
        {"role": "assistant", "content": <assistant_response>}
      ],
      "_meta": {<provenance fields>},
    }

Three task types are emitted per record (where applicable):

  * **report**  — given the code, produce the 9-field structured review
  * **fix**     — given the code, produce the patched code (and the review)
  * **explain** — given the code, explain the root cause and attack scenario
                  in natural language (no JSON envelope)

For samples without ``patched_code`` the fix task is skipped.

A *per-split* JSONL is written (``train.jsonl`` / ``val.jsonl`` /
``test.jsonl``) **plus** a combined ``all.jsonl`` for convenience.

Usage
-----
::

    python v2/dataset/to_instruct.py \\
        --in_dir v2/inputs/datasets/balanced \\
        --out_dir v2/inputs/datasets/instruct
"""
from __future__ import annotations

import argparse
import json
import random
import sys
from collections import Counter
from pathlib import Path
from typing import Iterable

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from v2.dataset.schema import SecuritySample  # noqa: E402


# ---------------------------------------------------------------------------
# System prompt
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = (
    "You are RakshakAI v2, a security-specialized code analysis model. "
    "When the user asks you to analyze a code snippet, you ALWAYS respond as a "
    "single JSON object with these exact fields:\n"
    '{\n'
    '  "vulnerability":   "<one-line human label or null>",\n'
    '  "cwe":             "<CWE-XXX or null>",\n'
    '  "severity":        "<critical|high|medium|low|info|null>",\n'
    '  "confidence":      <0.0..1.0>,\n'
    '  "explanation":     "<one paragraph>",\n'
    '  "attack_scenario": "<one paragraph>",\n'
    '  "secure_fix":      "<one paragraph>",\n'
    '  "patched_code":    "<full rewritten function or null>",\n'
    '  "references":      ["<CVE-...>", "<URL>", "..."]\n'
    "}\n"
    "NEVER add prose outside the JSON. NEVER omit fields. If the code is "
    "secure, return a JSON object with all fields set to null / 'clean'."
)


# ---------------------------------------------------------------------------
# Task builders
# ---------------------------------------------------------------------------


def _user_request(s: SecuritySample) -> str:
    return (
        f"Analyze the following `{s.language}` code for security vulnerabilities. "
        f"Identify the vulnerability, classify its CWE, explain the root cause, "
        f"describe a realistic attack scenario, propose a secure fix, and "
        f"provide the patched code. Respond as JSON only.\n\n"
        f"```{s.language}\n{s.vulnerable_code}\n```"
    )


def _report_response(s: SecuritySample) -> str:
    obj = {
        "vulnerability": _cwe_to_label(s.cwe),
        "cwe": s.cwe,
        "severity": s.severity or "info",
        "confidence": 0.9 if s.cwe and s.cwe != "CWE-UNKNOWN" else 0.5,
        "explanation": s.explanation or "No additional context available.",
        "attack_scenario": s.attack_scenario or "An attacker exploits the missing input handling.",
        "secure_fix": s.secure_fix or "Validate the input, apply context-appropriate neutralization, and add defence-in-depth controls.",
        "patched_code": s.patched_code,
        "references": _references(s),
    }
    return json.dumps(obj, indent=2)


def _fix_response(s: SecuritySample) -> str:
    obj = {
        "vulnerability": _cwe_to_label(s.cwe),
        "cwe": s.cwe,
        "severity": s.severity or "info",
        "confidence": 0.9,
        "explanation": s.explanation or "",
        "attack_scenario": s.attack_scenario or "",
        "secure_fix": s.secure_fix or "",
        "patched_code": s.patched_code,
        "references": _references(s),
    }
    return json.dumps(obj, indent=2)


def _explain_response(s: SecuritySample) -> str:
    # Natural-language alternative — no JSON envelope.
    parts = [
        f"This {s.language} snippet is vulnerable to **{_cwe_to_label(s.cwe)}** "
        f"(CWE-{s.cwe.split('-')[-1] if s.cwe else 'UNKNOWN'}, {s.severity or 'info'})."
        if s.cwe else f"This {s.language} snippet is **secure** as written.",
        s.explanation or "",
        s.attack_scenario or "",
        s.secure_fix or "",
    ]
    return "\n\n".join(p for p in parts if p)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


CWE_LABEL: dict[str, str] = {
    "CWE-22":  "Path Traversal",
    "CWE-77":  "Prompt Injection / Command Injection",
    "CWE-78":  "OS Command Injection",
    "CWE-79":  "Cross-Site Scripting (XSS)",
    "CWE-89":  "SQL Injection",
    "CWE-94":  "Code Injection / Server-Side Template Injection",
    "CWE-120": "Buffer Overflow",
    "CWE-190": "Integer Overflow",
    "CWE-200": "Information Exposure (Prompt Leakage)",
    "CWE-209": "Information Exposure Through Error Message",
    "CWE-250": "Execution with Unnecessary Privileges",
    "CWE-269": "Improper Privilege Management",
    "CWE-276": "Incorrect Default Permissions",
    "CWE-285": "Improper Authorization",
    "CWE-287": "Improper Authentication",
    "CWE-290": "Authentication Bypass by Spoofing",
    "CWE-295": "Improper Certificate Validation",
    "CWE-297": "Improper Validation of Certificate with Host Mismatch",
    "CWE-306": "Missing Authentication for Critical Function",
    "CWE-307": "Improper Restriction of Excessive Authentication Attempts",
    "CWE-311": "Missing Encryption of Sensitive Data",
    "CWE-319": "Cleartext Transmission of Sensitive Information",
    "CWE-321": "Use of Hard-coded Cryptographic Key",
    "CWE-322": "Key Exchange without Entity Authentication",
    "CWE-323": "Reusing a Nonce, Key Pair in Encryption",
    "CWE-325": "Missing Cryptographic Step",
    "CWE-326": "Inadequate Encryption Strength",
    "CWE-327": "Use of a Broken or Risky Cryptographic Algorithm",
    "CWE-328": "Reversible One-Way Hash",
    "CWE-329": "Not Using a Random IV with CBC Mode",
    "CWE-330": "Use of Insufficiently Random Values",
    "CWE-338": "Use of Cryptographically Weak PRNG",
    "CWE-345": "Insufficient Verification of Data Authenticity",
    "CWE-346": "Origin Validation Error",
    "CWE-347": "Improper Verification of Cryptographic Signature (JWT)",
    "CWE-348": "Use of Less Trusted Source",
    "CWE-349": "Acceptance of Extraneous Untrusted Data",
    "CWE-350": "Reliance on Reverse DNS Resolution for Security",
    "CWE-352": "Cross-Site Request Forgery (CSRF)",
    "CWE-362": "Race Condition",
    "CWE-367": "Time-of-Check Time-of-Use (TOCTOU)",
    "CWE-377": "Insecure Temporary File",
    "CWE-400": "Uncontrolled Resource Consumption",
    "CWE-416": "Use After Free",
    "CWE-434": "Unrestricted File Upload",
    "CWE-502": "Insecure Deserialization",
    "CWE-522": "Insufficiently Protected Credentials",
    "CWE-523": "Unprotected Credentials",
    "CWE-532": "Insertion of Sensitive Information into Log File",
    "CWE-540": "Inclusion of Sensitive Information in Source Code",
    "CWE-601": "URL Redirection to Untrusted Site (Open Redirect)",
    "CWE-611": "XML External Entity Reference (XXE)",
    "CWE-639": "Insecure Direct Object Reference (IDOR)",
    "CWE-642": "External Control of Critical State Data",
    "CWE-706": "Use of Incorrectly-Resolved Name or Reference",
    "CWE-707": "Improper Enforcement of Message Integrity",
    "CWE-749": "Exposed Dangerous Method or Function",
    "CWE-754": "Improper Check for Unusual Conditions",
    "CWE-770": "Allocation of Resources Without Limits",
    "CWE-776": "XML Entity Expansion (Billion Laughs)",
    "CWE-787": "Out-of-bounds Write",
    "CWE-789": "Memory Allocation with Excessive Size",
    "CWE-798": "Hardcoded Secret",
    "CWE-799": "Improper Control of Interaction Frequency",
    "CWE-829": "Inclusion of Functionality from Untrusted Control Sphere",
    "CWE-838": "Inappropriate Encoding for Output Context",
    "CWE-843": "Type Confusion",
    "CWE-862": "Missing Authorization",
    "CWE-863": "Incorrect Authorization",
    "CWE-915": "Improperly Controlled Modification of Dynamically-Determined Object Attributes",
    "CWE-918": "Server-Side Request Forgery (SSRF)",
    "CWE-1104": "Use of Unmaintained Third-Party Components (Supply Chain)",
    "CWE-1325": "Improperly Controlled Sequential Memory Allocation",
    "CWE-1333": "Inefficient Regular Expression Complexity (ReDoS)",
    "CWE-UNKNOWN": "Secure code (no vulnerability detected)",
}


def _cwe_to_label(cwe: str | None) -> str:
    if not cwe:
        return "Secure code (no vulnerability detected)"
    return CWE_LABEL.get(cwe, cwe)


def _references(s: SecuritySample) -> list[str]:
    refs: list[str] = []
    if s.cve:
        refs.append(s.cve)
    if s.cwe and s.cwe != "CWE-UNKNOWN":
        refs.append(f"https://cwe.mitre.org/data/definitions/{s.cwe.split('-')[-1]}.html")
    return refs


# ---------------------------------------------------------------------------
# Per-record conversion
# ---------------------------------------------------------------------------


def convert_record(s: SecuritySample, rng: random.Random) -> list[dict]:
    """Return a list of instruction records (1–3) for one sample."""
    out: list[dict] = []

    base_meta = {
        "id": s.id,
        "cwe": s.cwe,
        "severity": s.severity,
        "language": s.language,
        "source": s.source,
        "split": s.split,
    }

    # 1) report
    out.append({
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": _user_request(s)},
            {"role": "assistant", "content": _report_response(s)},
        ],
        "_meta": {**base_meta, "task": "report"},
    })

    # 2) fix-only — only when we have a fix
    if s.patched_code:
        out.append({
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": _user_request(s).replace(
                    "Respond as JSON only.",
                    "Rewrite this code to remove the vulnerability. "
                    "Output the complete patched function. Do not include "
                    "any other text.",
                )},
                {"role": "assistant", "content": f"```{s.language}\n{s.patched_code}\n```"},
            ],
            "_meta": {**base_meta, "task": "fix"},
        })

    # 3) explain — natural language (50% chance; with replacement)
    if rng.random() < 0.5:
        out.append({
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT.replace(
                    "When the user asks you to analyze a code snippet, you ALWAYS respond as a single JSON object with these exact fields:",
                    "When the user asks you to explain a code snippet, you respond in clear natural language with no JSON envelope.",
                )},
                {"role": "user", "content": _user_request(s).replace(
                    "Respond as JSON only.",
                    "Explain the issue, the attack scenario, and the fix in clear prose.",
                )},
                {"role": "assistant", "content": _explain_response(s)},
            ],
            "_meta": {**base_meta, "task": "explain"},
        })

    return out


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------


def _load(in_dir: Path) -> list[SecuritySample]:
    out: list[SecuritySample] = []
    for p in sorted(in_dir.glob("*.jsonl")):
        if p.name.startswith("_"):
            continue
        with p.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    d = json.loads(line)
                except json.JSONDecodeError:
                    continue
                s = SecuritySample.from_dict(d)
                if s.validate():
                    continue
                if s.split == "benchmark":
                    continue
                out.append(s)
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--in_dir", type=Path, default=Path("v2/inputs/datasets/balanced"))
    ap.add_argument("--out_dir", type=Path, default=Path("v2/inputs/datasets/instruct"))
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()
    args.out_dir.mkdir(parents=True, exist_ok=True)

    rng = random.Random(args.seed)

    samples = _load(args.in_dir)
    print(f"[instruct] loaded {len(samples)} samples from {args.in_dir}")

    # group by split
    by_split: dict[str, list[SecuritySample]] = {"train": [], "val": [], "test": []}
    for s in samples:
        by_split.setdefault(s.split, []).append(s)

    counts: Counter = Counter()
    for split, ss in by_split.items():
        out_path = args.out_dir / f"{split}.jsonl"
        n = 0
        with out_path.open("w", encoding="utf-8") as f:
            for s in ss:
                recs = convert_record(s, rng)
                for r in recs:
                    f.write(json.dumps(r, ensure_ascii=False) + "\n")
                    n += 1
                counts[split] += len(recs)
        print(f"  {split:5s}: {len(ss):>4} samples -> {n:>4} instruction records ({out_path})")

    # combined
    all_out = args.out_dir / "all.jsonl"
    n = 0
    with all_out.open("w", encoding="utf-8") as f:
        for split, ss in by_split.items():
            for s in ss:
                for r in convert_record(s, rng):
                    f.write(json.dumps(r, ensure_ascii=False) + "\n")
                    n += 1
    print(f"  all  : {n:>4} total instruction records -> {all_out}")

    # alias to the names requested in the task spec
    for src, dst in [("train.jsonl", "train.jsonl"),
                     ("val.jsonl",   "validation.jsonl"),
                     ("test.jsonl",  "test.jsonl")]:
        if dst != src:
            (args.out_dir / dst).write_bytes((args.out_dir / src).read_bytes())
            print(f"  alias: {src} -> {dst}")

    print(f"\n[instruct] total per-split:")
    for split, n in counts.most_common():
        print(f"  {split:5s}: {n}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
