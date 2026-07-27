#!/usr/bin/env python3
"""Convert cleaned Phase B dataset to Axolotl chat format."""

import json, sys
from pathlib import Path

CLEAN_DIR = Path("v2/inputs/datasets/phase_b/cleaned")
OUT_DIR = Path("v2/inputs/datasets/axolotl")
OUT_DIR.mkdir(parents=True, exist_ok=True)

SYSTEM_PROMPT = """You are RakshakAI, an expert security code analyzer.
Analyze code for vulnerabilities. First reason step-by-step about the code's
security, then output valid JSON with keys:
is_vulnerable, cwe, severity, explanation, attack_scenario, secure_fix"""


def make_cot_trace(sample: dict) -> str:
    is_vuln = sample["is_vulnerable"]
    cwe = sample.get("cwe") or "None"
    return (
        "Step 1 — Language & Context: Identify code language and execution context.\n"
        "Step 2 — Data Flow: Trace user-controlled inputs through the code.\n"
        "Step 3 — Sink Analysis: Check for dangerous function calls or operations.\n"
        "Step 4 — CWE Mapping: Match patterns to known vulnerability classes.\n"
        f"Step 5 — Verdict: {'Vulnerability confirmed: ' + cwe if is_vuln else 'No vulnerability detected.'}"
    )


def to_axolotl(sample: dict) -> dict:
    answer = {
        "is_vulnerable": sample["is_vulnerable"],
        "cwe": sample.get("cwe"),
        "severity": sample.get("severity", "clean"),
        "explanation": sample.get("explanation", ""),
        "attack_scenario": sample.get("attack_scenario", ""),
        "secure_fix": sample.get("secure_fix", "Not applicable."),
    }
    code = sample["vulnerable_code"]
    lang = sample.get("language", "")
    cot = make_cot_trace(sample)

    return {
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": f"Analyze this code:\n\n```{lang}\n{code}\n```"},
            {"role": "assistant", "content": f"{cot}\n\n{json.dumps(answer, indent=2)}"},
        ]
    }


for split in ["train", "val", "test"]:
    in_path = CLEAN_DIR / f"{split}.jsonl"
    out_path = OUT_DIR / f"{split}.jsonl"
    count = 0

    with in_path.open() as f_in, out_path.open("w") as f_out:
        for line in f_in:
            sample = json.loads(line)
            f_out.write(json.dumps(to_axolotl(sample)) + "\n")
            count += 1

    print(f"  {split}: {count} samples")

print(f"\nAxolotl format ready → {OUT_DIR}/")