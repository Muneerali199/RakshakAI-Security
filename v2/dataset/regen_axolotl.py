"""Regenerate corrupted axolotl train.jsonl from meta files."""
import json
from pathlib import Path

SYSTEM_PROMPT = (
    "You are RakshakAI v2, a security-specialized code analysis model."
    " Analyze the code snippet for security vulnerabilities."
)

meta_train = Path("inputs/datasets/phase_b/meta/train.jsonl")
axolotl_train = Path("v2/inputs/datasets/axolotl/train.jsonl")

count = 0
with open(axolotl_train, "w") as fout:
    for line in open(meta_train):
        s = json.loads(line)
        lang = s.get("language", "code")
        code = s.get("vulnerable_code", "")

        if s.get("is_vulnerable", True):
            cwe = s.get("cwe") or "CWE-UNKNOWN"
            sev = s.get("severity") or "high"
            expl = (s.get("explanation") or "").strip() or "Vulnerability detected."
            fix = (s.get("secure_fix") or "").strip() or "Apply standard security fixes."
            patched = (s.get("patched_code") or "").strip()

            cot_lines = [
                f"1. Vulnerability analysis: {cwe} - {expl}",
                f"2. Severity assessment: {sev}",
            ]
            if patched:
                cot_lines.append("3. Code fix: The vulnerable code should be rewritten.")
            cot_lines.append(f"4. Secure fix recommendation: {fix}")
            cot = "\n".join(cot_lines)

            result = {
                "is_vulnerable": True,
                "vulnerability_type": cwe,
                "severity": sev,
                "explanation": expl,
                "patched_code": patched if patched else None,
                "secure_fix_recommendation": fix,
            }
        else:
            cot = "1. Vulnerability analysis: No vulnerability detected.\n2. Severity assessment: clean"
            result = {
                "is_vulnerable": False,
                "vulnerability_type": None,
                "severity": "clean",
                "explanation": "Code appears to be secure.",
                "patched_code": None,
                "secure_fix_recommendation": "No fix needed.",
            }

        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {
                "role": "user",
                "content": (
                    f"Analyze the following {lang} code for security vulnerabilities:\n\n"
                    f"```{lang}\n{code}\n```"
                ),
            },
            {
                "role": "assistant",
                "content": (
                    f"Let me analyze this code step by step.\n\n{cot}\n\n{json.dumps(result, indent=2)}"
                ),
            },
        ]
        out = {
            "messages": messages,
            "_meta": {
                "cwe": s.get("cwe"),
                "severity": s.get("severity"),
                "language": lang,
                "source": s.get("source"),
                "is_vulnerable": s.get("is_vulnerable", True),
            },
        }
        fout.write(json.dumps(out, ensure_ascii=False) + "\n")
        count += 1

print(f"Regenerated: {count} samples, {axolotl_train.stat().st_size / 1e6:.1f} MB")
