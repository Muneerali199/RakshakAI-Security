"""Convert raw DPO pairs to axolotl-compatible format."""
import json
from pathlib import Path

SRC = Path("inputs/datasets/extra_vuln/dpo_pairs.jsonl")
OUT = Path("v2/inputs/datasets/axolotl")

SYSTEM_PROMPT = "You are RakshakAI v2, a security-specialized code analysis model. Analyze code for vulnerabilities and generate secure fixes."

pairs = []
with open(SRC) as f:
    for line in f:
        pairs.append(json.loads(line))

print(f"Loaded {len(pairs)} raw DPO pairs")

dpo_examples = []
for p in pairs:
    vuln = p.get("vulnerable_code", "")
    chosen = p.get("dpo_chosen", "")
    rejected = p.get("dpo_rejected", "")
    lang = p.get("language", "unknown")
    cwe = p.get("cwe", "CWE-UNKNOWN")

    user_msg = f"Analyze the following {lang} code for security vulnerabilities ({cwe}):\n\n```{lang}\n{vuln}\n```\n\nProvide a secure fix."

    dpo_examples.append({
        "chosen": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_msg},
            {"role": "assistant", "content": chosen},
        ],
        "rejected": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_msg},
            {"role": "assistant", "content": rejected},
        ],
        "_meta": {
            "cwe": cwe,
            "language": lang,
            "source": "dpo_pairs",
        }
    })

out_path = OUT / "dpo_train.jsonl"
with open(out_path, "w") as f:
    for ex in dpo_examples:
        f.write(json.dumps(ex) + "\n")

print(f"Wrote {len(dpo_examples)} DPO examples to {out_path}")

# Quick stats
cwes = {}
langs = {}
for ex in dpo_examples:
    m = ex["_meta"]
    cwes[m["cwe"]] = cwes.get(m["cwe"], 0) + 1
    langs[m["language"]] = langs.get(m["language"], 0) + 1
print(f"CWE count: {len(cwes)}")
print(f"Language count: {len(langs)}")
