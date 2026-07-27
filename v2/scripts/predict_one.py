"""
RakshakAI v2 — Run a single held-out sample end-to-end through the trained model
and pretty-print the structured output. Useful for sanity-checking after a
training run without spinning up the full eval suite.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True, help="merged model path or AWQ path")
    ap.add_argument("--awq", action="store_true")
    ap.add_argument("--code", required=True)
    ap.add_argument("--language", default="python")
    args = ap.parse_args()

    sys.path.insert(0, str(Path(__file__).parent))
    from evaluate import V2Model

    m = V2Model(args.model, args.model if args.awq else None)
    user = (
        f"```{args.language}\n{args.code}\n```\n\n"
        "Analyze this snippet. Identify any vulnerability, classify its CWE, "
        "explain the root cause, describe a realistic attack scenario, propose a "
        "secure fix, and provide the patched code. Respond as JSON only."
    )
    out, dt = m.generate_json(user)
    print(f"// inference: {dt:.2f}s")
    print(json.dumps(out, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
