"""
RakshakAI v2 — Convert instruct format to pack format with _text field.

The pack format adds a plain-text concatenation of messages using
the Qwen2.5-Coder chat template for sample packing in Axolotl.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

IN_DIR = Path("v2/inputs/datasets/phase_b/instruct")
OUT_DIR = Path("v2/inputs/datasets/phase_b/pack")


def _apply_chat_template(messages: list[dict]) -> str:
    """Convert messages dict list to Qwen2.5-Coder chat template."""
    parts = []
    for msg in messages:
        role = msg["role"]
        content = msg["content"]
        parts.append(f"<|im_start|>{role}\n{content}<|im_end|>")
    parts.append("<|im_start|>assistant\n")
    return "\n".join(parts)


def main():
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    for split in ["train", "val", "test", "all"]:
        in_path = IN_DIR / f"{split}.jsonl"
        out_path = OUT_DIR / f"{split}.jsonl"
        if not in_path.exists():
            print(f"[pack] {in_path} not found, skipping")
            continue

        n = 0
        with in_path.open("r") as fi, out_path.open("w") as fo:
            for line in fi:
                line = line.strip()
                if not line:
                    continue
                d = json.loads(line)
                messages = d.get("messages", [])
                text = _apply_chat_template(messages)
                d["_text"] = text
                fo.write(json.dumps(d, ensure_ascii=False) + "\n")
                n += 1

        print(f"[pack] wrote {n} samples -> {out_path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
