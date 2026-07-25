"""
RakshakAI v2 — Phase 3 (continued): Pack instruction JSONL into 4096-token shards
for Axolotl + flash-attn sample packing.

Writes:
  v2/inputs/datasets/pack/<phase>.jsonl
  v2/inputs/datasets/pack/<phase>_prepared/  (tokenized arrow shards)
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

from transformers import AutoTokenizer

DEFAULT_MODEL = os.environ.get("RAKSHAK_BASE", "Qwen/Qwen2.5-Coder-7B-Instruct")
SEQ_LEN = 4096


def apply_chat_template(tokenizer, messages: list[dict[str, str]]) -> str:
    return tokenizer.apply_chat_template(
        messages,
        tokenize=False,
        add_generation_prompt=False,
    )


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--in_dir", type=Path, default=Path("v2/inputs/datasets/instruct"))
    ap.add_argument("--out_dir", type=Path, default=Path("v2/inputs/datasets/pack"))
    ap.add_argument("--tokenizer", default=DEFAULT_MODEL)
    ap.add_argument("--seq_len", type=int, default=SEQ_LEN)
    ap.add_argument("--phases", nargs="*", default=["phase_a", "phase_b", "phase_c"])
    args = ap.parse_args()
    args.out_dir.mkdir(parents=True, exist_ok=True)

    print(f"[pack] loading tokenizer: {args.tokenizer}")
    tok = AutoTokenizer.from_pretrained(args.tokenizer, trust_remote_code=True)
    if tok.pad_token is None:
        tok.pad_token = tok.eos_token

    for phase in args.phases:
        in_path = args.in_dir / f"{phase}.jsonl"
        if not in_path.exists():
            print(f"[pack] {phase}: missing {in_path}; skipping")
            continue

        out_path = args.out_dir / f"{phase}.jsonl"
        n = n_kept = 0
        n_too_long = 0
        with in_path.open("r", encoding="utf-8") as fi, out_path.open("w", encoding="utf-8") as fo:
            for line in fi:
                line = line.strip()
                if not line:
                    continue
                n += 1
                rec = json.loads(line)
                text = apply_chat_template(tok, rec["messages"])
                ids = tok(text, add_special_tokens=False).input_ids
                if len(ids) > args.seq_len:
                    n_too_long += 1
                    continue
                rec["_text"] = text
                fo.write(json.dumps(rec, ensure_ascii=False) + "\n")
                n_kept += 1
        print(f"[pack] {phase}: kept {n_kept}/{n} (dropped {n_too_long} > {args.seq_len} tokens)")

    return 0


if __name__ == "__main__":
    sys.exit(main())
