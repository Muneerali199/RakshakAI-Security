"""
RakshakAI v2 — Merge a trained LoRA adapter into the base model in bf16.

This produces a single safetensors model that can be:
  - served with vLLM directly
  - quantized to AWQ for cheap GPU serving
  - exported to GGUF for CPU inference
  - further fine-tuned
"""
from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

import torch
from peft import PeftModel
from transformers import AutoModelForCausalLM, AutoTokenizer


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", required=True, help="base model id or local path")
    ap.add_argument("--adapter", required=True, help="LoRA adapter directory")
    ap.add_argument("--out", required=True, help="output directory")
    ap.add_argument("--dtype", default="bfloat16", choices=["bfloat16", "float16"])
    args = ap.parse_args()

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    dtype = torch.bfloat16 if args.dtype == "bfloat16" else torch.float16

    print(f"[merge] loading base {args.base} in {dtype}")
    base = AutoModelForCausalLM.from_pretrained(
        args.base,
        torch_dtype=dtype,
        device_map="cpu",            # do not OOM the GPU during merge
        trust_remote_code=True,
    )
    print(f"[merge] loading adapter {args.adapter}")
    model = PeftModel.from_pretrained(base, args.adapter)
    print("[merge] merging weights")
    model = model.merge_and_unload()

    print(f"[merge] saving to {out}")
    model.save_pretrained(out, safe_serialization=True, max_shard_size="5GB")

    tok = AutoTokenizer.from_pretrained(args.base, trust_remote_code=True)
    tok.save_pretrained(out)

    # copy any generation_config.json from base if present
    for fn in ("generation_config.json",):
        src = Path(args.base) / fn
        if src.exists():
            shutil.copy(src, out / fn)

    (out / "rakshakai-v2.manifest.json").write_text(json.dumps({
        "base": args.base,
        "adapter": str(args.adapter),
        "dtype": args.dtype,
        "merged_at": str(out),
    }, indent=2))

    print("[merge] done.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
