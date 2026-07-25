"""
RakshakAI v2 — Quantize a merged bf16 model to AWQ 4-bit for cheap vLLM serving.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True, help="path to merged bf16 model")
    ap.add_argument("--out", required=True, help="output dir for AWQ 4-bit")
    ap.add_argument("--bits", type=int, default=4)
    ap.add_argument("--group-size", type=int, default=128)
    ap.add_argument("--zero-point", action="store_true", default=True)
    args = ap.parse_args()

    from awq import AutoAWQForCausalLM
    from transformers import AutoTokenizer

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    print(f"[awq] loading {args.model}")
    model = AutoAWQForCausalLM.from_pretrained(args.model, safetensors=True)
    tok = AutoTokenizer.from_pretrained(args.model, trust_remote_code=True)

    quant_config = {
        "zero_point": args.zero_point,
        "q_group_size": args.group_size,
        "w_bit": args.bits,
        "version": "GEMM",
    }
    print(f"[awq] quantizing with {quant_config}")
    model.quantize(tok, quant_config=quant_config)

    print(f"[awq] saving to {out}")
    model.save_quantized(str(out))
    tok.save_pretrained(str(out))

    (out / "rakshakai-v2.awq.manifest.json").write_text(json.dumps({
        "source": args.model,
        "quant_config": quant_config,
    }, indent=2))

    print("[awq] done.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
