"""
RakshakAI v2 — Cost estimator.

Given a model size, sequence length, batch size, and number of steps,
estimate GPU hours and dollar cost across common MI300X cloud rates.

Usage:
    python v2/scripts/cost_estimate.py \
        --model 7B --seq 4096 --micro-bs 8 --grad-accum 4 \
        --steps 4000 --rate 2.00
"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass


@dataclass
class Estimate:
    model: str
    seq: int
    micro_bs: int
    grad_accum: int
    eff_bs: int
    steps: int
    tokens_processed: int
    gpu_hours: float
    cost_usd: float
    rate_usd_per_hr: float


# Empirical tokens/sec on 1× MI300X (QLoRA, NF4, bs 8, seq 4096, flash-attn 2)
# Calibrated against published QLoRA + MI300X community numbers, 2024-2025.
# Numbers rounded conservatively (× 0.85) to account for data-loader variance.
TOKENS_PER_SEC = {
    "7B":  18_000,
    "14B": 9_500,
    "32B": 4_500,
    "72B": 1_800,
}


def estimate(model: str, seq: int, micro_bs: int, grad_accum: int,
             steps: int, rate_usd_per_hr: float) -> Estimate:
    if model not in TOKENS_PER_SEC:
        raise ValueError(f"unknown model size: {model}")
    tps = TOKENS_PER_SEC[model]
    eff_bs = micro_bs * grad_accum
    toks_per_step = eff_bs * seq
    total_tokens = toks_per_step * steps
    seconds = total_tokens / tps
    hours = seconds / 3600.0
    cost = hours * rate_usd_per_hr
    return Estimate(
        model=model, seq=seq, micro_bs=micro_bs, grad_accum=grad_accum,
        eff_bs=eff_bs, steps=steps, tokens_processed=total_tokens,
        gpu_hours=hours, cost_usd=cost, rate_usd_per_hr=rate_usd_per_hr,
    )


def render(e: Estimate) -> str:
    return f"""
RakshakAI v2 cost estimate
--------------------------
Model              : {e.model} (Qwen2.5-Coder QLoRA, MI300X)
Sequence length    : {e.seq} tokens
Micro batch        : {e.micro_bs}
Gradient accum     : {e.grad_accum}
Effective batch    : {e.eff_bs} sequences / step
Steps              : {e.steps}
Tokens processed   : {e.tokens_processed / 1e6:.1f} M
GPU hours          : {e.gpu_hours:.2f}
Rate               : $ {e.rate_usd_per_hr:.2f} / hr
ESTIMATED COST     : $ {e.cost_usd:.2f}
"""


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", choices=list(TOKENS_PER_SEC), default="7B")
    ap.add_argument("--seq", type=int, default=4096)
    ap.add_argument("--micro-bs", type=int, default=8)
    ap.add_argument("--grad-accum", type=int, default=4)
    ap.add_argument("--steps", type=int, default=4000)
    ap.add_argument("--rate", type=float, default=2.00,
                    help="USD per GPU hour on the chosen MI300X provider")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    e = estimate(args.model, args.seq, args.micro_bs, args.grad_accum,
                 args.steps, args.rate)
    if args.json:
        print(json.dumps(e.__dict__, indent=2))
    else:
        print(render(e))
    return 0


if __name__ == "__main__":
    sys.exit(main())
