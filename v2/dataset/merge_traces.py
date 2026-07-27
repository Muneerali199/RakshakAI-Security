#!/usr/bin/env python3
"""Merge generated reasoning traces back into original records for SFT.

Usage:
  python v2/dataset/merge_traces.py \\
      --traces v2/inputs/datasets/reasoning_traces.jsonl \\
      --data v2/inputs/datasets/instruct_quality/train.jsonl \\
      --output v2/inputs/datasets/sft_ready.jsonl \\
      --poc-eval v2/inputs/datasets/poc_eval_results.jsonl \\
      --min-poc-score 12
"""
import json
import os
import re
import sys
from pathlib import Path
from collections import Counter


def load_traces(path):
    index = {}
    with open(path) as f:
        for line in f:
            d = json.loads(line)
            index[d["id"]] = d
    return index


def load_poc_eval(path):
    index = {}
    if os.path.exists(path):
        with open(path) as f:
            for line in f:
                d = json.loads(line)
                index[d["id"]] = d
    return index


def extract_code(user_msg):
    m = re.search(r'```\w*\n(.*?)```', user_msg, re.DOTALL)
    return m.group(1).strip() if m else user_msg[:2000]


def build_sft_record(original, trace, poc_eval=None):
    """Combine original record with reasoning trace into SFT format."""
    meta = original.get("_meta", {})
    msgs = original.get("messages", [])

    user_msg = msgs[1]["content"] if len(msgs) >= 2 else ""
    assistant_msg = msgs[2]["content"] if len(msgs) >= 3 else ""

    reasoning = trace.get("reasoning", "")
    poc = trace.get("poc", "N/A")

    poc_score = None
    if poc_eval:
        poc_score = poc_eval.get("total_score")

    sft = {
        "id": trace["id"],
        "cve": meta.get("cve"),
        "cwe": trace.get("cwe", meta.get("cwe")),
        "language": trace.get("language", meta.get("language")),
        "task": trace.get("task", meta.get("task")),
        "source": meta.get("source"),
        "question": user_msg,
        "original_response": assistant_msg,
        "reasoning": reasoning,
        "poc": poc,
        "poc_score": poc_score,
        "tokens_in": trace.get("tokens_in"),
        "tokens_out": trace.get("tokens_out"),
    }
    return sft


def build_chat_format(sft_record):
    """Convert to LLaMA-Factory chat format for fine-tuning."""
    system = "You are a security analyst specializing in C/C++ vulnerability analysis."
    user = sft_record["question"]

    reasoning = sft_record.get("reasoning", "")
    poc = sft_record.get("poc", "N/A")

    # Combine reasoning + PoC into assistant response
    response = json.dumps({
        "reasoning": reasoning,
        "poc": poc,
    }, ensure_ascii=False)

    return {
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
            {"role": "assistant", "content": response},
        ]
    }


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--traces", default="v2/inputs/datasets/reasoning_traces.jsonl")
    parser.add_argument("--data", default="v2/inputs/datasets/instruct_quality/train.jsonl")
    parser.add_argument("--output", default="v2/inputs/datasets/sft_ready.jsonl")
    parser.add_argument("--poc-eval", default="v2/inputs/datasets/poc_eval_results.jsonl")
    parser.add_argument("--min-poc-score", type=int, default=None)
    parser.add_argument("--format", choices=["sft", "chat"], default="sft",
                       help="Output format: 'sft' (flat) or 'chat' (LLaMA-Factory)")
    args = parser.parse_args()

    print("Loading traces...", flush=True)
    traces = load_traces(args.traces)
    print(f"  {len(traces)} traces loaded", flush=True)

    print("Loading PoC eval...", flush=True)
    poc_evals = load_poc_eval(args.poc_eval)
    print(f"  {len(poc_evals)} PoC evals loaded", flush=True)

    print("Loading original data and merging...", flush=True)
    stats = Counter()
    out = []
    with open(args.data) as f:
        for line in f:
            d = json.loads(line)
            meta = d.get("_meta", {})
            rid = meta.get("id", "")
            if not rid or rid not in traces:
                continue

            trace = traces[rid]
            pe = poc_evals.get(rid)

            # Filter by minimum PoC score
            if args.min_poc_score and pe:
                if pe.get("total_score", 0) < args.min_poc_score:
                    stats["filtered_low_poc"] += 1
                    continue

            sft = build_sft_record(d, trace, pe)
            out.append(sft)

            lang = trace.get("language", "?")
            cwe = trace.get("cwe", "?")
            stats[f"lang_{lang}"] += 1
            stats[f"cwe_{cwe}"] += 1
            stats[f"task_{trace.get('task','?')}"] += 1

    print(f"  Merged {len(out)} records", flush=True)
    print(f"  Stats: {dict(stats.most_common(15))}", flush=True)

    print(f"Writing to {args.output}...", flush=True)
    with open(args.output, "w") as f:
        for rec in out:
            if args.format == "chat":
                rec = build_chat_format(rec)
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")

    print(f"Done! {len(out)} records written to {args.output}", flush=True)


if __name__ == "__main__":
    main()
