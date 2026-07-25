#!/usr/bin/env python3
"""Prepare merged training data: traces matched with original records + axolotl SFT.

Usage:
  python v2/dataset/prepare_training_data.py
"""
import json, re
from pathlib import Path
from collections import Counter

TRACES_PATH = "v2/inputs/datasets/reasoning_traces.jsonl"
ORIG_DATA = "v2/inputs/datasets/instruct_quality/train.jsonl"
AXOLOTL_TRAIN = "v2/inputs/datasets/axolotl/train_250k.jsonl"
AXOLOTL_VAL = "v2/inputs/datasets/axolotl/val.jsonl"
OUT_TRAIN = "v2/inputs/datasets/train_merged.jsonl"
OUT_VAL = "v2/inputs/datasets/val_merged.jsonl"

SYSTEM_PROMPT = "You are RakshakAI v2, a security-specialized code analysis model. Analyze the code snippet for security vulnerabilities."

def extract_code(user_msg):
    m = re.search(r'```\w*\n(.*?)```', user_msg, re.DOTALL)
    return m.group(1).strip() if m else user_msg[:2000]

def load_traces(path):
    index = {}
    with open(path) as f:
        for line in f:
            if line.strip():
                d = json.loads(line)
                index[d["id"]] = d
    return index

def build_chat_from_trace(original, trace):
    """Build ChatML record from original + trace."""
    meta = original.get("_meta", {})
    msgs = original.get("messages", [])

    user_msg = msgs[1]["content"] if len(msgs) >= 2 else ""
    lang = trace.get("language", meta.get("language", "c"))
    reasoning = trace.get("reasoning", "")
    poc = trace.get("poc", "")

    assistant_parts = []
    if reasoning:
        assistant_parts.append(reasoning)
    if poc and poc not in ("N/A", ""):
        assistant_parts.append(f"PoC:\n```{lang}\n{poc}\n```")

    if not assistant_parts:
        assistant_content = "No vulnerability detected."
    else:
        assistant_content = "\n\n".join(assistant_parts)

    return {
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_msg},
            {"role": "assistant", "content": assistant_content},
        ],
        "_meta": {
            "id": trace.get("id", meta.get("id", "")),
            "cwe": trace.get("cwe", meta.get("cwe", "")),
            "language": lang,
            "source": "reasoning_trace",
        }
    }

def main():
    print("Loading traces...")
    traces = load_traces(TRACES_PATH)
    print(f"  {len(traces)} traces loaded")

    print("Matching traces with original records...")
    matched = []
    stats = Counter()
    with open(ORIG_DATA) as f:
        for line in f:
            d = json.loads(line)
            meta = d.get("_meta", {})
            rid = meta.get("id", "")
            if rid and rid in traces:
                chat = build_chat_from_trace(d, traces[rid])
                matched.append(chat)
                stats["matched"] += 1
            if stats["matched"] >= len(traces):
                break

    print(f"  Matched {len(matched)} records")
    print(f"  CWE dist: {dict(Counter(t['_meta']['cwe'] for t in matched).most_common(10))}")

    print("Loading axolotl train_250k...")
    axolotl_train = []
    with open(AXOLOTL_TRAIN) as f:
        for line in f:
            if line.strip():
                axolotl_train.append(json.loads(line))
    print(f"  {len(axolotl_train)} SFT records loaded")

    # Merge: traces first (higher priority), then axolotl
    merged_train = matched + axolotl_train
    print(f"  Merged train: {len(merged_train)} records")

    with open(OUT_TRAIN, "w") as f:
        for rec in merged_train:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    print(f"  Written to {OUT_TRAIN}")

    # Copy val
    val_count = 0
    with open(AXOLOTL_VAL) as f:
        with open(OUT_VAL, "w") as fw:
            for line in f:
                if line.strip():
                    fw.write(line)
                    val_count += 1
    print(f"  Val set: {val_count} records -> {OUT_VAL}")
    print("\nDone! Ready for Lightning training.")

if __name__ == "__main__":
    main()
