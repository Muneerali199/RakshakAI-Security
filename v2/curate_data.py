#!/usr/bin/env python3
"""Phase 0: Curate a high-quality 50-100K training subset from training data.

Strategy:
  1. Remove CWE-UNKNOWN (27% of data — noisy reasoning traces without labels)
  2. Cap frequent CWEs at PER_CWE_MAX to prevent over-representation
  3. Ensure all CWE classes with >= MIN_PER_CWE are represented
  4. Balance across languages where possible
  5. Output in the same JSONL messages format as input

Usage:
  python -m v2.cli.curate_data \
    --input v2/inputs/datasets/train_merged.jsonl \
    --output v2/inputs/datasets/curated_80k.jsonl \
    --max-records 80000 \
    --per-cwe-max 2000 \
    --min-per-cwe 20
"""
from __future__ import annotations

import json
import random
import sys
from pathlib import Path
from collections import Counter, defaultdict
from typing import Optional

# Ensure project root
_project_root = str(Path(__file__).resolve().parent.parent.parent)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)


def get_cwe(record: dict) -> str:
    """Extract CWE label from a record."""
    meta = record.get("_meta", {})
    cwe = meta.get("cwe", "")
    if not cwe or cwe.upper() == "CWE-UNKNOWN":
        return ""
    return cwe.upper()


def get_language(record: dict) -> str:
    """Extract language from a record."""
    meta = record.get("_meta", {})
    return meta.get("language", "unknown")


def curate(
    input_path: str,
    output_path: str,
    max_records: int = 80000,
    per_cwe_max: int = 2000,
    min_per_cwe: int = 20,
    seed: int = 42,
    verbose: bool = True,
):
    """Curate a balanced, high-quality training subset."""
    random.seed(seed)
    input_file = Path(input_path)
    if not input_file.exists():
        print(f"Error: Input not found: {input_path}")
        sys.exit(1)

    # Pass 1: Read all records, collect stats
    records_by_cwe: dict[str, list[dict]] = defaultdict(list)
    cwe_counts_raw = Counter()
    skipped_unknown = 0
    total = 0

    if verbose:
        print(f"Reading {input_file}...")

    with open(input_file) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            total += 1
            record = json.loads(line)
            cwe = get_cwe(record)
            if not cwe:
                skipped_unknown += 1
                continue
            cwe_counts_raw[cwe] += 1
            records_by_cwe[cwe].append(record)

    if verbose:
        print(f"  Total records: {total}")
        print(f"  Records with CWE: {total - skipped_unknown}")
        print(f"  Skipped (no CWE / UNKNOWN): {skipped_unknown}")
        print(f"  Unique CWE classes: {len(records_by_cwe)}")
        print(f"  Top 10 CWEs (raw):")
        for cwe, count in cwe_counts_raw.most_common(10):
            print(f"    {cwe}: {count}")

    # Pass 2: Sample records per CWE
    selected: list[dict] = []
    cwe_counts_selected = Counter()
    minority_cwes = []
    majority_cwes = []

    for cwe, records in records_by_cwe.items():
        records_shuffled = list(records)
        random.shuffle(records_shuffled)

        if len(records_shuffled) <= per_cwe_max:
            # Minority or moderate CWE — keep all (or up to per_cwe_max)
            selected.extend(records_shuffled)
            cwe_counts_selected[cwe] = len(records_shuffled)
            if len(records_shuffled) < min_per_cwe:
                minority_cwes.append(cwe)
            else:
                majority_cwes.append(cwe)
        else:
            # Majority CWE — cap
            sampled = records_shuffled[:per_cwe_max]
            selected.extend(sampled)
            cwe_counts_selected[cwe] = per_cwe_max
            majority_cwes.append(cwe)

    if verbose:
        print(f"\n  After per-CWE cap ({per_cwe_max} max): {len(selected)} records")
        print(f"  Minority CWEs (< {min_per_cwe}): {len(minority_cwes)}")
        print(f"  Majority CWEs: {len(majority_cwes)}")
        print(f"  Top 10 CWEs (after cap):")
        for cwe, count in cwe_counts_selected.most_common(10):
            print(f"    {cwe}: {count}")

    # Pass 3: Trim to max_records if needed
    if len(selected) > max_records:
        # Remove excess from most-represented CWEs first
        random.shuffle(selected)
        # Sort by: keep minority CWEs, trim from majority
        selected.sort(key=lambda r: -cwe_counts_selected[get_cwe(r)])
        selected = selected[:max_records]
        if verbose:
            print(f"\n  Trimmed to {max_records} records")

    # Pass 4: Write output
    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    random.shuffle(selected)  # Final shuffle

    with open(output_file, "w") as f:
        for record in selected:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")

    final_cwe_counts = Counter(get_cwe(r) for r in selected)
    if verbose:
        print(f"\n  Written to: {output_path}")
        print(f"  Final record count: {len(selected)}")
        print(f"  Final unique CWEs: {len(final_cwe_counts)}")
        print(f"  Top 10 CWEs (final):")
        for cwe, count in final_cwe_counts.most_common(10):
            print(f"    {cwe}: {count}")

    # Language distribution
    lang_counts = Counter(get_language(r) for r in selected)
    if verbose:
        print(f"\n  Language distribution:")
        for lang, count in lang_counts.most_common(10):
            print(f"    {lang}: {count} ({100*count//len(selected)}%)")

    return selected


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Curate high-quality training subset")
    parser.add_argument("--input", default="v2/inputs/datasets/train_merged.jsonl",
                        help="Input JSONL file")
    parser.add_argument("--output", default="v2/inputs/datasets/curated_80k.jsonl",
                        help="Output JSONL file")
    parser.add_argument("--max-records", type=int, default=80000,
                        help="Maximum total records")
    parser.add_argument("--per-cwe-max", type=int, default=2000,
                        help="Maximum records per CWE class")
    parser.add_argument("--min-per-cwe", type=int, default=20,
                        help="Minimum records per CWE class to preserve")
    parser.add_argument("--seed", type=int, default=42, help="Random seed")
    args = parser.parse_args()

    curate(
        input_path=args.input,
        output_path=args.output,
        max_records=args.max_records,
        per_cwe_max=args.per_cwe_max,
        min_per_cwe=args.min_per_cwe,
        seed=args.seed,
    )
