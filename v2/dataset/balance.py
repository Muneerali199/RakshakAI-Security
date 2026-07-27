"""
RakshakAI v2 — Dataset balancing (Task 4).

The raw security corpus is heavily skewed: SQL injection, XSS, and command
injection dominate (they are the most common real-world CWEs *and* the
easiest to template-synthesize).

This module **caps** the per-(CWE, language, severity) count to a configurable
maximum, applies mild **upsampling** of long-tail CWE classes, and produces
a **stratified train/val/test split** that preserves class balance.

The split is deterministic and idempotent: the same input + the same seed
always produces the same output.

Usage
-----
::

    python v2/dataset/balance.py \\
        --in_dir v2/inputs/datasets/clean \\
        --out_dir v2/inputs/datasets/balanced \\
        --max-per-class 80 \\
        --test-frac 0.1 --val-frac 0.05

Outputs
-------
- per-source JSONL files in ``--out_dir`` with the ``split`` field
  populated.
- a stats report at ``v2/inputs/datasets/balanced/_balance_report.json``
- prints a class distribution table to stdout
"""
from __future__ import annotations

import argparse
import json
import random
import sys
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from v2.dataset.schema import SecuritySample  # noqa: E402


# ---------------------------------------------------------------------------
# Balancing policy
# ---------------------------------------------------------------------------

# CWE families that are *intentionally* over-represented in real data and
# need explicit down-sampling to prevent domination.
COMMON_CWES: frozenset[str] = frozenset({"CWE-89", "CWE-79", "CWE-78"})

# Default cap per (CWE, language) bucket before splitting.  With
# --max-per-class 80, a CWE-89/Python bucket is capped at 80 samples.
DEFAULT_MAX_PER_BUCKET = 80

# Minimum samples per CWE before we upsample (long-tail rescue).
MIN_SAMPLES_PER_CWE = 20


@dataclass
class BalanceStats:
    total_input: int
    total_output: int
    per_cwe: dict[str, int]
    per_language: dict[str, int]
    per_severity: dict[str, int]
    per_split: dict[str, int]
    downsample_caps_applied: dict[str, int]
    upsample_lifts_applied: dict[str, int]


def _bucket_key(s: SecuritySample) -> tuple[str, str]:
    return ((s.cwe or "CWE-UNKNOWN"), s.language)


# ---------------------------------------------------------------------------
# Balancing
# ---------------------------------------------------------------------------


def balance(
    samples: list[SecuritySample],
    *,
    max_per_bucket: int = DEFAULT_MAX_PER_BUCKET,
    min_per_cwe: int = MIN_SAMPLES_PER_CWE,
    test_frac: float = 0.10,
    val_frac: float = 0.05,
    seed: int = 42,
) -> list[SecuritySample]:
    """Apply cap, upsample, then stratified split.

    Returns a new list of samples (the input is not modified) with
    ``split`` set on each.
    """
    rng = random.Random(seed)

    # ── 1. cap per (CWE, language) bucket ──────────────────────────────
    buckets: dict[tuple[str, str], list[SecuritySample]] = defaultdict(list)
    for s in samples:
        buckets[_bucket_key(s)].append(s)
    capped: list[SecuritySample] = []
    cap_applied: dict[str, int] = {}
    for k, items in buckets.items():
        rng.shuffle(items)
        if len(items) > max_per_bucket:
            cap_applied[f"{k[0]}|{k[1]}"] = max_per_bucket
        capped.extend(items[:max_per_bucket])

    # ── 2. upsample long-tail CWEs that fell below the minimum ─────────
    by_cwe: dict[str, list[SecuritySample]] = defaultdict(list)
    for s in capped:
        by_cwe[s.cwe or "CWE-UNKNOWN"].append(s)
    upsampled: list[SecuritySample] = list(capped)
    lift_applied: dict[str, int] = {}
    for cwe, items in by_cwe.items():
        if 0 < len(items) < min_per_cwe and cwe not in COMMON_CWES:
            # repeat (with a deterministic shuffle) until we hit the min
            needed = min_per_cwe - len(items)
            extras = []
            for i in range(needed):
                extras.append(items[i % len(items)])
            upsampled.extend(extras)
            lift_applied[cwe] = needed

    # ── 3. stratified split (per CWE) ─────────────────────────────────
    final_by_cwe: dict[str, list[SecuritySample]] = defaultdict(list)
    for s in upsampled:
        final_by_cwe[s.cwe or "CWE-UNKNOWN"].append(s)

    out: list[SecuritySample] = []
    for cwe, items in final_by_cwe.items():
        rng.shuffle(items)
        n = len(items)
        n_test = max(1, int(round(n * test_frac)))
        n_val = max(1, int(round(n * val_frac))) if n >= 10 else 0
        for i, s in enumerate(items):
            if i < n_test:
                s.split = "test"
            elif i < n_test + n_val:
                s.split = "val"
            else:
                s.split = "train"
            out.append(s)

    return out


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------


def report_distribution(samples: list[SecuritySample]) -> BalanceStats:
    cwe: Counter = Counter()
    lang: Counter = Counter()
    sev: Counter = Counter()
    split: Counter = Counter()
    for s in samples:
        cwe[s.cwe or "CWE-UNKNOWN"] += 1
        lang[s.language] += 1
        sev[s.severity or "unknown"] += 1
        split[s.split] += 1
    return BalanceStats(
        total_input=0,
        total_output=len(samples),
        per_cwe=dict(cwe.most_common()),
        per_language=dict(lang.most_common()),
        per_severity=dict(sev.most_common()),
        per_split=dict(split.most_common()),
        downsample_caps_applied={},
        upsample_lifts_applied={},
    )


def render_distribution(stats: BalanceStats) -> str:
    out: list[str] = []
    out.append("")
    out.append("Class distribution after balancing")
    out.append("====================================")
    out.append(f"  total samples:    {stats.total_output}")
    out.append(f"  by CWE ({len(stats.per_cwe)} classes):")
    max_len = max((len(k) for k in stats.per_cwe), default=12)
    for cwe, n in sorted(stats.per_cwe.items(), key=lambda x: -x[1]):
        bar = "#" * min(60, n)
        out.append(f"    {cwe:<{max_len}}  {n:>5}  {bar}")
    out.append("")
    out.append(f"  by language ({len(stats.per_language)} langs):")
    for lang, n in sorted(stats.per_language.items(), key=lambda x: -x[1]):
        bar = "#" * min(60, n)
        out.append(f"    {lang:<12}  {n:>5}  {bar}")
    out.append("")
    out.append(f"  by severity ({len(stats.per_severity)} buckets):")
    for sev, n in sorted(stats.per_severity.items(), key=lambda x: -x[1]):
        bar = "#" * min(60, n)
        out.append(f"    {sev:<10}  {n:>5}  {bar}")
    out.append("")
    out.append(f"  by split:")
    for split, n in sorted(stats.per_split.items()):
        bar = "#" * min(60, n)
        out.append(f"    {split:<10}  {n:>5}  {bar}")
    return "\n".join(out)


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------


def _load(in_dir: Path) -> list[SecuritySample]:
    out: list[SecuritySample] = []
    for p in sorted(in_dir.glob("*.jsonl")):
        with p.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    d = json.loads(line)
                except json.JSONDecodeError:
                    continue
                s = SecuritySample.from_dict(d)
                if s.validate():
                    continue
                out.append(s)
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--in_dir", type=Path, default=Path("v2/inputs/datasets/clean"))
    ap.add_argument("--out_dir", type=Path, default=Path("v2/inputs/datasets/balanced"))
    ap.add_argument("--max-per-class", type=int, default=DEFAULT_MAX_PER_BUCKET)
    ap.add_argument("--min-per-cwe", type=int, default=MIN_SAMPLES_PER_CWE)
    ap.add_argument("--test-frac", type=float, default=0.10)
    ap.add_argument("--val-frac", type=float, default=0.05)
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    args.out_dir.mkdir(parents=True, exist_ok=True)
    print(f"[balance] in  = {args.in_dir}")
    print(f"[balance] out = {args.out_dir}")

    samples = _load(args.in_dir)
    print(f"[balance] loaded {len(samples)} samples")

    balanced = balance(
        samples,
        max_per_bucket=args.max_per_class,
        min_per_cwe=args.min_per_cwe,
        test_frac=args.test_frac,
        val_frac=args.val_frac,
        seed=args.seed,
    )
    print(f"[balance] output: {len(balanced)} samples")

    # write per-source JSONL (preserves source for traceability)
    by_source: dict[str, list[SecuritySample]] = defaultdict(list)
    for s in balanced:
        by_source[s.source].append(s)
    for src, items in by_source.items():
        out = args.out_dir / f"{src}.jsonl"
        n = 0
        with out.open("w", encoding="utf-8") as f:
            for s in items:
                f.write(json.dumps(s.to_dict(), ensure_ascii=False) + "\n")
                n += 1
        print(f"  wrote {n:>5} -> {out}")

    # write a combined file
    all_out = args.out_dir / "_all.jsonl"
    with all_out.open("w", encoding="utf-8") as f:
        for s in balanced:
            f.write(json.dumps(s.to_dict(), ensure_ascii=False) + "\n")
    print(f"  wrote {len(balanced):>5} -> {all_out}")

    stats = report_distribution(balanced)
    print(render_distribution(stats))

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "policy": {
            "max_per_bucket": args.max_per_class,
            "min_per_cwe": args.min_per_cwe,
            "test_frac": args.test_frac,
            "val_frac": args.val_frac,
            "seed": args.seed,
        },
        "stats": asdict(stats),
    }
    rpt = args.out_dir / "_balance_report.json"
    rpt.write_text(json.dumps(report, indent=2))
    print(f"\n[balance] wrote report to {rpt}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
