"""
RakshakAI v2 — Phase 2.3: Deduplicate.

Strategy: MinHash LSH on normalized (lowercased, whitespace-collapsed) source,
per language, jaccard similarity threshold 0.85 over 5-gram shingles.

Reads:  v2/inputs/datasets/clean/*.jsonl
Writes: v2/inputs/datasets/dedup/*.jsonl  (with added 'dup_of' / 'is_dup' fields)
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Iterable

# use datasketch if available; otherwise an exact but slower fallback
try:
    from datasketch import MinHash, MinHashLSH
    HAVE_DATASKETCH = True
except Exception:  # noqa: BLE001
    HAVE_DATASKETCH = False


def normalize_for_hash(code: str) -> str:
    code = code.lower()
    code = re.sub(r"\s+", " ", code)
    code = re.sub(r"//.*?$|/\*.*?\*/|#.*?$", "", code)  # strip comments
    code = re.sub(r"\b[a-z_][a-z0-9_]{2,}\b", "ID", code)  # collapse identifiers
    return code.strip()


def shingles(s: str, k: int = 5) -> set[str]:
    toks = s.split()
    if len(toks) < k:
        return {" ".join(toks)} if toks else set()
    return {" ".join(toks[i:i + k]) for i in range(len(toks) - k + 1)}


def minhash(s: str, num_perm: int = 128):
    m = MinHash(num_perm=num_perm)
    for sh in shingles(s):
        m.update(sh.encode("utf-8"))
    return m


def dedup_file(in_path: Path, threshold: float = 0.85) -> tuple[list[dict], int]:
    rows = []
    with in_path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    seen_keys: set[str] = set()
    unique: list[dict] = []
    dropped = 0

    if HAVE_DATASKETCH:
        lsh = MinHashLSH(threshold=threshold, num_perm=128)
        sigs: dict[str, "MinHash"] = {}
        for r in rows:
            code = r.get("vulnerable_code") or r.get("code") or ""
            key = normalize_for_hash(code)
            if not key or key in seen_keys:
                dropped += 1
                continue
            seen_keys.add(key)
            sig = minhash(key)
            near = lsh.query(sig)
            if near:
                dropped += 1
                continue
            digest = hash(key)
            lsh.insert(str(digest), sig)
            sigs[str(digest)] = sig
            unique.append(r)
    else:
        # O(n^2) exact jaccard fallback for small files
        for r in rows:
            code = r.get("vulnerable_code") or r.get("code") or ""
            sh = shingles(normalize_for_hash(code))
            dup = False
            for u in unique:
                ush = shingles(normalize_for_hash(u.get("vulnerable_code") or u.get("code") or ""))
                if not sh or not ush:
                    continue
                inter = len(sh & ush)
                union = len(sh | ush)
                if union and inter / union >= threshold:
                    dup = True
                    break
            if dup:
                dropped += 1
            else:
                unique.append(r)
    return unique, dropped


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--in_dir", type=Path, default=Path("v2/inputs/datasets/clean"))
    ap.add_argument("--out_dir", type=Path, default=Path("v2/inputs/datasets/dedup"))
    ap.add_argument("--threshold", type=float, default=0.85)
    args = ap.parse_args()
    args.out_dir.mkdir(parents=True, exist_ok=True)

    if not HAVE_DATASKETCH:
        print("[dedup] WARNING: datasketch not installed; using O(n^2) exact jaccard (slow)",
              file=sys.stderr)

    for in_path in sorted(args.in_dir.glob("*.jsonl")):
        unique, dropped = dedup_file(in_path, threshold=args.threshold)
        out_path = args.out_dir / in_path.name
        with out_path.open("w", encoding="utf-8") as f:
            for r in unique:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")
        print(f"[dedup] {in_path.name}: {len(unique)} kept, {dropped} dropped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
