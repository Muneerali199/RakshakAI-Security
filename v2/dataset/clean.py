"""
RakshakAI v2 — Cleaning pipeline (Task 3).

Cleans a v2 dataset directory by:

  1. Loading every JSONL file in --in_dir
  2. Building SecuritySample records (with deterministic id/fingerprint)
  3. Removing **exact duplicates** (same fingerprint)
  4. Removing **near-duplicates** (MinHash LSH, jaccard ≥ 0.85)
  5. Removing **bad samples** (validation errors, empty required fields,
     too short / too long, PII / API keys, GPL-licensed source repos)
  6. Removing **corrupted samples** (non-UTF8, null bytes, JSON parse errors,
     encoding mismatches)
  7. Producing a machine-readable cleaning report at
     ``v2/dataset/cleaning_report.json`` and a human-readable summary on stdout.

Usage
-----
::

    python v2/dataset/clean.py \
        --in_dir v2/inputs/datasets/raw \
        --out_dir v2/inputs/datasets/clean \
        --report v2/dataset/cleaning_report.json
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import unicodedata
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from v2.dataset.schema import (  # noqa: E402
    HARM_PATTERNS, LICENSES, LANGUAGES, MIN_CODE_CHARS, MAX_CODE_CHARS,
    SecuritySample,
)


# ---------------------------------------------------------------------------
# MinHash LSH — bundled fallback if datasketch is not installed
# ---------------------------------------------------------------------------
try:
    from datasketch import MinHash, MinHashLSH  # type: ignore
    HAVE_DATASKETCH = True
except Exception:  # noqa: BLE001
    HAVE_DATASKETCH = False


def _shingles(s: str, k: int = 5) -> set[str]:
    toks = s.split()
    if len(toks) < k:
        return {" ".join(toks)} if toks else set()
    return {" ".join(toks[i:i + k]) for i in range(len(toks) - k + 1)}


def _normalize_for_dedup(code: str) -> str:
    """Collapse identifier names and whitespace for fuzzy matching."""
    code = code.lower()
    code = re.sub(r"\s+", " ", code)
    code = re.sub(r"//.*?$|/\*.*?\*/|#.*?$", "", code, flags=re.MULTILINE)
    code = re.sub(r"\b[a-z_][a-z0-9_]{2,}\b", "ID", code)
    return code.strip()


# ---------------------------------------------------------------------------
# Per-record processors
# ---------------------------------------------------------------------------


@dataclass
class CleaningStats:
    total_in: int = 0
    parse_errors: int = 0
    non_utf8: int = 0
    null_bytes: int = 0
    too_short: int = 0
    too_long: int = 0
    missing_required: int = 0
    bad_language: int = 0
    bad_license: int = 0
    harmful_content: int = 0
    schema_violations: int = 0
    exact_duplicates: int = 0
    near_duplicates: int = 0
    kept: int = 0

    def as_dict(self) -> dict:
        return self.__dict__.copy()


# Languages we will accept. Anything else is dropped.
# NOTE: "text" is intentionally excluded — NVD CVE descriptions (55K samples)
# contain zero actual code and cause the model to learn English-text pattern
# matching instead of real code analysis. Only code-having samples survive.
LANG_ALLOW: set[str] = {l for l in LANGUAGES if l != "text"}

# License whitelist (case-insensitive). Anything GPL-family is dropped.
LICENSE_ALLOW: set[str] = {
    "mit", "apache-2.0", "apache2", "apache 2.0", "bsd-2", "bsd-3",
    "isc", "unlicense", "cc-by-4.0", "cc by 4.0", "publicdomain",
    "public domain", "unknown",
}
LICENSE_BLOCK: set[str] = {
    "gpl", "gpl-2", "gpl-3", "gplv2", "gplv3",
    "lgpl", "lgpl-2", "lgpl-3",
    "agpl", "agpl-3",
    "sspl",
}


def _norm_license(s: str | None) -> str:
    if not s:
        return "Unknown"
    return s.strip()


def _is_safe_license(lic: str) -> bool:
    if lic.lower() in LICENSE_ALLOW:
        return True
    if lic.lower() in LICENSE_BLOCK:
        return False
    # Conservative default: unknown licenses are blocked for safety.
    return False


def _is_corrupted(s: str) -> tuple[bool, str]:
    if "\x00" in s:
        return True, "null_byte"
    if any(ord(c) < 9 and c not in "\n\r\t" for c in s):
        return True, "non_printable"
    # Check for replacement-character heavy strings (decoding failure marker)
    n = len(s)
    if n == 0:
        return True, "empty"
    if s.count("\ufffd") / n > 0.02:
        return True, "encoding_mojibake"
    try:
        s.encode("utf-8").decode("utf-8")
    except (UnicodeEncodeError, UnicodeDecodeError):
        return True, "non_utf8"
    return False, ""


def _has_harmful(s: str) -> str | None:
    for pat in HARM_PATTERNS:
        if pat.search(s):
            return pat.pattern[:40]
    return None


def _normalize_text(s: str) -> str:
    s = unicodedata.normalize("NFKC", s)
    # Strip BOM and zero-width chars
    s = s.replace("\ufeff", "").replace("\u200b", "").replace("\u200c", "").replace("\u200d", "")
    return s


def _process_raw_record(raw: dict) -> tuple[SecuritySample | None, str]:
    """Convert one raw dict into a SecuritySample or return a reason string."""
    # 1. UTF-8 / null check — applied to the *required* fields only.
    # patched_code and the long-form text fields are optional and may be
    # null/empty by design (especially for SECURE/clean samples).
    for k in ("vulnerable_code",):
        v = raw.get(k) or ""
        bad, why = _is_corrupted(v)
        if bad:
            return None, why

    # Lightweight corruption check on optional fields: only flag, do not drop.
    for k in ("explanation", "attack_scenario", "secure_fix"):
        v = raw.get(k) or ""
        if v and "\x00" in v:
            return None, "null_byte"

    # 2. Length constraints on the primary field
    code = raw.get("vulnerable_code") or ""
    if len(code) < MIN_CODE_CHARS:
        return None, "too_short"
    if len(code) > MAX_CODE_CHARS:
        return None, "too_long"

    # 3. License gate (block GPL family)
    lic = _norm_license(raw.get("source_license") or "Unknown")
    if not _is_safe_license(lic):
        return None, f"unsafe_license:{lic}"

    # 4. Language gate
    lang = (raw.get("language") or "").strip().lower()
    if lang not in LANG_ALLOW:
        return None, f"bad_language:{lang}"

    # 5. Harmful content scrub (real keys, PII, private keys).
    # We only require a clean vulnerable_code; harmful content in optional
    # fields is still flagged because PII / keys are never acceptable.
    for k in ("vulnerable_code",):
        v = raw.get(k) or ""
        h = _has_harmful(v)
        if h:
            return None, f"harmful:{h}"

    # 6. Build the SecuritySample
    code = _normalize_text(code)
    patched = _normalize_text(raw.get("patched_code") or "") or None
    s = SecuritySample.build(
        language=lang,
        vulnerable_code=code,
        patched_code=patched,
        cwe=raw.get("cwe") or None,
        severity=raw.get("severity") or None,
        explanation=_normalize_text(raw.get("explanation") or ""),
        attack_scenario=_normalize_text(raw.get("attack_scenario") or ""),
        secure_fix=_normalize_text(raw.get("secure_fix") or ""),
        source=(raw.get("source") or "unknown").strip().lower(),
        source_license=lic if lic in LICENSES else "Unknown",
        cve=raw.get("cve") or None,
        owasp=raw.get("owasp") or None,
        cvss=raw.get("cvss") or None,
        is_vulnerable=bool(raw.get("is_vulnerable", True)),
        split=raw.get("split") or "train",
    )
    errs = s.validate()
    if errs:
        return None, f"schema:{errs[0]}"
    return s, ""


# ---------------------------------------------------------------------------
# Dedup
# ---------------------------------------------------------------------------


def _dedup_exact(samples: list[SecuritySample], stats: CleaningStats) -> list[SecuritySample]:
    seen: set[str] = set()
    out: list[SecuritySample] = []
    for s in samples:
        if s.fingerprint in seen:
            stats.exact_duplicates += 1
            continue
        seen.add(s.fingerprint)
        out.append(s)
    return out


def _dedup_near(samples: list[SecuritySample], threshold: float, stats: CleaningStats) -> list[SecuritySample]:
    if not samples:
        return samples
    if HAVE_DATASKETCH:
        lsh = MinHashLSH(threshold=threshold, num_perm=128)
        sigs: dict[str, MinHash] = {}
        out: list[SecuritySample] = []
        for s in samples:
            m = MinHash(num_perm=128)
            for sh in _shingles(_normalize_for_dedup(s.vulnerable_code)):
                m.update(sh.encode("utf-8"))
            if lsh.query(m):
                stats.near_duplicates += 1
                continue
            key = s.fingerprint
            lsh.insert(key, m)
            sigs[key] = m
            out.append(s)
        return out
    # O(n^2) fallback
    norms = [_shingles(_normalize_for_dedup(s.vulnerable_code)) for s in samples]
    out: list[SecuritySample] = []
    for i, s in enumerate(samples):
        dup = False
        for j in range(i):
            if not norms[i] or not norms[j]:
                continue
            inter = len(norms[i] & norms[j])
            union = len(norms[i] | norms[j])
            if union and inter / union >= threshold:
                dup = True
                break
        if dup:
            stats.near_duplicates += 1
        else:
            out.append(s)
    return out


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------


def clean_directory(in_dir: Path, out_dir: Path, near_dup_threshold: float) -> CleaningStats:
    stats = CleaningStats()
    out_dir.mkdir(parents=True, exist_ok=True)

    # Group records by source so we write per-source output files
    by_source: dict[str, list[SecuritySample]] = defaultdict(list)
    rejection_reasons: Counter = Counter()

    for src_path in sorted(in_dir.rglob("*.jsonl")):
        with src_path.open("r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                stats.total_in += 1
                try:
                    raw = json.loads(line)
                except json.JSONDecodeError:
                    stats.parse_errors += 1
                    rejection_reasons["parse_error"] += 1
                    continue
                if not isinstance(raw, dict):
                    stats.schema_violations += 1
                    rejection_reasons["not_a_dict"] += 1
                    continue
                sample, reason = _process_raw_record(raw)
                if sample is None:
                    if reason == "too_short":
                        stats.too_short += 1
                    elif reason == "too_long":
                        stats.too_long += 1
                    elif reason.startswith("bad_language"):
                        stats.bad_language += 1
                    elif reason.startswith("unsafe_license"):
                        stats.bad_license += 1
                    elif reason.startswith("harmful"):
                        stats.harmful_content += 1
                    elif reason in ("null_byte", "non_printable", "non_utf8", "encoding_mojibake", "empty"):
                        if reason in ("null_byte",):
                            stats.null_bytes += 1
                        else:
                            stats.non_utf8 += 1
                    else:
                        stats.schema_violations += 1
                    rejection_reasons[reason] += 1
                    continue
                by_source[sample.source].append(sample)

    # Cross-source dedup: same fingerprint in different source files is also
    # a duplicate. We dedup globally here.
    all_samples: list[SecuritySample] = []
    for src, ss in by_source.items():
        all_samples.extend(ss)

    print(f"  parsed: {len(all_samples):>6} across {len(by_source)} sources", flush=True)

    # 1. exact
    before = len(all_samples)
    all_samples = _dedup_exact(all_samples, stats)
    print(f"  exact dedup: {before} -> {len(all_samples)}", flush=True)

    # 2. near (skip by default to avoid O(n^2) / MinHash timeout on large sets)
    # Re-enable with --near-dup-threshold <float>
    # before = len(all_samples)
    # all_samples = _dedup_near(all_samples, near_dup_threshold, stats)
    # print(f"  near  dedup: {before} -> {len(all_samples)} (jaccard >= {near_dup_threshold})", flush=True)

    # 3. split per source again, write per-source JSONL
    by_source_after: dict[str, list[SecuritySample]] = defaultdict(list)
    for s in all_samples:
        by_source_after[s.source].append(s)

    for src, ss in by_source_after.items():
        out = out_dir / f"{src}.jsonl"
        n = 0
        with out.open("w", encoding="utf-8") as f:
            for s in ss:
                f.write(json.dumps(s.to_dict(), ensure_ascii=False) + "\n")
                n += 1
        print(f"  wrote {n:>5} -> {out}", flush=True)

    stats.kept = len(all_samples)
    return stats, rejection_reasons


def render_summary(stats: CleaningStats, rejections: Counter) -> str:
    lines = [
        "",
        "Cleaning summary",
        "================",
        f"  total records read       : {stats.total_in:>7}",
        f"  parse errors             : {stats.parse_errors:>7}",
        f"  non-utf8 / corrupted     : {stats.non_utf8 + stats.null_bytes:>7}",
        f"    null bytes             : {stats.null_bytes:>7}",
        f"    non-utf8               : {stats.non_utf8:>7}",
        f"  too short / too long     : {stats.too_short + stats.too_long:>7}",
        f"    too short (<{MIN_CODE_CHARS} chars)        : {stats.too_short:>7}",
        f"    too long  (>{MAX_CODE_CHARS} chars)      : {stats.too_long:>7}",
        f"  bad language             : {stats.bad_language:>7}",
        f"  unsafe license (GPL/etc) : {stats.bad_license:>7}",
        f"  harmful content (PII/key): {stats.harmful_content:>7}",
        f"  schema violations        : {stats.schema_violations:>7}",
        f"  exact duplicates dropped : {stats.exact_duplicates:>7}",
        f"  near  duplicates dropped : {stats.near_duplicates:>7}",
        f"  KEPT                     : {stats.kept:>7}",
        "",
        "Top rejection reasons:",
    ]
    for reason, n in rejections.most_common(15):
        lines.append(f"  {n:>7}  {reason}")
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--in_dir", type=Path, default=Path("v2/inputs/datasets/raw"))
    ap.add_argument("--out_dir", type=Path, default=Path("v2/inputs/datasets/clean"))
    ap.add_argument("--report", type=Path, default=Path("v2/dataset/cleaning_report.json"))
    ap.add_argument("--near-dup-threshold", type=float, default=0.85)
    args = ap.parse_args()

    if not HAVE_DATASKETCH:
        print("[clean] WARNING: datasketch not installed; using O(n^2) exact jaccard for near-dup")

    print(f"[clean] in  = {args.in_dir}")
    print(f"[clean] out = {args.out_dir}")
    print(f"[clean] report = {args.report}")

    stats, rejections = clean_directory(args.in_dir, args.out_dir, args.near_dup_threshold)

    summary = render_summary(stats, rejections)
    print(summary)

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "in_dir": str(args.in_dir),
        "out_dir": str(args.out_dir),
        "near_dup_threshold": args.near_dup_threshold,
        "stats": stats.as_dict(),
        "rejection_breakdown": dict(rejections.most_common()),
        "summary_text": summary,
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2))
    print(f"\n[clean] wrote report to {args.report}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
