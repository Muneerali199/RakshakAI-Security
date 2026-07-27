"""
RakshakAI v2 — OWASP Benchmark importer (Phase 2.5).

Source:  https://github.com/OWASP-Benchmark/BenchmarkJava
Format:  Java test cases in ``src/main/java/org/owasp/benchmark/testcode/``
         and ``expectedresults-1.2.csv`` mapping test case names to CWE
         ids and true-positive / false-positive labels.

The Benchmark project is a Java test suite of ~3,000 deliberately
crafted test cases covering 11 CWE categories.  Each test case is a
single Java servlet endpoint that is either vulnerable or not.
Test case ``BenchmarkTest00001.java`` etc.

We pull the full repo as a tarball (much faster than 3,000 blob calls)
and extract the testcode/ directory.

Output: v2/inputs/datasets/raw/owasp_benchmark.jsonl
"""
from __future__ import annotations

import csv
import io
import json
import sys
import tarfile
import urllib.error
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from v2.dataset.importers.common import (  # noqa: E402
    ImportStats, fetch, normalize_cwe, write_samples, is_harmful,
)
from v2.dataset.schema import SecuritySample  # noqa: E402


REPO = "OWASP-Benchmark/BenchmarkJava"
BRANCH = "master"
TARBALL_URL = f"https://codeload.github.com/{REPO}/tar.gz/refs/heads/{BRANCH}"
LIST_URL = (
    "https://raw.githubusercontent.com/OWASP-Benchmark/BenchmarkJava/"
    "master/expectedresults-1.2.csv"
)
TESTCODE_PREFIX = "src/main/java/org/owasp/benchmark/testcode/"
FILE_LIMIT = 6000   # hard cap; safety net so a misconfigured prefix
                    # doesn't sweep the whole repo


def _fetch_list_csv() -> dict[str, dict]:
    """Map test case name → row of expectedresults-1.2.csv.

    Schema:  ``# test name, category, real vulnerability, cwe``
    """
    text = fetch(LIST_URL, timeout=60)
    if isinstance(text, bytes):
        text = text.decode("utf-8", errors="replace")
    out: dict[str, dict] = {}
    # The header starts with "# " — strip it so csv.DictReader works.
    lines = []
    for line in text.splitlines():
        stripped = line.lstrip()
        if stripped.startswith("#"):
            line = stripped.lstrip("#").strip()
        lines.append(line)
    cleaned = "\n".join(lines)
    reader = csv.DictReader(io.StringIO(cleaned))
    for row in reader:
        name = (row.get("test name") or "").strip()
        if name:
            out[name] = row
    return out


def _extract_testcode_from_tar(tar_bytes: bytes) -> dict[str, dict[str, str]]:
    """Return a mapping {test_id: {filename: content}} for files in
    the testcode/ directory of the tarball."""
    by_id: dict[str, dict[str, str]] = {}
    count = 0
    with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:gz") as tf:
        for member in tf:
            if count > FILE_LIMIT:
                break
            name = member.name
            # The tarball prefixes everything with the repo name, e.g.
            # "BenchmarkJava-master/src/main/java/..."
            idx = name.find(TESTCODE_PREFIX)
            if idx < 0:
                continue
            sub = name[idx + len(TESTCODE_PREFIX):]
            if not sub.endswith(".java"):
                continue
            count += 1
            try:
                f = tf.extractfile(member)
                if f is None:
                    continue
                content = f.read().decode("utf-8", errors="replace")
            except Exception:
                continue
            fname = sub.split("/")[-1]
            stem = fname[:-5]  # strip .java
            by_id.setdefault(stem, {})[fname] = content
    return by_id


def main() -> int:
    stats = ImportStats(source="owasp_benchmark")
    samples: list[SecuritySample] = []

    try:
        list_map = _fetch_list_csv()
    except Exception as e:
        print(f"  [owasp] BenchmarkList.csv failed: {e!r}", file=sys.stderr)
        stats.error = repr(e)
        write_samples("owasp_benchmark", samples, stats)
        return 1
    print(f"  [owasp] list: {len(list_map)} entries")

    print(f"  [owasp] downloading tarball...")
    try:
        tar_bytes = fetch(TARBALL_URL, timeout=300, max_retries=2)
        print(f"  [owasp] tarball: {len(tar_bytes)/1e6:.1f} MB")
    except Exception as e:
        print(f"  [owasp] tarball download failed: {e!r}", file=sys.stderr)
        stats.error = repr(e)
        write_samples("owasp_benchmark", samples, stats)
        return 1
    by_id = _extract_testcode_from_tar(tar_bytes)
    print(f"  [owasp] extracted {len(by_id)} test cases")

    for tc_id, files in by_id.items():
        vuln_name = f"{tc_id}.java"
        fixed_name = f"{tc_id}_fixed.java" if f"{tc_id}_fixed.java" in files else None
        if vuln_name not in files:
            continue
        vuln_code = files[vuln_name]
        fixed_code = files[fixed_name] if fixed_name else None
        if len(vuln_code.strip()) < 30:
            stats.skipped_too_short += 1
            continue
        meta = list_map.get(vuln_name, {})
        cwe_raw = meta.get("cwe") or meta.get("CWE") or ""
        cwe = f"CWE-{cwe_raw}" if cwe_raw and cwe_raw.isdigit() else normalize_cwe(cwe_raw)
        if not cwe:
            category = meta.get("category") or meta.get("Category") or ""
            cwe = "CWE-1004" if category else "CWE-20"
        sev = "high"
        is_real = (meta.get("real vulnerability") or "").lower() == "true"
        if not is_real:
            # Clean baseline sample
            try:
                s = SecuritySample.build(
                    language="java",
                    vulnerable_code=vuln_code[:8000],
                    patched_code=None,
                    cwe="CWE-UNKNOWN",
                    severity="clean",
                    explanation=f"OWASP Benchmark false positive control case "
                                f"({meta.get('category', '')}).",
                    attack_scenario="This code is intentionally not vulnerable.",
                    secure_fix="No fix needed; this is a clean baseline.",
                    source=f"owasp-benchmark:{tc_id}",
                    source_license="MIT",
                    split="train",
                )
            except Exception:
                continue
            samples.append(s)
            stats.built += 1
            continue
        if is_harmful(vuln_code + (fixed_code or "")):
            stats.skipped_harmful += 1
            continue
        try:
            s = SecuritySample.build(
                language="java",
                vulnerable_code=vuln_code[:8000],
                patched_code=fixed_code[:8000] if fixed_code else None,
                cwe=cwe,
                severity=sev,
                explanation=(
                    f"OWASP Benchmark vulnerable test case "
                    f"({meta.get('category', '')})."
                )[:1500],
                attack_scenario=f"OWASP Benchmark attack pattern for {cwe}.",
                secure_fix=(
                    "See the fixed variant in OWASP Benchmark."
                    if fixed_code else "Apply parameterized input handling."
                ),
                source=f"owasp-benchmark:{tc_id}",
                source_license="MIT",
                split="train",
            )
        except Exception:
            continue
        samples.append(s)
        stats.built += 1

    write_samples("owasp_benchmark", samples, stats)
    print(json.dumps(stats.to_dict(), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
