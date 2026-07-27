"""
RakshakAI v2 — OSV.dev importer (Phase 2.5).

Source:  https://osv-vulnerabilities.storage.googleapis.com/{ecosystem}/all.zip
Format:  ZIP of JSON files, one per OSV vulnerability record.

The OSV database aggregates GitHub Advisories, NVD CVEs, and ecosystem
package-security advisories into a single uniform schema.  Each record
contains:

* ``id``                 — OSV id (e.g. PYSEC-2024-12345 or GHSA-xxxx-yyyy-zzzz)
* ``summary``            — human title
* ``details``            — long markdown description
* ``affected``           — list of {package, ranges, versions}
* ``severity``           — list of {type: CVSS_V3, score}
* ``cwe_ids``            — list of "CWE-89" etc. (in database_specific)
* ``references``         — list of {type, url}  (includes commit URLs)
* ``aliases``            — CVE-xxxx-yyyy ids

We translate each record to a SecuritySample.  The ``vulnerable_code``
field holds the long description (since OSV records do not include the
raw vulnerable code).  When the record has a GitHub commit URL in
``references``, we attempt to fetch the diff and put it in
``patched_code`` so the sample has both sides.

Output: v2/inputs/datasets/raw/osv.jsonl
"""
from __future__ import annotations

import io
import json
import re
import sys
import time
import zipfile
from pathlib import Path
from typing import Iterator, Optional
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from v2.dataset.importers.common import (  # noqa: E402
    ImportStats, RAW_DIR, fetch, normalize_cwe, cvss_to_severity,
    detect_language, is_harmful, write_samples,
)
from v2.dataset.schema import SecuritySample  # noqa: E402


# OSV ecosystem → our language code
ECOSYSTEM_LANG = {
    "PyPI":     "python",
    "npm":      "javascript",
    "Maven":    "java",
    "Go":       "go",
    "crates.io":"rust",
    "Packagist":"php",
    "NuGet":    "csharp",
    "RubyGems": "ruby",
    "SwiftPM":  "swift",
    "Pub":      "dart",
    "Hex":      "elixir",
    "ConanCenter": "cpp",
}


def _commit_url_to_diff(url: str) -> Optional[str]:
    """Try to fetch a unified diff for a GitHub commit URL.

    Returns the diff text, or None on any failure.
    """
    try:
        # https://github.com/owner/repo/commit/<sha>  →  .patch
        m = re.match(r"https?://github\.com/([^/]+)/([^/]+)/commit/([0-9a-f]+)", url)
        if m:
            owner, repo, sha = m.group(1), m.group(2), m.group(3)
            patch_url = f"https://github.com/{owner}/{repo}/commit/{sha}.patch"
            return fetch(patch_url, timeout=15, max_retries=1).decode("utf-8", "replace")
        # https://github.com/owner/repo/pull/<n>/files
        m = re.match(r"https?://github\.com/([^/]+)/([^/]+)/pull/(\d+)/files", url)
        if m:
            owner, repo, pr = m.group(1), m.group(2), m.group(3)
            patch_url = f"https://github.com/{owner}/{repo}/pull/{pr}.patch"
            return fetch(patch_url, timeout=15, max_retries=1).decode("utf-8", "replace")
    except Exception:
        return None
    return None


def _commit_url_to_files(url: str) -> Optional[str]:
    """Return the diff of the first file in the commit, or None."""
    diff = _commit_url_to_diff(url)
    if not diff:
        return None
    # Take the first file's diff (most advisories touch one file)
    chunks = re.split(r"^diff --git ", diff, flags=re.M)
    chunks = [c for c in chunks if c.strip()]
    if not chunks:
        return None
    return "diff --git " + chunks[0][:3000]


def _record_to_samples(adv: dict, stats: ImportStats) -> Iterator[SecuritySample]:
    summary = (adv.get("summary") or "").strip()
    details = (adv.get("details") or "").strip()
    # CWE ids: may be at top level OR in database_specific
    cwe_ids = list(adv.get("cwe_ids") or [])
    db_specific = adv.get("database_specific") or {}
    cwe_ids += db_specific.get("cwe_ids") or []
    cwe_ids = [normalize_cwe(c) for c in cwe_ids]
    cwe_ids = [c for c in cwe_ids if c]
    if not cwe_ids:
        # Last-ditch: extract CWE-NNN from details text
        m = re.findall(r"CWE-?\d+", details or summary, flags=re.I)
        cwe_ids = [normalize_cwe(c) for c in m]
    if not cwe_ids:
        stats.skipped_no_cwe += 1
        return
    primary_cwe = cwe_ids[0]
    # Severity
    sev_label = "high"
    for sev in adv.get("severity") or []:
        s = sev.get("score")
        if isinstance(s, (int, float)):
            sev_label = cvss_to_severity(float(s))
            break
    # Fallback to database_specific.severity (GitHub-style labels)
    db_specific = adv.get("database_specific") or {}
    gh_sev = db_specific.get("severity")
    if isinstance(gh_sev, str):
        gh_sev = gh_sev.upper()
        if gh_sev == "MODERATE":
            sev_label = "medium"
        elif gh_sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            sev_label = gh_sev.lower()
    # Normalize to whitelist
    if sev_label not in ("critical", "high", "medium", "low"):
        sev_label = "high"
    # Affected → language
    pkg_lang = None
    pkg_name = ""
    for aff in adv.get("affected") or []:
        pkg = (aff or {}).get("package") or {}
        eco = (pkg.get("ecosystem") or "").strip()
        pkg_name = pkg.get("name") or ""
        if eco in ECOSYSTEM_LANG:
            pkg_lang = ECOSYSTEM_LANG[eco]
            break
    if pkg_lang is None:
        stats.skipped_no_cwe += 1  # reuse as "not usable"
        return
    # Explanation (schema max is 1500 chars; trim aggressively)
    explanation = (summary + "\n\n" + details)[:1500]
    if is_harmful(explanation):
        stats.skipped_harmful += 1
        return
    # CVE id from aliases
    cve = None
    for a in adv.get("aliases") or []:
        if a.startswith("CVE-"):
            cve = a
            break
    # Try to fetch a commit diff from references (best-effort, rate-limited)
    patched_code: Optional[str] = None
    references = adv.get("references") or []
    ref_urls = [r.get("url", "") for r in references if r.get("url")]
    # We skip commit fetches by default; a separate pass
    # (``osv_patches.py``) can backfill them at lower priority.
    # Build sample
    try:
        s = SecuritySample.build(
            language=pkg_lang,
            vulnerable_code=(explanation[:2000] or summary or details[:2000]),
            patched_code=patched_code,
            cwe=primary_cwe,
            severity=sev_label,
            explanation=(explanation or summary)[:1500],
            attack_scenario=summary[:1500],
            secure_fix=(f"Upgrade {pkg_name} per advisory {adv.get('id', 'unknown')}"
                        if pkg_name else f"Apply patch from {adv.get('id', 'advisory')}"),
            source=f"osv:{adv.get('id', 'unknown')}",
            source_license="CC-BY-4.0",
            cve=cve,
            references=ref_urls,
            split="train",
        )
    except Exception:
        return
    yield s


def main() -> int:
    stats = ImportStats(source="osv")
    samples: list[SecuritySample] = []
    # ── Which ecosystems to pull ──────────────────────────────────
    # Skip Maven and npm for now (very large).  We focus on smaller
    # ecosystems that yield a higher per-record signal-to-noise ratio.
    ecosystems = ["PyPI", "npm", "Maven", "Go", "crates.io", "Packagist", "NuGet", "RubyGems"]
    for eco in ecosystems:
        url = f"https://osv-vulnerabilities.storage.googleapis.com/{eco}/all.zip"
        out_zip = RAW_DIR / f"osv-{eco}.zip"
        out_zip.parent.mkdir(parents=True, exist_ok=True)
        try:
            data = fetch(url, timeout=120, max_retries=2)
        except Exception as e:
            print(f"  [osv] {eco}: download failed: {e!r}", file=sys.stderr)
            stats.error = str(e)
            continue
        out_zip.write_bytes(data)
        print(f"  [osv] {eco}: downloaded {len(data)/1e6:.1f} MB")
        # Open the zip in memory
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            for name in zf.namelist():
                if not name.endswith(".json"):
                    continue
                try:
                    raw = zf.read(name)
                    adv = json.loads(raw)
                except Exception:
                    continue
                for s in _record_to_samples(adv, stats):
                    samples.append(s)
        # Persist after each ecosystem so partial progress is saved
        write_samples("osv", samples, stats)
        print(f"  [osv] cumulative: {len(samples)} samples, {stats.to_dict()}")
    print(json.dumps(stats.to_dict(), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
