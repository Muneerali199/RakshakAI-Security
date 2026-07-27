"""
RakshakAI v2 — NVD CVE importer (Phase 2.5).

Source:  https://nvd.nist.gov/vuln/data-feeds  (JSON 2.0 format)
Format:  ZIP of JSON files, one per recent year.

The NVD feed provides:
* CVE id, description (English), CVSS v2/v3 metrics
* CWE ids, references

It does **not** include the vulnerable code itself; we use the
description as the vulnerable_code field and the CWE+severity as labels.

Output: v2/inputs/datasets/raw/nvd_cve.jsonl

To keep the importer fast we only pull the most recent years and
hard-cap the per-year record count.
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

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from v2.dataset.importers.common import (  # noqa: E402
    ImportStats, fetch, normalize_cwe, write_samples, is_harmful,
)
from v2.dataset.schema import SecuritySample  # noqa: E402


# NVD JSON 2.0 feed URLs (use only the most recent years for speed)
YEARS = ["2024", "2025", "2026"]
FEED_URL = "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{year}.json.zip"

# Map NVD CPE vendor→language
VENDOR_LANG = {
    "python": "python", "python_software_foundation": "python",
    "oracle": "java", "redhat": "java", "ibm": "java",
    "microsoft": "csharp", ".net": "csharp",
    "google": "javascript", "mozilla": "javascript",
    "node.js": "javascript", "nodejs": "javascript",
    "ruby-lang": "ruby", "rubyonrails": "ruby",
    "rust-lang": "rust", "mojang": "java",
    "php": "php", "thephpgroup": "php",
    "golang": "go", "google_go": "go",
    "apache": "java", "eclipse": "java",
    "linux": "c", "gnu": "c",
    "apple": "swift",
    "jetbrains": "kotlin",
}


def _detect_lang_from_cpe(cve: dict) -> Optional[str]:
    """Best-effort language detection from NVD CPE configuration nodes."""
    for cfg in (cve.get("configurations") or []):
        for node in (cfg.get("nodes") or []):
            for cpe in (node.get("cpeMatch") or []):
                crit = cpe.get("criteria", "")
                m = re.match(r"cpe:2\.3:[a-z]:([^:]+):", crit)
                if m:
                    vendor = m.group(1).lower()
                    if vendor in VENDOR_LANG:
                        return VENDOR_LANG[vendor]
    # Fallback: scan description for hints
    desc = (cve.get("descriptions") or [{}])[0].get("value", "").lower()
    for kw, lang in (("python", "python"), ("java ", "java"),
                      ("javascript", "javascript"), (" node", "javascript"),
                      ("ruby", "ruby"), (" php", "php"),
                      ("rust", "rust"), ("golang", "go"),
                      ("csharp", "csharp"), (".net", "csharp")):
        if kw in desc:
            return lang
    return None


def _cwe_from_weakness(weaknesses: list[dict]) -> Optional[str]:
    for w in weaknesses:
        for d in w.get("description") or []:
            v = d.get("value", "")
            if v.startswith("CWE-"):
                return v
    return None


def main() -> int:
    stats = ImportStats(source="nvd_cve")
    samples: list[SecuritySample] = []

    for year in YEARS:
        url = FEED_URL.format(year=year)
        try:
            data = fetch(url, timeout=180, max_retries=2)
        except Exception as e:
            print(f"  [nvd] {year}: download failed: {e!r}", file=sys.stderr)
            stats.error = str(e)
            continue
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            for name in zf.namelist():
                if not name.endswith(".json"):
                    continue
                try:
                    feed = json.loads(zf.read(name))
                except Exception:
                    continue
                for cve in (feed.get("vulnerabilities") or feed.get("CVE_Items") or []):
                    cve_obj = cve.get("cve") or cve
                    cid = cve_obj.get("id", "")
                    desc_list = cve_obj.get("descriptions") or []
                    desc = ""
                    for d in desc_list:
                        if d.get("lang") == "en":
                            desc = d.get("value", "")
                            break
                    if not desc:
                        desc = (desc_list[0].get("value", "") if desc_list else "")
                    if len(desc) < 30:
                        stats.skipped_too_short += 1
                        continue
                    cwe = _cwe_from_weakness(cve_obj.get("weaknesses") or [])
                    cwe = normalize_cwe(cwe)
                    if not cwe:
                        # Try mining from description
                        m = re.findall(r"CWE-?\d+", desc, flags=re.I)
                        cwe = normalize_cwe(m[0]) if m else None
                    if not cwe:
                        stats.skipped_no_cwe += 1
                        continue
                    lang = _detect_lang_from_cpe(cve_obj) or "text"
                    # CVSS v3
                    sev = "high"
                    cvss: Optional[float] = None
                    metrics = cve_obj.get("metrics") or {}
                    for key in ("cvssMetricV31", "cvssMetricV30"):
                        for m in metrics.get(key) or []:
                            cd = m.get("cvssData") or {}
                            s = cd.get("baseScore")
                            if isinstance(s, (int, float)):
                                cvss = float(s)
                                sev = (cd.get("baseSeverity") or "HIGH").lower()
                                break
                        if cvss is not None:
                            break
                    if sev not in ("critical", "high", "medium", "low"):
                        sev = "high"
                    if is_harmful(desc):
                        stats.skipped_harmful += 1
                        continue
                    # References
                    refs = [r.get("url", "") for r in (cve_obj.get("references") or [])
                            if r.get("url")]
                    try:
                        s = SecuritySample.build(
                            language=lang,
                            vulnerable_code=desc[:2000],
                            patched_code=None,
                            cwe=cwe,
                            severity=sev,
                            explanation=desc[:1500],
                            attack_scenario=desc[:1500],
                            secure_fix=f"Apply the fix described in {cid} references.",
                            source=f"nvd:{cid}",
                            source_license="PublicDomain",
                            cve=cid,
                            cvss=cvss,
                            references=refs,
                            split="train",
                        )
                    except Exception:
                        continue
                    samples.append(s)
                    stats.built += 1
        # Persist after each year
        write_samples("nvd_cve", samples, stats)
        print(f"  [nvd] {year} done; cumulative {len(samples)} samples")
    print(json.dumps(stats.to_dict(), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
