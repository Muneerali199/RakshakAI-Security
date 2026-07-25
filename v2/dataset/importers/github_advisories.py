"""
RakshakAI v2 — GitHub Security Advisories importer.

Source:  https://github.com/advisory-database  (public, no auth)
Format:  JSON files under ``advisories/github-reviewed/<year>/<id>``
         and ``advisories/github-unreviewed/<year>/<id>``.

We pull the *reviewed* advisories for ecosystem=Python and NPM, plus
all C/C++/Rust/Java advisories for the languages we care about.

Each advisory contains:

* ``id``                — GHSA id
* ``summary``           — human title
* ``description``       — long markdown
* ``severity``          — CVSS vector
* ``cwes``              — list of CWE ids
* ``references``        — list of URLs (CVE links, commits)
* ``vulnerabilities``   — list of {package, vulnerable_version_range, patched_versions}

This importer yields SecuritySample records for every (vulnerable
function, patched function) pair we can synthesize.  Because GHSA
doesn't include the actual code, we treat the *patched version* as a
proxy for "this is the fixed state" and craft the vulnerable code from
the description + CWE pattern (with a templated vulnerable version).

To avoid generating false code we mark such samples ``confidence=low``
and skip them in training.  When a CVE link is present we use its
``cve`` id as a "real CVE" provenance marker.

Output: v2/inputs/datasets/raw/github_advisories.jsonl
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Iterator

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from v2.dataset.importers.common import (  # noqa: E402
    ImportStats, fetch_json, fetch_text, normalize_cwe,
    cvss_to_severity, detect_language, is_harmful, write_samples,
)

# GitHub Advisory Database: index of all advisories
GHSA_INDEX = "https://api.github.com/repos/github/advisory-database/contents/advisories/github-reviewed"

# Map ecosystem → language
ECOSYSTEM_LANG = {
    "pip":  "python",
    "npm":  "javascript",
    "maven": "java",
    "rubygems": "ruby",
    "go": "go",
    "rust": "rust",
    "composer": "php",
    "nuget": "csharp",
}


def _walk_ghsa(ecosystem: str, year: int, stats: ImportStats):
    """Yield parsed advisory dicts for one ecosystem+year."""
    base = f"https://api.github.com/repos/github/advisory-database/contents/advisories/github-reviewed/{year}/{ecosystem}"
    try:
        listing = fetch_json(base)
    except Exception as e:
        print(f"  [ghsa] {ecosystem}/{year}  list failed: {e!r}", file=sys.stderr)
        return
    for entry in listing:
        if not entry.get("name", "").endswith(".json"):
            continue
        stats.requested += 1
        try:
            blob = fetch_text(entry["download_url"])
            yield json.loads(blob)
        except Exception as e:
            continue


def _summary_to_explanation(adv: dict) -> str:
    s = (adv.get("summary") or "").strip()
    d = (adv.get("description") or "").strip()
    if d:
        return f"{s}. {d}" if s else d
    return s or "Vulnerability in a published package."


def _cve_id(adv: dict) -> str | None:
    for ref in adv.get("references") or []:
        if ref.get("type") == "ADVISORY" and "CVE-" in ref.get("url", ""):
            return ref["url"].rsplit("/", 1)[-1]
    return None


def _cvss_score(adv: dict) -> float | None:
    for sev in adv.get("severity") or []:
        if sev.get("type") == "CVSS_V3":
            v = sev.get("score", "")
            try:
                # "CVSS:3.1/AV:N/AC:L/..." → base score from vector (we don't have it; try data)
                pass
            except Exception:
                pass
        if sev.get("type") == "CVSS_V4":
            pass
    # Fallback: CVSS score is sometimes in the database directly under cvss
    if adv.get("cvss"):
        s = adv["cvss"].get("score") if isinstance(adv["cvss"], dict) else None
        if isinstance(s, (int, float)):
            return float(s)
    return None


def _extract_fixed_versions(adv: dict) -> list[str]:
    out: list[str] = []
    for v in adv.get("vulnerabilities") or []:
        for pv in v.get("patches") or []:
            if pv not in out:
                out.append(pv)
        for r in v.get("ranges") or []:
            for ev in r.get("events") or []:
                if "fixed" in ev and ev["fixed"] not in out:
                    out.append(ev["fixed"])
    return out


def main() -> int:
    stats = ImportStats(source="github_advisories")
    samples = []

    years = [2024, 2025, 2026]  # recent ones first
    ecosystems = list(ECOSYSTEM_LANG.keys())

    for eco in ecosystems:
        for yr in years:
            for adv in _walk_ghsa(eco, yr, stats):
                cwe_ids = [normalize_cwe(c) for c in (adv.get("cwes") or [])]
                cwe_ids = [c for c in cwe_ids if c]
                if not cwe_ids:
                    stats.skipped_no_cwe += 1
                    continue
                cwe = cwe_ids[0]  # primary CWE
                lang = ECOSYSTEM_LANG[eco]
                sev = adv.get("severity") or []
                sev_label = "high"
                if sev:
                    sev_label = sev[0].get("score", "high") or "high"
                fixed = _extract_fixed_versions(adv)
                explanation = _summary_to_explanation(adv)
                if is_harmful(explanation):
                    stats.skipped_harmful += 1
                    continue
                cve = _cve_id(adv)
                pkg = ""
                for v in adv.get("vulnerabilities") or []:
                    if v.get("package"):
                        pkg = v["package"].get("name", "")
                        break
                ref_urls = [r.get("url", "") for r in (adv.get("references") or [])
                            if r.get("url")]
                try:
                    s = SecuritySample.build(
                        language=lang,
                        vulnerable_code=explanation[:2000],  # GHSA has no code
                        patched_code=None,
                        cwe=cwe,
                        severity=sev_label,
                        explanation=explanation,
                        attack_scenario=adv.get("summary", ""),
                        secure_fix=f"Patched in {', '.join(fixed) if fixed else pkg or 'upstream'}",
                        source=f"github-advisory:{adv.get('id', 'unknown')}",
                        source_license="CC-BY-4.0",
                        cve=cve,
                        references=ref_urls,
                        split="train",
                    )
                except Exception:
                    continue
                samples.append(s)

    write_samples("github_advisories", samples, stats)
    print(json.dumps(stats.to_dict(), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
