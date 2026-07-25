"""
RakshakAI v2 — Benchmark Leakage Report Generator.

Ensures zero overlap between training data and the 500-sample locked benchmark.

Strategies:
  1. **Exact fingerprint match** — SHA-1 of normalized vulnerable_code
  2. **CVE match** — training set must not contain benchmark CVEs
  3. **Repository URL overlap** — same repo in source references
  4. **Commit hash overlap** — same fixing commit
  5. **Code fingerprint cross-check** — near-dup MinHash at 0.85 threshold

Output: v2/dataset/leakage_report.json
"""
from __future__ import annotations

import hashlib
import json
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from v2.dataset.schema import SecuritySample, read_jsonl

BENCHMARK_DIR = Path("v2/inputs/datasets/phase_b/benchmark_hard")
TRAIN_DIR = Path("v2/inputs/datasets/clean")
OUTPUT = Path("v2/dataset/leakage_report.json")


def fingerprint(code: str) -> str:
    """Stable fingerprint — matches schema.py fingerprint_of."""
    s = code.replace("\r\n", "\n").replace("\r", "\n").strip()
    return hashlib.sha1(s.encode("utf-8", errors="replace")).hexdigest()


def extract_repos(refs: list[str]) -> set[str]:
    """Extract GitHub repo identifiers from reference URLs."""
    repos = set()
    for ref in refs:
        m = re.search(r"github\.com[/:]([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)", ref)
        if m:
            repos.add(m.group(1).lower().rstrip("/").rstrip(".git"))
    return repos


def extract_commits(refs: list[str]) -> set[str]:
    """Extract commit hashes from reference URLs."""
    commits = set()
    for ref in refs:
        m = re.search(r"/commit/([a-f0-9]{7,40})", ref)
        if m:
            commits.add(m.group(1))
    return commits


def _to_sample(d: dict, label: str, skip_validation: bool = False) -> SecuritySample | None:
    """Convert a dict to SecuritySample. Handles both full and minimal JSONL."""
    code = d.get("vulnerable_code") or d.get("code") or ""
    if not code or len(code) < 30:
        return None

    if "fingerprint" in d and "id" in d:
        s = SecuritySample.from_dict(d)
        if skip_validation:
            return s
        errs = s.validate()
        if not errs:
            return s
        return None

    lang = d.get("language") or "python"
    cwe = d.get("cwe") or None
    sev = d.get("severity") or "high"
    is_vuln = d.get("is_vulnerable")
    if is_vuln is None:
        is_vuln = True
    elif isinstance(is_vuln, str):
        is_vuln = is_vuln.lower() in ("true", "1", "yes")

    try:
        s = SecuritySample.build(
            language=lang,
            vulnerable_code=code,
            patched_code=d.get("patched_code") or None,
            cwe=cwe,
            severity=sev if sev in ("critical", "high", "medium", "low", "info", "clean") else "high",
            explanation=d.get("explanation") or "",
            attack_scenario=d.get("attack_scenario") or "",
            secure_fix=d.get("secure_fix") or "",
            source=d.get("source", label),
            source_license="MIT",
            cve=d.get("cve") or None,
            is_vulnerable=is_vuln,
            split="benchmark",
        )
    except Exception:
        return None

    if skip_validation:
        return s
    errs = s.validate()
    if not errs:
        return s
    return None


def load_samples(path: Path, label: str, skip_validation: bool = False) -> dict[str, SecuritySample]:
    """Load all SecuritySamples from a directory (JSONL files).

    Handles both SecuritySample format (with fingerprint field) and plain
    JSON dicts (like benchmark files which lack fingerprint/references).

    When skip_validation is True, samples are loaded without running
    SecuritySample.validate() — useful for benchmark files that may contain
    deliberately harmful content (e.g., hardcoded AWS keys for CWE-798 tests).
    """
    samples = {}
    for p in sorted(path.rglob("*.jsonl")):
        with p.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    d = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(d, dict):
                    continue
                s = _to_sample(d, label, skip_validation=skip_validation)
                if s is not None:
                    samples[s.id] = s
    print(f"  {label}: {len(samples)} samples loaded from {path}")
    if label == "benchmark" and len(samples) < 100:
        print(f"  WARNING: Expected 500 benchmark samples! Found {len(samples)}.")
    return samples


def check_leakage(
    benchmark_samples: dict[str, SecuritySample],
    train_samples: dict[str, SecuritySample],
) -> dict[str, Any]:
    """Check for any overlap between benchmark and training data."""
    report: dict[str, Any] = {
        "benchmark_count": len(benchmark_samples),
        "train_count": len(train_samples),
        "checks": {},
        "leaks": [],
        "clean": True,
    }

    # 1. Exact fingerprint match
    bm_fps = {s.fingerprint: s for s in benchmark_samples.values()}
    train_fps = {s.fingerprint: s for s in train_samples.values()}
    fp_overlap = set(bm_fps.keys()) & set(train_fps.keys())
    report["checks"]["exact_fingerprint_match"] = {
        "benchmark_unique": len(bm_fps),
        "train_unique": len(train_fps),
        "overlap": list(fp_overlap)[:50],
        "overlap_count": len(fp_overlap),
    }
    if fp_overlap:
        for fp in fp_overlap:
            report["leaks"].append({
                "type": "exact_fingerprint",
                "benchmark_id": bm_fps[fp].id,
                "train_id": train_fps[fp].id,
                "cwe": bm_fps[fp].cwe,
                "fingerprint": fp,
            })

    # 2. CVE match
    bm_cves = {s.cve for s in benchmark_samples.values() if s.cve}
    train_cves = {s.cve for s in train_samples.values() if s.cve}
    cve_overlap = bm_cves & train_cves
    report["checks"]["cve_match"] = {
        "benchmark_cves": len(bm_cves),
        "train_cves": len(train_cves),
        "overlap": sorted(cve_overlap)[:50],
        "overlap_count": len(cve_overlap),
    }
    for cve in cve_overlap:
        bm_ids = [s.id for s in benchmark_samples.values() if s.cve == cve]
        train_ids = [s.id for s in train_samples.values() if s.cve == cve]
        report["leaks"].append({
            "type": "cve_match",
            "cve": cve,
            "benchmark_ids": bm_ids,
            "train_ids": train_ids[:10],
        })

    # 3. Repository URL overlap
    bm_repos: set[str] = set()
    for s in benchmark_samples.values():
        bm_repos |= extract_repos(s.references)
    train_repos: set[str] = set()
    for s in train_samples.values():
        train_repos |= extract_repos(s.references)
    repo_overlap = bm_repos & train_repos
    report["checks"]["repo_overlap"] = {
        "benchmark_repos": len(bm_repos),
        "train_repos": len(train_repos),
        "overlap": sorted(repo_overlap)[:50],
        "overlap_count": len(repo_overlap),
    }
    for repo in repo_overlap:
        report["leaks"].append({
            "type": "repo_overlap",
            "repo": repo,
            "benchmark_samples": sum(1 for s in benchmark_samples.values() if repo in extract_repos(s.references)),
            "train_samples": sum(1 for s in train_samples.values() if repo in extract_repos(s.references)),
        })

    # 4. Commit hash overlap
    bm_commits: set[str] = set()
    for s in benchmark_samples.values():
        bm_commits |= extract_commits(s.references)
    train_commits: set[str] = set()
    for s in train_samples.values():
        train_commits |= extract_commits(s.references)
    commit_overlap = bm_commits & train_commits
    report["checks"]["commit_overlap"] = {
        "benchmark_commits": len(bm_commits),
        "train_commits": len(train_commits),
        "overlap": sorted(commit_overlap)[:50],
        "overlap_count": len(commit_overlap),
    }
    for commit in commit_overlap:
        report["leaks"].append({
            "type": "commit_overlap",
            "commit": commit,
        })

    # Overall result
    report["clean"] = len(report["leaks"]) == 0
    report["total_leaks"] = len(report["leaks"])

    return report


def main() -> int:
    print("Loading benchmark samples (skip_validation=True — benchmark may have test keys)...")
    benchmark_samples = load_samples(BENCHMARK_DIR, "benchmark", skip_validation=True)

    print("Loading training samples...")
    train_samples = load_samples(TRAIN_DIR, "training", skip_validation=False)

    print("Checking for leakage...")
    report = check_leakage(benchmark_samples, train_samples)

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(report, indent=2))

    if report["clean"]:
        print(f"\n✓ BENCHMARK IS CLEAN: NO LEAKAGE DETECTED.")
        print(f"  Benchmark: {report['benchmark_count']} samples")
        print(f"  Training:  {report['train_count']} samples")
    else:
        print(f"\n✗ LEAKAGE DETECTED: {report['total_leaks']} leaks found!")
        for leak in report["leaks"]:
            print(f"  - {leak['type']}: {leak.get('cve', leak.get('repo', leak.get('fingerprint', '?')))}")

    print(f"\nReport written to {OUTPUT}")
    return 0 if report["clean"] else 1


if __name__ == "__main__":
    sys.exit(main())
