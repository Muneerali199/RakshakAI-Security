#!/usr/bin/env python3
"""
Import real CVE data from OSV + GitHub Advisory DB.
Extracts actual code diffs from commit URLs to create real vulnerable→patched code pairs.

Output: v2/inputs/datasets/phase_b/real_cve_generated/real_cves.jsonl
Target: 50,000+ real vulnerability samples with actual code diffs.
"""
import json
import re
import subprocess
import sys
import time
import hashlib
from pathlib import Path
from collections import Counter

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

OUT_DIR = Path("v2/inputs/datasets/phase_b/real_cve_generated")
META_DIR = Path("v2/inputs/datasets/phase_b/meta")
OSV_FILE = Path("v2/inputs/datasets/raw/osv.jsonl")
GH_ADVISORY_FILE = Path("v2/inputs/datasets/raw/github_advisories.jsonl")
GH_WITH_CODE_FILE = Path("v2/inputs/datasets/raw/github_advisories_with_code.jsonl")

OUT_DIR.mkdir(parents=True, exist_ok=True)

LANG_MAP = {
    ".py": "python", ".js": "javascript", ".ts": "typescript",
    ".jsx": "javascript", ".tsx": "typescript",
    ".java": "java", ".go": "go", ".rs": "rust",
    ".c": "c", ".cpp": "cpp", ".h": "c", ".hpp": "cpp",
    ".php": "php", ".rb": "ruby", ".cs": "csharp",
    ".swift": "swift", ".kt": "kotlin", ".sol": "solidity",
    ".scala": "scala", ".ex": "elixir", ".exs": "elixir",
}


def guess_language_from_path(path: str) -> str:
    ext = "." + path.rsplit("/", 1)[-1].rsplit(".", 1)[-1].lower() if "." in path else ""
    return LANG_MAP.get(ext, "text")


def fetch_commit_diff(owner: str, repo: str, sha: str) -> tuple:
    """Fetch a GitHub commit diff and return (vulnerable_code, patched_code)."""
    patch_url = f"https://github.com/{owner}/{repo}/commit/{sha}.patch"
    try:
        r = subprocess.run(
            ["curl", "-sL", patch_url],
            capture_output=True, text=True, timeout=30
        )
        if r.returncode != 0 or not r.stdout:
            return None, None
        patch = r.stdout
    except Exception:
        return None, None

    # Parse patch to extract vulnerable and patched code
    before_lines = []
    after_lines = []
    current_file = ""
    file_before = []
    file_after = []

    for line in patch.split("\n"):
        if line.startswith("--- a/"):
            current_file = line[6:]
            continue
        if line.startswith("+++ b/"):
            continue
        if line.startswith("@@"):
            # Save previous file
            if file_before and any(l.strip() for l in file_before):
                before_lines.append((current_file, "\n".join(file_before)))
            if file_after and any(l.strip() for l in file_after):
                after_lines.append((current_file, "\n".join(file_after)))
            file_before = []
            file_after = []
            continue
        if line.startswith("---") or line.startswith("+++"):
            continue
        if line.startswith("-"):
            file_before.append(line[1:])
        elif line.startswith("+"):
            file_after.append(line[1:])
        else:
            file_before.append(line)
            file_after.append(line)

    # Last file
    if file_before and any(l.strip() for l in file_before):
        before_lines.append((current_file, "\n".join(file_before)))
    if file_after and any(l.strip() for l in file_after):
        after_lines.append((current_file, "\n".join(file_after)))

    if not before_lines:
        return None, None

    # Take the file with most changes
    best = max(before_lines, key=lambda x: x[1].count("\n") if x[1] else 0)
    best_file, vuln_code = best
    patch_code = ""
    for fname, code in after_lines:
        if fname == best_file:
            patch_code = code
            break
    if not patch_code and after_lines:
        patch_code = after_lines[0][1]

    if not vuln_code or len(vuln_code) < 10:
        return None, None

    return vuln_code, patch_code


def parse_references(refs: list) -> list:
    """Extract (owner, repo, sha) tuples from reference URLs."""
    results = []
    pattern = re.compile(r"github\.com/([^/]+)/([^/]+)/commit/([0-9a-f]{7,40})")
    for url in refs:
        m = pattern.search(url)
        if m:
            results.append((m.group(1), m.group(2), m.group(3)))
    return results


def process_osv() -> Counter:
    """Process OSV data and extract commit diffs."""
    stats = Counter()
    out_file = OUT_DIR / "osv_extracted.jsonl"
    checkpoint_file = OUT_DIR / ".osv_checkpoint.json"

    # Resume from checkpoint
    processed = set()
    if out_file.exists():
        for line in open(out_file):
            s = json.loads(line)
            processed.add(s.get("source", ""))
    if checkpoint_file.exists():
        try:
            ckpt = json.loads(checkpoint_file.read_text())
            processed.update(ckpt.get("processed", []))
        except Exception:
            pass

    # Also skip samples already in meta
    existing_ids = set()
    for meta_file in META_DIR.glob("*.jsonl"):
        for line in open(meta_file):
            s = json.loads(line)
            existing_ids.add(s.get("id", ""))

    extracted = len(processed)
    skipped_no_code = 0
    skipped_api_error = 0
    skipped_existing = 0

    print(f"[osv] Loading {OSV_FILE}...")
    osv_samples = []
    for line in open(OSV_FILE):
        osv_samples.append(json.loads(line))
    print(f"[osv] {len(osv_samples)} total samples")

    for i, s in enumerate(osv_samples):
        source = s.get("source", "")
        if source in processed:
            continue
        sid = s.get("id", "")
        if sid in existing_ids:
            skipped_existing += 1
            processed.add(source)
            continue

        refs = s.get("references", [])
        commits = parse_references(refs)
        if not commits:
            skipped_no_code += 1
            processed.add(source)
            continue

        vuln_code = None
        patch_code = None
        for owner, repo, sha in commits[:3]:  # Try up to 3 commits
            vc, pc = fetch_commit_diff(owner, repo, sha)
            if vc:
                vuln_code = vc
                patch_code = pc
                break

        if not vuln_code:
            skipped_api_error += 1
            processed.add(source)
            continue

        lang = guess_language_from_path("")
        # Detect language from file extension if possible
        for ref in refs:
            if "." in ref.rsplit("/", 1)[-1]:
                lang = guess_language_from_path(ref)
                break
        if lang == "text":
            lang = s.get("language", "python")

        fp = hashlib.md5(vuln_code.encode()).hexdigest()[:12]
        record = {
            "id": f"real_{fp}",
            "language": lang,
            "vulnerable_code": vuln_code,
            "patched_code": patch_code or None,
            "cwe": s.get("cwe", "CWE-000"),
            "severity": s.get("severity", "medium"),
            "explanation": s.get("explanation", "")[:1500],
            "attack_scenario": s.get("attack_scenario", "")[:500],
            "secure_fix": patch_code[:500] if patch_code else s.get("secure_fix", ""),
            "source": source,
            "source_license": "CC-BY-4.0",
            "cve": s.get("cve"),
            "owasp": None,
            "cvss": s.get("cvss"),
            "is_vulnerable": True,
            "split": "train",
            "fingerprint": fp,
            "added_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "references": refs,
        }

        with open(out_file, "a") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
        extracted += 1
        processed.add(source)

        if extracted % 50 == 0:
            print(f"  [osv] extracted {extracted}, skipped (no code: {skipped_no_code}, api: {skipped_api_error}, existing: {skipped_existing})")
            # Checkpoint
            with open(checkpoint_file, "w") as f:
                json.dump({"count": extracted, "processed": list(processed)[-1000:]}, f)

    print(f"[osv] Done: {extracted} extracted, {skipped_no_code} no commit, {skipped_api_error} fetch failed, {skipped_existing} already in meta")
    return stats


def process_github_with_code() -> Counter:
    """Copy GitHub advisories that already have real code extracted."""
    stats = Counter()
    out_file = OUT_DIR / "github_with_code.jsonl"

    if not GH_WITH_CODE_FILE.exists():
        print("[gh] No github_advisories_with_code.jsonl found")
        return stats

    # Check which samples are already in meta
    existing_ids = set()
    for meta_file in META_DIR.glob("*.jsonl"):
        for line in open(meta_file):
            s = json.loads(line)
            existing_ids.add(s.get("id", ""))

    added = 0
    skipped = 0
    with open(out_file, "w") as out_f:
        for line in open(GH_WITH_CODE_FILE):
            s = json.loads(line)
            if s.get("id", "") in existing_ids:
                skipped += 1
                continue
            # Ensure it has the right fields
            record = {
                "id": s.get("id", ""),
                "language": s.get("language", "python"),
                "vulnerable_code": s.get("vulnerable_code", ""),
                "patched_code": s.get("patched_code"),
                "cwe": s.get("cwe", "CWE-000"),
                "severity": s.get("severity", "medium"),
                "explanation": s.get("explanation", "")[:1500],
                "attack_scenario": s.get("attack_scenario", "")[:500],
                "secure_fix": s.get("secure_fix", ""),
                "source": s.get("source", "github_advisory"),
                "source_license": "CC-BY-4.0",
                "cve": s.get("cve"),
                "owasp": None,
                "cvss": None,
                "is_vulnerable": True,
                "split": "train",
                "fingerprint": hashlib.md5((s.get("vulnerable_code", "") or "").encode()).hexdigest()[:12],
                "added_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "references": s.get("references", []),
            }
            out_f.write(json.dumps(record, ensure_ascii=False) + "\n")
            added += 1
    print(f"[gh] {added} added, {skipped} already in meta")
    return stats


def merge_all():
    """Merge all extracted real CVE files into one plus meta integration."""
    combined = OUT_DIR / "all_real_cves.jsonl"
    all_samples = []

    for source_file in sorted(OUT_DIR.glob("*.jsonl")):
        if source_file.name == "all_real_cves.jsonl":
            continue
        count = 0
        for line in open(source_file):
            s = json.loads(line)
            if s.get("vulnerable_code") and len(s.get("vulnerable_code", "")) > 20:
                all_samples.append(s)
                count += 1
        print(f"  {source_file.name}: {count} samples")

    print(f"\nTotal real CVE samples with code: {len(all_samples)}")

    # Deduplicate by fingerprint
    seen = set()
    deduped = []
    for s in all_samples:
        fp = s.get("fingerprint", "")
        if fp in seen:
            continue
        seen.add(fp)
        deduped.append(s)
    print(f"After dedup: {len(deduped)}")

    # Write combined
    with open(combined, "w") as f:
        for s in deduped:
            f.write(json.dumps(s, ensure_ascii=False) + "\n")

    # Write stats
    cwes = Counter(s["cwe"] for s in deduped if s.get("cwe"))
    langs = Counter(s["language"] for s in deduped if s.get("language"))
    with_patch = sum(1 for s in deduped if s.get("patched_code"))
    print(f"\nStats:")
    print(f"  CWEs: {len(cwes)} unique")
    print(f"  Languages: {dict(langs.most_common(10))}")
    print(f"  With patch: {with_patch}/{len(deduped)} ({100*with_patch/len(deduped):.1f}%)")
    print(f"\nTop 10 CWEs:")
    for cwe, n in cwes.most_common(10):
        print(f"  {cwe}: {n}")

    return len(deduped)


def main():
    print("=" * 60)
    print("Real CVE Import Pipeline")
    print("=" * 60)

    print("\n1. Processing GitHub advisories with existing code...")
    process_github_with_code()

    print("\n2. Extracting commit diffs from OSV data...")
    process_osv()

    print("\n3. Merging all real CVE samples...")
    total = merge_all()

    print(f"\n{'=' * 60}")
    print(f"Done. {total:,} real CVE samples with actual code extracted.")
    print(f"Next: python2 v2/dataset/import_real_cves.py")
    print(f"      → run merge into meta")


if __name__ == "__main__":
    main()
