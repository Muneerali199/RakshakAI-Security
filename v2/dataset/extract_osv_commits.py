#!/usr/bin/env python3
"""
Fast extraction of vulnerable→patched code from OSV commit references.
Uses threading + .patch URLs for high throughput.

Usage: python3 v2/dataset/extract_osv_commits.py [--workers 10]
"""
import json
import hashlib
import os
import re
import sys
import time
from pathlib import Path
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional
import urllib.request
import urllib.error

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

OUT_DIR = Path("v2/inputs/datasets/phase_b/real_cve_generated")
META_DIR = Path("v2/inputs/datasets/phase_b/meta")
OSV_FILE = Path("v2/inputs/datasets/raw/osv.jsonl")
OUT_DIR.mkdir(parents=True, exist_ok=True)

GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")

LANG_MAP = {
    ".py": "python", ".js": "javascript", ".ts": "typescript",
    ".jsx": "javascript", ".tsx": "typescript",
    ".java": "java", ".go": "go", ".rs": "rust",
    ".c": "c", ".cpp": "cpp", ".h": "c", ".hpp": "cpp",
    ".php": "php", ".rb": "ruby", ".cs": "csharp",
    ".swift": "swift", ".kt": "kotlin", ".sol": "solidity",
    ".scala": "scala", ".ex": "elixir", ".exs": "elixir",
    ".vue": "javascript", ".jsx": "react",
    ".pyi": "python", ".pyx": "python",
}

COMMIT_PATTERN = re.compile(r"github\.com/([^/]+)/([^/]+)/commit/([0-9a-f]{7,40})")


def guess_language(path: str) -> str:
    parts = path.rsplit("/", 1)[-1].rsplit(".", 1)
    if len(parts) == 2:
        return LANG_MAP.get("." + parts[1].lower(), "text")
    return "text"


def fetch_patch(owner: str, repo: str, sha: str) -> Optional[str]:
    url = f"https://github.com/{owner}/{repo}/commit/{sha}.patch"
    req = urllib.request.Request(url)
    req.add_header("Authorization", f"Bearer {GITHUB_TOKEN}")
    req.add_header("User-Agent", "RakshakAI/1.0")
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except Exception:
        return None


def parse_patch(patch: str) -> tuple:
    """Parse a .patch file into (vulnerable_code, patched_code)."""
    hunks = re.split(r'^diff --git a/(.*?) b/(.*?)$', patch, flags=re.MULTILINE)
    if len(hunks) < 3:
        return None, None

    best_vuln, best_patch, best_len = None, None, 0

    # Process each file in diff
    for i in range(1, len(hunks) - 1, 3):
        if i + 2 >= len(hunks):
            break
        old_file = hunks[i]
        new_file = hunks[i + 1]
        content = hunks[i + 2]

        before = []
        after = []
        for line in content.split("\n"):
            if line.startswith("---") or line.startswith("+++") or line.startswith("@@") or line.startswith("diff"):
                continue
            if line.startswith("-"):
                before.append(line[1:])
            elif line.startswith("+"):
                after.append(line[1:])
            else:
                before.append(line)
                after.append(line)

        vuln = "\n".join(before).strip()
        patched = "\n".join(after).strip()
        if len(vuln) > best_len and len(vuln) >= 20:
            best_vuln = vuln
            best_patch = patched if len(patched) > 10 else None
            best_len = len(vuln)

    if best_vuln and best_len >= 20:
        return best_vuln, best_patch
    return None, None


def extract_one(s: dict) -> Optional[dict]:
    refs = s.get("references", [])
    if not refs:
        return None

    commits = []
    for url in refs:
        m = COMMIT_PATTERN.search(url)
        if m:
            commits.append((m.group(1), m.group(2), m.group(3)))

    if not commits:
        return None

    for owner, repo, sha in commits[:5]:
        patch = fetch_patch(owner, repo, sha)
        if not patch:
            continue
        vuln, patched = parse_patch(patch)
        if vuln:
            fp = hashlib.md5(vuln.encode()).hexdigest()[:12]
            lang = "text"
            for ref in refs:
                lg = guess_language(ref)
                if lg != "text":
                    lang = lg
                    break
            if lang == "text":
                lang = s.get("language", "python")

            return {
                "id": f"real_{fp}",
                "language": lang,
                "vulnerable_code": vuln,
                "patched_code": patched,
                "cwe": s.get("cwe", "CWE-000"),
                "severity": s.get("severity", "medium"),
                "explanation": (s.get("explanation", "") or "")[:1500],
                "attack_scenario": (s.get("attack_scenario", "") or "")[:500],
                "source": s.get("source", "osv"),
                "source_license": "CC-BY-4.0",
                "cve": s.get("cve"),
                "owasp": None,
                "cvss": s.get("cvss"),
                "is_vulnerable": True,
                "split": "train",
                "fingerprint": fp,
                "added_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "references": refs[:5],
            }
    return None


def build_source_set() -> set:
    """Build set of already-processed sources from existing files."""
    processed = set()
    for f in OUT_DIR.glob("*.jsonl"):
        if f.name == "all_real_cves.jsonl":
            continue
        for line in open(f):
            try:
                s = json.loads(line)
                if s.get("source"):
                    processed.add(s["source"])
            except Exception:
                pass
    return processed


def build_existing_id_set() -> set:
    existing = set()
    for f in META_DIR.glob("*.jsonl"):
        for line in open(f):
            try:
                s = json.loads(line)
                if s.get("id"):
                    existing.add(s["id"])
                if s.get("fingerprint"):
                    existing.add("fp:" + s["fingerprint"])
            except Exception:
                pass
    return set()


def main():
    workers = int(sys.argv[1]) if len(sys.argv) > 1 else 15

    print("=" * 60, flush=True)
    print(f"OSV Commit Extraction (workers={workers})", flush=True)
    print("=" * 60, flush=True)

    print("\n1. Loading OSV data...", flush=True)
    osv_samples = [json.loads(line) for line in open(OSV_FILE)]
    print(f"   {len(osv_samples):,} total OSV samples", flush=True)

    # Filter to only those with commit refs
    has_commits = []
    for s in osv_samples:
        refs = s.get("references", [])
        if refs and any(COMMIT_PATTERN.search(u) for u in refs):
            has_commits.append(s)
    print(f"   {len(has_commits):,} have commit references", flush=True)

    print("\n2. Building skip sets...", flush=True)
    processed = build_source_set()
    existing_ids = build_existing_id_set()
    print(f"   Already processed: {len(processed):,}", flush=True)
    print(f"   Already in meta:   {len(existing_ids):,}", flush=True)

    to_process = [s for s in has_commits if s.get("source", "") not in processed]
    print(f"   Remaining to extract: {len(to_process):,}", flush=True)
    
    if not to_process:
        print("   Nothing to do!", flush=True)
        return

    print(f"\n3. Extracting commits (this will take a while)...", flush=True)
    out_file = OUT_DIR / "osv_extracted.jsonl"
    
    start = time.time()
    extracted = 0
    errors = 0
    skipped = 0
    batch = []

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(extract_one, s): s for s in to_process}
        
        for i, future in enumerate(as_completed(futures)):
            try:
                result = future.result()
                if result:
                    batch.append(result)
                    extracted += 1
                else:
                    skipped += 1
            except Exception:
                errors += 1

            if (i + 1) % 50 == 0:
                elapsed = time.time() - start
                rate = (i + 1) / elapsed if elapsed > 0 else 0
                eta = (len(to_process) - i - 1) / rate if rate > 0 else 0
                print(f"   [{i+1}/{len(to_process)}] extracted={extracted} skipped={skipped} err={errors} "
                      f"rate={rate:.1f}/s eta={eta:.0f}s")

            # Flush batch periodically
            if len(batch) >= 100:
                with open(out_file, "a") as f:
                    for r in batch:
                        f.write(json.dumps(r, ensure_ascii=False) + "\n")
                batch = []

    # Final flush
    if batch:
        with open(out_file, "a") as f:
            for r in batch:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")

    elapsed = time.time() - start
    print(f"\n4. Done in {elapsed:.0f}s")
    print(f"   Extracted: {extracted:,}")
    print(f"   Skipped:   {skipped:,}")
    print(f"   Errors:    {errors:,}")
    print(f"   Rate:      {extracted/elapsed:.1f}/s")

    print(f"\n5. Summary stats of extracted data:")
    if out_file.exists():
        samples = [json.loads(l) for l in open(out_file)]
        cwes = Counter(s.get("cwe", "CWE-000") for s in samples)
        langs = Counter(s.get("language", "?") for s in samples)
        with_patch = sum(1 for s in samples if s.get("patched_code"))
        print(f"   Total:       {len(samples):,}")
        print(f"   CWEs:        {len(cwes)} unique")
        print(f"   Languages:   {len(langs)} unique")
        print(f"   Top langs:   {dict(langs.most_common(8))}")
        print(f"   With patch:  {with_patch}/{len(samples)} ({100*with_patch/len(samples):.1f}%)")
        print(f"\n   Top 10 CWEs:")
        for cwe, n in cwes.most_common(10):
            print(f"     {cwe}: {n}")

    print(f"\n   Next step: merge into meta")

if __name__ == "__main__":
    main()
