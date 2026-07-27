"""
Download full CVEfixes (12,987 records) from HuggingFace + process into meta format.
Converts raw fields (vulnerable_code, fixed_code, cwe_id, language) to our schema.
Output: extra_vuln/cvefixes_full.jsonl
"""
import json, hashlib, sys, os, time
from pathlib import Path
from collections import Counter

try:
    from datasets import load_dataset
except ImportError:
    print("pip install datasets")
    sys.exit(1)

OUT = Path("inputs/datasets/extra_vuln")
RAW = Path("inputs/datasets/raw")
OUT.mkdir(parents=True, exist_ok=True)

CWE_PREFIX_MAP = {
    "cwe-": "", "CWE-": "", "cwe_": "", "CWE_": "",
}
EXISTING_CVEFIXES = RAW / "cvefixes.jsonl"

def normalize_cwe(raw):
    if not raw:
        return "CWE-000"
    raw = raw.strip().replace(" ", "-")
    if raw.startswith("CWE-") or raw.startswith("cwe-"):
        return raw.upper()
    if raw.startswith("CWE_") or raw.startswith("cwe_"):
        return "CWE-" + raw.split("_", 1)[1]
    return f"CWE-{raw}"

def normalize_lang(raw):
    m = {"c": "c", "c++": "cpp", "cpp": "cpp", "python": "python", "java": "java",
         "javascript": "javascript", "js": "javascript", "go": "go", "rust": "rust",
         "php": "php", "ruby": "ruby", "c#": "csharp", "csharp": "csharp",
         "typescript": "typescript", "swift": "swift", "kotlin": "kotlin",
         "scala": "scala", "perl": "perl", "shell": "shell", "bash": "shell",
         "solidity": "solidity", "html": "html", "css": "css"}
    return m.get(raw.lower().strip(), raw.lower().strip())

def make_fingerprint(code):
    return hashlib.md5((code or "").encode()).hexdigest()[:12]

def main():
    # Load existing CVEfixes fingerprints to skip dupes
    existing_fps = set()
    existing_ids = set()
    if EXISTING_CVEFIXES.exists():
        for line in open(EXISTING_CVEFIXES):
            try:
                d = json.loads(line)
                fp = d.get("fingerprint", "") or make_fingerprint(d.get("vulnerable_code", ""))
                existing_fps.add(fp)
                existing_ids.add(d.get("cve", ""))
            except Exception:
                pass
        print(f"Loaded {len(existing_fps)} existing fingerprints from {EXISTING_CVEFIXES}")

    print("Downloading CVEfixes from HuggingFace (streaming)...")
    ds = load_dataset("hitoshura25/cvefixes", split="train", streaming=True)

    out_file = OUT / "cvefixes_full.jsonl"
    lang_dist = Counter()
    cwe_dist = Counter()
    total = 0
    skipped_dup = 0
    skipped_short = 0
    skipped_no_code = 0
    start = time.time()

    with open(out_file, "w") as f:
        for i, row in enumerate(ds):
            vuln = (row.get("vulnerable_code") or "").strip()
            fix = (row.get("fixed_code") or "").strip()
            cve_id = (row.get("cve_id") or "").strip()
            lang = normalize_lang(row.get("language") or "")
            cwe = normalize_cwe(row.get("cwe_id") or "")

            if not vuln or len(vuln) < 20:
                skipped_short += 1
                continue
            if not fix:
                skipped_no_code += 1
                continue

            fp = make_fingerprint(vuln)
            if fp in existing_fps or cve_id in existing_ids:
                skipped_dup += 1
                continue

            explanation = (row.get("cve_description") or "")
            if isinstance(explanation, list):
                explanation = " ".join(e.get("value", "") for e in explanation)
            explanation = (explanation or "")[:1500]

            sample = {
                "vulnerable_code": vuln,
                "patched_code": fix,
                "cwe": cwe,
                "language": lang,
                "source": "cvefixes_full",
                "source_license": "Apache-2.0",
                "is_vulnerable": True,
                "explanation": explanation or f"Real CVE: {cve_id}. {cwe} vulnerability in {lang} code.",
                "severity": (row.get("severity") or "high").lower(),
                "cve": cve_id,
                "cvss": row.get("cvss3_base_score") or row.get("cvss2_base_score") or None,
                "fingerprint": fp,
                "commit_message": (row.get("commit_message") or "")[:500],
                "repo_url": (row.get("repo_url") or ""),
                "file_paths": row.get("file_paths") or [],
                "added_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            }

            f.write(json.dumps(sample, ensure_ascii=False) + "\n")
            total += 1
            lang_dist[lang] += 1
            cwe_dist[cwe] += 1
            existing_fps.add(fp)
            existing_ids.add(cve_id)

            if total > 0 and total % 1000 == 0:
                elapsed = time.time() - start
                print(f"  {total} samples ({elapsed:.0f}s), skipped: {skipped_dup} dup + {skipped_short} short + {skipped_no_code} no-fix")

    elapsed = time.time() - start
    print(f"\nDone: {total} new CVEfixes samples in {elapsed:.0f}s")
    print(f"Skipped: {skipped_dup} dup, {skipped_short} short code, {skipped_no_code} no fix")
    print(f"\nLanguage distribution:")
    for l, n in sorted(lang_dist.items(), key=lambda x: -x[1]):
        print(f"  {l}: {n}")
    print(f"\nTop CWEs:")
    for c, n in sorted(cwe_dist.items(), key=lambda x: -x[1])[:15]:
        print(f"  {c}: {n}")
    print(f"\nSaved to {out_file}")

if __name__ == "__main__":
    main()
