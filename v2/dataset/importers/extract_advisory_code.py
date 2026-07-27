#!/usr/bin/env python3
"""Extract real code from GitHub advisory patch URLs."""
import json
import os
import re
import subprocess
from pathlib import Path
import time
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

def extract_code_from_commit(owner: str, repo: str, commit: str, token: str = None) -> tuple:
    """Fetch commit diff and extract before/after code."""
    try:
        # Use GitHub API with authentication for higher rate limits
        auth_header = f"-H 'Authorization: token {token}'" if token else ""
        cmd = f"curl -s -H 'Accept: application/vnd.github.v3+json' {auth_header} 'https://api.github.com/repos/{owner}/{repo}/commits/{commit}'"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=15)
        
        if result.returncode != 0 or not result.stdout:
            return None, None
        
        commit_data = json.loads(result.stdout)
        
        # Check for rate limit
        if "message" in commit_data and "API rate limit" in commit_data["message"]:
            print("Rate limited, waiting 60s...", end="\r")
            time.sleep(60)
            return None, None
        
        files = commit_data.get("files", [])
        if not files:
            return None, None
        
        # Find the main file with most changes
        main_file = max(files, key=lambda f: f.get("changes", 0))
        patch = main_file.get("patch", "")
        
        if not patch or len(patch) < 100:
            return None, None
        
        # Parse diff to extract before/after code
        before_lines = []
        after_lines = []
        context_lines = []
        
        for line in patch.split("\n"):
            if line.startswith("@@"):
                continue
            elif line.startswith("---") or line.startswith("+++"):
                continue
            elif line.startswith("-"):
                before_lines.append(line[1:])
            elif line.startswith("+"):
                after_lines.append(line[1:])
            else:
                # Context line - add to both
                context_lines.append(line)
                before_lines.append(line)
                after_lines.append(line)
        
        vuln_code = "\n".join(before_lines)
        patched_code = "\n".join(after_lines)
        
        # Minimum code length
        if len(vuln_code.strip()) < 80 or len(patched_code.strip()) < 80:
            return None, None
        
        return vuln_code, patched_code
        
    except Exception as e:
        return None, None

def process_advisories():
    """Process GitHub advisories and extract real code."""
    
    # GitHub token for authentication (5000 requests/hour vs 60)
    token = os.environ.get("GITHUB_TOKEN", "")
    
    # Check if raw advisories exist
    advisory_file = Path("v2/inputs/datasets/raw/github_advisories.jsonl")
    if not advisory_file.exists():
        print(f"❌ {advisory_file} not found")
        print("Run: python3 v2/dataset/importers/convert_github_advisories.py first")
        return
    
    output_file = Path("v2/inputs/datasets/raw/github_advisories_with_code.jsonl")
    log_file = Path("v2/inputs/datasets/raw/extraction.log")
    
    samples_with_code = []
    processed = 0
    skipped = 0
    checked = 0
    
    print("Extracting real code from GitHub advisories...")
    print("This will take time due to API rate limiting (~5K samples in 2-3 hours)\n")
    print(f"Logging to: {log_file}\n")
    
    # Write progress incrementally
    def write_samples():
        with open(output_file, "w") as f:
            for s in samples_with_code:
                f.write(json.dumps(s) + "\n")
    
    with open(advisory_file) as f:
        for line in f:
            checked += 1
            if checked % 1000 == 0:
                print(f"Checked {checked:,} advisories, found {len(samples_with_code)} with code, skipped {skipped}...", end="\r")
                sys.stdout.flush()
            sample = json.loads(line)
            
            # Skip if already has real code
            code = sample.get("vulnerable_code", "")
            if "// GitHub Advisory" not in code:
                continue
            
            # Look for GitHub commit URLs in references
            refs = sample.get("references", [])
            commit_url = None
            
            for ref in refs:
                if isinstance(ref, str) and "github.com" in ref and "/commit/" in ref:
                    commit_url = ref
                    break
            
            if not commit_url:
                skipped += 1
                continue
            
            # Extract owner/repo/commit from URL
            match = re.search(r"github\.com/([^/]+)/([^/]+)/commit/([a-f0-9]+)", commit_url)
            if not match:
                skipped += 1
                continue
            
            owner, repo, commit = match.groups()
            
            # Extract code with authentication
            vuln_code, patched_code = extract_code_from_commit(owner, repo, commit, token)
            
            if vuln_code and patched_code:
                # Update sample with real code
                sample["vulnerable_code"] = vuln_code
                sample["patched_code"] = patched_code
                samples_with_code.append(sample)
                
                processed += 1
                
                # Write incrementally every 10 samples
                if len(samples_with_code) % 10 == 0:
                    write_samples()
                    print(f"\nExtracted {len(samples_with_code)} samples with code (checked {checked:,})  ")
                
                # Rate limit: 5000/hour with auth = ~80/min, use 60/min to be safe
                if processed % 100 == 0:
                    print(f"\nBrief pause... (extracted {len(samples_with_code)} so far)")
                    time.sleep(10)
                else:
                    time.sleep(0.2)  # 60 requests per minute
                
                # Target: 5K samples
                if len(samples_with_code) >= 5000:
                    print(f"\n✅ Reached target of 5000 samples")
                    break
            else:
                skipped += 1
    
    # Final write
    if samples_with_code:
        write_samples()
        
        print(f"\n\n✅ Extracted {len(samples_with_code)} samples with real code")
        print(f"Checked {checked:,} advisories, skipped {skipped:,}")
        print(f"Written to: {output_file}")
        
        # Stats
        by_lang = {}
        with_patches = 0
        for s in samples_with_code:
            lang = s.get("language", "unknown")
            by_lang[lang] = by_lang.get(lang, 0) + 1
            if s.get("patched_code"):
                with_patches += 1
        
        print(f"\nWith patches: {with_patches} ({with_patches/len(samples_with_code)*100:.1f}%)")
        print("\nBy language:")
        for lang, count in sorted(by_lang.items(), key=lambda x: -x[1])[:10]:
            print(f"  {lang}: {count:,}")
    else:
        print("\n❌ No samples with real code extracted")

if __name__ == "__main__":
    process_advisories()
