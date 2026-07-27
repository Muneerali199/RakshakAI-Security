#!/usr/bin/env python3
"""Mine npm vulnerability advisories (NO API KEY NEEDED)."""
import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from v2.dataset.schema import SecuritySample, write_jsonl

OUTPUT = Path("v2/inputs/datasets/raw/npm_vulns.jsonl")

# Use GitHub advisory database (public, no auth needed)
vuln_packages = [
    "lodash", "axios", "moment", "request", "express", "jquery", "react", 
    "vue", "angular", "webpack", "babel-core", "grunt", "gulp"
]

samples = []
for pkg in vuln_packages[:5]:  # Limit for quick test
    try:
        # Get package info from npm registry (public API)
        result = subprocess.run(
            ["curl", "-s", f"https://registry.npmjs.org/{pkg}"],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            print(f"✓ Fetched {pkg}")
    except:
        pass

print(f"\n📊 Mined 0 npm vulnerabilities (stub - need GitHub API integration)")
print(f"   Alternative: Use existing OSV npm data")
