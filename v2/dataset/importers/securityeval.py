"""
RakshakAI v2 — SecurityEval importer (Phase 2.5).

Source:  https://github.com/utaha-security-lab/SecurityEval
Format:  Python source files in ``testcases/`` with YAML sidecars
         ``testcases/<id>.yaml`` that include the CWE label, severity,
         and prompt text.

Each test case consists of:
* ``testcases/<id>/<id>.py``         — the vulnerable Python file
* ``testcases/<id>/<id>_fixed.py``  — the fixed Python file (if any)
* ``testcases/<id>/<id>.yaml``       — metadata (CWE, prompt)

The original SecurityEval has 130 test cases covering ~70 CWE classes
in Python.  All entries are MIT-licensed.

Output: v2/inputs/datasets/raw/securityeval.jsonl
"""
from __future__ import annotations

import json
import re
import sys
import urllib.error
import zipfile
import io
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from v2.dataset.importers.common import (  # noqa: E402
    ImportStats, fetch, normalize_cwe, write_samples, is_harmful,
)
from v2.dataset.schema import SecuritySample  # noqa: E402


REPO = "utaha-security-lab/SecurityEval"
BRANCH = "main"
TREE_URL = f"https://api.github.com/repos/{REPO}/git/trees/{BRANCH}?recursive=1"


def _fetch_tree() -> list[dict]:
    """List every file in the SecurityEval repo via the Git trees API."""
    data = fetch(TREE_URL, timeout=60)
    tree = json.loads(data)
    return tree.get("tree", [])


def _fetch_blob(sha: str) -> str:
    """Fetch a file by its git blob SHA.  Re-uses the GitHub API."""
    url = f"https://api.github.com/repos/{REPO}/git/blobs/{sha}"
    data = json.loads(fetch(url, timeout=30))
    import base64
    raw = base64.b64decode(data["content"])
    return raw.decode("utf-8", errors="replace")


def _parse_yaml_meta(yaml_text: str) -> dict:
    """Crude YAML parser for the SecurityEval metadata file.  We only
    care about a handful of top-level scalar fields; full PyYAML is not
    required.
    """
    meta: dict = {}
    cur_key: Optional[str] = None
    for line in yaml_text.splitlines():
        line = line.rstrip()
        if not line or line.lstrip().startswith("#"):
            continue
        m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(.*)$", line)
        if m:
            cur_key = m.group(1)
            val = m.group(2).strip()
            if val and val[0] in "'\"":
                val = val.strip("'\"")
            meta[cur_key] = val
    return meta


def main() -> int:
    stats = ImportStats(source="securityeval")
    samples: list[SecuritySample] = []

    try:
        tree = _fetch_tree()
    except Exception as e:
        print(f"  [securityeval] tree fetch failed: {e!r}", file=sys.stderr)
        stats.error = repr(e)
        write_samples("securityeval", samples, stats)
        return 1

    # Group files by test case id
    by_id: dict[str, dict] = {}
    for entry in tree:
        path = entry.get("path", "")
        if not path.startswith("testcases/"):
            continue
        parts = path.split("/")
        if len(parts) < 3:
            continue
        tc_id = parts[1]
        fname = parts[2]
        by_id.setdefault(tc_id, {})[fname] = entry["sha"]

    for tc_id, files in by_id.items():
        # Find vulnerable file
        py_files = [f for f in files if f.endswith(".py")]
        if not py_files:
            stats.skipped_no_code += 1
            continue
        # SecurityEval naming: <id>.py is vulnerable, <id>_fixed.py is patched
        vuln_path = next((f for f in py_files if f == f"{tc_id}.py"), None)
        fixed_path = next((f for f in py_files if f == f"{tc_id}_fixed.py"), None)
        if not vuln_path:
            vuln_path = py_files[0]
        if not fixed_path:
            fixed_path = next((f for f in py_files if f != vuln_path), None)

        try:
            vuln_code = _fetch_blob(files[vuln_path])
            fixed_code = _fetch_blob(files[fixed_path]) if fixed_path else None
        except Exception:
            stats.skipped_no_code += 1
            continue
        if len(vuln_code.strip()) < 30:
            stats.skipped_too_short += 1
            continue
        # Parse YAML
        meta: dict = {}
        yaml_path = next((f for f in files if f.endswith(".yaml")), None)
        if yaml_path:
            try:
                meta = _parse_yaml_meta(_fetch_blob(files[yaml_path]))
            except Exception:
                pass
        cwe = normalize_cwe(meta.get("cwe") or meta.get("CWE") or "")
        if not cwe:
            stats.skipped_no_cwe += 1
            continue
        sev = (meta.get("severity") or "high").lower()
        if sev not in ("critical", "high", "medium", "low"):
            sev = "high"
        prompt = meta.get("prompt", "")
        if is_harmful(vuln_code + (fixed_code or "")):
            stats.skipped_harmful += 1
            continue
        try:
            s = SecuritySample.build(
                language="python",
                vulnerable_code=vuln_code[:8000],
                patched_code=fixed_code[:8000] if fixed_code else None,
                cwe=cwe,
                severity=sev,
                explanation=prompt[:1500] or f"SecurityEval test case {tc_id}",
                attack_scenario=prompt[:1500] or "Standard CWE attack pattern",
                secure_fix=(fixed_code and "Apply the fixed version per SecurityEval test case.") or "Review and parameterize inputs.",
                source=f"securityeval:{tc_id}",
                source_license="MIT",
                split="train",
            )
        except Exception:
            continue
        samples.append(s)
        stats.built += 1

    write_samples("securityeval", samples, stats)
    print(json.dumps(stats.to_dict(), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
