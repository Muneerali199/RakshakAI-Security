"""Security Gate — blocks git commits/pushes when vulnerabilities are found.

Installs git hooks that scan staged code before commit and before push.
Configurable severity thresholds via .rakshakai/config.json.
"""
from __future__ import annotations
import os
import sys
import json
import subprocess
from pathlib import Path
from typing import Optional

DEFAULT_CONFIG = {
    "security_gate": {
        "enabled": True,
        "block_on": ["critical", "high"],
        "server_url": "http://localhost:8080",
        "scan_staged": True,
        "pre_push": True,
        "exclude_patterns": [
            "test_*", "*_test.py", "*.test.js",
            "node_modules/**", ".git/**", "__pycache__/**",
            "*.min.js", "*.min.css", "*.map",
        ],
        "fail_message": "RakshakAI blocked this commit — vulnerability detected.",
        "allow_bypass": True,
    }
}


def _load_config(repo_path: str = ".") -> dict:
    """Load config from .rakshakai/config.json or create defaults."""
    config_path = Path(repo_path) / ".rakshakai" / "config.json"
    if config_path.exists():
        try:
            return json.loads(config_path.read_text())
        except (json.JSONDecodeError, OSError):
            pass
    return DEFAULT_CONFIG


def _save_config(config: dict, repo_path: str = "."):
    """Save config to .rakshakai/config.json."""
    config_path = Path(repo_path) / ".rakshakai" / "config.json"
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(json.dumps(config, indent=2))


def _get_staged_files(repo_path: str = ".") -> list[str]:
    """Get list of staged source files."""
    try:
        result = subprocess.run(
            ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"],
            capture_output=True, text=True, cwd=repo_path, timeout=10,
        )
        if result.returncode != 0:
            return []
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return []

    scan_exts = {
        ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".c", ".cpp",
        ".h", ".hpp", ".go", ".rs", ".rb", ".php", ".cs", ".swift",
        ".kt", ".scala", ".sql", ".sh", ".bash", ".sol", ".vue",
    }

    files = []
    for f in result.stdout.strip().split("\n"):
        f = f.strip()
        if not f:
            continue
        ext = Path(f).suffix.lower()
        if ext in scan_exts:
            full_path = os.path.join(repo_path, f)
            if os.path.exists(full_path):
                files.append(full_path)
    return files


def _scan_file(file_path: str, server_url: str) -> list[dict]:
    """Scan a single file via the server API."""
    try:
        import urllib.request
        import urllib.error

        with open(file_path, "r", errors="replace") as fh:
            code = fh.read()

        lang_map = {
            ".py": "python", ".js": "javascript", ".ts": "typescript",
            ".jsx": "javascript", ".tsx": "typescript", ".java": "java",
            ".c": "c", ".cpp": "cpp", ".h": "c", ".hpp": "cpp",
            ".go": "go", ".rs": "rust", ".rb": "ruby", ".php": "php",
            ".cs": "csharp", ".swift": "swift", ".kt": "kotlin",
            ".sql": "sql", ".sh": "shell", ".sol": "solidity",
        }
        ext = Path(file_path).suffix.lower()
        language = lang_map.get(ext, "auto")

        payload = json.dumps({
            "code": code,
            "language": language,
            "provider": "groq",
        }).encode()

        req = urllib.request.Request(
            f"{server_url}/v2/scan",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read())

        finding = data.get("finding", {})
        if finding.get("vulnerability"):
            return [{
                "file": file_path,
                "vulnerability": finding.get("vulnerability", "Unknown"),
                "cwe": finding.get("cwe", ""),
                "severity": finding.get("severity", "medium"),
                "confidence": finding.get("confidence", 0),
                "root_cause": finding.get("root_cause", ""),
                "engine": data.get("engine", "unknown"),
            }]
        return []
    except (urllib.error.URLError, OSError, json.JSONDecodeError, TimeoutError):
        return []


def _should_block(vulns: list[dict], block_on: list[str]) -> bool:
    """Check if any vulnerability should block the commit."""
    for v in vulns:
        sev = v.get("severity", "").lower()
        if sev in block_on:
            return True
    return False


PRE_COMMIT_HOOK = '''#!/usr/bin/env python3
"""RakshakAI Security Gate — pre-commit hook.

Scans staged code for vulnerabilities before allowing commit.
Configure via .rakshakai/config.json
Bypass with: git commit --no-verify
"""
import os, sys, subprocess, json
from pathlib import Path

REPO_ROOT = subprocess.check_output(
    ["git", "rev-parse", "--show-toplevel"]
).decode().strip()

# Load config
config_path = Path(REPO_ROOT) / ".rakshakai" / "config.json"
if config_path.exists():
    try:
        config = json.loads(config_path.read_text())
    except Exception:
        config = {}
else:
    config = {}

gate = config.get("security_gate", {})
if not gate.get("enabled", True):
    sys.exit(0)

server_url = gate.get("server_url", "http://localhost:8080")
block_on = gate.get("block_on", ["critical", "high"])

# Check if server is running
try:
    import urllib.request
    urllib.request.urlopen(f"{server_url}/v2/health", timeout=3)
except Exception:
    print("[RakshakAI] Server not running — skipping security scan.")
    print("[RakshakAI] Start server: python3 -m v2.deploy.server")
    sys.exit(0)

# Get staged files
try:
    result = subprocess.run(
        ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"],
        capture_output=True, text=True, cwd=REPO_ROOT, timeout=10,
    )
    staged = [f.strip() for f in result.stdout.strip().split("\\n") if f.strip()]
except Exception:
    sys.exit(0)

scan_exts = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".c", ".cpp",
    ".h", ".hpp", ".go", ".rs", ".rb", ".php", ".cs", ".swift",
    ".kt", ".scala", ".sql", ".sh", ".bash", ".sol", ".vue",
}

source_files = []
for f in staged:
    ext = Path(f).suffix.lower()
    full = os.path.join(REPO_ROOT, f)
    if ext in scan_exts and os.path.exists(full):
        source_files.append(full)

if not source_files:
    sys.exit(0)

lang_map = {
    ".py": "python", ".js": "javascript", ".ts": "typescript",
    ".jsx": "javascript", ".tsx": "typescript", ".java": "java",
    ".c": "c", ".cpp": "cpp", ".h": "c", ".hpp": "cpp",
    ".go": "go", ".rs": "rust", ".rb": "ruby", ".php": "php",
    ".cs": "csharp", ".swift": "swift", ".kt": "kotlin",
    ".sql": "sql", ".sh": "shell", ".sol": "solidity",
}

print(f"\\n[RakshakAI] Scanning {len(source_files)} staged file(s)...")

import urllib.request, urllib.error

blocked = []
scanned = 0

for fp in source_files:
    try:
        with open(fp, "r", errors="replace") as fh:
            code = fh.read()
        ext = Path(fp).suffix.lower()
        payload = json.dumps({
            "code": code,
            "language": lang_map.get(ext, "auto"),
            "provider": "groq",
        }).encode()
        req = urllib.request.Request(
            f"{server_url}/v2/scan",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read())
        finding = data.get("finding", {})
        scanned += 1
        if finding.get("vulnerability"):
            sev = finding.get("severity", "medium")
            vuln_name = finding.get("vulnerability", "Unknown")
            cwe = finding.get("cwe", "")
            rel = os.path.relpath(fp, REPO_ROOT)
            blocked.append({
                "file": rel,
                "severity": sev,
                "vulnerability": vuln_name,
                "cwe": cwe,
            })
    except Exception:
        pass

if blocked:
    critical_high = [b for b in blocked if b["severity"].lower() in block_on]
    if critical_high:
        print(f"\\n\\033[91m[RakshakAI] BLOCKED: {len(critical_high)} vulnerability(ies) found\\033[0m\\n")
        for b in critical_high:
            sev_color = "\\033[91m" if b["severity"] == "critical" else "\\033[93m"
            print(f"  {sev_color}[{b['severity'].upper()}]\\033[0m {b['file']}: {b['vulnerability']} ({b['cwe']})")
        print(f"\\n\\033[93mBypass with: git commit --no-verify\\033[0m")
        sys.exit(1)
    else:
        info_sev = [b for b in blocked if b["severity"].lower() not in block_on]
        if info_sev:
            print(f"\\n[RakshakAI] {len(info_sev)} informational finding(s) (not blocking):")
            for b in info_sev:
                print(f"  [{b['severity'].upper()}] {b['file']}: {b['vulnerability']} ({b['cwe']})")
        print(f"\\n[RakshakAI] {scanned} file(s) scanned. No blocking vulnerabilities. ✅")
        sys.exit(0)
else:
    print(f"[RakshakAI] {scanned} file(s) scanned. No vulnerabilities found. ✅")
    sys.exit(0)
'''

PRE_PUSH_HOOK = '''#!/usr/bin/env python3
"""RakshakAI Security Gate — pre-push hook.

Final security scan before pushing to remote.
Configure via .rakshakai/config.json
Bypass with: git push --no-verify
"""
import os, sys, subprocess, json
from pathlib import Path

REPO_ROOT = subprocess.check_output(
    ["git", "rev-parse", "--show-toplevel"]
).decode().strip()

config_path = Path(REPO_ROOT) / ".rakshakai" / "config.json"
if config_path.exists():
    try:
        config = json.loads(config_path.read_text())
    except Exception:
        config = {}
else:
    config = {}

gate = config.get("security_gate", {})
if not gate.get("enabled", True) or not gate.get("pre_push", True):
    sys.exit(0)

server_url = gate.get("server_url", "http://localhost:8080")
block_on = gate.get("block_on", ["critical", "high"])

try:
    import urllib.request
    urllib.request.urlopen(f"{server_url}/v2/health", timeout=3)
except Exception:
    print("[RakshakAI] Server not running — skipping pre-push scan.")
    sys.exit(0)

# Get all files changed vs remote
try:
    result = subprocess.run(
        ["git", "diff", "--name-only", "HEAD~1..HEAD"],
        capture_output=True, text=True, cwd=REPO_ROOT, timeout=10,
    )
    changed = [f.strip() for f in result.stdout.strip().split("\\n") if f.strip()]
except Exception:
    sys.exit(0)

scan_exts = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".c", ".cpp",
    ".h", ".hpp", ".go", ".rs", ".rb", ".php", ".cs", ".swift",
    ".kt", ".scala", ".sql", ".sh", ".bash", ".sol", ".vue",
}

source_files = []
for f in changed:
    ext = Path(f).suffix.lower()
    full = os.path.join(REPO_ROOT, f)
    if ext in scan_exts and os.path.exists(full):
        source_files.append(full)

if not source_files:
    sys.exit(0)

lang_map = {
    ".py": "python", ".js": "javascript", ".ts": "typescript",
    ".jsx": "javascript", ".tsx": "typescript", ".java": "java",
    ".c": "c", ".cpp": "cpp", ".h": "c", ".hpp": "cpp",
    ".go": "go", ".rs": "rust", ".rb": "ruby", ".php": "php",
    ".cs": "csharp", ".swift": "swift", ".kt": "kotlin",
    ".sql": "sql", ".sh": "shell", ".sol": "solidity",
}

print(f"\\n[RakshakAI] Pre-push: scanning {len(source_files)} file(s)...")

import urllib.request, urllib.error

blocked = []

for fp in source_files:
    try:
        with open(fp, "r", errors="replace") as fh:
            code = fh.read()
        ext = Path(fp).suffix.lower()
        payload = json.dumps({
            "code": code,
            "language": lang_map.get(ext, "auto"),
            "provider": "groq",
        }).encode()
        req = urllib.request.Request(
            f"{server_url}/v2/scan",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read())
        finding = data.get("finding", {})
        if finding.get("vulnerability"):
            sev = finding.get("severity", "medium")
            if sev.lower() in block_on:
                blocked.append({
                    "file": os.path.relpath(fp, REPO_ROOT),
                    "severity": sev,
                    "vulnerability": finding.get("vulnerability", "Unknown"),
                    "cwe": finding.get("cwe", ""),
                })
    except Exception:
        pass

if blocked:
    print(f"\\n\\033[91m[RakshakAI] PUSH BLOCKED: {len(blocked)} vulnerability(ies)\\033[0m\\n")
    for b in blocked:
        sev_color = "\\033[91m" if b["severity"] == "critical" else "\\033[93m"
        print(f"  {sev_color}[{b['severity'].upper()}]\\033[0m {b['file']}: {b['vulnerability']} ({b['cwe']})")
    print(f"\\nFix vulnerabilities or bypass with: git push --no-verify")
    sys.exit(1)
else:
    print(f"[RakshakAI] Push scan passed. ✅")
    sys.exit(0)
'''


def install_security_gate(repo_path: str = ".", config: Optional[dict] = None) -> dict:
    """Install pre-commit and pre-push hooks."""
    repo_dir = subprocess.check_output(
        ["git", "rev-parse", "--show-toplevel"],
        cwd=repo_path, text=True, timeout=5,
    ).strip()

    hooks_dir = Path(repo_dir) / ".git" / "hooks"
    hooks_dir.mkdir(parents=True, exist_ok=True)

    results = {"pre_commit": False, "pre_push": False, "config": False}

    # Install pre-commit hook
    pc_path = hooks_dir / "pre-commit"
    pc_path.write_text(PRE_COMMIT_HOOK)
    pc_path.chmod(0o755)
    results["pre_commit"] = True

    # Install pre-push hook
    pp_path = hooks_dir / "pre-push"
    pp_path.write_text(PRE_PUSH_HOOK)
    pp_path.chmod(0o755)
    results["pre_push"] = True

    # Save config
    if config:
        _save_config(config, repo_path)
    else:
        existing = _load_config(repo_path)
        if "security_gate" not in existing:
            existing.update(DEFAULT_CONFIG)
            _save_config(existing, repo_path)
    results["config"] = True

    return results


def uninstall_security_gate(repo_path: str = ".") -> dict:
    """Remove RakshakAI hooks."""
    try:
        repo_dir = subprocess.check_output(
            ["git", "rev-parse", "--show-toplevel"],
            cwd=repo_path, text=True, timeout=5,
        ).strip()
    except Exception:
        return {"error": "Not a git repository"}

    hooks_dir = Path(repo_dir) / ".git" / "hooks"
    results = {"pre_commit": False, "pre_push": False}

    for hook_name in ["pre-commit", "pre-push"]:
        hook_path = hooks_dir / hook_name
        if hook_path.exists():
            content = hook_path.read_text()
            if "RakshakAI" in content or "Security Gate" in content:
                hook_path.unlink()
                results[hook_name.replace("-", "_")] = True

    return results


def get_gate_status(repo_path: str = ".") -> dict:
    """Check status of security gate hooks."""
    try:
        repo_dir = subprocess.check_output(
            ["git", "rev-parse", "--show-toplevel"],
            cwd=repo_path, text=True, timeout=5,
        ).strip()
    except Exception:
        return {"installed": False, "error": "Not a git repository"}

    hooks_dir = Path(repo_dir) / ".git" / "hooks"
    config = _load_config(repo_path)
    gate_config = config.get("security_gate", {})

    status = {
        "installed": False,
        "pre_commit": False,
        "pre_push": False,
        "config": gate_config,
    }

    for hook_name, key in [("pre-commit", "pre_commit"), ("pre-push", "pre_push")]:
        hook_path = hooks_dir / hook_name
        if hook_path.exists():
            content = hook_path.read_text()
            if "RakshakAI" in content or "Security Gate" in content:
                status[key] = True

    status["installed"] = status["pre_commit"] or status["pre_push"]
    return status
