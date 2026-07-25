"""Git integration — diff scanning, pre-commit hooks, PR review."""
from __future__ import annotations
import os, subprocess, sys, tempfile
from pathlib import Path
from typing import Optional

import git

from v2.cli.scanner import BatchScanner, SCAN_EXTS


def get_repo(path: str = ".") -> Optional[git.Repo]:
    """Get git repo from path."""
    try:
        return git.Repo(path, search_parent_directories=True)
    except git.InvalidGitRepositoryError:
        return None


def get_diff_files(repo: git.Repo, staged: bool = False) -> list[str]:
    """Get files changed in working tree (or staged if staged=True)."""
    if staged:
        diffs = repo.index.diff("HEAD")
    else:
        diffs = repo.index.diff(None)  # unstaged
    files = []
    for d in diffs:
        p = Path(repo.working_dir) / d.a_path
        if p.suffix.lower() in SCAN_EXTS and p.exists():
            files.append(str(p))
    return files


def get_committed_diff(repo: git.Repo, base: str = "HEAD~1") -> list[str]:
    """Get files changed in last N commits."""
    try:
        diffs = repo.commit(base).diff("HEAD")
    except Exception:
        diffs = repo.head.commit.diff(None)
    files = []
    for d in diffs:
        p = Path(repo.working_dir) / d.a_path
        if p.suffix.lower() in SCAN_EXTS and p.exists():
            files.append(str(p))
    return files


def scan_diff_files(
    files: list[str],
    model: str = "deepseek",
) -> list[dict]:
    """Scan a list of changed files and return results."""
    scanner = BatchScanner(max_workers=3)
    results = scanner.scan_files(files, model=model)
    return [r.to_dict() for r in results]


# ── Pre-commit hook ──────────────────────────────────────

HOOK_TEMPLATE = """#!/usr/bin/env python3
\"\"\"RakshakAI pre-commit hook — scan staged changes for vulns.\"\"\"
import os, sys, subprocess, json
from pathlib import Path

REPO_ROOT = subprocess.check_output(["git", "rev-parse", "--show-toplevel"]).decode().strip()
sys.path.insert(0, str(Path(REPO_ROOT)))

try:
    from v2.cli.scanner import BatchScanner, SCAN_EXTS
    from v2.cli.llm import registry
except ImportError:
    print("âœ– RakshakAI not installed. Run: pip install -e .")
    sys.exit(1)

# Get staged files
result = subprocess.run(
    ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"],
    capture_output=True, text=True, cwd=REPO_ROOT,
)
staged = [f for f in result.stdout.strip().split("\\n") if f]
source_files = [
    os.path.join(REPO_ROOT, f) for f in staged
    if Path(f).suffix.lower() in SCAN_EXTS and os.path.exists(os.path.join(REPO_ROOT, f))
]

if not source_files:
    sys.exit(0)

print(f"âš  RakshakAI scanning {len(source_files)} staged file(s)...")
scanner = BatchScanner(max_workers=3)
results = scanner.scan_files(source_files, model="deepseek")
vulns = [r for r in results if r.cwe]

if vulns:
    print(f"\\nâœ– {len(vulns)} vulnerability(ies) found in staged changes:")
    for v in vulns:
        sev = v.severity.upper() if v.severity else "?"
        print(f"  [{sev}] {os.path.relpath(v.file, REPO_ROOT)}: {v.cwe}")
    print("\\nAborting commit. Use `git commit --no-verify` to bypass.")
    sys.exit(1)
else:
    print(f"âœ… No vulnerabilities in staged changes.")
    sys.exit(0)
"""


def install_precommit_hook(repo_path: str = ".") -> bool:
    """Install RakshakAI pre-commit hook."""
    repo = get_repo(repo_path)
    if not repo:
        return False
    hooks_dir = Path(repo.git_dir) / "hooks"
    hooks_dir.mkdir(parents=True, exist_ok=True)
    hook_path = hooks_dir / "pre-commit"
    hook_path.write_text(HOOK_TEMPLATE)
    hook_path.chmod(0o755)
    return True


def uninstall_precommit_hook(repo_path: str = ".") -> bool:
    """Remove RakshakAI pre-commit hook."""
    repo = get_repo(repo_path)
    if not repo:
        return False
    hook_path = Path(repo.git_dir) / "hooks" / "pre-commit"
    if hook_path.exists() and "RakshakAI" in hook_path.read_text():
        hook_path.unlink()
        return True
    return False


def is_hook_installed(repo_path: str = ".") -> bool:
    """Check if RakshakAI pre-commit hook is installed."""
    repo = get_repo(repo_path)
    if not repo:
        return False
    hook_path = Path(repo.git_dir) / "hooks" / "pre-commit"
    return hook_path.exists() and "RakshakAI" in hook_path.read_text()
