"""RAKSHAKAI.md project context — like CLAUDE.md for project memory.
Auto-loaded at session start. Lets users define rules, preferences, commands."""
from __future__ import annotations
import os, re, json
from pathlib import Path
from typing import Optional

RAKSHAKAI_FILENAME = "RAKSHAKAI.md"
RULE_DIR = ".rakshakai/rules"


def find_project_root(start: str | None = None) -> Optional[Path]:
    """Walk up from start to find project root (git repo or RAKSHAKAI.md)."""
    cwd = Path(start or os.getcwd()).resolve()
    for parent in [cwd] + list(cwd.parents):
        if (parent / ".git").exists() or (parent / RAKSHAKAI_FILENAME).exists():
            return parent
    return cwd


def load_rakshakai_md(path: str | None = None) -> str:
    """Load RAKSHAKAI.md from project root."""
    root = find_project_root(path)
    ctx_path = root / RAKSHAKAI_FILENAME
    if ctx_path.exists():
        content = ctx_path.read_text(encoding="utf-8", errors="replace")
        return f"<project_context from=\"{ctx_path}\">\n{content.strip()}\n</project_context>"

    # Auto-generate if not found
    content = f"""# RAKSHAKAI.md — Project Context for RakshakAI

This file defines project-specific rules, conventions, and preferences
that RakshakAI loads at the start of each session.

## Build & Test Commands

- Build: `make build` or `npm run build`
- Test all: `pytest` or `npm test`
- Test single: `pytest tests/test_file.py -k test_name`
- Lint: `ruff check .`

## Project Conventions
- Language: (auto-detected)
- Style guide: (describe your conventions)

## Security Rules
- Never commit secrets or API keys
- Validate all user input
- Use parameterized queries for databases

## Critical Rules (These Cannot Be Violated)
- (add your non-negotiable rules here)
"""
    return content


def load_scoped_rules(path: str | None = None) -> list[dict[str, str]]:
    """Load path-scoped rules from .rakshakai/rules/ directory."""
    root = find_project_root(path)
    rules_dir = root / RULE_DIR
    if not rules_dir.exists():
        return []

    rules = []
    for f in sorted(rules_dir.rglob("*.md")):
        rel = f.relative_to(rules_dir)
        content = f.read_text(encoding="utf-8", errors="replace")
        rules.append({
            "path": str(rel),
            "pattern": str(rel).replace(".md", "").replace("/", "/**/"),
            "content": content.strip(),
        })
    return rules


def get_relevant_rules(file_path: str, rules: list[dict[str, str]]) -> list[str]:
    """Get rules that match a given file path."""
    matched = []
    for rule in rules:
        pattern = rule["pattern"]
        if pattern.startswith("**") or pattern in file_path or any(
            part in file_path for part in pattern.replace("**/", "").split("/")
        ):
            matched.append(rule["content"])
    return matched


def build_project_context(path: str | None = None) -> str:
    """Build full project context string for the LLM."""
    root = find_project_root(path)
    parts = [f"Project root: {root}"]

    # RAKSHAKAI.md
    ctx = load_rakshakai_md(path)
    if ctx:
        parts.append(ctx)

    # Scoped rules
    rules = load_scoped_rules(path)
    if rules:
        parts.append(f"<scoped_rules count=\"{len(rules)}\">")
        for r in rules:
            parts.append(f"  [{r['path']}]: {r['content'][:100]}")
        parts.append("</scoped_rules>")

    # Git info
    try:
        repo = _get_git_info(root)
        if repo:
            parts.append(f"\n<git branch=\"{repo['branch']}\" dirty=\"{repo['dirty']}\"/>")
    except Exception:
        pass

    return "\n".join(parts)


def _get_git_info(root: Path) -> dict | None:
    try:
        import subprocess
        branch = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            capture_output=True, text=True, cwd=root, timeout=5
        ).stdout.strip()
        dirty = subprocess.run(
            ["git", "status", "--porcelain"],
            capture_output=True, text=True, cwd=root, timeout=5
        ).stdout.strip()
        return {"branch": branch or "detached", "dirty": bool(dirty)}
    except Exception:
        return None
