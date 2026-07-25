"""System prompt — compact (<1K chars framework)."""
from __future__ import annotations
import os, subprocess
from pathlib import Path
from typing import Optional
from v2.cli.project_context import find_project_root, load_rakshakai_md


def _git_status() -> str:
    try:
        out = subprocess.run(["git", "status", "--short"], capture_output=True, text=True, timeout=2).stdout.strip()
        return out[:200]
    except Exception:
        return ""


def build_system_prompt(
    cwd: Optional[str] = None,
    include_tools: bool = True,
    include_git: bool = True,
    include_rakshakai_md: bool = True,
    include_agents_md: bool = True,
    extra_context: Optional[str] = None,
) -> str:
    parts = ["You are RakshakAI, a security coding agent. Respond concisely."]
    if include_git:
        st = _git_status()
        if st:
            parts.append(f"git: {st}")
    if include_rakshakai_md:
        ctx = load_rakshakai_md(cwd)
        if ctx:
            parts.append(ctx[:500])
    if include_agents_md:
        root = find_project_root(cwd)
        if root:
            ap = root / "AGENTS.md"
            if ap.exists():
                c = ap.read_text(encoding="utf-8", errors="replace").strip()[:500]
                if c:
                    parts.append(c)
    if extra_context:
        parts.append(extra_context[:500])
    return "\n".join(parts)


def build_scan_system_prompt() -> str:
    return (
        "Analyze code for security vulnerabilities. "
        'Reply JSON: {"is_vulnerable":bool,"vulnerability_type":str|null,"severity":"critical|high|medium|low|clean",'
        '"explanation":str,"attack_scenario":str,"secure_fix":str,"confidence":float}. '
        "Focus: injection, XSS, CSRF, broken auth, path traversal, insecure deserialization, SSRF, crypto misuse."
    )
