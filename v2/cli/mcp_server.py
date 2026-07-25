#!/usr/bin/env python3
"""MCP server for RakshakAI security scanning.

Exposes scan, explain, and fix tools via the Model Context Protocol.
Works in Cursor, Claude Code, and any MCP client.

Usage:
  rkscan mcp                    # Start stdio MCP server
  python -m v2.cli.mcp_server   # Same
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

_project_root = str(Path(__file__).resolve().parent.parent.parent)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from mcp.server.fastmcp import FastMCP
from v2.cli.llm import registry, chat_sync
from v2.cli.prompts import get_explain_messages, get_fix_messages

mcp = FastMCP("rakcli-security")

def _read_file(path: str) -> str:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"File not found: {path}")
    return p.read_text(encoding="utf-8", errors="replace")

@mcp.tool(
    name="scan_file",
    description="Scan a source code file for security vulnerabilities. Returns structured findings with CWE, severity, location, and fix suggestions.",
)
async def scan_file(
    file_path: str = "",
    code: str = "",
    language: str = "c",
    model: str = "deepseek",
) -> str:
    """Scan source code for vulnerabilities.

    Args:
        file_path: Path to the file to scan. If provided, reads the file.
        code: Raw code to scan. Used if file_path is not provided.
        language: The programming language (c, python, java, etc).
        model: Model to use (deepseek, gpt-4o, gpt-4o-mini).

    Returns:
        JSON string with vulnerabilities and summary.
    """
    if file_path:
        code = _read_file(file_path)
        language = Path(file_path).suffix.lstrip(".") or language

    from v2.cli.scanner import scan_code as _scan_code
    result = _scan_code(code, model=model, language=language)
    # Drop the _raw field for cleaner MCP output
    output = {k: v for k, v in result.items() if k != "_raw"}
    return json.dumps(output, indent=2)


@mcp.tool(
    name="explain_code",
    description="Explain what a source code file does — high-level purpose, key functions, and notable patterns.",
)
async def explain_code(
    file_path: str = "",
    code: str = "",
    language: str = "c",
    model: str = "deepseek",
) -> str:
    """Explain source code in plain language.

    Args:
        file_path: Path to the file to explain.
        code: Raw code to explain.
        language: Programming language.
        model: Model to use.

    Returns:
        Explanation of the code.
    """
    if file_path:
        code = _read_file(file_path)
        language = Path(file_path).suffix.lstrip(".") or language

    cfg = registry.get(model)
    messages = get_explain_messages(f"```{language}\n{code}\n```")
    return chat_sync(messages, cfg)


@mcp.tool(
    name="fix_vulnerability",
    description="Generate a secure fix for a vulnerable code file or code snippet.",
)
async def fix_vulnerability(
    file_path: str = "",
    code: str = "",
    description: str = "",
    model: str = "deepseek",
) -> str:
    """Generate a fix for a vulnerability.

    Args:
        file_path: Path to the vulnerable file.
        code: Vulnerable code snippet.
        description: Description of the vulnerability (optional, overrides file/code).
        model: Model to use.

    Returns:
        Fix with explanation.
    """
    cfg = registry.get(model)
    if description:
        messages = get_fix_messages(description)
    elif file_path:
        code = _read_file(file_path)
        messages = get_fix_messages(f"```\n{code}\n```")
    elif code:
        messages = get_fix_messages(f"```\n{code}\n```")
    else:
        return "No input provided. Pass file_path, code, or description."

    return chat_sync(messages, cfg)


@mcp.tool(
    name="list_models",
    description="List available AI models for code analysis.",
)
async def list_models() -> str:
    """List all available models."""
    models = []
    for name, cfg in registry.models.items():
        models.append({"name": name, "model": cfg.model, "provider": cfg.provider})
    return json.dumps(models, indent=2)


def main():
    """Run the MCP server over stdio."""
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
