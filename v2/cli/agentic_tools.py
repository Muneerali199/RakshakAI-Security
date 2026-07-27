"""Agentic coding tools — Read, Edit, Glob, Grep, Bash (Claude Code-style).
These tools let the model autonomously navigate and modify the codebase."""
from __future__ import annotations
import os, re, subprocess, json, difflib, shutil, tempfile, time
from pathlib import Path
from typing import Optional


def _ensure_str(data):
    if isinstance(data, bytes):
        return data.decode("utf-8", errors="replace")
    return str(data)


class ReadTool:
    """Read file contents with line numbers and syntax context."""

    def read(self, file_path: str, offset: int = 0, limit: int = 2000) -> dict:
        p = Path(file_path).resolve()
        if not p.exists():
            return {"error": f"File not found: {file_path}"}
        if not p.is_file():
            return {"error": f"Not a file: {file_path}"}
        size = p.stat().st_size
        if size > 5_000_000:
            return {"error": f"File too large ({size/1e6:.1f}MB)"}
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
            lines = text.splitlines()
            total = len(lines)
            if offset > 0:
                lines = lines[offset:]
            if limit and len(lines) > limit:
                lines = lines[:limit]
            return {
                "file_path": str(p),
                "total_lines": total,
                "offset": offset,
                "content": "\n".join(lines),
                "truncated": total > (offset + limit) if limit else False,
            }
        except Exception as e:
            return {"error": str(e)}


class EditTool:
    """Apply exact string replacements to files. Pre-edit snapshots for safety."""

    def __init__(self):
        self._snapshots: dict[str, str] = {}

    def edit(self, file_path: str, old_string: str, new_string: str) -> dict:
        p = Path(file_path).resolve()
        if not p.exists():
            return {"error": f"File not found: {file_path}"}
        try:
            content = p.read_text(encoding="utf-8", errors="replace")
            if old_string not in content:
                # Try fuzzy match
                matches = self._find_similar(content, old_string)
                if matches:
                    return {
                        "error": f"String not found. Did you mean one of:\n" +
                                 "\n".join(f"  {m}" for m in matches[:5])
                    }
                return {"error": "String not found in file"}
            if content.count(old_string) > 1:
                return {"error": "Multiple matches. Provide more surrounding context."}

            # Snapshot for undo
            if file_path not in self._snapshots:
                self._snapshots[file_path] = content

            new_content = content.replace(old_string, new_string, 1)
            backup = p.with_suffix(p.suffix + ".bak")
            if not backup.exists():
                shutil.copy2(str(p), str(backup))

            p.write_text(new_content, encoding="utf-8")

            diff = self._make_diff(content, new_content, str(p))
            return {
                "success": True,
                "file_path": str(p),
                "diff": diff,
                "backup": str(backup),
            }
        except Exception as e:
            return {"error": str(e)}

    def undo(self, file_path: str) -> dict:
        if file_path not in self._snapshots:
            return {"error": "No snapshot to undo"}
        backup = Path(file_path).with_suffix(Path(file_path).suffix + ".bak")
        if backup.exists():
            shutil.copy2(str(backup), file_path)
            backup.unlink()
            del self._snapshots[file_path]
            return {"success": True, "file_path": file_path}
        return {"error": "Backup file not found"}

    def write(self, file_path: str, content: str) -> dict:
        p = Path(file_path).resolve()
        p.parent.mkdir(parents=True, exist_ok=True)
        if p.exists():
            self._snapshots[file_path] = p.read_text(encoding="utf-8", errors="replace")
        p.write_text(content, encoding="utf-8")
        return {"success": True, "file_path": str(p), "created": not p.exists()}

    def _make_diff(self, old: str, new: str, filepath: str) -> str:
        diff = difflib.unified_diff(
            old.splitlines(keepends=True),
            new.splitlines(keepends=True),
            fromfile=filepath, tofile=filepath,
        )
        return "".join(diff)

    def _find_similar(self, content: str, target: str, max_diff: float = 0.3) -> list[str]:
        target_lines = target.strip().splitlines()
        content_lines = content.splitlines()
        matches = []
        for i, line in enumerate(content_lines):
            if len(target_lines) == 1:
                ratio = difflib.SequenceMatcher(None, target.strip(), line.strip()).ratio()
                if ratio > (1 - max_diff):
                    context_start = max(0, i - 2)
                    context_end = min(len(content_lines), i + 3)
                    context = content_lines[context_start:context_end]
                    matches.append(f"  line {i+1}: ...{context[0]}...")
                    if len(matches) >= 5:
                        break
            elif i + len(target_lines) <= len(content_lines):
                block = "\n".join(content_lines[i:i+len(target_lines)])
                ratio = difflib.SequenceMatcher(None, target.strip(), block.strip()).ratio()
                if ratio > (1 - max_diff):
                    matches.append(f"  line {i+1}: {content_lines[i][:80]}...")
                    if len(matches) >= 5:
                        break
        return matches


class GlobTool:
    """Fast file pattern matching using glob patterns."""

    def glob(self, pattern: str, path: str | None = None) -> dict:
        search_dir = Path(path or os.getcwd()).resolve()
        if not search_dir.exists():
            return {"error": f"Directory not found: {path}"}

        try:
            files = sorted(search_dir.rglob(pattern))
            results = [str(f.relative_to(search_dir)) for f in files if f.is_file()]
            return {
                "files": results,
                "count": len(results),
                "search_dir": str(search_dir),
                "pattern": pattern,
            }
        except Exception as e:
            return {"error": str(e)}


class GrepTool:
    """Fast content search using regex patterns."""

    def grep(self, pattern: str, include: str | None = None, path: str | None = None) -> dict:
        search_dir = Path(path or os.getcwd()).resolve()
        if not search_dir.exists():
            return {"error": f"Directory not found: {path}"}

        try:
            matches = []
            for f in search_dir.rglob("*"):
                if not f.is_file():
                    continue
                if include and not f.match(include):
                    continue
                if f.stat().st_size > 1_000_000:
                    continue
                try:
                    text = f.read_text(encoding="utf-8", errors="replace")
                    for m in re.finditer(pattern, text, re.IGNORECASE):
                        line_num = text[:m.start()].count("\n") + 1
                        line_start = text.rfind("\n", 0, m.start()) + 1
                        line_end = text.find("\n", m.end())
                        line = text[line_start:line_end] if line_end > 0 else text[line_start:]
                        matches.append({
                            "file": str(f.relative_to(search_dir)),
                            "line": line_num,
                            "match": m.group()[:60],
                            "context": line.strip()[:120],
                        })
                except (UnicodeDecodeError, OSError):
                    continue

            matches = matches[:500]
            return {
                "matches": matches,
                "count": len(matches),
                "pattern": pattern,
                "search_dir": str(search_dir),
            }
        except Exception as e:
            return {"error": str(e)}


class BashTool:
    """Execute shell commands with timeout and output capture."""

    DENIED_PREFIXES = [
        "rm -rf /", "rm -rf ~", "mkfs", "dd if=", ":(){ :|:& };:",
        "> /dev/sda", "chmod 777 /", "sudo", "su ",
    ]

    def __init__(self):
        self._env = os.environ.copy()

    def bash(self, command: str, timeout: int = 120, workdir: str | None = None) -> dict:
        cmd_stripped = command.strip()
        for denied in self.DENIED_PREFIXES:
            if cmd_stripped.startswith(denied):
                return {"error": f"Command blocked for safety: {denied}"}

        cwd = workdir or os.getcwd()
        t0 = time.time()
        try:
            r = subprocess.run(
                ["bash", "-c", command],
                capture_output=True, text=True,
                timeout=timeout, cwd=cwd,
                env=self._env,
            )
            duration = time.time() - t0
            stdout = r.stdout[-100000:] if len(r.stdout) > 100000 else r.stdout
            stderr = r.stderr[-50000:] if len(r.stderr) > 50000 else r.stderr
            return {
                "success": r.returncode == 0,
                "exit_code": r.returncode,
                "stdout": stdout,
                "stderr": stderr,
                "duration_s": round(duration, 2),
                "truncated": len(r.stdout) > 100000 or len(r.stderr) > 50000,
            }
        except subprocess.TimeoutExpired:
            return {"error": f"Command timed out after {timeout}s", "duration_s": timeout}
        except FileNotFoundError:
            return {"error": "Shell not found"}
        except Exception as e:
            return {"error": str(e)}


def build_openai_tools_v2():
    """Build OpenAI-compatible tool definitions for the enhanced tools."""
    return [
        {
            "type": "function",
            "function": {
                "name": "read",
                "description": "Read file contents with line numbers. Use offset/limit to read specific portions of large files.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "file_path": {"type": "string", "description": "Absolute path to the file"},
                        "offset": {"type": "integer", "description": "Line number to start reading from (0-indexed)", "default": 0},
                        "limit": {"type": "integer", "description": "Maximum number of lines to read", "default": 2000},
                    },
                    "required": ["file_path"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "edit",
                "description": "Apply an exact string replacement in a file. Creates a backup before editing.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "file_path": {"type": "string", "description": "Absolute path to the file"},
                        "old_string": {"type": "string", "description": "The exact text to replace (must be unique in the file)"},
                        "new_string": {"type": "string", "description": "The new text to insert"},
                    },
                    "required": ["file_path", "old_string", "new_string"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "write",
                "description": "Create or overwrite a file with the given content.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "file_path": {"type": "string", "description": "Absolute path to the file"},
                        "content": {"type": "string", "description": "Full content to write"},
                    },
                    "required": ["file_path", "content"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "glob",
                "description": "Search for files matching a glob pattern. E.g. '**/*.py' finds all Python files.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "pattern": {"type": "string", "description": "Glob pattern (e.g. '**/*.py', 'src/**/*.ts')"},
                        "path": {"type": "string", "description": "Directory to search in (default: current)"},
                    },
                    "required": ["pattern"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "grep",
                "description": "Search file contents using a regex pattern. Returns file paths and line numbers.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "pattern": {"type": "string", "description": "Regex pattern to search for"},
                        "include": {"type": "string", "description": "File glob pattern to filter (e.g. '*.py')"},
                        "path": {"type": "string", "description": "Directory to search in (default: current)"},
                    },
                    "required": ["pattern"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "bash",
                "description": "Execute a shell command. Use for running builds, tests, git operations, etc.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "command": {"type": "string", "description": "Shell command to execute"},
                        "timeout": {"type": "integer", "description": "Timeout in seconds", "default": 120},
                        "workdir": {"type": "string", "description": "Working directory for the command"},
                    },
                    "required": ["command"],
                },
            },
        },
    ]


TOOL_MAP = {
    "read": ReadTool(),
    "edit": EditTool(),
    "write": EditTool().write,
    "glob": GlobTool(),
    "grep": GrepTool(),
    "bash": BashTool(),
}


def dispatch(name: str, args: dict) -> dict:
    tool = TOOL_MAP.get(name)
    if not tool:
        return {"error": f"Unknown tool: {name}"}
    if name == "write":
        return tool(**args)
    if hasattr(tool, name):
        return getattr(tool, name)(**args)
    return tool(**args)
