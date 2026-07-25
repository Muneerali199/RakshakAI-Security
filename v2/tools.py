"""Tool implementations — OpenAI function-calling format + agent dispatch."""
from __future__ import annotations
import os, json, re, subprocess
from pathlib import Path
from typing import Any, Optional


# ── Tool Implementations ────────────────────────────────────

class FileOpsTool:
    def __init__(self, allowed_dirs: list[str] | None = None):
        dirs = allowed_dirs or ["."]
        self.allowed_dirs = [Path(d).resolve() for d in dirs]
        # Also allow common user directories
        home = Path.home()
        desktop = home / "Desktop"
        if desktop.exists() and desktop not in self.allowed_dirs:
            self.allowed_dirs.append(desktop)
        if home not in self.allowed_dirs:
            self.allowed_dirs.append(home)

    def _safe(self, path: str) -> bool:
        p = Path(path).resolve()
        return any(str(p).startswith(str(d)) for d in self.allowed_dirs)

    def read_file(self, path: str) -> str | None:
        if not self._safe(path):
            return None
        try:
            p = Path(path)
            if p.exists() and p.stat().st_size <= 1_000_000:
                return p.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return None

    def write_file(self, path: str, content: str) -> bool:
        if not self._safe(path):
            return False
        try:
            p = Path(path)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content, encoding="utf-8")
            return True
        except Exception:
            return False

    def list_files(self, directory: str, pattern: str = "*") -> list[str]:
        if not self._safe(directory):
            return []
        try:
            return [str(f.relative_to(directory)) for f in Path(directory).glob(pattern) if f.is_file()]
        except Exception:
            return []

    def search_in_files(self, directory: str, pattern: str, file_pattern: str = "*.py") -> list[dict]:
        if not self._safe(directory):
            return []
        results = []
        try:
            for fp in Path(directory).rglob(file_pattern):
                if not fp.is_file() or not self._safe(str(fp)):
                    continue
                try:
                    content = fp.read_text("utf-8", errors="replace")
                    matches = list(re.finditer(pattern, content, re.IGNORECASE))
                    if matches:
                        results.append({
                            "file": str(fp.relative_to(directory)),
                            "matches": len(matches),
                            "lines": [content[:m.start()].count("\n") + 1 for m in matches[:5]],
                        })
                except Exception:
                    pass
        except Exception:
            pass
        return results


class ShellTool:
    ALLOWED = {"ls", "cat", "grep", "find", "wc", "head", "tail", "sort", "uniq",
               "git", "npm", "pip", "python", "python3", "node", "mkdir", "cp", "mv",
               "echo", "pwd", "which", "file", "du", "df", "ps", "env"}

    def execute(self, command: str, timeout: int = 30, cwd: str | None = None) -> dict:
        parts = command.split()
        if not parts:
            return {"success": False, "error": "Empty command"}
        if parts[0] not in self.ALLOWED:
            return {"success": False, "error": f"Command '{parts[0]}' not allowed"}
        # Defensive: some models return timeout/cwd as strings
        if isinstance(timeout, str):
            timeout = float(timeout) if '.' in timeout else int(timeout)
        if isinstance(cwd, str) and not cwd.strip():
            cwd = None
        try:
            r = subprocess.run(parts, capture_output=True, text=True, timeout=timeout, cwd=cwd)
            return {"success": r.returncode == 0, "stdout": r.stdout[:5000], "stderr": r.stderr[:2000], "exit_code": r.returncode}
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "Timeout"}
        except Exception as e:
            return {"success": False, "error": str(e)}


class WebSearchTool:
    def search(self, query: str, limit: int = 5) -> list[dict]:
        import requests
        try:
            r = requests.get("https://api.duckduckgo.com/", params={"q": query, "format": "json", "no_html": 1}, timeout=10)
            results = []
            data = r.json()
            if data.get("Abstract"):
                results.append({"title": data.get("Heading", ""), "snippet": data["Abstract"], "url": data.get("AbstractURL", "")})
            for t in data.get("RelatedTopics", [])[:limit]:
                if isinstance(t, dict) and "Text" in t:
                    results.append({"title": t.get("FirstURL", "").split("/")[-1].replace("_", " "), "snippet": t["Text"], "url": t.get("FirstURL", "")})
            return results[:limit]
        except Exception:
            return []


class HTTPTool:
    def request(self, method: str, url: str, headers: dict | None = None, data: dict | None = None, timeout: int = 30) -> dict:
        import requests
        method = method.upper()
        if method not in {"GET", "POST", "PUT", "DELETE", "PATCH"}:
            return {"success": False, "error": f"Unsupported method {method}"}
        try:
            r = requests.request(method, url, headers=headers, json=data, timeout=timeout)
            try:
                content = r.json()
            except Exception:
                content = r.text[:3000]
            return {"success": r.status_code < 400, "status_code": r.status_code, "content": content}
        except Exception as e:
            return {"success": False, "error": str(e)}


class GitHubTool:
    def __init__(self):
        self.token = os.environ.get("GITHUB_TOKEN")
        self.headers = {}
        if self.token:
            self.headers["Authorization"] = f"token {self.token}"

    def _get(self, url: str, params: dict | None = None) -> Any:
        import requests
        try:
            r = requests.get(url, headers=self.headers, params=params, timeout=10)
            return r.json() if r.status_code == 200 else None
        except Exception:
            return None

    def _post(self, url: str, data: dict) -> Any:
        import requests
        if not self.token:
            return None
        try:
            r = requests.post(url, headers=self.headers, json=data, timeout=10)
            return r.json() if r.status_code == 201 else None
        except Exception:
            return None

    def search_repos(self, q: str, limit: int = 10) -> Any:
        return self._get("https://api.github.com/search/repositories", {"q": q, "per_page": limit, "sort": "stars"})

    def get_repo(self, owner: str, repo: str) -> Any:
        return self._get(f"https://api.github.com/repos/{owner}/{repo}")

    def list_issues(self, owner: str, repo: str, state: str = "open") -> Any:
        return self._get(f"https://api.github.com/repos/{owner}/{repo}/issues", {"state": state, "per_page": 20})

    def create_issue(self, owner: str, repo: str, title: str, body: str, labels: list[str] | None = None) -> Any:
        data = {"title": title, "body": body}
        if labels:
            data["labels"] = labels
        return self._post(f"https://api.github.com/repos/{owner}/{repo}/issues", data)


# ── Tool Instances ──────────────────────────────────────────

file_ops = FileOpsTool()
shell = ShellTool()
web_search = WebSearchTool()
http_tool = HTTPTool()
github = GitHubTool()

TOOLS = {
    "file_ops": file_ops,
    "shell": shell,
    "web_search": web_search,
    "http": http_tool,
    "github": github,
}


# ── OpenAI Function-Calling Definitions ─────────────────────

def build_openai_tools() -> list[dict]:
    """Return tool definitions in OpenAI-compatible JSON Schema format."""
    return [
        {
            "type": "function",
            "function": {
                "name": "read_file",
                "description": "Read a file from the filesystem. Use this when you need to examine source code, config files, logs, or any other file content.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "Absolute or relative path to the file to read"}
                    },
                    "required": ["path"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "write_file",
                "description": "Write content to a file. Creates parent directories if needed. Use this to create or modify files.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "Absolute or relative path to write to"},
                        "content": {"type": "string", "description": "Full content to write to the file"}
                    },
                    "required": ["path", "content"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "list_files",
                "description": "List files in a directory matching a glob pattern. Use this to explore directory structure.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "directory": {"type": "string", "description": "Directory path"},
                        "pattern": {"type": "string", "description": "Glob pattern (e.g. '*.py', '**/*.js')", "default": "*"}
                    },
                    "required": ["directory"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "search_in_files",
                "description": "Search for a regex pattern in files within a directory. Use this to find code patterns, function definitions, variable usage, etc.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "directory": {"type": "string", "description": "Directory to search in"},
                        "pattern": {"type": "string", "description": "Regex pattern to search for"},
                        "file_pattern": {"type": "string", "description": "File glob pattern (e.g. '*.py', '*.{js,ts}')", "default": "*.py"}
                    },
                    "required": ["directory", "pattern"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "execute_shell",
                "description": "Execute a shell command. Allowed commands: ls, cat, grep, find, wc, head, tail, git, npm, pip, python, python3, node, mkdir, cp, mv, echo, pwd, which, file, du, df, ps, env.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "command": {"type": "string", "description": "Shell command to execute"},
                        "timeout": {"type": "integer", "description": "Timeout in seconds", "default": 30},
                        "cwd": {"type": "string", "description": "Working directory (optional)"}
                    },
                    "required": ["command"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "web_search",
                "description": "Search the web using DuckDuckGo. Use this to look up documentation, known vulnerabilities, security advisories, or general information.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "query": {"type": "string", "description": "Search query"},
                        "limit": {"type": "integer", "description": "Max results to return", "default": 5}
                    },
                    "required": ["query"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "http_request",
                "description": "Make an HTTP request to any REST API. Use for fetching data from APIs or web services.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "method": {"type": "string", "enum": ["GET", "POST", "PUT", "DELETE", "PATCH"], "description": "HTTP method"},
                        "url": {"type": "string", "description": "Full URL"},
                        "headers": {"type": "object", "description": "Optional HTTP headers"},
                        "data": {"type": "object", "description": "Optional JSON body for POST/PUT"},
                        "timeout": {"type": "integer", "description": "Timeout in seconds", "default": 30}
                    },
                    "required": ["method", "url"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "github_search_repos",
                "description": "Search GitHub repositories by query.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "q": {"type": "string", "description": "Search query"},
                        "limit": {"type": "integer", "description": "Max results", "default": 10}
                    },
                    "required": ["q"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "github_get_repo",
                "description": "Get detailed information about a GitHub repository.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "owner": {"type": "string", "description": "Repository owner (user or org)"},
                        "repo": {"type": "string", "description": "Repository name"}
                    },
                    "required": ["owner", "repo"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "github_list_issues",
                "description": "List issues for a GitHub repository.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "owner": {"type": "string", "description": "Repository owner"},
                        "repo": {"type": "string", "description": "Repository name"},
                        "state": {"type": "string", "enum": ["open", "closed", "all"], "default": "open"}
                    },
                    "required": ["owner", "repo"]
                }
            }
        },
    ]


# ── Tool Call Dispatcher ────────────────────────────────────

def dispatch_tool_call(name: str, arguments: dict) -> Any:
    """Dispatch a function-call name + args to the right tool implementation.

    Maps OpenAI function names like 'read_file', 'execute_shell', etc.
    to the correct Tool class method.
    """
    # Map function names -> (tool_instance, method_name)
    dispatch_map = {
        "read_file": (file_ops, "read_file"),
        "write_file": (file_ops, "write_file"),
        "list_files": (file_ops, "list_files"),
        "search_in_files": (file_ops, "search_in_files"),
        "execute_shell": (shell, "execute"),
        "web_search": (web_search, "search"),
        "http_request": (http_tool, "request"),
        "github_search_repos": (github, "search_repos"),
        "github_get_repo": (github, "get_repo"),
        "github_list_issues": (github, "list_issues"),
        "github_create_issue": (github, "create_issue"),
    }
    entry = dispatch_map.get(name)
    if not entry:
        return {"error": f"Unknown function: {name}"}
    instance, method_name = entry
    method = getattr(instance, method_name, None)
    if not method:
        return {"error": f"Method {method_name} not found on {type(instance).__name__}"}
    try:
        return method(**arguments)
    except TypeError as e:
        return {"error": f"Invalid arguments for {name}: {e}"}
    except Exception as e:
        return {"error": str(e)}
