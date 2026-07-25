#!/usr/bin/env python3
"""
RakshakAI CLI — Scan, review, and fix code vulnerabilities from your terminal.

Usage:
    rakshak scan <file-or-dir>              Scan file(s) for vulnerabilities
    rakshak review <diff-file>              Review a unified diff
    rakshak generate <prompt>               Generate secure code from prompt
    rakshak server [--port PORT]            Start the backend server
    rakshak health                          Check server status
    rakshak config                          Show current configuration
    rakshak batch <file1> [file2 ...]       Scan multiple files
    rakshak watch [--dir DIR]               Watch directory for changes (background)
    rakshak install-hook                    Install git pre-commit hook
    rakshak cache                           Show cache stats

Examples:
    rakshak scan app.py
    rakshak scan src/ --format table
    rakshak review pr.diff --output results.json
    rakshak generate "secure file upload in Python"
    rakshak server --port 3000
    rakshak watch                           # Background file watcher
    rakshak install-hook                    # Install pre-commit hook
"""

import argparse
import hashlib
import json
import os
import re
import sys
import time
import subprocess
from pathlib import Path
from threading import Thread, Event
from typing import Optional

# ── Config ──────────────────────────────────────────────────────────
CONFIG_FILE = Path.home() / ".rakshak" / "config.json"
CACHE_FILE = Path.home() / ".rakshak" / "cache.json"
DEFAULT_CONFIG = {
    "v1_url": "http://127.0.0.1:3000",
    "v2_url": "http://127.0.0.1:8080",
    "format": "table",
    "timeout": 120,
    "mock": True,
    "severity_threshold": "low",
    "auto_cache": True,
}

# ── Cache System (Invisible — operates silently) ───────────────────
def load_cache() -> dict:
    try:
        return json.loads(CACHE_FILE.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

def save_cache(cache: dict):
    CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = CACHE_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(cache))
    tmp.rename(CACHE_FILE)

def content_hash(text: str) -> str:
    return hashlib.md5(text.encode("utf-8")).hexdigest()[:16]

def cache_get(path: str) -> Optional[list]:
    cache = load_cache()
    entry = cache.get(path)
    if not entry:
        return None
    try:
        current = Path(path).read_text(encoding="utf-8", errors="replace")
    except (OSError, IOError):
        return None
    if entry.get("hash") != content_hash(current):
        return None
    return entry.get("findings")

def cache_set(path: str, findings: list):
    try:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
    except (OSError, IOError):
        return
    cache = load_cache()
    cache[path] = {"hash": content_hash(text), "findings": findings, "cached_at": time.time()}
    save_cache(cache)

def cache_clear(path: str = None):
    if path:
        cache = load_cache()
        cache.pop(path, None)
        save_cache(cache)
    else:
        CACHE_FILE.unlink(missing_ok=True)
        CACHE_FILE.write_text("{}")

def cache_stats() -> dict:
    cache = load_cache()
    total = len(cache)
    with_issues = sum(1 for v in cache.values() if v.get("findings"))
    total_issues = sum(len(v.get("findings", [])) for v in cache.values())
    return {"total_files": total, "with_issues": with_issues, "total_issues": total_issues}

# ── Git Hook (Invisible — auto-installs) ───────────────────────────
GIT_HOOK_SCRIPT = r"""#!/bin/sh
# RakshakAI pre-commit hook — auto-scans staged files
# Installed by: rakshak install-hook

echo "🔍 RakshakAI: Scanning staged files for vulnerabilities..."
RAKSHAK="$(which python3) -m rakshak_cli"
STAGED=$(git diff --cached --name-only --diff-filter=ACM)

HAS_ISSUES=0
for file in $STAGED; do
    if [ -f "$file" ]; then
        ISSUES=$($RAKSHAK scan "$file" --format json 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d) if isinstance(d,list) else 0)" 2>/dev/null)
        if [ "$ISSUES" -gt 0 ]; then
            echo "⚠  $file: $ISSUES issue(s) found"
            HAS_ISSUES=1
        fi
    fi
done

if [ "$HAS_ISSUES" -eq 1 ]; then
    echo ""
    echo "❌ Commit blocked: vulnerabilities found in staged files."
    echo "   Run 'rakshak scan <file>' to see details."
    echo "   To commit anyway: git commit --no-verify"
    exit 1
fi

echo "✅ RakshakAI: No issues found."
exit 0
"""

def install_git_hook():
    """Install a pre-commit hook that auto-scans staged files."""
    git_dir = Path(".git")
    if not git_dir.exists():
        print("✖ Not a git repository. Run from the repo root.")
        return False
    hook_path = git_dir / "hooks" / "pre-commit"
    hook_path.write_text(GIT_HOOK_SCRIPT)
    hook_path.chmod(0o755)
    print(f"✅ Pre-commit hook installed: {hook_path}")
    print("   Staged files will be auto-scanned before every commit.")
    return True


# ── Background File Watcher (Invisible — autonomous) ──────────────
class FileWatcher:
    """Watches a directory and auto-scans changed files in background."""

    def __init__(self, root_dir: str, cfg: dict, stop_event: Event):
        self.root = Path(root_dir)
        self.cfg = cfg
        self.stop = stop_event
        self.mtimes: dict[str, float] = {}
        self.scanned: set = set()

    def _supported(self, path: Path) -> bool:
        return path.suffix.lower() in {
            ".py", ".js", ".ts", ".java", ".go", ".rs", ".c", ".cpp",
            ".h", ".hpp", ".rb", ".php", ".cs", ".swift", ".kt",
        }

    def _scan_file(self, path: Path):
        """Scan a file silently and cache results."""
        from rakshak_cli import scan_file
        try:
            start = time.time()
            issues = scan_file(str(path), self.cfg)
            elapsed = time.time() - start
            status = "⚠" if issues else "✓"
            print(f"  [{status}] {path.relative_to(self.root)}  ({len(issues)} issues, {elapsed:.1f}s)")
        except Exception as e:
            print(f"  [✖] {path.relative_to(self.root)}  error: {e}")

    def run(self):
        """Main watch loop."""
        supported_exts = {".py", ".js", ".ts", ".java", ".go", ".rs", ".c", ".cpp", ".rb", ".php", ".cs", ".yml", ".yaml", ".json"}
        print(f"\n  🔍 Watching {self.root} for changes...")
        print(f"  Press Ctrl+C to stop.\n")

        while not self.stop.is_set():
            for f in self.root.rglob("*"):
                if self.stop.is_set():
                    return
                if f.suffix not in supported_exts:
                    continue
                if f.name.startswith("."):
                    continue
                try:
                    mtime = f.stat().st_mtime
                except OSError:
                    continue

                key = str(f)
                prev = self.mtimes.get(key)
                if prev is not None and mtime > prev and key not in self.scanned:
                    self._scan_file(f)
                    self.scanned.add(key)
                    # Re-scan after 60s if changed again
                    Thread(target=self._delayed_rescan, args=(key, 60), daemon=True).start()

                self.mtimes[key] = mtime

            time.sleep(1.5)

    def _delayed_rescan(self, key: str, delay: float):
        time.sleep(delay)
        self.scanned.discard(key)


# ── Config / Helpers ───────────────────────────────────────────────
def load_config() -> dict:
    if CONFIG_FILE.exists():
        return {**DEFAULT_CONFIG, **json.loads(CONFIG_FILE.read_text())}
    return dict(DEFAULT_CONFIG)

def save_config(cfg: dict):
    CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(json.dumps(cfg, indent=2))

def get_backend_url(cfg: dict, tier: str = "v1") -> str:
    return cfg.get(f"{tier}_url", DEFAULT_CONFIG[f"{tier}_url"])


# ── Output Formatting ───────────────────────────────────────────────
def print_json(data, indent=2):
    print(json.dumps(data, indent=indent, default=str))

def print_table(issues: list[dict]):
    if not issues:
        print("  ✅ No vulnerabilities found.")
        return

    severity_colors = {
        "critical": "\033[91m", "high": "\033[91m",
        "medium": "\033[93m", "low": "\033[94m", "info": "\033[90m",
    }
    reset = "\033[0m"

    print(f"\n  {'Line':<6} {'Severity':<10} {'CWE':<12} {'Category':<25} {'Message'}")
    print(f"  {'-'*4:<6} {'-'*8:<10} {'-'*10:<12} {'-'*23:<25} {'-'*40}")
    for issue in issues:
        sev = issue.get("severity", "info").lower()
        color = severity_colors.get(sev, "")
        sev_str = f"{color}{sev:<10}{reset}"
        cwe = issue.get("cweId") or issue.get("cwe") or ""
        cat = (issue.get("category") or issue.get("type") or "")[:23]
        msg = (issue.get("message") or "")[:60]
        line = issue.get("line", "?")
        print(f"  {str(line):<6} {sev_str} {cwe:<12} {cat:<25} {msg}")

    print(f"\n  {'─'*60}")
    sev_counts = {}
    for i in issues:
        s = i.get("severity", "unknown")
        sev_counts[s] = sev_counts.get(s, 0) + 1
    print(f"  Total: {len(issues)} issue(s) — " + ", ".join(f"{c} {s}" for s, c in sev_counts.items()))

    # Show fix info
    for i in issues:
        if i.get("remediation") and i["remediation"].get("example"):
            print(f"\n  \033[96m💡 Fix for line {i.get('line', '?')}:\033[0m")
            print(f"    {i['remediation']['example']}")

def print_sarif(issues: list[dict], filename: str) -> str:
    results = []
    for issue in issues:
        results.append({
            "ruleId": issue.get("cweId", "unknown"),
            "level": issue.get("severity", "warning"),
            "message": {"text": issue.get("message", "")},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": filename},
                    "region": {"startLine": issue.get("line", 0), "endLine": issue.get("line", 0)}
                }
            }]
        })
    return json.dumps({
        "$schema": "https://schemastore.aws.dev/sarif/2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "RakshakAI", "version": "1.0.0"}}, "results": results}]
    }, indent=2)


# ── API Client ──────────────────────────────────────────────────────
def api_post(url: str, path: str, payload: dict, timeout: int = 120) -> Optional[dict]:
    try:
        import urllib.request
        import urllib.error
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            f"{url}{path}", data=data,
            headers={"Content-Type": "application/json"}, method="POST",
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception as e:
        print(f"\033[91m✖ Error: {e}\033[0m", file=sys.stderr)
        return None

def api_get(url: str, path: str, timeout: int = 10) -> Optional[dict]:
    try:
        import urllib.request
        req = urllib.request.Request(f"{url}{path}")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception as e:
        print(f"\033[91m✖ Error: {e}\033[0m", file=sys.stderr)
        return None


# ── Scanner Logic (Cache-Aware) ────────────────────────────────────
SUPPORTED_EXTS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rs",
    ".c", ".cpp", ".h", ".hpp", ".rb", ".php", ".cs", ".swift",
    ".kt", ".sol", ".scala", ".vue",
}

def guess_language(path: str) -> str:
    ext = Path(path).suffix.lower()
    return {
        ".py": "python", ".js": "javascript", ".ts": "typescript",
        ".java": "java", ".go": "go", ".rs": "rust", ".c": "c",
        ".cpp": "cpp", ".rb": "ruby", ".php": "php", ".cs": "csharp",
        ".swift": "swift", ".kt": "kotlin",
    }.get(ext, "text")

def scan_file(path: str, cfg: dict, language: str = None) -> list[dict]:
    """Scan a single file — tries server first, falls back to local."""
    if not os.path.isfile(path):
        print(f"\033[93m⚠ Skipping {path} (not a file)\033[0m")
        return []

    lang = language or guess_language(path)

    # Check cache first (invisible — no output)
    if cfg.get("auto_cache", True):
        cached = cache_get(path)
        if cached is not None:
            return cached

    # Try server first
    code = Path(path).read_text(encoding="utf-8", errors="replace")
    url = get_backend_url(cfg)
    resp = api_post(url, "/api/scan", {
        "code": code, "language": lang, "filename": path,
    }, timeout=cfg.get("timeout", 120))

    if resp and "issues" in resp:
        issues = resp["issues"]
        if cfg.get("auto_cache", True):
            cache_set(path, issues)
        return issues

    # Server unavailable — fall back to local scanner
    issues = local_scan_file(path)

    if cfg.get("auto_cache", True):
        cache_set(path, issues)

    return issues


def scan_directory(path: str, cfg: dict, exclude: list[str] = None) -> dict[str, list[dict]]:
    exclude_dirs = set(exclude or [])
    results = {}
    p = Path(path)
    files = []
    for f in p.rglob("*"):
        if f.suffix not in SUPPORTED_EXTS or f.name.startswith("."):
            continue
        if any(excl in f.parts for excl in exclude_dirs):
            continue
        files.append(f)
    total = len(files)

    if not files:
        print(f"\033[93m⚠ No supported files found in {path}\033[0m")
        return results

    print(f"\n  Scanning {total} file(s) in {path}...\n")

    for i, f in enumerate(files, 1):
        fpath = str(f)
        show_path = fpath[:80] + "..." if len(fpath) > 80 else fpath
        print(f"  [{i}/{total}] \033[90m{show_path}\033[0m", end="\r")
        issues = scan_file(fpath, cfg)
        if issues:
            results[fpath] = issues
        sys.stdout.flush()

    print(f"\n  {'─'*50}")
    total_issues = sum(len(v) for v in results.values())
    print(f"  ✅ Done. Found {total_issues} issue(s) in {len(results)} file(s).")
    return results


# ── Server Management ───────────────────────────────────────────────
def start_server(port: int = 3000, mock: bool = True):
    env = os.environ.copy()
    if mock:
        env["RAKSHAK_MOCK"] = "1"
    try:
        import uvicorn
        sys.path.insert(0, str(Path(__file__).parent))
        from server import app
        print(f"\033[92m▶ Starting RakshakAI server on port {port} (mock={mock})...\033[0m")
        uvicorn.run(app, host="0.0.0.0", port=port, log_level="info")
    except ImportError:
        print("\033[91m✖ Error: uvicorn not installed. Run: pip install uvicorn fastapi\033[0m", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"\033[91m✖ Error starting server: {e}\033[0m", file=sys.stderr)
        sys.exit(1)


# ── CLI Commands ────────────────────────────────────────────────────
def _write_json_output(data, output_path: Optional[str] = None):
    text = json.dumps(data, indent=2, default=str)
    if output_path:
        Path(output_path).write_text(text)
        print(f"\033[92m✓ Results written to {output_path}\033[0m")
    else:
        print(text)


def cmd_scan(args: argparse.Namespace, cfg: dict) -> int:
    path = args.path
    fmt = args.format or cfg.get("format", "table")
    lang = args.language
    excludes = args.exclude or []

    if args.no_cache:
        cfg["auto_cache"] = False

    if os.path.isdir(path):
        results = scan_directory(path, cfg, exclude=excludes)
        if fmt == "json":
            _write_json_output(results, args.output)
        elif fmt == "sarif":
            text = "\n".join(print_sarif(issues, fpath) for fpath, issues in results.items())
            if args.output:
                Path(args.output).write_text(text)
                print(f"\033[92m✓ Results written to {args.output}\033[0m")
            else:
                print(text)
        else:
            for fpath, issues in results.items():
                if issues:
                    print(f"\n  \033[1m📄 {fpath}\033[0m")
                    print_table(issues)
        return 0

    issues = scan_file(path, cfg, lang)

    if not issues:
        msg = f"\n  ✅ \033[92mNo vulnerabilities found in {path}\033[0m"
        if args.output:
            Path(args.output).write_text(json.dumps([], indent=2))
            print(f"\033[92m✓ Results written to {args.output}\033[0m")
        else:
            print(msg)
        return 0

    if fmt == "json":
        _write_json_output(issues, args.output)
    elif fmt == "sarif":
        text = print_sarif(issues, path)
        if args.output:
            Path(args.output).write_text(text)
            print(f"\033[92m✓ Results written to {args.output}\033[0m")
        else:
            print(text)
    else:
        print_table(issues)

    return 0


# ── Local Scanner (offline regex-based — no server needed) ─────────

LOCAL_PATTERNS = [
    # ── SQL Injection ──────────────────────────────────
    (r"execute\([^)]*['\"`][^'\"`]*['\"`]\s*[+%]", "SQL_INJECTION", "CWE-89", "critical", "SQL injection via string concatenation"),
    (r"cursor\.execute\s*\(\s*f['\"]", "SQL_INJECTION", "CWE-89", "critical", "SQL injection via f-string"),
    (r"query\s*=.*\+\s*(?:user|input|name|id|param|get|request)", "SQL_INJECTION", "CWE-89", "critical", "SQL injection via user input"),
    (r"db\.execute\s*\(\s*['\"`][^'\"`]*\{", "SQL_INJECTION", "CWE-89", "critical", "SQL injection via formatted string"),
    (r"db\.query\s*\(\s*`[^`]*\$\{", "SQL_INJECTION", "CWE-89", "critical", "SQL injection via template literal"),
    (r"\$conn->query\s*\(\s*['\"][^'\"]*\$", "SQL_INJECTION", "CWE-89", "critical", "SQL injection via PHP interpolation"),
    (r"f['\"][^'\"]*SELECT[^'\"]*['\"]\s*[.%]", "SQL_INJECTION", "CWE-89", "critical", "SQL injection via f-string"),
    (r"raw\(|Raw\(|\.raw\s*\(", "SQL_INJECTION", "CWE-89", "high", "Raw SQL query — possible injection"),
    (r"EntityManager\.createNativeQuery", "SQL_INJECTION", "CWE-89", "critical", "JPA native query — possible injection", ["java"]),
    (r"\$wpdb->query\s*\(\s*['\"][^'\"]*\$", "SQL_INJECTION", "CWE-89", "critical", "WordPress raw SQL query", ["php"]),
    (r"\[injection\]|SELECT.*FROM.*WHERE.*=.*OR", "NO_SQL_INJECTION", "CWE-943", "critical", "NoSQL injection via query operator"),
    (r"\.find\s*\(\s*\{.*\$where", "NO_SQL_INJECTION", "CWE-943", "critical", "MongoDB $where injection", ["js", "ts"]),

    # ── OS Command Injection ──────────────────────────
    (r"os\.system\s*\(", "COMMAND_INJECTION", "CWE-78", "critical", "os.system() allows shell injection", ["py"]),
    (r"os\.popen\s*\(", "COMMAND_INJECTION", "CWE-78", "critical", "os.popen() allows shell injection", ["py"]),
    (r"subprocess\.\w+\s*\(.*shell\s*=\s*True", "COMMAND_INJECTION", "CWE-78", "critical", "subprocess with shell=True", ["py"]),
    (r"Runtime\.getRuntime\(\)\.exec\s*\(", "COMMAND_INJECTION", "CWE-78", "critical", "Runtime.exec() command injection", ["java"]),
    (r"(?:exec|execSync|spawn)\s*\(\s*`[^`]*\$\{", "COMMAND_INJECTION", "CWE-78", "critical", "Shell cmd via template literal in exec()", ["js", "ts"]),
    (r"child_process\.exec\s*\(", "COMMAND_INJECTION", "CWE-78", "critical", "child_process.exec() shell injection", ["js", "ts"]),
    (r"shell_exec\s*\(", "COMMAND_INJECTION", "CWE-78", "critical", "PHP shell_exec() injection", ["php"]),
    (r"`[^`]*\$\{[^`]*`[^`]*`", "COMMAND_INJECTION", "CWE-78", "high", "Shell command substitution in string"),

    # ── Hardcoded Secrets ─────────────────────────────
    (r"(?:password|passwd)\s*[=:]\s*['\"`][^'\"`\s]{4,}['\"`]", "HARDCODED_SECRET", "CWE-798", "high", "Hardcoded password"),
    (r"(?:api[_-]?key|apikey)\s*[=:]\s*['\"`][A-Za-z0-9_-]{8,}['\"`]", "HARDCODED_SECRET", "CWE-798", "high", "Hardcoded API key"),
    (r"(?:secret|secret_key)\s*[=:]\s*['\"`][^'\"`\s]{8,}['\"`]", "HARDCODED_SECRET", "CWE-798", "high", "Hardcoded secret"),
    (r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----", "HARDCODED_SECRET", "CWE-798", "high", "Embedded private key"),
    (r"AWS[A-Z0-9]{16}", "HARDCODED_SECRET", "CWE-798", "high", "AWS access key"),
    (r"['\"`](?:sk[-_]|pk[-_]|ghp_|gho_|ghu_|ghs_|ghr_)[A-Za-z0-9_-]{20,}['\"`]", "HARDCODED_SECRET", "CWE-798", "high", "Hardcoded API token"),
    (r"-----BEGIN CERTIFICATE-----", "HARDCODED_SECRET", "CWE-798", "medium", "Embedded certificate"),
    (r"(?:jwt|JWT|jwt_token|jwt_secret)\s*[=:]\s*['\"`][^'\"`\s]{8,}['\"`]", "HARDCODED_SECRET", "CWE-798", "high", "Hardcoded JWT secret"),
    (r"(?:db_?url|database_url)\s*[=:]\s*['\"`]postgresql://.*:.*@", "HARDCODED_SECRET", "CWE-798", "high", "Database URL with embedded password"),
    (r"redis://.*:.*@", "HARDCODED_SECRET", "CWE-798", "high", "Redis URL with embedded password"),

    # ── XSS ───────────────────────────────────────────
    (r"\.innerHTML\s*=\s*['\"`][^'\"`]*\+", "XSS", "CWE-79", "critical", "innerHTML concatenation leads to XSS", ["js", "ts"]),
    (r"document\.write\s*\([^)]*\+", "XSS", "CWE-79", "critical", "document.write() with concatenation", ["js", "ts"]),
    (r"dangerouslySetInnerHTML", "XSS", "CWE-79", "critical", "dangerouslySetInnerHTML bypasses React XSS protection", ["js", "ts"]),
    (r"v-html\s*=", "XSS", "CWE-79", "critical", "v-html renders raw HTML in Vue", ["js", "ts"]),
    (r"\|\s*safe\b", "XSS", "CWE-79", "critical", "|safe filter bypasses HTML escaping in templates", ["py"]),
    (r"\.html\s*\([^)]*\+", "XSS", "CWE-79", "critical", "jQuery .html() with concatenation", ["js", "ts"]),
    (r"\.append\s*\([^)]*\+", "XSS", "CWE-79", "high", "jQuery .append() with concatenation", ["js", "ts"]),
    (r"response\.write\s*\([^)]*request", "XSS", "CWE-79", "critical", "ASP Response.Write with user input"),
    (r"echo\s+['\"]<[^'\"]*['\"]\s*\.\s*\$", "XSS", "CWE-79", "critical", "PHP echo with unescaped HTML", ["php"]),
    (r"print\s*\([^)]*\$_(?:GET|POST|REQUEST)", "XSS", "CWE-79", "critical", "PHP print with unsanitized input", ["php"]),
    (r"implausible_sanitization|strip_tags\s*\([^)]*\.", "XSS", "CWE-79", "medium", "strip_tags may not fully prevent XSS"),

    # ── Path Traversal ────────────────────────────────
    (r"open\([^)]*\+\s*(?:user|input|file|path|name|filename)", "PATH_TRAVERSAL", "CWE-22", "high", "User input in file open() allows path traversal"),
    (r"(?:readFile|readFileSync|writeFile|writeFileSync)\s*\([^)]*\+\s*(?:user|input|file|path|name)", "PATH_TRAVERSAL", "CWE-22", "high", "User input in file I/O operation"),
    (r"File\.ReadAllText|File\.ReadAllLines|File\.WriteAllText", "PATH_TRAVERSAL", "CWE-22", "high", "File I/O with possible path traversal", ["cs"]),
    (r"\.\./|\.\.\\", "PATH_TRAVERSAL", "CWE-22", "medium", "Directory traversal pattern (../)"),
    (r"getResourceAsStream|getResource", "PATH_TRAVERSAL", "CWE-22", "medium", "Resource loading may allow path traversal", ["java"]),
    (r"sendFile\s*\([^)]*request", "PATH_TRAVERSAL", "CWE-22", "critical", "Express sendFile with user input", ["js", "ts"]),

    # ── Weak Crypto ───────────────────────────────────
    (r"\bmd5\s*\(", "WEAK_CRYPTO", "CWE-327", "medium", "MD5 is vulnerable to collision attacks"),
    (r"\bsha1\s*\(", "WEAK_CRYPTO", "CWE-327", "medium", "SHA-1 is deprecated and collision-prone"),
    (r"\bDES_CBC\b", "WEAK_CRYPTO", "CWE-327", "medium", "DES encryption is deprecated"),
    (r"MessageDigest\.getInstance\s*\(\s*['\"]MD5['\"]", "WEAK_CRYPTO", "CWE-327", "medium", "Java MD5 MessageDigest", ["java"]),
    (r"Cipher\.getInstance\s*\(\s*['\"]DES['\"]", "WEAK_CRYPTO", "CWE-326", "high", "DES is deprecated — use AES", ["java"]),
    (r"Cipher\.getInstance\s*\(\s*['\"]AES/ECB", "WEAK_CRYPTO", "CWE-326", "high", "AES/ECB mode is deterministic — use GCM"),
    (r"Cipher\.getInstance\s*\(\s*['\"]RC4|ARC4['\"]", "WEAK_CRYPTO", "CWE-327", "high", "RC4 is broken — use AES-GCM"),
    (r"new\s+SecureRandom\s*\(\s*\)", "WEAK_CRYPTO", "CWE-330", "low", "SecureRandom without seed entropy", ["java"]),
    (r"setSeed\s*\([^)]*\d+", "WEAK_CRYPTO", "CWE-330", "medium", "Hardcoded PRNG seed is predictable"),
    (r"random\.randint|random\.random|Random\s*\(", "WEAK_CRYPTO", "CWE-338", "low", "Using non-cryptographic PRNG for security"),
    (r"(?:ECB|CBC)\s*(?:mode|padding)", "WEAK_CRYPTO", "CWE-326", "medium", "ECB/CBC mode may be insecure; prefer GCM"),
    (r"\bIV\s*=\s*['\"`][a-fA-F0-9]{6,}['\"`]", "WEAK_CRYPTO", "CWE-326", "medium", "Hardcoded IV in encryption"),
    (r"\bnonce\s*=\s*['\"`][^'\"`]+['\"`]", "WEAK_CRYPTO", "CWE-330", "medium", "Hardcoded nonce — should be random"),
    (r"hashlib\.pbkdf2|bcrypt|scrypt|argon2", "WEAK_CRYPTO", "CWE-759", "info", "Weak KDF — prefer bcrypt/argon2"),

    # ── Buffer Overflow (C/C++) ────────────────────────
    (r"\bstrcpy\s*\(", "BUFFER_OVERFLOW", "CWE-120", "critical", "strcpy() unsafe — use strncpy()", ["c", "cpp"]),
    (r"\bstrcat\s*\(", "BUFFER_OVERFLOW", "CWE-120", "critical", "strcat() unsafe — use strncat()", ["c", "cpp"]),
    (r"\bgets\s*\(", "BUFFER_OVERFLOW", "CWE-120", "critical", "gets() no bounds checking", ["c", "cpp"]),
    (r"\bsprintf\s*\(", "BUFFER_OVERFLOW", "CWE-120", "high", "sprintf() unsafe — use snprintf()", ["c", "cpp"]),
    (r"\bscanf\s*\(", "BUFFER_OVERFLOW", "CWE-120", "high", "scanf() no bounds checking", ["c", "cpp"]),
    (r"\brealpath\s*\(", "BUFFER_OVERFLOW", "CWE-120", "medium", "realpath() buffer overflow risk", ["c", "cpp"]),
    (r"\bmemcpy\s*\([^)]*\d+\s*\)", "BUFFER_OVERFLOW", "CWE-787", "high", "memcpy with constant size may overflow", ["c", "cpp"]),
    (r"\bwcscpy\s*\(", "BUFFER_OVERFLOW", "CWE-120", "critical", "wcscpy() unsafe — use wcsncpy()", ["c", "cpp"]),

    # ── Use After Free / Memory (C/C++) ────────────────
    (r"\bfree\s*\(.*\);\s*\n.*\b\1\b", "USE_AFTER_FREE", "CWE-416", "critical", "Use after free — accessing freed pointer", ["c", "cpp"]),
    (r"\brealloc\s*\(", "USE_AFTER_FREE", "CWE-416", "high", "realloc() may produce dangling pointer", ["c", "cpp"]),
    (r"\bdelete\b.*;.*\b\1\b", "DOUBLE_FREE", "CWE-415", "critical", "Possible double free", ["c", "cpp"]),
    (r"\balloca\s*\(", "STACK_OVERFLOW", "CWE-770", "high", "alloca() may cause stack overflow", ["c", "cpp"]),
    (r"\bVLA\b|\[.*\*.*\]", "STACK_OVERFLOW", "CWE-770", "medium", "Variable-length array — possible stack overflow", ["c", "cpp"]),

    # ── Format String (C/C++) ──────────────────────────
    (r"\bprintf\s*\([^)]*user", "FORMAT_STRING", "CWE-134", "critical", "printf with user input allows format string attack", ["c", "cpp"]),
    (r"\bsprintf\s*\([^)]*user", "FORMAT_STRING", "CWE-134", "critical", "sprintf with user input allows format string attack", ["c", "cpp"]),
    (r"\bfprintf\s*\([^,]+,\s*user", "FORMAT_STRING", "CWE-134", "critical", "fprintf with user input allows format string attack", ["c", "cpp"]),
    (r"\bvsprintf\s*\(", "FORMAT_STRING", "CWE-134", "high", "vsprintf() format string risk", ["c", "cpp"]),

    # ── Integer Overflow ───────────────────────────────
    (r"(?:int|int32|int64|uint|size_t)\s+\w+\s*=\s*[^(]*\*\s*[^(]*\)", "INTEGER_OVERFLOW", "CWE-190", "medium", "Possible integer overflow in allocation"),
    (r"malloc\s*\([^)]*\*\s*[^)]*\)", "INTEGER_OVERFLOW", "CWE-190", "high", "Integer overflow in malloc size", ["c", "cpp"]),
    (r"\+\s*1\s*\)?\s*>\s*(?:INT_MAX|INT32_MAX|LONG_MAX)", "INTEGER_OVERFLOW", "CWE-190", "medium", "Possible integer overflow near max value"),

    # ── Insecure Deserialization ───────────────────────
    (r"\bpickle\.loads?\s*\(", "INSECURE_DESERIALIZATION", "CWE-502", "critical", "Pickle deserialization can execute arbitrary code", ["py"]),
    (r"\byaml\.load\s*\(", "INSECURE_DESERIALIZATION", "CWE-502", "critical", "yaml.load() unsafe — use safe_load()", ["py"]),
    (r"unserialize\s*\(", "INSECURE_DESERIALIZATION", "CWE-502", "critical", "PHP unserialize() with user input", ["php"]),
    (r"readObject\s*\(\s*\)", "INSECURE_DESERIALIZATION", "CWE-502", "critical", "Java readObject() deserialization", ["java"]),
    (r"ObjectMapper\.enableDefaultTyping", "INSECURE_DESERIALIZATION", "CWE-502", "high", "Jackson polymorphic deserialization", ["java"]),
    (r"JSON\.parse\s*\([^)]*input", "INSECURE_DESERIALIZATION", "CWE-502", "medium", "JSON.parse on user input", ["js", "ts"]),
    (r"eval\s*\([^)]*JSON\.stringify", "INSECURE_DESERIALIZATION", "CWE-502", "high", "eval with serialized data", ["js", "ts"]),
    (r"XmlSerializer\s*\(\s*typeof", "XXE_INJECTION", "CWE-611", "critical", "XML deserializer without XXE protection", ["cs"]),

    # ── XXE (XML External Entity) ──────────────────────
    (r"etree\.parse\s*\(", "XXE_INJECTION", "CWE-611", "critical", "XML parse without entity disabling", ["py"]),
    (r"DocumentBuilderFactory\.newInstance", "XXE_INJECTION", "CWE-611", "critical", "Java XML parser without XXE protection", ["java"]),
    (r"SAXParser|SAXBuilder|SAXReader", "XXE_INJECTION", "CWE-611", "critical", "SAX XML parser may allow XXE"),
    (r"DocumentBuilder|DocumentHelper", "XXE_INJECTION", "CWE-611", "critical", "XML document builder may allow XXE"),
    (r"XmlDocument\.Load\s*\(", "XXE_INJECTION", "CWE-611", "critical", ".NET XML document may allow XXE", ["cs"]),
    (r"XDocument\.Load\s*\(", "XXE_INJECTION", "CWE-611", "critical", ".NET XDocument may allow XXE", ["cs"]),
    (r"XMLReader\.Settings\.DtdProcessing", "XXE_INJECTION", "CWE-611", "high", "XMLReader DTD processing may allow XXE", ["cs"]),

    # ── SSRF (Server-Side Request Forgery) ────────────
    (r"requests\.(?:get|post|put|delete)\s*\([^)]*user", "SSRF", "CWE-918", "high", "User input in HTTP request — possible SSRF"),
    (r"urlopen\s*\([^)]*user", "SSRF", "CWE-918", "high", "User input in urlopen() — possible SSRF", ["py"]),
    (r"fetch\s*\([^)]*user", "SSRF", "CWE-918", "high", "User input in fetch() — possible SSRF", ["js", "ts"]),
    (r"axios\.(?:get|post)\s*\([^)]*user", "SSRF", "CWE-918", "high", "User input in axios — possible SSRF", ["js", "ts"]),
    (r"HttpURLConnection.*user", "SSRF", "CWE-918", "high", "User input in HTTP connection", ["java"]),
    (r"HttpClient\.(?:Get|Post|Send)\s*\([^)]*user", "SSRF", "CWE-918", "high", "User input in HttpClient — possible SSRF", ["cs"]),
    (r"curl_\w+\s*\([^)]*user", "SSRF", "CWE-918", "high", "User input in cURL", ["php"]),

    # ── SSTI (Server-Side Template Injection) ─────────
    (r"\.render\s*\([^)]*\+\s*(?:user|input|name|query)", "SSTI", "CWE-1336", "critical", "Template injection in render()"),
    (r"\{\{.*\(.*\)\}\}", "SSTI", "CWE-1336", "critical", "Jinja2 template injection expression"),
    (r"Template\s*\([^)]*user", "SSTI", "CWE-1336", "critical", "Template string with user input"),
    (r"render_to_string\s*\([^)]*user", "SSTI", "CWE-1336", "critical", "Template rendering with user input"),
    (r"\.render\(request,", "SSTI", "CWE-1336", "medium", "Template may receive user data in context"),
    (r"nunjucks|pug|handlebars|mustache|ejs\s*\.(?:compile|render)", "SSTI", "CWE-1336", "high", "JS template engine with user input"),

    # ── Open Redirect ─────────────────────────────────
    (r"redirect\s*\([^)]*request", "OPEN_REDIRECT", "CWE-601", "medium", "Open redirect via user input"),
    (r"redirect\s*\([^)]*\.query\.", "OPEN_REDIRECT", "CWE-601", "medium", "Open redirect via query parameter"),
    (r"res\.redirect\s*\([^)]*req\.", "OPEN_REDIRECT", "CWE-601", "medium", "Express open redirect", ["js", "ts"]),
    (r"header\s*\(\s*['\"]Location['\"]\s*,\s*\$", "OPEN_REDIRECT", "CWE-601", "medium", "PHP header redirect with user input", ["php"]),
    (r"next\(|res\.redirect|redirect\(req", "OPEN_REDIRECT", "CWE-601", "medium", "Possible open redirect handler"),

    # ── Prototype Pollution (JS) ───────────────────────
    (r"Object\.assign\s*\([^)]*source", "PROTOTYPE_POLLUTION", "CWE-1321", "high", "Object.assign may allow prototype pollution", ["js", "ts"]),
    (r"merge\s*\([^)]*(?:true|false)", "PROTOTYPE_POLLUTION", "CWE-1321", "high", "Deep merge may allow prototype pollution", ["js", "ts"]),
    (r"cloneDeep|extend|merge\s*\([^)]*source", "PROTOTYPE_POLLUTION", "CWE-1321", "high", "Clone/extend may allow prototype pollution", ["js", "ts"]),
    (r"lodash\.merge|_.merge|\.defaultsDeep", "PROTOTYPE_POLLUTION", "CWE-1321", "high", "Lodash merge vulnerable to prototype pollution", ["js", "ts"]),
    (r"\[['\"]__proto__['\"]\]|\.__proto__", "PROTOTYPE_POLLUTION", "CWE-1321", "high", "Direct __proto__ access leads to pollution", ["js", "ts"]),
    (r"constructor.*prototype", "PROTOTYPE_POLLUTION", "CWE-1321", "high", "Constructor.prototype manipulation", ["js", "ts"]),

    # ── Session / Auth Issues ─────────────────────────
    (r"session\[['\"]user['\"\]\]\s*=\s*[^)]*input", "AUTH_ISSUE", "CWE-287", "high", "User-controlled session value"),
    (r"req\.session\.user\s*=\s*req\.", "AUTH_ISSUE", "CWE-287", "high", "Session user set from request params", ["js", "ts"]),
    (r"session_start\s*\(\s*\)", "AUTH_ISSUE", "CWE-384", "medium", "Session fixation — regenerate session ID", ["php"]),
    (r"cookie\[['\"]user['\"\]\]\s*=\s*", "AUTH_ISSUE", "CWE-565", "high", "User info in cookie — may be tampered"),
    (r"jwt\.sign\s*\([^)]*['\"]none['\"]", "AUTH_ISSUE", "CWE-347", "critical", "JWT with 'none' algorithm — signature bypass"),
    (r"jwt\.verify\s*\([^)]*['\"]['\"]\)", "AUTH_ISSUE", "CWE-347", "critical", "JWT verify with empty secret"),
    (r"req\.session\.regenerate", "AUTH_ISSUE", "CWE-384", "info", "Session regeneration after login is good practice"),
    (r"(?:secret|key)\s*=\s*['\"]secret['\"]", "AUTH_ISSUE", "CWE-798", "high", "Weak default JWT secret"),
    (r"res\.cookie\s*\([^)]*(?:httpOnly|secure|sameSite)", "AUTH_ISSUE", "CWE-614", "medium", "Cookie without security flags"),

    # ── CSRF ──────────────────────────────────────────
    (r"@app\.route\s*\([^)]*methods=\[['\"]POST['\"]", "CSRF", "CWE-352", "high", "POST endpoint without CSRF protection", ["py"]),
    (r"app\.post\s*\([^)]*\)", "CSRF", "CWE-352", "high", "POST endpoint without CSRF token", ["js", "ts"]),
    (r"@csrf_exempt", "CSRF", "CWE-352", "high", "CSRF protection disabled", ["py"]),
    (r"csrf_protect\s*=\s*False", "CSRF", "CWE-352", "high", "CSRF protection disabled"),
    (r"\[ValidateAntiForgeryToken\]", "CSRF", "CWE-352", "info", "CSRF token validation is good practice", ["cs"]),
    (r"\[HttpPost\]", "CSRF", "CWE-352", "medium", "POST handler without anti-forgery token", ["cs"]),

    # ── Null Pointer / Error Handling ─────────────────
    (r"\->\s*\w+\s*\(.*\)[^;]*null", "NULL_DEREFERENCE", "CWE-476", "high", "Method call on possibly null object"),
    (r"\.\s*\w+\s*\([^)]*\)\s*;\s*\n\s*(?!if)", "NULL_DEREFERENCE", "CWE-476", "medium", "Possible null dereference"),
    (r"\bnull\b.*\.\s*equals", "NULL_DEREFERENCE", "CWE-476", "medium", "Calling .equals() on null reference", ["java"]),
    (r"except\s*:?\s*\n\s*pass", "ERROR_HANDLING", "CWE-391", "low", "Bare except:pass swallows all errors", ["py"]),
    (r"except\s+Exception\s*:\s*\n\s*pass", "ERROR_HANDLING", "CWE-391", "low", "Exception silently ignored", ["py"]),
    (r"try\s*\{[^}]*\}\s*catch\s*\(\s*\)\s*\{[^}]*\}", "ERROR_HANDLING", "CWE-391", "low", "Catch block empty — error silently ignored"),
    (r"@\s*SuppressWarnings", "ERROR_HANDLING", "CWE-391", "low", "Suppressed warnings may hide bugs"),

    # ── Race Condition / Threading ────────────────────
    (r"(?:threading\.Thread|thread\.start_new)", "RACE_CONDITION", "CWE-362", "medium", "Thread without synchronization"),
    (r"counter\s*\+=\s*1|counter\s*-=\s*1", "RACE_CONDITION", "CWE-362", "medium", "Non-atomic counter increment"),
    (r"global\s+\w+\s*\n.*\w+\s*\+=", "RACE_CONDITION", "CWE-362", "medium", "Global variable modified without lock"),
    (r"self\.\w+\s*\+=", "RACE_CONDITION", "CWE-362", "low", "Instance variable modified without synchronization"),
    (r"if\s+os\.path\.exists\s*\([^)]*\)\s*:\s*\n\s*open\s*\(", "RACE_CONDITION", "CWE-367", "high", "TOCTOU — file existence check then open"),
    (r"if\s+file_exists\s*\([^)]*\)\s*\{[^}]*fopen", "RACE_CONDITION", "CWE-367", "high", "TOCTOU — file exists check then open"),

    # ── LDAP Injection ────────────────────────────────
    (r"ldap_search|ldap_list|ldap_read", "LDAP_INJECTION", "CWE-90", "high", "LDAP query with user input"),
    (r"search\s*\([^)]*dc=", "LDAP_INJECTION", "CWE-90", "high", "LDAP search filter with user input"),

    # ── Log Injection ─────────────────────────────────
    (r"logging\.(?:info|debug|warning|error)\s*\([^)]*user", "LOG_INJECTION", "CWE-117", "medium", "User input in log message — log injection"),
    (r"log\.(?:Info|Debug|Warn|Error)\s*\([^)]*user", "LOG_INJECTION", "CWE-117", "medium", "User input in log — log injection"),
    (r"console\.log\s*\([^)]*user", "LOG_INJECTION", "CWE-117", "low", "User input in console output"),
    (r"fprintf\s*\([^,]+,\s*user", "LOG_INJECTION", "CWE-117", "medium", "User input in file log"),

    # ── Information Disclosure ────────────────────────
    (r"debug\s*=\s*True\b", "INFO_DISCLOSURE", "CWE-200", "medium", "Debug mode enabled in production"),
    (r"stack[\s_]trace|print_exc|format_exc|traceback\.print", "INFO_DISCLOSURE", "CWE-200", "medium", "Stack trace may expose sensitive info"),
    (r"app\.run\s*\([^)]*debug\s*=\s*True", "INFO_DISCLOSURE", "CWE-200", "medium", "Flask debug mode exposes console", ["py"]),
    (r"error_reporting\s*\(\s*E_ALL\s*\)", "INFO_DISCLOSURE", "CWE-200", "medium", "Full error reporting in production", ["php"]),
    (r"display_errors\s*=\s*On", "INFO_DISCLOSURE", "CWE-200", "medium", "Display errors enabled in production", ["php"]),
    (r"wp-config\.php|config\.json|\.env", "INFO_DISCLOSURE", "CWE-200", "low", "Config file may expose credentials"),
    (r"print_r\s*\(|var_dump\s*\(|var_export\s*\(", "INFO_DISCLOSURE", "CWE-200", "medium", "Debug output in production code"),
    (r"app\.config\[\s*['\"]DEBUG['\"]\]\s*=\s*True", "INFO_DISCLOSURE", "CWE-200", "medium", "Flask DEBUG config enabled"),
    (r"phpinfo\s*\(\s*\)", "INFO_DISCLOSURE", "CWE-200", "high", "phpinfo() exposes system configuration", ["php"]),
    (r"git\.config|\.gitignore", "INFO_DISCLOSURE", "CWE-200", "low", "Possible .git exposure in production"),

    # ── Insecure CORS ─────────────────────────────────
    (r"CORS_ORIGIN_ALLOW_ALL\s*=\s*True", "INSECURE_CORS", "CWE-942", "medium", "CORS allows all origins", ["py"]),
    (r"Access-Control-Allow-Origin\s*:\s*\*", "INSECURE_CORS", "CWE-942", "medium", "Wildcard CORS — any origin allowed"),
    (r"allow_origins\s*=\s*\[\s*['\"]\*['\"]\s*\]", "INSECURE_CORS", "CWE-942", "medium", "CORS allows all origins"),
    (r"cors\s*\(\s*\{\s*origin\s*:\s*true\s*\}", "INSECURE_CORS", "CWE-942", "medium", "CORS reflects origin — insecure"),
    (r"cors\s*\(\s*\{\s*origin\s*:\s*['\"]\*['\"]\s*\}", "INSECURE_CORS", "CWE-942", "medium", "CORS with wildcard origin"),

    # ── Security Misconfiguration ─────────────────────
    (r"verify\s*=\s*False\b", "SECURITY_MISCONFIG", "CWE-295", "high", "SSL/TLS verification disabled"),
    (r"rejectUnauthorized\s*:\s*false", "SECURITY_MISCONFIG", "CWE-295", "high", "SSL verification disabled", ["js", "ts"]),
    (r"chmod\s*\([^)]*0o?777", "SECURITY_MISCONFIG", "CWE-732", "high", "World-writable permissions (777)"),
    (r"chmod\s*\([^)]*0o?666", "SECURITY_MISCONFIG", "CWE-732", "medium", "World-readable permissions (666)"),
    (r"umask\s*\(\s*0\s*\)", "SECURITY_MISCONFIG", "CWE-732", "medium", "umask(0) creates files with no permissions restriction"),
    (r"app\.run\s*\(\s*host\s*=\s*['\"]0\.0\.0\.0['\"]", "SECURITY_MISCONFIG", "CWE-200", "medium", "Binding to 0.0.0.0 exposes to network"),
    (r"ALLOWED_HOSTS\s*=\s*\[\s*['\"]\*['\"]", "SECURITY_MISCONFIG", "CWE-200", "medium", "Wildcard ALLOWED_HOSTS — any host accepted"),
    (r"SECRET_KEY\s*=\s*['\"][^'\"]{3,12}['\"]", "SECURITY_MISCONFIG", "CWE-798", "high", "Weak Django SECRET_KEY"),
    (r"admin/|administrator", "SECURITY_MISCONFIG", "CWE-200", "low", "Exposed admin path in code"),

    # ── WebSocket Injection ────────────────────────────
    (r"ws\.send\s*\([^)]*user", "WEBSOCKET_INJECTION", "CWE-79", "medium", "User input sent to WebSocket without sanitization"),
    (r"WebSocket.*message.*user", "WEBSOCKET_INJECTION", "CWE-79", "medium", "WebSocket message with user input"),

    # ── Header Injection ──────────────────────────────
    (r"res\.setHeader\s*\([^)]*user", "HEADER_INJECTION", "CWE-113", "high", "User input in HTTP header — CRLF injection"),
    (r"header\s*\([^)]*\$", "HEADER_INJECTION", "CWE-113", "high", "PHP header with user input", ["php"]),
    (r"setHeader\s*\([^)]*req\.", "HEADER_INJECTION", "CWE-113", "high", "Header set from request without validation"),

    # ── HTTP Parameter Pollution ──────────────────────
    (r"req\.query\s*=\s*{.+req\.query", "HPP", "CWE-235", "low", "Merging query params — possible HPP", ["js", "ts"]),
    (r":params|request\.params", "HPP", "CWE-235", "low", "Parameter pollution possible"),

    # ── SMTP Injection ────────────────────────────────
    (r"smtplib\.SMTP|sendmail\s*\([^)]*user", "SMTP_INJECTION", "CWE-93", "high", "User input in SMTP headers — mail injection"),
    (r"mail\s*\([^)]*\$", "SMTP_INJECTION", "CWE-93", "high", "PHP mail with user input", ["php"]),

    # ── XPath Injection ───────────────────────────────
    (r"xpath\s*\([^)]*user", "XPATH_INJECTION", "CWE-643", "high", "XPath query with user input"),
    (r"XPathExpression|XPath\.compile", "XPATH_INJECTION", "CWE-643", "high", "XPath expression with user input", ["java"]),

    # ── ReDoS (Regex DoS) ─────────────────────────────
    (r"re\.compile\s*\(\s*r['\"]\^?\([^)]*(?:a|b|c|d|e|f|g|h|i|j|k|l|m|n|o|p|q|r|s|t|u|v|w|x|y|z)\s*\|\s*[a-z]+\s*\)\+", "REDOS", "CWE-1333", "medium", "Regex may be vulnerable to ReDoS — nested quantifiers"),
    (r"re\.compile\s*\(\s*r['\"][^'\"]*(?:\([^)]*\)\+)+[^'\"]*['\"]", "REDOS", "CWE-1333", "medium", "Regex with nested quantifiers — possible ReDoS"),
    (r"\b\w+\s*\|\s*\w+\s*\)\+", "REDOS", "CWE-1333", "low", "Alternation with quantifier may cause ReDoS"),

    # ── Hardcoded Test / Debug ────────────────────────
    (r"test_password|testuser|test@test\.com", "TEST_CREDENTIALS", "CWE-798", "medium", "Test credentials in code"),
    (r"TODO|FIXME|HACK|XXX|BUG", "CODE_QUALITY", "CWE-546", "info", "Code quality issue — incomplete work"),
    (r"print\s*\([^)]*debug|logger\.debug", "CODE_QUALITY", "CWE-489", "low", "Debug logging left in production"),
    (r"if\s+__name__\s*==\s*['\"]__main__['\"]", "CODE_QUALITY", "CWE-489", "info", "Script entry point — ensure not imported"),

    # ── Exposed Endpoints ─────────────────────────────
    (r"@app\.route\s*\(\s*['\"]/debug['\"]", "EXPOSED_ENDPOINT", "CWE-200", "high", "Debug endpoint exposed in production"),
    (r"@app\.route\s*\(\s*['\"]/admin['\"]", "EXPOSED_ENDPOINT", "CWE-200", "medium", "Admin endpoint without auth"),
    (r"@app\.route\s*\(\s*['\"]/health['\"]", "EXPOSED_ENDPOINT", "CWE-200", "low", "Health endpoint may expose system info"),
    (r"graphql|/api/graphql", "EXPOSED_ENDPOINT", "CWE-200", "medium", "GraphQL endpoint may expose schema"),

    # ── Clickjacking ──────────────────────────────────
    (r"X-Frame-Options|DENY|SAMEORIGIN", "CLICKJACKING", "CWE-1021", "info", "X-Frame-Options header recommended for clickjacking prevention"),
    (r"Content-Security-Policy.*frame-ancestors", "CLICKJACKING", "CWE-1021", "info", "CSP frame-ancestors recommended for clickjacking"),
    (r"frame-ancestors\s+['\"]none['\"]", "CLICKJACKING", "CWE-1021", "info", "Consider X-Frame-Options: DENY for older browsers"),

    # ── Cache / HTTPS ─────────────────────────────────
    (r"Cache-Control:\s*public", "CACHE_ISSUE", "CWE-524", "medium", "Cacheable response — may expose sensitive data"),
    (r"Cache-Control:\s*max-age\s*=\s*[3-9]\d{4,}", "CACHE_ISSUE", "CWE-524", "medium", "Long cache duration for sensitive content"),
    (r"http://", "HTTPS_ISSUE", "CWE-319", "medium", "HTTP URL instead of HTTPS"),
    (r"strict-transport-security|HSTS|Strict-Transport-Security", "HTTPS_ISSUE", "CWE-319", "info", "HSTS header recommended for HTTPS enforcement"),

    # ── Solidity / Smart Contracts ────────────────────
    (r"tx\.origin", "SOLIDITY_ISSUE", "CWE-348", "high", "tx.origin vulnerable to phishing attacks", ["sol"]),
    (r"\.call\s*\{value", "SOLIDITY_ISSUE", "CWE-682", "high", "Unchecked external call — reentrancy risk", ["sol"]),
    (r"pragma\s+solidity\s+\^", "SOLIDITY_ISSUE", "CWE-676", "low", "Floating pragma — pin Solidity version", ["sol"]),
    (r"selfdestruct\s*\(", "SOLIDITY_ISSUE", "CWE-123", "high", "selfdestruct enables contract destruction", ["sol"]),
    (r"delegatecall\s*\(", "SOLIDITY_ISSUE", "CWE-829", "critical", "delegatecall — storage manipulation risk", ["sol"]),
    (r"callcode\s*\(", "SOLIDITY_ISSUE", "CWE-829", "critical", "callcode deprecated — use delegatecall", ["sol"]),
    (r"require\s*\([^)]*==\s*owner", "SOLIDITY_ISSUE", "CWE-287", "medium", "Basic access control via owner comparison", ["sol"]),
    (r"block\.timestamp|block\.number|now\b", "SOLIDITY_ISSUE", "CWE-682", "medium", "Block values are miner-influenced", ["sol"]),
    (r"msg\.value\s*/\s*|msg\.value\s*%", "SOLIDITY_ISSUE", "CWE-682", "medium", "msg.value arithmetic — rounding risk", ["sol"]),
    (r"for\s*\(\s*[^)]*\+\+\s*\)\s*\{[^}]*\.call", "SOLIDITY_ISSUE", "CWE-682", "high", "Loop with external call — gas griefing", ["sol"]),
    (r"\.transfer\s*\(|\.send\s*\(", "SOLIDITY_ISSUE", "CWE-682", "medium", "transfer/send may fail — use call pattern", ["sol"]),

    # ── CSV Injection ─────────────────────────────────
    (r"csv\.writer|fputcsv|CsvWriter", "CSV_INJECTION", "CWE-1236", "medium", "CSV export may allow formula injection"),
    (r"\.csv['\"]|\"text/csv\"", "CSV_INJECTION", "CWE-1236", "medium", "CSV content type — possible formula injection"),

    # ── Mass Assignment ───────────────────────────────
    (r"update_attributes|update\(request|update!\(request", "MASS_ASSIGNMENT", "CWE-915", "high", "Mass assignment via request params", ["rb"]),
    (r"fill\(request|update\(request\.|assign_attributes", "MASS_ASSIGNMENT", "CWE-915", "high", "Mass assignment from user data"),
    (r"Object\.assign\s*\([^)]*req\.", "MASS_ASSIGNMENT", "CWE-915", "high", "Object.assign with request data — mass assignment", ["js", "ts"]),

    # ── Directory Listing ─────────────────────────────
    (r"Options\s+\+Indexes", "DIRECTORY_LISTING", "CWE-548", "medium", "Directory listing enabled — exposes file structure"),
    (r"DirectoryIndex\s+disabled", "DIRECTORY_LISTING", "CWE-548", "low", "Directory listing may be enabled"),

    # ── Weak SSL/TLS ─────────────────────────────────
    (r"ssl\.PROTOCOL_TLSv1|SSLv23|PROTOCOL_SSLv", "WEAK_TLS", "CWE-327", "high", "Weak TLS/SSL protocol version", ["py"]),
    (r"min_version\s*=\s*ssl\.TLSVersion\.TLSv1", "WEAK_TLS", "CWE-327", "high", "Minimum TLS version too low", ["py"]),
    (r"tls_version\s*=\s*['\"]tls1['\"]", "WEAK_TLS", "CWE-327", "high", "TLS v1.0 is deprecated"),
    (r"ssl_protocols\s+TLSv1\s+TLSv1\.1", "WEAK_TLS", "CWE-327", "high", "TLS 1.0/1.1 enabled — use TLS 1.2+"),

    # ── Docker Security ────────────────────────────────
    (r"^FROM\s+\S+:latest\s*$", "DOCKER_SECURITY", "CWE-1220", "high", "Docker 'latest' tag is ambiguous — pin a specific version", ["dockerfile"]),
    (r"^USER\s+root\s*$", "DOCKER_SECURITY", "CWE-1220", "high", "Container runs as root — use non-root user", ["dockerfile"]),
    (r"^ADD\s+", "DOCKER_SECURITY", "CWE-1220", "medium", "ADD pulls remote archives — use COPY instead", ["dockerfile"]),
    (r"ENV\s+(?:NODE_ENV|FLASK_ENV)\s*=\s*development", "DOCKER_SECURITY", "CWE-1220", "high", "Development env vars baked into production image", ["dockerfile"]),
    (r"ARG\s+(?:API_KEY|SECRET|PASSWORD|TOKEN|CREDENTIAL)", "DOCKER_SECURITY", "CWE-1220", "high", "Build args may leak secrets into image history", ["dockerfile"]),
    (r"pip\s+install\b(?!.*--no-cache-dir)", "DOCKER_SECURITY", "CWE-1220", "medium", "pip without --no-cache-dir increases image size", ["dockerfile"]),
    (r"npm\s+install\b(?!.*--only=prod)", "DOCKER_SECURITY", "CWE-1220", "medium", "npm install without --only=prod includes dev deps", ["dockerfile"]),
    (r"apt-get\s+update\b(?!.*rm\s)", "DOCKER_SECURITY", "CWE-1220", "high", "apt-get without cleanup leaves cache", ["dockerfile"]),

    # ── Kubernetes Security ────────────────────────────
    (r"privileged:\s*true", "K8S_SECURITY", "CWE-250", "critical", "Privileged container — grants all capabilities", ["yaml"]),
    (r"hostNetwork:\s*true", "K8S_SECURITY", "CWE-250", "high", "Host network mode exposes host network", ["yaml"]),
    (r"hostPID:\s*true", "K8S_SECURITY", "CWE-250", "high", "Host PID namespace exposes host processes", ["yaml"]),
    (r"hostIPC:\s*true", "K8S_SECURITY", "CWE-250", "high", "Host IPC namespace exposes host IPC", ["yaml"]),
    (r"runAsUser:\s*0", "K8S_SECURITY", "CWE-250", "high", "Container runs as root (UID 0)", ["yaml"]),
    (r"allowPrivilegeEscalation:\s*true", "K8S_SECURITY", "CWE-250", "high", "Privilege escalation allowed", ["yaml"]),
    (r"readOnlyRootFilesystem:\s*false", "K8S_SECURITY", "CWE-250", "medium", "Root filesystem is writable", ["yaml"]),
    (r"capabilities.*ADD", "K8S_SECURITY", "CWE-250", "high", "Extra capabilities added to container", ["yaml"]),
    (r"hostPath:", "K8S_SECURITY", "CWE-250", "high", "HostPath volume risks host access", ["yaml"]),
    (r"automountServiceAccountToken:\s*true", "K8S_SECURITY", "CWE-250", "medium", "SA token auto-mounted unnecessarily", ["yaml"]),

    # ── Dependency Vulnerabilities ─────────────────────
    (r'"express"\s*:\s*["\']\^?[0-3]\.', "DEPENDENCY_VULN", "CWE-1104", "high", "Express < 4.x has known vulnerabilities", ["json"]),
    (r'"lodash"\s*:\s*["\']\^?4\.17\.(?:[0-3]\d|4[0-8])\b', "DEPENDENCY_VULN", "CWE-1104", "medium", "lodash < 4.17.49 has prototype pollution vuln", ["json"]),
    (r'"axios"\s*:\s*["\']\^?0\.(?:1\d|2[0-4])\.', "DEPENDENCY_VULN", "CWE-1104", "high", "axios < 0.25.0 has SSRF vulnerability", ["json"]),
    (r'"jsonwebtoken"\s*:\s*["\']\^?[0-8]\.', "DEPENDENCY_VULN", "CWE-1104", "high", "jsonwebtoken < 9.x has JWT bypass vulns", ["json"]),
    (r"Django\s*[<>=]+\s*[0-2]\.", "DEPENDENCY_VULN", "CWE-1104", "high", "Django < 3.x has known vulnerabilities"),
    (r"Flask\s*[<>=]+\s*[0-1]\.", "DEPENDENCY_VULN", "CWE-1104", "high", "Flask < 2.x lacks security improvements"),
    (r"requests\s*[<>=]+\s*[0-1]\.", "DEPENDENCY_VULN", "CWE-1104", "medium", "requests < 2.x may have SSL issues"),
    (r"cryptography\s*[<>=]+\s*[0-2]\.", "DEPENDENCY_VULN", "CWE-1104", "high", "cryptography < 3.x has known vulnerabilities"),
]

SUPPORTED_LANGS_LOCAL = {
    ".py": "py", ".js": "js", ".ts": "ts", ".jsx": "js", ".tsx": "ts",
    ".java": "java", ".go": "go", ".rs": "rs", ".c": "c", ".cpp": "cpp",
    ".h": "c", ".hpp": "cpp", ".rb": "rb", ".php": "php",
    ".cs": "cs", ".swift": "swift", ".kt": "kt", ".sol": "sol",
    ".scala": "scala", ".vue": "vue",
    ".yml": "yaml", ".yaml": "yaml",
    ".json": "json",
}

IGNORE_DIRS_LOCAL = {"node_modules", ".git", "__pycache__", "venv", ".venv",
                     "dist", "build", ".next", ".nuxt", "target", "vendor",
                     ".cache", ".opencode", "bower_components"}

def local_scan_file(path: str) -> list[dict]:
    """Offline regex-based scan — no server needed."""
    ext = Path(path).suffix.lower()
    fname = os.path.basename(path).lower()

    lang_key = SUPPORTED_LANGS_LOCAL.get(ext)
    if not lang_key:
        if fname == "dockerfile" or fname.startswith("dockerfile."):
            lang_key = "dockerfile"
        elif fname.startswith("docker-compose"):
            lang_key = "yaml"
        elif fname in ("package.json", "package-lock.json", "yarn.lock"):
            lang_key = "json"
        elif fname in ("requirements.txt", "pipfile", "pipfile.lock"):
            lang_key = "py"
        else:
            return []
    if os.path.basename(os.path.dirname(path)) in IGNORE_DIRS_LOCAL:
        return []

    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except (OSError, IOError):
        return []

    findings = []
    seen_keys = set()

    for i, line in enumerate(lines, 1):
        for pattern in LOCAL_PATTERNS:
            if len(pattern) == 6:
                regex, label, cwe, sev, msg, langs = pattern
                if lang_key not in langs:
                    continue
            else:
                regex, label, cwe, sev, msg = pattern

            if re.search(regex, line, re.IGNORECASE):
                key = f"{label}:{msg}"
                if key not in seen_keys:
                    seen_keys.add(key)
                    findings.append({
                        "line": i,
                        "message": msg,
                        "severity": sev,
                        "category": label,
                        "cweId": cwe,
                    })

    return findings


def cmd_review(args: argparse.Namespace, cfg: dict) -> int:
    diff = Path(args.path).read_text(encoding="utf-8", errors="replace")

    # Try v2 server first
    url = get_backend_url(cfg, "v2")
    resp = api_post(url, "/v2/review", {
        "diff": diff, "language": args.language or "python",
    }, timeout=cfg.get("timeout", 120))

    if resp:
        finding = resp.get("finding", {})
    else:
        # Local fallback
        match = _local_vuln_match(diff)
        if match:
            finding = {
                "vulnerability": match[0],
                "cwe": match[1],
                "severity": match[2],
                "root_cause": match[3],
                "secure_fix": match[4],
                "patched_code": f"# Replace with:\n# {match[4]}",
            }
        else:
            finding = {"vulnerability": "No obvious vulnerability detected", "severity": "clean"}

    if args.format == "json":
        print_json({"finding": finding})
    else:
        print(f"\n  \033[1m📋 Security Review\033[0m")
        print(f"  Vulnerability: {finding.get('vulnerability', 'N/A')}")
        print(f"  CWE: {finding.get('cwe', 'N/A')}")
        print(f"  Severity: {finding.get('severity', 'N/A')}")
        if finding.get("root_cause"):
            print(f"\n  Root Cause: {finding['root_cause']}")
        if finding.get("attack_scenario"):
            print(f"  Attack: {finding['attack_scenario']}")
        if finding.get("secure_fix"):
            print(f"  Fix: {finding['secure_fix']}")
        if finding.get("patched_code"):
            print(f"\n  \033[96m📝 Patched Code:\033[0m")
            print(f"  {finding['patched_code']}")
        if finding.get("references"):
            print(f"  References: {', '.join(finding['references'])}")
    return 0


SECURE_CODE_TEMPLATES: dict[str, str] = {
    "python": {
        "file upload": """import os
from werkzeug.utils import secure_filename

ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg'}
UPLOAD_DIR = "/var/uploads"

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def handle_upload(file):
    if not allowed_file(file.filename):
        raise ValueError("File type not allowed")
    filename = secure_filename(file.filename)
    filepath = os.path.join(UPLOAD_DIR, filename)
    file.save(filepath)
    return filepath""",
        "database query": """import psycopg2
from contextlib import closing

def get_user(user_id: int) -> dict:
    with closing(psycopg2.connect(os.environ["DATABASE_URL"])) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM users WHERE id = %s", (user_id,))
            row = cur.fetchone()
    return {"id": row[0], "name": row[1]} if row else {}""",
        "api endpoint": """from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import hashlib, hmac, os

app = FastAPI()

class Request(BaseModel):
    user_id: str
    data: str

@app.post("/api/process")
async def process(req: Request):
    # Validate input
    if not req.user_id.isalnum():
        raise HTTPException(status_code=400, detail="Invalid user")
    # Process safely
    return {"status": "ok", "hash": hashlib.sha256(req.data.encode()).hexdigest()}""",
    },
    "javascript": {
        "file upload": """const express = require('express');
const multer = require('multer');
const path = require('path');

const storage = multer.diskStorage({
  destination: '/var/uploads',
  filename: (req, file, cb) => {
    const safe = file.originalname.replace(/[^\\w.-]/g, '_');
    cb(null, Date.now() + '-' + safe);
  }
});
const upload = multer({ storage, limits: { fileSize: 5 * 1024 * 1024 } });
app.post('/upload', upload.single('file'), (req, res) => {
  res.json({ path: req.file.path });
});""",
    },
}


def cmd_generate(args: argparse.Namespace, cfg: dict) -> int:
    prompt_lower = args.prompt.lower()
    lang = args.language or "python"

    # Try v2 server first
    url = get_backend_url(cfg, "v2")
    resp = api_post(url, "/v2/generate", {
        "prompt": args.prompt, "language": lang,
    }, timeout=cfg.get("timeout", 120))

    if resp:
        finding = resp.get("finding", {})
    else:
        # Local fallback — match template
        templates = SECURE_CODE_TEMPLATES.get(lang, SECURE_CODE_TEMPLATES["python"])
        code = "No matching template found. Try: 'file upload', 'database query', 'api endpoint'"
        note = ""
        for key, val in templates.items():
            if key in prompt_lower:
                code = val
                note = f"Template: {key}"
                break
        if lang != "python":
            note += f"\n  \033[93mNote: Showing {lang} template (reuse from python templates)\033[0m"
        finding = {"patched_code": code, "secure_fix": note or "AI-generated secure code (local)"}

    if args.format == "json":
        print_json({"finding": finding})
    else:
        print(f"\n  \033[1m🔒 Generated Secure Code ({lang})\033[0m")
        if finding.get("patched_code"):
            print(f"\n  \033[96m{'-'*50}\033[0m")
            print(f"  {finding['patched_code']}")
            print(f"  \033[96m{'-'*50}\033[0m")
        if finding.get("secure_fix"):
            print(f"\n  Note: {finding['secure_fix']}")
    return 0


def cmd_server(args: argparse.Namespace, cfg: dict) -> int:
    start_server(port=args.port, mock=cfg.get("mock", True))
    return 0


def cmd_health(args: argparse.Namespace, cfg: dict) -> int:
    url = args.url or get_backend_url(cfg)
    resp = api_get(url, "/ml/health", timeout=5)
    if not resp:
        v2_url = get_backend_url(cfg, "v2")
        resp = api_get(v2_url, "/v2/health", timeout=5)
    if not resp:
        print(f"\033[91m✖ Server is not responding at {url}\033[0m")
        return 1
    print(f"\n  \033[92m✅ Server is healthy\033[0m")
    print_json(resp)
    return 0


def cmd_batch(args: argparse.Namespace, cfg: dict) -> int:
    results = {}
    for path in args.paths:
        if os.path.isdir(path):
            results.update(scan_directory(path, cfg))
        else:
            issues = scan_file(path, cfg)
            if issues:
                results[path] = issues
    fmt = args.format or cfg.get("format", "table")
    if fmt == "json":
        _write_json_output(results, args.output)
    else:
        for fpath, issues in results.items():
            if issues:
                print(f"\n  \033[1m📄 {fpath}\033[0m")
                print_table(issues)
    total = sum(len(v) for v in results.values())
    print(f"\n  \033[1mSummary: {total} issue(s) in {len(results)} file(s)\033[0m")
    return 0


def cmd_config(args: argparse.Namespace, cfg: dict) -> int:
    if args.show:
        print_json(cfg)
        return 0
    if args.key and args.value:
        cfg[args.key] = args.value
        save_config(cfg)
        print(f"\033[92m✅ Config updated: {args.key} = {args.value}\033[0m")
        return 0
    if args.reset:
        save_config(DEFAULT_CONFIG)
        print("\033[92m✅ Config reset to defaults\033[0m")
        return 0
    print_json(cfg)
    return 0


def cmd_watch(args: argparse.Namespace, cfg: dict) -> int:
    """Watch a directory for file changes and auto-scan in background."""
    root = args.dir or "."
    if not os.path.isdir(root):
        print(f"\033[91m✖ Directory not found: {root}\033[0m")
        return 1

    stop = Event()
    watcher = FileWatcher(root, cfg, stop)

    print(f"\033[92m▶ Background file watcher started\033[0m")
    print(f"  Watching: {os.path.abspath(root)}")
    print(f"  Cache: {CACHE_FILE}")
    print(f"  Files scanned will print below:\n")

    try:
        watcher.run()
    except KeyboardInterrupt:
        print("\n\n  \033[93m⏹ Watcher stopped.\033[0m")

    s = cache_stats()
    print(f"\n  \033[92mCache stats: {s['total_files']} files, {s['with_issues']} with issues\033[0m")
    return 0


def cmd_install_hook(args: argparse.Namespace, cfg: dict) -> int:
    """Install git pre-commit hook."""
    if install_git_hook():
        return 0
    return 1


def cmd_cache(args: argparse.Namespace, cfg: dict) -> int:
    """Show cache statistics."""
    s = cache_stats()
    print(f"\n  \033[1m📦 Scan Cache\033[0m")
    print(f"  {'─'*40}")
    print(f"  File:   {CACHE_FILE}")
    print(f"  Files:  {s['total_files']}")
    print(f"  With issues: {s['with_issues']}")
    print(f"  Total issues: {s['total_issues']}")
    print(f"\n  \033[90mCache is persistent across CLI runs.\033[0m")
    print(f"  \033[90mUse --no-cache on scan to bypass.\033[0m")
    return 0


# ── Main Entry Point ────────────────────────────────────────────────
def main():
    cfg = load_config()

    ap = argparse.ArgumentParser(
        prog="rakshak",
        description="RakshakAI — AI-powered security scanner for your code.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--url", help="Backend server URL (overrides config)")
    ap.add_argument("--mock", action="store_true", help="Force mock mode")

    sub = ap.add_subparsers(dest="cmd")

    # scan
    s = sub.add_parser("scan", help="Scan file(s) for vulnerabilities")
    s.add_argument("path", help="File or directory to scan")
    s.add_argument("--format", choices=["table", "json", "sarif"], default=cfg.get("format", "table"))
    s.add_argument("--language", "-l", help="Force language (default: auto-detect)")
    s.add_argument("--output", "-o", help="Save results to file")
    s.add_argument("--exclude", "-e", action="append", default=[], help="Exclude directories")
    s.add_argument("--no-cache", action="store_true", help="Bypass cache")
    s.set_defaults(fn=cmd_scan)

    # review
    r = sub.add_parser("review", help="Review a unified diff for security issues")
    r.add_argument("path", help="Path to diff file")
    r.add_argument("--format", choices=["table", "json"], default=cfg.get("format", "table"))
    r.add_argument("--language", "-l", default="python")
    r.set_defaults(fn=cmd_review)

    # generate
    g = sub.add_parser("generate", help="Generate secure code from a prompt")
    g.add_argument("prompt", help="Describe what you need")
    g.add_argument("--format", choices=["table", "json"], default=cfg.get("format", "table"))
    g.add_argument("--language", "-l", default="python")
    g.set_defaults(fn=cmd_generate)

    # server
    sv = sub.add_parser("server", help="Start the RakshakAI backend server")
    sv.add_argument("--port", type=int, default=3000)
    sv.set_defaults(fn=cmd_server)

    # health
    h = sub.add_parser("health", help="Check if the server is running")
    h.set_defaults(fn=cmd_health)

    # batch
    b = sub.add_parser("batch", help="Scan multiple files")
    b.add_argument("paths", nargs="+", help="Files or directories to scan")
    b.add_argument("--format", choices=["table", "json", "sarif"], default=cfg.get("format", "table"))
    b.add_argument("--output", "-o", help="Save results to file")
    b.set_defaults(fn=cmd_batch)

    # config
    c = sub.add_parser("config", help="View or modify configuration")
    c.add_argument("--show", action="store_true", help="Show current config")
    c.add_argument("--reset", action="store_true", help="Reset to defaults")
    c.add_argument("key", nargs="?", help="Config key to set")
    c.add_argument("value", nargs="?", help="Value to set")
    c.set_defaults(fn=cmd_config)

    # watch (background)
    w = sub.add_parser("watch", help="Watch directory for changes (background scanner)")
    w.add_argument("--dir", default=".", help="Directory to watch (default: current)")
    w.set_defaults(fn=cmd_watch)

    # install-hook (invisible git integration)
    ih = sub.add_parser("install-hook", help="Install git pre-commit hook (auto-scan staged files)")
    ih.set_defaults(fn=cmd_install_hook)

    # cache stats
    cs = sub.add_parser("cache", help="Show scan cache statistics")
    cs.set_defaults(fn=cmd_cache)

    args = ap.parse_args()

    if not args.cmd:
        ap.print_help()
        return 0

    if hasattr(args, "format") and args.format:
        cfg["format"] = args.format
    if args.url:
        cfg["v1_url"] = args.url
        cfg["v2_url"] = args.url
    if hasattr(args, "mock") and args.mock:
        cfg["mock"] = True

    result = args.fn(args, cfg)
    return result if result is not None else 0


if __name__ == "__main__":
    sys.exit(main())
