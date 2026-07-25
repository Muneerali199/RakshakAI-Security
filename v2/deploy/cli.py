"""
RakshakAI v2 — CLI.

Usage:
    rakshakai-v2 scan <file>
    rakshakai-v2 review <diff>
    rakshakai-v2 generate --language python "read user file safely"
    rakshakai-v2 server
    rakshakai-v2 health

Calls the FastAPI server (default http://localhost:8080). The server itself
loads the model; the CLI is a thin client.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

DEFAULT_URL = os.environ.get("RAKSHAK_V2_URL", "http://localhost:8080")


def _http_post(path: str, payload: dict, url: str = DEFAULT_URL, timeout: int = 120) -> dict:
    import requests
    r = requests.post(f"{url}{path}", json=payload, timeout=timeout)
    r.raise_for_status()
    return r.json()


def cmd_scan(args: argparse.Namespace) -> int:
    code = Path(args.path).read_text(encoding="utf-8", errors="replace")
    lang = args.language or _guess_lang(args.path)
    out = _http_post("/v2/scan", {"code": code, "language": lang, "filename": args.path})
    print(json.dumps(out, indent=2))
    return 0


def cmd_review(args: argparse.Namespace) -> int:
    diff = Path(args.path).read_text(encoding="utf-8", errors="replace")
    out = _http_post("/v2/review", {"diff": diff, "language": args.language or "python"})
    print(json.dumps(out, indent=2))
    return 0


def cmd_generate(args: argparse.Namespace) -> int:
    out = _http_post("/v2/generate", {"prompt": args.prompt, "language": args.language})
    print(json.dumps(out, indent=2))
    return 0


def cmd_server(args: argparse.Namespace) -> int:
    import uvicorn
    uvicorn.run("v2.deploy.server:app", host=args.host, port=args.port, workers=1, log_level="info")
    return 0


def cmd_health(args: argparse.Namespace) -> int:
    import requests
    try:
        r = requests.get(f"{args.url}/v2/health", timeout=5)
        r.raise_for_status()
        print(json.dumps(r.json(), indent=2))
        return 0
    except Exception as e:  # noqa: BLE001
        print(f"unhealthy: {e}", file=sys.stderr)
        return 1


def _guess_lang(path: str) -> str:
    ext = Path(path).suffix.lower()
    return {
        ".py": "python", ".js": "javascript", ".ts": "typescript",
        ".java": "java", ".go": "go", ".rs": "rust", ".c": "c",
        ".cpp": "cpp", ".cc": "cpp", ".h": "c", ".hpp": "cpp",
        ".rb": "ruby", ".php": "php", ".cs": "csharp",
        ".swift": "swift", ".kt": "kotlin", ".scala": "scala",
    }.get(ext, "text")


def main() -> int:
    ap = argparse.ArgumentParser(prog="rakshakai-v2", description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="scan a single file")
    s.add_argument("path")
    s.add_argument("--language", default=None)
    s.set_defaults(fn=cmd_scan)

    rv = sub.add_parser("review", help="review a unified diff")
    rv.add_argument("path")
    rv.add_argument("--language", default=None)
    rv.set_defaults(fn=cmd_review)

    g = sub.add_parser("generate", help="generate secure code from a prompt")
    g.add_argument("prompt")
    g.add_argument("--language", default="python")
    g.set_defaults(fn=cmd_generate)

    sv = sub.add_parser("server", help="run the FastAPI server")
    sv.add_argument("--host", default="0.0.0.0")
    sv.add_argument("--port", type=int, default=8080)
    sv.set_defaults(fn=cmd_server)

    h = sub.add_parser("health", help="ping the server")
    h.add_argument("--url", default=DEFAULT_URL)
    h.set_defaults(fn=cmd_health)

    args = ap.parse_args()
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
