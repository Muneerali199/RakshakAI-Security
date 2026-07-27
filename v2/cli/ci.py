#!/usr/bin/env python3
"""Non-interactive CI mode — scan files/dirs and output structured results.

Usage:
    python -m v2.cli.ci scan --format json src/
    python -m v2.cli.ci scan --format sarif src/
    python -m v2.cli.ci scan --format json --model gpt-4o src/
    echo 'int main() { char buf[10]; strcpy(buf, input); }' | python -m v2.cli.ci scan --format json -
"""
from __future__ import annotations
import argparse
import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from v2.cli.scanner import (
    BatchScanner, ScanResult, collect_source_files, results_to_sarif,
)


def main():
    parser = argparse.ArgumentParser(
        prog="rakshakai",
        description="RakshakAI v3 — Non-interactive security scanner",
    )
    sub = parser.add_subparsers(dest="command")

    scan_p = sub.add_parser("scan", help="Scan files or directories")
    scan_p.add_argument("path", help="File or directory to scan (use - for stdin)")
    scan_p.add_argument(
        "--format", "-f",
        choices=["json", "sarif", "text"],
        default="json",
        help="Output format (default: json)",
    )
    scan_p.add_argument("--model", "-m", default="deepseek", help="Model to use")
    scan_p.add_argument("--max-files", type=int, default=500, help="Max files to scan")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    if args.command == "scan":
        target = args.path
        model = args.model
        files = []

        if target == "-":
            # stdin mode
            content = sys.stdin.read()
            if not content.strip():
                print("Error: no input on stdin", file=sys.stderr)
                sys.exit(1)
            import tempfile
            with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
                f.write(content)
                tmp_path = f.name
            files = [tmp_path]
        elif os.path.isfile(target):
            files = [target]
        elif os.path.isdir(target):
            files = collect_source_files(target, max_files=args.max_files)
            if not files:
                print(json.dumps({"error": "no source files found", "path": target}))
                sys.exit(0)
        else:
            print(json.dumps({"error": f"path not found: {target}"}))
            sys.exit(1)

        scanner = BatchScanner(max_workers=4)
        results = scanner.scan_files(files, model=model)

        if args.format == "json":
            output = {
                "tool": "RakshakAI",
                "version": "3.0.0",
                "model": model,
                "path": target,
                "total": len(results),
                "vulnerable": sum(1 for r in results if r.cwe),
                "errors": sum(1 for r in results if r.status == "error"),
                "results": [r.to_dict() for r in results],
            }
            print(json.dumps(output, indent=2))

        elif args.format == "sarif":
            sarif = results_to_sarif(results)
            print(json.dumps(sarif, indent=2))

        elif args.format == "text":
            smry = scanner.summary()
            print(f"Scanned: {smry['scanned']}  Vuln: {smry['vulnerable']}  "
                  f"Crit: {smry['critical']}  High: {smry['high']}  Err: {smry['errors']}")
            for r in results:
                if r.cwe:
                    print(f"  [{r.severity}] {r.file}: {r.cwe} — {r.summary}")
                elif r.status == "error":
                    print(f"  [error] {r.file}: {r.error}")

        if target == "-" and files:
            try:
                os.unlink(files[0])
            except OSError:
                pass


if __name__ == "__main__":
    main()
