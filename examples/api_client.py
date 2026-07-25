#!/usr/bin/env python3
"""Example: scan code via the FastAPI API server."""
import requests
import sys

def main():
    if len(sys.argv) < 2:
        code = 'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")'
    else:
        with open(sys.argv[1]) as f:
            code = f.read()

    resp = requests.post(
        "http://localhost:8000/ml/scan",
        json={"code": code, "language": "python", "filename": "test.py"},
        timeout=10,
    )
    result = resp.json()
    print(f"Language: {result['language']}")
    print(f"Issues: {result['total_issues']}")
    print(f"Scan time: {result['scan_time_ms']}ms")
    for issue in result["issues"]:
        print(f"  [{issue['severity']}] {issue['type']} (line {issue['line']}) "
              f"— conf: {issue['confidence']}")


if __name__ == "__main__":
    main()
