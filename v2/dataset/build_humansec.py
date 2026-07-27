"""
RakshakAI v2 — Synthesize the 100-sample HumanSecEval benchmark.

This is a hand-curated, held-out test set used for the judge-LLM scoring pass.
We ship a small starter set (10) and document how to grow it to 100+.

Format per line: one JSON object with:
  id, language, vulnerable_code, fixed_code, cwe, cve, severity, root_cause,
  attack_scenario, secure_fix (ground truth)
"""
from __future__ import annotations

import json
import sys
from pathlib import Path


# 10 hand-written, CWE-diverse seed samples. Expand to 100 by following the
# pattern: pick a CWE, write a small but real-world vulnerable snippet, write
# the minimal fix, write a one-paragraph root cause and attack scenario.
SEEDS: list[dict] = [
    {
        "id": "hsec-001",
        "language": "python",
        "vulnerable_code": (
            "def lookup(user_id):\n"
            "    sql = f'SELECT * FROM accounts WHERE id = {user_id}'\n"
            "    return db.execute(sql).fetchone()\n"
        ),
        "fixed_code": (
            "def lookup(user_id):\n"
            "    return db.execute('SELECT * FROM accounts WHERE id = %s', (user_id,)).fetchone()\n"
        ),
        "cwe": "CWE-89",
        "cve": None,
        "severity": "high",
        "root_cause": "User-controlled `user_id` is concatenated into a SQL string; the database driver treats the entire string as a command.",
        "attack_scenario": "An attacker submits `1 OR 1=1` as the id, dumping every account row.",
        "secure_fix": "Use a parameterized query; pass `user_id` as a bound parameter.",
    },
    {
        "id": "hsec-002",
        "language": "python",
        "vulnerable_code": (
            "from flask import request, make_response\n"
            "def hello():\n"
            "    name = request.args.get('name', 'world')\n"
            "    resp = make_response(f'<h1>Hello {name}</h1>')\n"
            "    return resp\n"
        ),
        "fixed_code": (
            "from flask import request, make_response\n"
            "from markupsafe import escape\n"
            "def hello():\n"
            "    name = request.args.get('name', 'world')\n"
            "    resp = make_response(f'<h1>Hello {escape(name)}</h1>')\n"
            "    resp.headers['Content-Security-Policy'] = \"default-src 'self'\"\n"
            "    return resp\n"
        ),
        "cwe": "CWE-79",
        "cve": None,
        "severity": "high",
        "root_cause": "The `name` query parameter is interpolated into the response without HTML-encoding.",
        "attack_scenario": "An attacker hosts a link with `?name=<script>fetch(...)</script>` that exfiltrates session cookies when clicked.",
        "secure_fix": "HTML-encode the user input with `markupsafe.escape` and add a strict Content-Security-Policy.",
    },
    {
        "id": "hsec-003",
        "language": "python",
        "vulnerable_code": (
            "import subprocess\n"
            "def ping(host):\n"
            "    return subprocess.run(f'ping -c 1 {host}', shell=True, capture_output=True)\n"
        ),
        "fixed_code": (
            "import subprocess, re, ipaddress\n"
            "def ping(host):\n"
            "    if not re.match(r'^[A-Za-z0-9.\\-]+$', host):\n"
            "        raise ValueError('invalid host')\n"
            "    return subprocess.run(['ping', '-c', '1', host], capture_output=True)\n"
        ),
        "cwe": "CWE-78",
        "cve": None,
        "severity": "critical",
        "root_cause": "`host` is concatenated into a shell command string with `shell=True`.",
        "attack_scenario": "An attacker supplies `; rm -rf /` as the host and the server executes the appended command.",
        "secure_fix": "Pass the command as a list, never use `shell=True`; validate `host` against an allowlist.",
    },
    {
        "id": "hsec-004",
        "language": "python",
        "vulnerable_code": (
            "import pickle\n"
            "def load_session(raw):\n"
            "    return pickle.loads(raw)\n"
        ),
        "fixed_code": (
            "import json\n"
            "def load_session(raw):\n"
            "    return json.loads(raw)\n"
        ),
        "cwe": "CWE-502",
        "cve": None,
        "severity": "critical",
        "root_cause": "Python `pickle` deserializes arbitrary objects and invokes their `__reduce__` callback, executing attacker code.",
        "attack_scenario": "An attacker submits a crafted pickle payload that calls `os.system('id')` on `__reduce__`.",
        "secure_fix": "Use a safe format like JSON. If pickle is unavoidable, sign and verify the payload first.",
    },
    {
        "id": "hsec-005",
        "language": "javascript",
        "vulnerable_code": (
            "const express = require('express');\n"
            "const app = express();\n"
            "app.get('/file', (req, res) => {\n"
            "  const fs = require('fs');\n"
            "  const p = '/var/data/' + req.query.name;\n"
            "  res.send(fs.readFileSync(p));\n"
            "});\n"
        ),
        "fixed_code": (
            "const path = require('path');\n"
            "const fs = require('fs');\n"
            "const ROOT = '/var/data';\n"
            "app.get('/file', (req, res) => {\n"
            "  const resolved = path.resolve(ROOT, req.query.name);\n"
            "  if (!resolved.startsWith(ROOT + path.sep)) return res.status(400).end();\n"
            "  res.send(fs.readFileSync(resolved));\n"
            "});\n"
        ),
        "cwe": "CWE-22",
        "cve": None,
        "severity": "high",
        "root_cause": "User-supplied `name` is concatenated to a base path with no normalization, allowing `..` segments to escape.",
        "attack_scenario": "An attacker requests `?name=../../etc/passwd` and the file is returned.",
        "secure_fix": "Resolve the requested path and verify it remains inside the allowed root.",
    },
    {
        "id": "hsec-006",
        "language": "python",
        "vulnerable_code": (
            "import hashlib\n"
            "def sign(secret, msg):\n"
            "    return hashlib.md5((secret + msg).encode()).hexdigest()\n"
        ),
        "fixed_code": (
            "import hmac, hashlib\n"
            "def sign(secret, msg):\n"
            "    return hmac.new(secret.encode(), msg.encode(), hashlib.sha256).hexdigest()\n"
        ),
        "cwe": "CWE-327",
        "cve": None,
        "severity": "high",
        "root_cause": "MD5 is broken and the construction is not HMAC; both the algorithm and the construction are wrong.",
        "attack_scenario": "An attacker forges a colliding message and produces a valid signature for arbitrary data.",
        "secure_fix": "Use HMAC-SHA256 with a constant-time compare.",
    },
    {
        "id": "hsec-007",
        "language": "python",
        "vulnerable_code": (
            "import jwt\n"
            "def verify(token, public_key):\n"
            "    return jwt.decode(token, public_key, algorithms=['HS256', 'none'])\n"
        ),
        "fixed_code": (
            "import jwt\n"
            "def verify(token, public_key):\n"
            "    return jwt.decode(token, public_key, algorithms=['RS256'])\n"
        ),
        "cwe": "CWE-347",
        "cve": None,
        "severity": "high",
        "root_cause": "The verifier permits the `none` algorithm and an HMAC algorithm with the public key as the secret, both of which allow forgery.",
        "attack_scenario": "An attacker sets `alg=none` and removes the signature; the server accepts the token as authentic.",
        "secure_fix": "Pin the verification to the expected asymmetric algorithm (RS256 / ES256).",
    },
    {
        "id": "hsec-008",
        "language": "python",
        "vulnerable_code": (
            "DB_PASSWORD = 'hunter2'\n"
            "AWS_KEY = 'AKIAEXAMPLEEXAMPLE'\n"
            "def connect():\n"
            "    return psycopg2.connect(password=DB_PASSWORD)\n"
        ),
        "fixed_code": (
            "import os\n"
            "def connect():\n"
            "    return psycopg2.connect(password=os.environ['DB_PASSWORD'])\n"
        ),
        "cwe": "CWE-798",
        "cve": None,
        "severity": "high",
        "root_cause": "Secrets are hard-coded in source and committed to the repository.",
        "attack_scenario": "Anyone with read access to the repository or its git history recovers the production credentials.",
        "secure_fix": "Load secrets from environment variables or a secret manager. Rotate the leaked values immediately.",
    },
    {
        "id": "hsec-009",
        "language": "python",
        "vulnerable_code": (
            "import requests\n"
            "def proxy(url):\n"
            "    return requests.get(url).text\n"
        ),
        "fixed_code": (
            "import ipaddress, socket, requests\n"
            "def proxy(url):\n"
            "    host = requests.utils.urlparse(url).hostname\n"
            "    ip = ipaddress.ip_address(socket.gethostbyname(host))\n"
            "    if ip.is_private or ip.is_loopback or ip.is_link_local:\n"
            "        raise ValueError('blocked')\n"
            "    return requests.get(url, timeout=5).text\n"
        ),
        "cwe": "CWE-918",
        "cve": None,
        "severity": "high",
        "root_cause": "The server fetches any URL supplied by the caller, including addresses inside the private network.",
        "attack_scenario": "An attacker submits `http://169.254.169.254/latest/meta-data/iam/security-credentials/` and reads IAM credentials.",
        "secure_fix": "Resolve the host and block private, loopback, and link-local addresses.",
    },
    {
        "id": "hsec-010",
        "language": "java",
        "vulnerable_code": (
            "@GetMapping(\"/user\")\n"
            "public String getUser(@RequestParam String id) {\n"
            "    return userRepo.findById(id).map(u -> u.getEmail()).orElse(\"n/a\");\n"
            "}\n"
        ),
        "fixed_code": (
            "@GetMapping(\"/user\")\n"
            "@PreAuthorize(\"#id == authentication.principal.id\")\n"
            "public String getUser(@RequestParam String id) {\n"
            "    return userRepo.findById(id).map(u -> u.getEmail()).orElse(\"n/a\");\n"
            "}\n"
        ),
        "cwe": "CWE-639",
        "cve": None,
        "severity": "high",
        "root_cause": "The endpoint returns data keyed by an attacker-controllable `id` with no authorization check.",
        "attack_scenario": "An attacker enumerates `/user?id=1..10000` and exfiltrates the email of every user.",
        "secure_fix": "Authorize the request against the resource owner; deny by default.",
    },
]


def main() -> int:
    out = Path("v2/inputs/datasets/eval/humansec.jsonl")
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as f:
        for s in SEEDS:
            f.write(json.dumps(s, ensure_ascii=False) + "\n")
    print(f"[hsec] wrote {len(SEEDS)} seed samples to {out}")
    print("[hsec] expand to 100 by following the same schema; see comments in the script.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
