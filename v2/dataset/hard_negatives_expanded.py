"""
RakshakAI v2 — Mass hard negative generation (25K+ samples).

Generates diverse secure code snippets that appear vulnerable at first glance.
These "hard negatives" train the model to distinguish between genuine
vulnerabilities and well-defended code.

Strategy: Template + combinatorial variation to produce mass quantity.
"""
import json
import random
import hashlib
import itertools
from pathlib import Path
from datetime import datetime, timezone
from collections import Counter

random.seed(42)

HARD_NEGATIVES_DIR = Path("inputs/datasets/nonvuln")
OUTPUT_FILE = HARD_NEGATIVES_DIR / "hard_negatives.jsonl"

# ---------------------------------------------------------------------------
# GENERATORS: each yields a list of unique hard negative code snippets
# ---------------------------------------------------------------------------

GENERATORS = []

def register(fn):
    GENERATORS.append(fn)
    return fn

FUNC_PREFIXES = ["safe", "secure", "validate", "process", "handle", "get", "fetch",
                  "load", "check", "verify", "compute", "build", "create", "sanitize",
                  "filter", "escape", "render", "convert", "parse", "format"]
FUNC_SUFFIXES = ["Data", "Input", "User", "Value", "Item", "Entry", "Request",
                  "Content", "Payload", "Param", "Arg", "Field", "Result", "Buffer",
                  "Record", "Resource", "Element", "Key", "Token", "Session"]
PARAM_NAMES = ["input", "data", "value", "content", "payload", "source", "target",
               "param", "arg", "item", "identifier", "key", "token", "user_input",
               "raw_data", "text", "body", "query", "path", "name"]

def rand_func(rng):
    return rng.choice(FUNC_PREFIXES) + "_" + rng.choice(FUNC_SUFFIXES).lower()

def rand_param(rng):
    return rng.choice(PARAM_NAMES)


# ─── SQL INJECTION LOOKALIKES ─────────────────────────────────────────

@register
def gen_sqli_hard_negatives(rng, count=15000):
    results = []
    for _ in range(count):
        func = rand_func(rng)
        param = rand_param(rng)
        tab = "    "
        variant = rng.randint(0, 3)

        if variant == 0:
            code = f"""import sqlite3

def {func}({param}: str) -> list:
    conn = sqlite3.connect("db.sqlite")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM records WHERE key = ?", ({param},))
    return cursor.fetchall()"""
        elif variant == 1:
            code = f"""import psycopg2

def {func}({param}: str):
    conn = psycopg2.connect(database="app")
    cur = conn.cursor()
    cur.execute("SELECT id, data FROM items WHERE owner = %s", ({param},))
    return cur.fetchone()"""
        elif variant == 2:
            code = f"""from django.db import connection

def {func}({param}):
    with connection.cursor() as cursor:
        cursor.execute("UPDATE users SET last_login = NOW() WHERE username = %s", [{param}])
    return True"""
        else:
            code = f"""import mysql.connector

def {func}({param}):
    conn = mysql.connector.connect(database="app")
    cursor = conn.cursor(prepared=True)
    cursor.execute("SELECT * FROM config WHERE name = %s", ({param},))
    return cursor.fetchone()"""

        results.append(("python", code.strip(), "CWE-89",
            "Parameterized query with placeholder (?, %s): the SQL structure is fixed at prepare time, and user input is bound as a data parameter. SQL injection is impossible through parameterized queries."))
    return results


@register
def gen_java_sqli_hard_negatives(rng, count=10000):
    results = []
    for _ in range(count):
        func = f"find{rng.choice(FUNC_SUFFIXES)}"
        param = rand_param(rng)
        variant = rng.randint(0, 2)
        if variant == 0:
            code = f"""public List<User> {func}(String {param}) {{
    String sql = "SELECT * FROM users WHERE email = ?";
    try (PreparedStatement stmt = connection.prepareStatement(sql)) {{
        stmt.setString(1, {param});
        ResultSet rs = stmt.executeQuery();
        List<User> users = new ArrayList<>();
        while (rs.next()) {{
            users.add(new User(rs.getInt("id"), rs.getString("name")));
        }}
        return users;
    }} catch (SQLException e) {{
        throw new RuntimeException(e);
    }}
}}"""
        elif variant == 1:
            code = f"""public boolean {func}(String {param}) {{
    String sql = "UPDATE accounts SET verified = true WHERE token = ?";
    try (PreparedStatement stmt = connection.prepareStatement(sql)) {{
        stmt.setString(1, {param});
        return stmt.executeUpdate() > 0;
    }} catch (SQLException e) {{
        return false;
    }}
}}"""
        else:
            code = f"""public int {func}(String {param}) {{
    String sql = "DELETE FROM sessions WHERE expiry < ?";
    try (PreparedStatement stmt = connection.prepareStatement(sql)) {{
        stmt.setString(1, {param});
        return stmt.executeUpdate();
    }} catch (SQLException e) {{
        return 0;
    }}
}}"""
        results.append(("java", code.strip(), "CWE-89",
            "Java PreparedStatement with ? placeholder: SQL is precompiled, user input is bound as a typed parameter. SQL injection is structurally impossible."))
    return results


@register
def gen_js_sqli_hard_negatives(rng, count=8000):
    results = []
    for _ in range(count):
        func = rand_func(rng)
        param = rand_param(rng)
        variant = rng.randint(0, 2)
        if variant == 0:
            code = f"""async function {func}({param}) {{
    const result = await db.query(
        'SELECT * FROM users WHERE email = $1',
        [{param}]
    );
    return result.rows;
}}"""
        elif variant == 1:
            code = f"""const {func} = async ({param}) => {{
    const {{ rows }} = await pool.query(
        'UPDATE inventory SET quantity = quantity - 1 WHERE id = $1 AND quantity > 0',
        [{param}]
    );
    return rows;
}}"""
        else:
            code = f"""async function {func}({param}) {{
    const {{ rows }} = await client.query(
        'SELECT id, name, email FROM employees WHERE department_id = $1',
        [{param}]
    );
    return rows;
}}"""
        results.append(("javascript", code.strip(), "CWE-89",
            "Parameterized PostgreSQL query with $1 placeholder: user input is bound as a data parameter, not interpolated into SQL."))
    return results


# ─── XSS LOOKALIKES ──────────────────────────────────────────────────

@register
def gen_xss_hard_negatives(rng, count=12000):
    results = []
    for _ in range(count):
        func = rand_func(rng)
        param = rand_param(rng)
        variant = rng.randint(0, 4)

        if variant == 0:
            code = f"""function {func}({param}) {{
    const clean = DOMPurify.sanitize({param});
    document.getElementById('output').innerHTML = clean;
}}"""
        elif variant == 1:
            code = f"""function {func}({param}) {{
    const el = document.createElement('div');
    el.textContent = {param};
    document.body.appendChild(el);
}}"""
        elif variant == 2:
            code = f"""import {{ sanitize }} from 'isomorphic-dompurify';

function {func}({param}) {{
    return <div dangerouslySetInnerHTML={{{{ __html: sanitize({param}) }}}} />;
}}"""
        elif variant == 3:
            code = f"""def {func}({param}):
    import html
    safe = html.escape({param})
    return f"<div>{{safe}}</div>"""
        else:
            code = f"""import org.owasp.encoder.Encode;

public String {func}(String {param}) {{
    return "<div class='msg'>" + Encode.forHtml({param}) + "</div>";
}}"""
        results.append((["python", "javascript", "java"][variant % 3] if variant < 3 else
                        (["python", "java"][variant - 3] if variant < 5 else "javascript"),
                        code.strip(), "CWE-79",
                        "Output is properly escaped/sanitized before rendering. DOMPurify, textContent, html.escape(), and Encode.forHtml() all prevent XSS."))
    return results


# ─── COMMAND INJECTION LOOKALIKES ────────────────────────────────────

@register
def gen_cmdi_hard_negatives(rng, count=10000):
    results = []
    for _ in range(count):
        func = rand_func(rng)
        param = rand_param(rng)
        variant = rng.randint(0, 3)

        if variant == 0:
            code = f"""import subprocess

def {func}({param}: str) -> str:
    result = subprocess.run(
        ["ping", "-c", "3", {param}],
        capture_output=True, text=True, check=True
    )
    return result.stdout"""
        elif variant == 1:
            code = f"""const {{ execFile }} = require('child_process');

async function {func}({param}) {{
    const {{ stdout }} = await execFile('ping', ['-c', '3', {param}]);
    return stdout;
}}"""
        elif variant == 2:
            code = f"""import subprocess

def {func}({param}):
    return subprocess.check_output(
        ["df", "-h", {param}],
        stderr=subprocess.STDOUT
    ).decode()"""
        else:
            code = f"""import subprocess

def {func}({param}):
    with subprocess.Popen(
        ["ls", "-la", {param}],
        stdout=subprocess.PIPE
    ) as proc:
        return proc.stdout.read().decode()"""

        lang = "python" if variant != 1 else "javascript"
        results.append((lang, code.strip(), "CWE-78",
            "Uses argument list form of process execution, not a shell string. No shell is spawned, so shell metacharacters are inert."))
    return results


# ─── PATH TRAVERSAL LOOKALIKES ──────────────────────────────────────

@register
def gen_path_hard_negatives(rng, count=8000):
    results = []
    for _ in range(count):
        func = rand_func(rng)
        param = rand_param(rng)
        base = rng.choice(["/var/data", "/app/uploads", "/home/user/files", "/opt/storage"])
        variant = rng.randint(0, 2)

        if variant == 0:
            code = f"""import os

def {func}({param}):
    base = "{base}"
    path = os.path.realpath(os.path.join(base, {param}))
    if not path.startswith(os.path.realpath(base)):
        raise ValueError("Invalid path")
    with open(path) as f:
        return f.read()"""
        elif variant == 1:
            code = f"""import os

def {func}({param}):
    safe_dir = os.path.realpath("{base}")
    requested = os.path.realpath(os.path.join(safe_dir, {param}))
    if not requested.startswith(safe_dir):
        return None, "Access denied"
    return open(requested, "rb").read(), None"""
        else:
            code = f"""import os

def {func}({param}):
    upload_dir = "{base}"
    clean_name = os.path.basename({param})
    return os.path.join(upload_dir, clean_name)"""

        results.append(("python", code.strip(), "CWE-22",
            "Real path resolution with prefix check prevents path traversal. os.path.realpath eliminates '..' components before the security check."))
    return results


# ─── DESERIALIZATION LOOKALIKES ─────────────────────────────────────

@register
def gen_deser_hard_negatives(rng, count=6000):
    results = []
    for _ in range(count):
        func = rand_func(rng)
        param = rand_param(rng)
        variant = rng.randint(0, 2)

        if variant == 0:
            code = f"""import json

def {func}({param}: str) -> dict:
    return json.loads({param})"""
        elif variant == 1:
            code = f"""import yaml

def {func}({param}):
    return yaml.safe_load({param})"""
        else:
            code = f"""import json
import hmac
import hashlib

SECRET = b"your-secret-key"

def {func}({param}):
    payload, sig = {param}.rsplit(".", 1)
    expected = hmac.new(SECRET, payload.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected):
        raise ValueError("Invalid signature")
    return json.loads(payload)"""

        results.append(("python", code.strip(), "CWE-502",
            "Uses safe deserialization: JSON is not executable, yaml.safe_load blocks dangerous YAML tags, and HMAC verification ensures integrity before parsing."))
    return results


# ─── CRYPTO LOOKALIKES ──────────────────────────────────────────────

@register
def gen_crypto_hard_negatives(rng, count=6000):
    results = []
    for _ in range(count):
        func = rand_func(rng)
        param = rand_param(rng)
        variant = rng.randint(0, 2)

        if variant == 0:
            code = f"""import hashlib

def {func}({param}: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac("sha256", {param}.encode(), salt.encode(), 600000).hex()"""
        elif variant == 1:
            code = f"""import bcrypt

def {func}({param}: str) -> str:
    return bcrypt.hashpw({param}.encode(), bcrypt.gensalt(12)).decode()"""
        else:
            code = f"""from cryptography.fernet import Fernet

def {func}({param}: bytes) -> bytes:
    key = Fernet.generate_key()
    cipher = Fernet(key)
    return cipher.encrypt({param})"""
        results.append(("python", code.strip(), "CWE-327",
            "Uses strong cryptographic primitives: PBKDF2-HMAC-SHA256 (600K iterations), bcrypt (cost 12), or Fernet (AES-128-CBC + HMAC)."))
    return results


# ─── BUFFER OVERFLOW LOOKALIKES (C) ─────────────────────────────────

@register
def gen_bo_hard_negatives(rng, count=8000):
    results = []
    for _ in range(count):
        func = f"{rng.choice(FUNC_PREFIXES)}_{rng.choice(FUNC_SUFFIXES).lower()}"
        buf_size = rng.choice([32, 64, 128, 256, 512])
        variant = rng.randint(0, 2)

        if variant == 0:
            code = f"""#include <string.h>
#include <stdio.h>

void {func}(const char* input) {{
    char buf[{buf_size}];
    strncpy(buf, input, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\\0';
    printf("Result: %s\\n", buf);
}}"""
        elif variant == 1:
            code = f"""#include <stdio.h>

void {func}(const char* input) {{
    char buf[{buf_size}];
    snprintf(buf, sizeof(buf), "%s", input);
    puts(buf);
}}"""
        else:
            code = f"""#include <string.h>

void {func}(const char* src) {{
    char dest[{buf_size}];
    size_t len = strnlen(src, sizeof(dest) - 1);
    memcpy(dest, src, len);
    dest[len] = '\\0';
}}"""

        results.append(("c", code.strip(), "CWE-119",
            "Uses bounded operations (strncpy, snprintf, memcpy with size limit). The buffer size parameter prevents writes beyond the allocated capacity."))
    return results


# ─── SSRF LOOKALIKES ────────────────────────────────────────────────

@register
def gen_ssrf_hard_negatives(rng, count=6000):
    results = []
    for _ in range(count):
        func = rand_func(rng)
        param = rand_param(rng)
        variant = rng.randint(0, 2)

        if variant == 0:
            code = f"""import requests
from urllib.parse import urlparse

ALLOWED_HOSTS = {{"api.example.com", "cdn.trusted.org"}}

def {func}({param}):
    parsed = urlparse({param})
    if parsed.hostname not in ALLOWED_HOSTS:
        raise ValueError(f"Host {{parsed.hostname}} not allowed")
    return requests.get({param}, timeout=10)"""
        elif variant == 1:
            code = f"""import requests

def {func}(endpoint: str):
    if not endpoint.startswith("https://api.example.com/"):
        raise ValueError("Invalid endpoint")
    return requests.get(endpoint, timeout=5)"""
        else:
            code = f"""import aiohttp

ALLOWED = ["https://api.trusted.com", "https://cdn.trusted.com"]

async def {func}({param}):
    if not any({param}.startswith(url) for url in ALLOWED):
        raise ValueError("URL not allowed")
    async with aiohttp.ClientSession() as session:
        async with session.get({param}) as resp:
            return await resp.text()"""

        results.append(("python", code.strip(), "CWE-918",
            "Allowlist-based URL validation prevents SSRF. Only explicitly permitted hosts/URLs can be accessed."))
    return results


# ─── AUTH BYPASS LOOKALIKES ─────────────────────────────────────────

@register
def gen_auth_hard_negatives(rng, count=6000):
    results = []
    for _ in range(count):
        func = rand_func(rng)
        variant = rng.randint(0, 2)

        if variant == 0:
            code = f"""from flask import session, redirect, abort

@app.route('/{func}')
def {func}():
    if 'user_id' not in session:
        return redirect('/login')
    user = get_user(session['user_id'])
    if not user.is_admin:
        abort(403)
    return render_template('admin.html')"""
        elif variant == 1:
            code = f"""import jwt
from functools import wraps

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
            request.user = payload
        except jwt.InvalidTokenError:
            return {{'error': 'Unauthorized'}}, 401
        return f(*args, **kwargs)
    return decorated

@app.route('/{func}')
@require_auth
def {func}():
    return {{'data': 'sensitive'}}"""
        else:
            code = f"""from django.contrib.auth.decorators import login_required, user_passes_test

@login_required
@user_passes_test(lambda u: u.is_staff)
def {func}(request):
    return render(request, 'admin/panel.html')"""

        results.append(("python", code.strip(), "CWE-284",
            "Authentication and authorization checks are in place: session validation, JWT token verification, or Django's @login_required decorator."))
    return results


# ─── CSRF LOOKALIKES ───────────────────────────────────────────────

@register
def gen_csrf_hard_negatives(rng, count=4000):
    results = []
    for _ in range(count):
        func = rand_func(rng)
        variant = rng.randint(0, 1)

        if variant == 0:
            code = f"""from flask_wtf.csrf import CSRFProtect

csrf = CSRFProtect(app)

@app.route('/{func}', methods=['POST'])
@csrf.exempt
def {func}():
    # CSRF exempt only for webhooks with signature verification
    if not verify_signature(request):
        abort(401)
    return process(request.json)"""
        else:
            code = f"""import {{ CsrfProtection }} from '@core/security';

app.post('/{func}', csrfProtection, async (req, res) => {{
    const result = await processPayment(req.body);
    res.json({{ status: 'ok', id: result.id }});
}});"""

        results.append((["python", "javascript"][variant], code.strip(), "CWE-352",
            "CSRF protection is enabled via middleware or route-level protection. State-changing operations require valid CSRF tokens."))
    return results


# ─── PROTOTYPE POLLUTION LOOKALIKES ─────────────────────────────────

@register
def gen_proto_hard_negatives(rng, count=4000):
    results = []
    for _ in range(count):
        func = rand_func(rng)
        variant = rng.randint(0, 1)

        if variant == 0:
            code = f"""function {func}(target, source) {{
    for (const key of Object.keys(source)) {{
        if (key === '__proto__' || key === 'constructor') continue;
        if (typeof source[key] === 'object' && source[key] !== null) {{
            target[key] = {func}(target[key] || {{}}, source[key]);
        }} else {{
            target[key] = source[key];
        }}
    }}
    return target;
}}"""
        else:
            code = f"""const {func} = (obj) => {{
    const safe = Object.create(null);
    for (const [key, value] of Object.entries(obj)) {{
        if (!['__proto__', 'constructor', 'prototype'].includes(key)) {{
            safe[key] = value;
        }}
    }}
    return safe;
}}"""

        results.append(("javascript", code.strip(), "CWE-1321",
            "Explicitly filters __proto__ and constructor keys during object operations, preventing prototype pollution attacks."))
    return results


# ─── NOSQL INJECTION LOOKALIKES ─────────────────────────────────────

@register
def gen_nosql_hard_negatives(rng, count=4000):
    results = []
    for _ in range(count):
        func = rand_func(rng)
        param = rand_param(rng)
        variant = rng.randint(0, 2)

        if variant == 0:
            code = f"""async function {func}({param}) {{
    const user = await db.collection('users').findOne({{ _id: new ObjectId({param}) }});
    return user;
}}"""
        elif variant == 1:
            code = f"""def {func}({param}):
    return collection.find_one({{"_id": ObjectId({param})}})"""
        else:
            code = f"""async function {func}({param}) {{
    const session = await db.collection('sessions').findOne(
        {{ token: {param}, expires: {{ $gt: new Date() }} }}
    );
    return session;
}}"""

        results.append((["javascript", "python", "javascript"][variant], code.strip(), "CWE-943",
            "Uses typed ObjectId queries, not raw user objects. The query structure is fixed; user input is bound as a typed parameter."))
    return results


# ─── WEAK RANDOMNESS LOOKALIKES ─────────────────────────────────────

@register
def gen_random_hard_negatives(rng, count=4000):
    results = []
    for _ in range(count):
        func = rand_func(rng)
        variant = rng.randint(0, 2)

        if variant == 0:
            code = f"""import secrets

def {func}(length: int = 32) -> str:
    return secrets.token_hex(length)"""
        elif variant == 1:
            code = f"""import secrets
import string

def {func}(length: int = 16) -> str:
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))"""
        else:
            code = f"""const crypto = require('crypto');

function {func}(length = 32) {{
    return crypto.randomBytes(length).toString('hex');
}}"""

        results.append((["python", "python", "javascript"][variant], code.strip(), "CWE-338",
            "Uses cryptographically secure random number generators: secrets module (Python) or crypto.randomBytes (Node.js)."))
    return results


# ─── PHP HARD NEGATIVES ────────────────────────────────────────────

@register
def gen_php_hard_negatives(rng, count=6000):
    results = []
    for _ in range(count):
        func = rand_func(rng)
        param = rand_param(rng)
        variant = rng.randint(0, 2)

        if variant == 0:
            code = f"""function {func}(string ${param}): ?array {{
    global $conn;
    $stmt = $conn->prepare("SELECT * FROM users WHERE email = ?");
    $stmt->bind_param("s", ${param});
    $stmt->execute();
    $result = $stmt->get_result();
    return $result->fetch_assoc();
}}"""
        elif variant == 1:
            code = f"""function {func}(string ${param}): string {{
    return htmlspecialchars(${param}, ENT_QUOTES | ENT_HTML5, 'UTF-8');
}}"""
        else:
            code = f"""function {func}(string ${param}): string {{
    return password_hash(${param}, PASSWORD_BCRYPT, ['cost' => 12]);
}}"""

        cwe_map = ["CWE-89", "CWE-79", "CWE-327"]
        expl_map = [
            "MySQLi prepared statement with bind_param separates SQL code from data. SQL injection is structurally impossible.",
            "htmlspecialchars with ENT_QUOTES converts all HTML-special characters to entities, preventing XSS.",
            "password_hash with BCRYPT and cost=12 provides strong, salted password hashing resistant to brute force.",
        ]
        results.append(("php", code.strip(), cwe_map[variant], expl_map[variant]))
    return results


# ─── GO HARD NEGATIVES ─────────────────────────────────────────────

@register
def gen_go_hard_negatives(rng, count=6000):
    results = []
    for _ in range(count):
        func = f"{rng.choice(FUNC_PREFIXES)}{rng.choice(FUNC_SUFFIXES)}"
        param = rand_param(rng)
        variant = rng.randint(0, 2)

        if variant == 0:
            code = f"""func {func}(db *sql.DB, {param} string) (*User, error) {{
    row := db.QueryRow("SELECT id, name FROM users WHERE email = $1", {param})
    user := &User{{}}
    err := row.Scan(&user.ID, &user.Name)
    return user, err
}}"""
        elif variant == 1:
            code = f"""func {func}({param} string) (string, error) {{
    cmd := exec.Command("ping", "-c", "1", {param})
    out, err := cmd.Output()
    return string(out), err
}}"""
        else:
            code = f"""func {func}({param} string) string {{
    var buf bytes.Buffer
    enc := json.NewEncoder(&buf)
    enc.SetEscapeHTML(true)
    enc.Encode(map[string]string{{"data": {param}}})
    return buf.String()
}}"""

        cwe_map = ["CWE-89", "CWE-78", "CWE-79"]
        expl_map = [
            "Go's database/sql with $1 placeholder: parameterized query prevents SQL injection.",
            "exec.Command uses argument list form, not shell string. No shell metacharacters are interpreted.",
            "json.Encode with SetEscapeHTML(true) escapes HTML-special characters in JSON output, preventing XSS.",
        ]
        results.append(("go", code.strip(), cwe_map[variant], expl_map[variant]))
    return results


# ─── CSHARP HARD NEGATIVES ─────────────────────────────────────────

@register
def gen_csharp_hard_negatives(rng, count=4000):
    results = []
    for _ in range(count):
        func = rng.choice(FUNC_PREFIXES) + rng.choice(FUNC_SUFFIXES)
        param = rand_param(rng)

        code = f"""public List<User> {func}(string {param}) {{
    using var conn = new SqlConnection(_connectionString);
    using var cmd = new SqlCommand("SELECT * FROM users WHERE email = @email", conn);
    cmd.Parameters.AddWithValue("@email", {param});
    conn.Open();
    using var reader = cmd.ExecuteReader();
    var users = new List<User>();
    while (reader.Read()) {{
        users.Add(new User {{ Id = reader.GetInt32(0), Name = reader.GetString(1) }});
    }}
    return users;
}}"""
        results.append(("csharp", code.strip(), "CWE-89",
            "ADO.NET SqlCommand with @email named parameter: SQL is parameterized, user input is bound as a typed parameter."))
    return results


# ─── RUBY HARD NEGATIVES ──────────────────────────────────────────

@register
def gen_ruby_hard_negatives(rng, count=4000):
    results = []
    for _ in range(count):
        func = rand_func(rng)
        param = rand_param(rng)

        code = f"""def {func}({param})
    User.where("email = ?", {param})
end"""
        results.append(("ruby", code.strip(), "CWE-89",
            "ActiveRecord's parameterized query with ? placeholder: Rails handles escaping automatically, preventing SQL injection."))
    return results


# ─── RUST HARD NEGATIVES ──────────────────────────────────────────

@register
def gen_rust_hard_negatives(rng, count=4000):
    results = []
    for _ in range(count):
        func = rand_func(rng)
        param = rand_param(rng)
        variant = rng.randint(0, 1)

        if variant == 0:
            code = f"""async fn {func}(pool: &PgPool, {param}: &str) -> Result<User, sqlx::Error> {{
    sqlx::query_as::<_, User>("SELECT id, name FROM users WHERE email = $1")
        .bind({param})
        .fetch_one(pool)
        .await
}}"""
        else:
            code = f"""fn {func}({param}: &str) -> String {{
    let hash = sha2::Sha256::digest({param}.as_bytes());
    hex::encode(hash)
}}"""
        cwe_map = ["CWE-89", "CWE-327"]
        expl_map = [
            "sqlx parameterized query with $1 placeholder and typed bind: SQL injection is prevented at the API level, with compile-time type checking.",
            "Uses SHA-256 (strong hash) via the sha2 crate, not MD5 or SHA-1. Suitable for non-password integrity checks.",
        ]
        results.append(("rust", code.strip(), cwe_map[variant], expl_map[variant]))
    return results


# ─── SWIFT HARD NEGATIVES ─────────────────────────────────────────

@register
def gen_swift_hard_negatives(rng, count=4000):
    results = []
    for _ in range(count):
        func = rand_func(rng)
        param = rand_param(rng)

        code = f"""func {func}(db: Database, {param}: String) async throws -> User? {{
    let rows = try await db.sql("SELECT id, name FROM users WHERE email = $1")
        .bind({param})
        .fetch()
    return rows.first.map(User.init)
}}"""
        results.append(("swift", code.strip(), "CWE-89",
            "Swift's PostgresNIO with $1 placeholder and typed bind: SQL is parameterized, preventing injection."))
    return results


# ─── KOTLIN HARD NEGATIVES ────────────────────────────────────────

@register
def gen_kotlin_hard_negatives(rng, count=4000):
    results = []
    for _ in range(count):
        func = rand_func(rng)
        param = rand_param(rng)

        code = f"""fun {func}({param}: String): User? {{
    val sql = "SELECT * FROM users WHERE email = ?"
    return jdbcTemplate.query(sql, arrayOf({param})) {{ rs, _ ->
        User(rs.getInt("id"), rs.getString("name"))
    }}.firstOrNull()
}}"""
        results.append(("kotlin", code.strip(), "CWE-89",
            "Spring's JdbcTemplate with ? placeholder: user input is bound as a parameter, preventing SQL injection."))
    return results


# ─── XXE LOOKALIKES ──────────────────────────────────────────────

@register
def gen_xxe_hard_negatives(rng, count=4000):
    results = []
    for _ in range(count):
        func = rand_func(rng)
        param = rand_param(rng)
        variant = rng.randint(0, 1)

        if variant == 0:
            code = f"""from defusedxml import ElementTree

def {func}({param}):
    tree = ElementTree.fromstring({param})
    return tree.findtext('.//data')"""
        else:
            code = f"""import lxml.etree as ET

def {func}({param}):
    parser = ET.XMLParser(resolve_entities=False, no_network=True, dtd_validation=False)
    tree = ET.fromstring({param}, parser)
    return tree.xpath('//data/text()')"""
        results.append(("python", code.strip(), "CWE-611",
            "Uses defusedxml or lxml with disabled entity resolution and network access, preventing XXE attacks."))
    return results


# ─── RACE CONDITION LOOKALIKES ────────────────────────────────────

@register
def gen_race_hard_negatives(rng, count=4000):
    results = []
    for _ in range(count):
        func = rand_func(rng)
        variant = rng.randint(0, 2)

        if variant == 0:
            code = f"""import threading

class {rng.choice(FUNC_SUFFIXES)}Counter:
    def __init__(self):
        self._lock = threading.Lock()
        self._count = 0
    
    def increment(self):
        with self._lock:
            self._count += 1
            return self._count"""
        elif variant == 1:
            code = f"""import asyncio

_lock = asyncio.Lock()

async def {func}(resource_id: str):
    async with _lock:
        resource = await load_resource(resource_id)
        resource.processed = True
        await save_resource(resource)"""
        else:
            code = f"""import fcntl

def {func}(fileobj):
    fcntl.flock(fileobj, fcntl.LOCK_EX)
    try:
        data = fileobj.read()
        fileobj.seek(0)
        fileobj.write(data.upper())
        fileobj.truncate()
    finally:
        fcntl.flock(fileobj, fcntl.LOCK_UN)"""
        results.append(("python", code.strip(), "CWE-362",
            "Proper synchronization via threading.Lock, asyncio.Lock, or fcntl.flock. Shared state access is atomic and race-condition-free."))
    return results


# ─── SSTI LOOKALIKES ─────────────────────────────────────────────

@register
def gen_ssti_hard_negatives(rng, count=4000):
    results = []
    for _ in range(count):
        func = rand_func(rng)
        param = rand_param(rng)

        code = f"""from jinja2 import Environment, FileSystemLoader

env = Environment(loader=FileSystemLoader("templates"))

def {func}({param}):
    tpl = env.get_template("user_profile.html")
    return tpl.render(name={param})"""
        results.append(("python", code.strip(), "CWE-94",
            "Uses file-based Jinja2 template loading, not render_template_string. Template content is controlled by the developer, not user input."))
    return results


# ─── IDOR LOOKALIKES ─────────────────────────────────────────────

@register
def gen_idor_hard_negatives(rng, count=4000):
    results = []
    for _ in range(count):
        func = rand_func(rng)

        code = f"""from django.shortcuts import get_object_or_404
from django.core.exceptions import PermissionDenied

def {func}(request, pk):
    obj = get_object_or_404(MyModel, pk=pk)
    if obj.user != request.user:
        raise PermissionDenied
    return render(request, "detail.html", {{"object": obj}})"""
        results.append(("python", code.strip(), "CWE-639",
            "Ownership verification: the view checks that the requested resource belongs to the authenticated user before returning it."))
    return results


# ─── LOG INJECTION LOOKALIKES ─────────────────────────────────────

@register
def gen_log_hard_negatives(rng, count=4000):
    results = []
    for _ in range(count):
        func = rand_func(rng)
        param = rand_param(rng)

        code = f"""import logging

logger = logging.getLogger(__name__)

def {func}({param}):
    logger.info("User action: %%s", {param})
    return process({param})"""
        results.append(("python", code.strip(), "CWE-117",
            "Parameterized logging with %%s format specifier: user input is passed as a data parameter, not interpolated into the format string. Prevents log injection."))
    return results


# ---------------------------------------------------------------------------
# GENERATION ENGINE
# ---------------------------------------------------------------------------

def generate_all_hard_negatives(target=25000) -> list[dict]:
    rng = random.Random(2024)
    all_samples = []
    lang_counts = Counter()
    cwe_counts = Counter()

    for gen in GENERATORS:
        try:
            results = gen(rng)
            for lang, code, cwe_lookalike, explanation in results:
                sample_id = hashlib.sha1(code.encode()).hexdigest()[:12]
                fp = hashlib.sha1(code.strip().encode()).hexdigest()
                sample = {
                    "id": sample_id,
                    "language": lang,
                    "vulnerable_code": code,
                    "patched_code": None,
                    "cwe": "CWE-CLEAN",
                    "severity": "clean",
                    "explanation": explanation,
                    "attack_scenario": f"This code appears vulnerable to {cwe_lookalike} at first glance due to the presence of security-sensitive APIs, but it actually uses proper security controls that prevent the attack.",
                    "secure_fix": "No fix needed — the code is already secure. The security-sensitive APIs are used correctly with proper controls in place.",
                    "source": "hard_negative_v4",
                    "source_license": "MIT",
                    "is_vulnerable": False,
                    "split": "train",
                    "fingerprint": fp,
                    "added_at": datetime.now(timezone.utc).isoformat(),
                    "references": [],
                }
                all_samples.append(sample)
                lang_counts[lang] += 1
                cwe_counts[cwe_lookalike] += 1
        except Exception as e:
            print(f"[warn] Generator {gen.__name__} failed: {e}")
            continue

    rng.shuffle(all_samples)
    actual = min(len(all_samples), target)
    all_samples = all_samples[:actual]

    print(f"Generated {len(all_samples)} hard negatives")
    print(f"\nLanguage distribution:")
    for lang, cnt in sorted(lang_counts.items(), key=lambda x: -x[1]):
        print(f"  {lang}: {cnt}")
    print(f"\nCWE lookalike distribution:")
    for cwe, cnt in sorted(cwe_counts.most_common(10)):
        print(f"  {cwe}: {cnt}")

    return all_samples


def main():
    target = 150000
    samples = generate_all_hard_negatives(target=target)

    HARD_NEGATIVES_DIR.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_FILE, "w") as f:
        for s in samples:
            f.write(json.dumps(s, ensure_ascii=False) + "\n")

    print(f"\nSaved {len(samples)} hard negatives to {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
