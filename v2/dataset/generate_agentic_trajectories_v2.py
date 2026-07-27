"""Generate 10K+ realistic agentic security trajectories for CyberGym-style training.
Uses a parameterized framework to create diverse multi-step reasoning chains."""
import json, hashlib, random
from pathlib import Path
from collections import Counter

rng = random.Random(42)
OUT = Path("inputs/datasets/extra_vuln")
OUT.mkdir(parents=True, exist_ok=True)

# ── VULNERABLE CODE TEMPLATES (with {n} placeholder) ──
VULN_TEMPLATES = [
    # SQLi
    ("python", "CWE-89",
     "def get_user_{n}(user_id):\n    query = \"SELECT * FROM users WHERE id = '\" + user_id + \"'\"\n    return db.execute(query)",
     "def get_user_{n}(user_id):\n    query = \"SELECT * FROM users WHERE id = %s\"\n    return db.execute(query, (user_id,))"),
    ("java", "CWE-89",
     "public User getUser_{n}(String id) {\n  return jdbcTemplate.query(\"SELECT * FROM users WHERE id = \" + id, new UserRowMapper());\n}",
     "public User getUser_{n}(String id) {\n  return jdbcTemplate.query(\"SELECT * FROM users WHERE id = ?\", new Object[]{id}, new UserRowMapper());\n}"),
    ("javascript", "CWE-89",
     "function getUser_{n}(id) {\n  const query = `SELECT * FROM users WHERE id = ${id}`;\n  return db.execute(query);\n}",
     "function getUser_{n}(id) {\n  const query = \"SELECT * FROM users WHERE id = ?\";\n  return db.execute(query, [id]);\n}"),
    # XSS
    ("javascript", "CWE-79",
     "function render_{n}(req, res) {\n  const name = req.query.name;\n  res.send(`<h1>Hello ${name}</h1>`);\n}",
     "function render_{n}(req, res) {\n  const escape = require(\"escape-html\");\n  const name = escape(req.query.name);\n  res.send(`<h1>Hello ${name}</h1>`);\n}"),
    ("python", "CWE-79",
     "def render_{n}(request):\n    name = request.GET.get(\"name\", \"\")\n    return HttpResponse(f\"<h1>Hello {name}</h1>\")",
     "def render_{n}(request):\n    from django.utils.html import escape\n    name = escape(request.GET.get(\"name\", \"\"))\n    return HttpResponse(f\"<h1>Hello {name}</h1>\")"),
    # CMDI
    ("python", "CWE-78",
     "def ping_{n}(hostname):\n    return os.system(\"ping -c 4 \" + hostname)",
     "def ping_{n}(hostname):\n    import subprocess\n    return subprocess.run([\"ping\", \"-c\", \"4\", hostname], capture_output=True)"),
    ("go", "CWE-78",
     "func Ping_{n}(host string) {\n  cmd := exec.Command(\"ping\", \"-c\", \"4\", host)\n  out, _ := cmd.Output()\n  fmt.Println(string(out))\n}",
     "func Ping_{n}(host string) {\n  if strings.ContainsAny(host, \";|&$`\\\\\") { log.Fatal(\"Invalid host\") }\n  cmd := exec.Command(\"ping\", \"-c\", \"4\", host)\n  out, _ := cmd.Output()\n  fmt.Println(string(out))\n}"),
    ("php", "CWE-78",
     "function ping_{n}($host) {\n  $output = shell_exec(\"ping -c 4 \" . $host);\n  echo $output;\n}",
     "function ping_{n}($host) {\n  $sanitized = escapeshellcmd($host);\n  $output = shell_exec(\"ping -c 4 \" . $sanitized);\n  echo $output;\n}"),
    # Path Traversal
    ("python", "CWE-22",
     "def read_file_{n}(filename):\n    path = \"/var/data/\" + filename\n    return open(path).read()",
     "def read_file_{n}(filename):\n    import os\n    safe = os.path.realpath(\"/var/data/\" + filename)\n    if not safe.startswith(\"/var/data/\"):\n        raise ValueError(\"Invalid path\")\n    return open(safe).read()"),
    ("java", "CWE-22",
     "public String readFile_{n}(String filename) throws Exception {\n  return new String(Files.readAllBytes(Paths.get(\"/var/data/\" + filename)));\n}",
     "public String readFile_{n}(String filename) throws Exception {\n  Path path = Paths.get(\"/var/data/\", filename).normalize();\n  if (!path.startsWith(\"/var/data/\")) throw new SecurityException();\n  return new String(Files.readAllBytes(path));\n}"),
    # SSRF
    ("python", "CWE-918",
     "def fetch_url_{n}(url):\n    import requests\n    return requests.get(url).text",
     "def fetch_url_{n}(url):\n    from urllib.parse import urlparse\n    parsed = urlparse(url)\n    if parsed.hostname in (\"localhost\", \"127.0.0.1\"):\n        raise ValueError(\"Blocked\")\n    import requests\n    return requests.get(url, timeout=10).text"),
    ("go", "CWE-918",
     "func FetchURL_{n}(url string) (string, error) {\n  resp, err := http.Get(url)\n  if err != nil { return \"\", err }\n  defer resp.Body.Close()\n  body, _ := io.ReadAll(resp.Body)\n  return string(body), nil\n}",
     "func FetchURL_{n}(url string) (string, error) {\n  u, _ := url.Parse(url)\n  if u.Hostname() == \"localhost\" || u.Hostname() == \"127.0.0.1\" {\n    return \"\", fmt.Errorf(\"blocked\")\n  }\n  resp, err := http.Get(url)\n  if err != nil { return \"\", err }\n  defer resp.Body.Close()\n  body, _ := io.ReadAll(resp.Body)\n  return string(body), nil\n}"),
    # Deserialization
    ("python", "CWE-502",
     "def load_data_{n}(data):\n    import pickle\n    return pickle.loads(data)",
     "def load_data_{n}(data):\n    import json\n    return json.loads(data)"),
    ("java", "CWE-502",
     "public Object deserialize_{n}(byte[] data) throws Exception {\n  ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));\n  return ois.readObject();\n}",
     "public Object deserialize_{n}(byte[] data) throws Exception {\n  String json = new String(data, \"UTF-8\");\n  return new JSONObject(json);\n}"),
    # XXE
    ("java", "CWE-611",
     "public Document parseXML_{n}(String xml) throws Exception {\n  DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();\n  DocumentBuilder builder = factory.newDocumentBuilder();\n  return builder.parse(new InputSource(new StringReader(xml)));\n}",
     "public Document parseXML_{n}(String xml) throws Exception {\n  DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();\n  factory.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true);\n  DocumentBuilder builder = factory.newDocumentBuilder();\n  return builder.parse(new InputSource(new StringReader(xml)));\n}"),
    # Prototype Pollution
    ("javascript", "CWE-1321",
     "function merge_{n}(target, source) {\n  for (const key in source) {\n    target[key] = source[key];\n  }\n  return target;\n}",
     "function merge_{n}(target, source) {\n  for (const key in source) {\n    if (key === \"__proto__\" || key === \"constructor\") continue;\n    target[key] = source[key];\n  }\n  return target;\n}"),
    # NoSQLi
    ("python", "CWE-943",
     "def login_{n}(username, password):\n    return list(db.users.find({'$where': 'this.username == \\\"' + username + '\\\"'}))",
     "def login_{n}(username, password):\n    return list(db.users.find({\"username\": username, \"password\": password}))"),
    # Race Condition
    ("python", "CWE-362",
     "def withdraw_{n}(account_id, amount):\n    balance = db.get_balance(account_id)\n    if balance >= amount:\n        db.set_balance(account_id, balance - amount)\n        return True\n    return False",
     "def withdraw_{n}(account_id, amount):\n    with db.transaction():\n        balance = db.get_balance(account_id)\n        if balance >= amount:\n            db.set_balance(account_id, balance - amount)\n            return True\n    return False"),
    # IDOR
    ("python", "CWE-639",
     "def get_invoice_{n}(invoice_id):\n    return jsonify(db.query(\"SELECT * FROM invoices WHERE id = ?\", invoice_id))",
     "def get_invoice_{n}(invoice_id, user_id):\n    return jsonify(db.query(\"SELECT * FROM invoices WHERE id = ? AND user_id = ?\", invoice_id, user_id))"),
    # Hardcoded Creds
    ("python", "CWE-798",
     "def connect_{n}():\n    return mysql.connector.connect(user=\"admin\", password=\"password123!\", host=\"localhost\", database=\"prod\")",
     "def connect_{n}():\n    import os\n    return mysql.connector.connect(user=os.environ[\"DB_USER\"], password=os.environ[\"DB_PASSWORD\"], host=os.environ[\"DB_HOST\"], database=os.environ[\"DB_NAME\"])"),
]

# ── AGENTIC PHASES ──
PHASES = [
    "reconnaissance",
    "vulnerability_discovery",
    "exploitation_primitive",
    "exploit_development",
    "post_exploitation",
]

PHASE_ACTIONS = {
    "reconnaissance": [
        "Scan application entry points and user input vectors",
        "Map API endpoints and parameter injection points",
        "Review authentication and authorization mechanisms",
        "Analyze third-party dependencies for known vulnerabilities",
        "Enumerate file upload functionality and storage locations",
        "Identify database query patterns in the codebase",
        "Trace data flow from user input to sensitive operations",
        "Review error handling for information disclosure",
    ],
    "vulnerability_discovery": [
        "Test input validation by sending crafted payloads to each endpoint",
        "Analyze string concatenation in query building functions",
        "Review file path construction for traversal patterns",
        "Check for unsafe deserialization of user-controlled data",
        "Verify XML parser configuration for external entity processing",
        "Test for command injection in system call wrappers",
        "Audit template rendering for unescaped user content",
        "Check merge/assign functions for prototype pollution",
    ],
    "exploitation_primitive": [
        "Confirm the vulnerability is reachable without authentication",
        "Determine the minimum payload needed to trigger the bug",
        "Verify the vulnerability allows data exfiltration or code execution",
        "Test payload encoding variations to bypass WAF filters",
        "Establish the exploitation primitive reliability",
        "Document the preconditions and constraints for exploitation",
    ],
    "exploit_development": [
        "Craft a minimal proof-of-concept that demonstrates the vulnerability",
        "Develop a full exploit that achieves the desired impact",
        "Add payload encoding and evasion techniques",
        "Implement retry logic and error handling in the exploit",
        "Test the exploit against the target environment",
        "Optimize exploit reliability and speed",
    ],
    "post_exploitation": [
        "Establish persistent access to the compromised system",
        "Escalate privileges to highest available level",
        "Dump password hashes and sensitive configuration files",
        "Pivot to internal network services and adjacent systems",
        "Exfiltrate targeted data through encrypted channels",
        "Cover tracks by clearing logs and removing artifacts",
    ],
}

PHASE_OBSERVATIONS = {
    "reconnaissance": [
        "Found 12 input parameters across 5 endpoints, 3 appear injectable",
        "Identified 2 authentication bypass opportunities in session handling",
        "Discovered 4 third-party libraries with known CVEs in dependency tree",
        "Mapped 6 file upload endpoints with insufficient validation",
        "Found 22 database queries, 8 use string concatenation for parameters",
        "Traced 3 data flows from HTTP request to file system operations",
    ],
    "vulnerability_discovery": [
        "Confirmed injectable parameter with time-based payload: {payload}",
        "String concatenation in SQL query builder at line {line}: `'SELECT * FROM users WHERE id = ' + param`",
        "Path traversal allows reading arbitrary files: ../etc/passwd returned {status}",
        "pickle.loads() called on user-controlled data without validation",
        "XML parser has external entities enabled: file:///etc/passwd resolves",
        "os.system() called with user input: ping -c 4 {payload}",
        "Template engine auto-escapes disabled, user content rendered raw",
        "Recursive merge function copies prototype properties: Object.prototype.{key} set",
    ],
    "exploitation_primitive": [
        "Vulnerability reachable without authentication - CVSS increased to {cvss}",
        "Minimum payload: `{min_payload}` - obfuscation not needed",
        "Confirmed at least {exfil_bytes} bytes of arbitrary data can be exfiltrated",
        "WAF bypass achieved with Unicode encoding: {encoding}",
        "Exploitation primitive reliable across {test_count} consecutive attempts",
        "Precondition: target must have {precondition} enabled/exposed",
    ],
    "exploit_development": [
        "PoC completed: {poc_desc} - demonstrates {impact} in {poc_loc} lines",
        "Full exploit developed: {exploit_desc} targeting {target_desc}",
        "Payload encoding implemented: {encoding_desc}",
        "Retry mechanism: {retry_desc}. Error handling covers {error_cases} cases",
        "Exploit tested against {test_env}: {test_result}",
        "Exploit optimized: {optimization} - {speed_improvement}x speed improvement",
    ],
    "post_exploitation": [
        "Persistence established via {persistence_method}",
        "Privileges escalated from {from_priv} to {to_priv}",
        "Exfiltrated {data_type} from {source_path}",
        "Pivoted to {pivot_target}: accessible services: {services}",
        "Data exfiltrated: {data_size}MB via {channel}",
        "Logs cleared from {log_locations}",
    ],
}

# ── EXPLOIT TEMPLATES ──
MIN_PAYLOADS = {
    "CWE-89": "' OR 1=1-- ",
    "CWE-78": "; id",
    "CWE-22": "../../etc/passwd",
    "CWE-79": "<img src=x>",
    "CWE-918": "http://127.0.0.1:8080",
    "CWE-502": "base64_encoded_pickle_payload",
    "CWE-611": "<!ENTITY xxe SYSTEM 'file:///etc/passwd'>",
    "CWE-1321": '{"__proto__": {"polluted": true}}',
    "CWE-943": '{"$ne": ""}',
    "CWE-362": "50_concurrent_requests",
    "CWE-639": "incrementing_numeric_ids",
    "CWE-798": "common_default_passwords",
}

IMPACTS = {
    "CWE-89": "SQL injection yielding full database contents",
    "CWE-78": "Remote code execution on the target server",
    "CWE-22": "Read arbitrary files including /etc/shadow and configs",
    "CWE-79": "Cross-site scripting enabling session hijacking",
    "CWE-918": "Server-side request forgery exposing internal services",
    "CWE-502": "Remote code execution via deserialization gadget chain",
    "CWE-611": "Read arbitrary files via XML external entities",
    "CWE-1321": "Prototype pollution enabling privilege escalation",
    "CWE-943": "NoSQL injection bypassing authentication entirely",
    "CWE-362": "Race condition enabling unauthorized fund transfers",
    "CWE-639": "Access to other users' private data via IDOR",
    "CWE-798": "Full database access via exposed credentials",
}


def generate_trajectory(lang, cwe, vcode, pcode, uid):
    """Generate a full agentic trajectory for a given vulnerability."""
    r = random.Random(uid)
    phases_used = r.sample(PHASES, r.randint(3, 5))
    phases_used.sort(key=lambda p: PHASES.index(p))

    trajectory = []
    step_num = 1

    for phase in phases_used:
        action = r.choice(PHASE_ACTIONS[phase])
        obs_template = r.choice(PHASE_OBSERVATIONS[phase])

        # Format observation template with realistic values
        obs = obs_template.format(
            payload=MIN_PAYLOADS.get(cwe, "generic"),
            line=r.randint(10, 200),
            status="200 OK" if r.random() < 0.8 else "500 Error",
            cvss=f"{r.randint(7,10)}.{r.randint(0,9)}",
            min_payload=MIN_PAYLOADS.get(cwe, "test"),
            exfil_bytes=r.randint(100, 100000),
            encoding=r.choice(["UTF-16", "double URL", "Unicode normalization"]),
            test_count=r.randint(3, 20),
            precondition=r.choice(["verbose errors", "debug mode", "default config"]),
            poc_desc=f"{r.randint(5, 50)}-line script",
            impact=IMPACTS.get(cwe, "impact"),
            poc_loc=r.randint(10, 100),
            exploit_desc=f"{r.randint(50, 200)}-line {cwe} exploit",
            target_desc=f"{lang} application",
            encoding_desc=r.choice(["Base64 + URL encoding", "Unicode normalization", "Case variation bypass"]),
            retry_desc=f"{r.randint(2, 5)} retries with exponential backoff",
            error_cases=r.randint(3, 8),
            test_env=r.choice(["local Docker", "staging server", "CTF environment"]),
            test_result=r.choice(["100% success rate", "85% reliability", "works with specific timing"]),
            optimization=r.choice(["binary search", "parallel requests", "asynchronous I/O"]),
            speed_improvement=r.randint(2, 50),
            persistence_method=r.choice(["cron job", "SSH key", "web shell", "service installation"]),
            from_priv=r.choice(["www-data", "nobody", "apache"]),
            to_priv=r.choice(["root", "SYSTEM", "Administrator"]),
            data_type=r.choice(["password hashes", "database dumps", "SSH keys", "API tokens"]),
            source_path=r.choice(["/etc/shadow", "/var/backups/db.sql", "/root/.ssh/id_rsa", "/var/www/.env"]),
            pivot_target=f"10.0.{r.randint(0,255)}.{r.randint(1,254)}",
            services=r.choice(["SSH, MySQL, Redis", "HTTP, SMB, RDP", "PostgreSQL, Elasticsearch"]),
            data_size=r.randint(1, 500),
            channel=r.choice(["DNS tunneling", "HTTPS", "ICMP", "WebSocket"]),
            log_locations=r.choice(["/var/log", "/var/log/apache2", "/var/log/nginx"]),
            key=r.choice(["isAdmin", "polluted", "shell", "env"]),
        )

        trajectory.append({
            "step": step_num,
            "phase": phase,
            "action": action,
            "observation": obs,
        })
        step_num += 1

    return trajectory


def main():
    TARGET_TOTAL = 15000
    samples = []
    existing_fps = set()
    cwe_counts = Counter()
    lang_counts = Counter()

    print(f"Generating {TARGET_TOTAL} agentic trajectory samples...")
    templates = VULN_TEMPLATES

    attempts = 0
    while len(samples) < TARGET_TOTAL and attempts < TARGET_TOTAL * 5:
        lang, cwe, vcode_tmpl, pcode_tmpl = rng.choice(templates)
        uid = rng.randint(10000, 99999)
        vcode = vcode_tmpl.replace("{n}", str(uid))
        pcode = pcode_tmpl.replace("{n}", str(uid))
        attempts += 1

        fp = hashlib.md5(vcode.encode()).hexdigest()[:12]
        if fp in existing_fps:
            continue
        existing_fps.add(fp)

        trajectory = generate_trajectory(lang, cwe, vcode, pcode, uid)
        attack_scenario = f"{IMPACTS.get(cwe, 'Vulnerability')} in {lang} application via crafted input."

        sample = {
            "vulnerable_code": vcode,
            "patched_code": pcode,
            "cwe": cwe,
            "language": lang,
            "source": "agentic_trajectory_v2",
            "is_vulnerable": True,
            "has_trajectory": True,
            "trajectory": trajectory,
            "attack_scenario": attack_scenario,
            "explanation": f"Multi-step {cwe} exploitation chain in {lang}. Traces from reconnaissance through post-exploitation.",
            "severity": "critical" if cwe in ("CWE-78", "CWE-502", "CWE-89", "CWE-918") else "high",
            "fingerprint": fp,
            "sample_type": "agentic_trajectory_v2",
        }
        samples.append(sample)
        cwe_counts[cwe] += 1
        lang_counts[lang] += 1

        if len(samples) % 2000 == 0:
            print(f"  {len(samples)} generated...")

    out_file = OUT / "agentic_trajectories_v2.jsonl"
    with open(out_file, "w") as f:
        for s in samples:
            f.write(json.dumps(s, ensure_ascii=False) + "\n")

    print(f"\n=== Summary ===")
    print(f"Total trajectories: {len(samples)}")
    print(f"Saved to: {out_file}")
    print(f"\nBy CWE:")
    for c, n in sorted(cwe_counts.items(), key=lambda x: -x[1]):
        print(f"  {c}: {n}")
    print(f"\nBy Language:")
    for l, n in sorted(lang_counts.items(), key=lambda x: -x[1]):
        print(f"  {l}: {n}")


if __name__ == "__main__":
    main()
