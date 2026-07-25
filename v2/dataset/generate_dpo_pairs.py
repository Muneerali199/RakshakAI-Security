"""
Generate DPO (Direct Preference Optimization) training pairs for fix quality.
Creates correct_fix / incorrect_fix pairs so the model learns to prefer
secure code over vulnerable code + good patches over bad patches.
"""
import json, hashlib, random
from pathlib import Path
from collections import Counter

rng = random.Random(42)
OUT = Path("inputs/datasets/extra_vuln")
OUT.mkdir(parents=True, exist_ok=True)

def fp(c): return hashlib.md5((c or "").encode()).hexdigest()

# Each entry: (lang, cwe, vulnerable_code, good_fix, bad_fix, reason_good, reason_bad)
DPO_PAIRS = []

def add(lang, cwe, vuln, good, bad, reason_good, reason_bad):
    DPO_PAIRS.append((lang, cwe, vuln, good, bad, reason_good, reason_bad))

# ══════════════════════════════════════════════════════════════
# SQL Injection DPO pairs
# ══════════════════════════════════════════════════════════════
add("python", "CWE-89",
    "def get_user_{n}(id):\n    query = \"SELECT * FROM users WHERE id = '\" + id + \"'\"\n    return db.execute(query)",
    # Good fix: parameterized query
    "def get_user_{n}(id):\n    query = \"SELECT * FROM users WHERE id = %s\"\n    return db.execute(query, (id,))",
    # Bad fix: just adds string escaping (still injectable)
    "def get_user_{n}(id):\n    safe_id = id.replace(\"'\", \"''\")\n    query = \"SELECT * FROM users WHERE id = '\" + safe_id + \"'\"\n    return db.execute(query)",
    "Parameterized query completely separates code from data, preventing ANY SQL injection.",
    "Escaping single quotes is insufficient - does not prevent second-order injection, numeric injection, or LIKE wildcard attacks."),

add("java", "CWE-89",
    'public User getUser_{n}(String id) {\n  String sql = "SELECT * FROM users WHERE id = \'" + id + "\'";\n  return jdbcTemplate.query(sql, new UserRowMapper());\n}',
    # Good fix: PreparedStatement
    'public User getUser_{n}(String id) {\n  String sql = "SELECT * FROM users WHERE id = ?";\n  return jdbcTemplate.query(sql, new Object[]{id}, new UserRowMapper());\n}',
    # Bad fix: input validation
    'public User getUser_{n}(String id) {\n  if (id.matches("\\\\d+")) {\n    String sql = "SELECT * FROM users WHERE id = \'" + id + "\'";\n    return jdbcTemplate.query(sql, new UserRowMapper());\n  }\n  return null;\n}',
    "PreparedStatement with ? placeholders ensures database driver handles escaping correctly.",
    "Input validation is fragile - regex can be bypassed, and the real fix is parameterized queries."),

# ══════════════════════════════════════════════════════════════
# XSS DPO pairs
# ══════════════════════════════════════════════════════════════
add("javascript", "CWE-79",
    'function render_{n}(req, res) {\n  const name = req.query.name;\n  res.send(`<h1>Hello ${name}</h1>`);\n}',
    # Good fix: HTML entity encoding
    'function render_{n}(req, res) {\n  const escape = require("escape-html");\n  const name = escape(req.query.name);\n  res.send(`<h1>Hello ${name}</h1>`);\n}',
    # Bad fix: strip script tags
    'function render_{n}(req, res) {\n  let name = req.query.name.replace(/<script>/gi, "").replace(/<\\/script>/gi, "");\n  res.send(`<h1>Hello ${name}</h1>`);\n}',
    "HTML entity encoding escapes ALL HTML special characters, making injection impossible regardless of payload.",
    "Stripping script tags is easily bypassed (e.g., <img src=x onerror=alert(1)>, <svg onload=alert(1)>, event handlers)."),

add("python", "CWE-79",
    'def render_{n}(request):\n    name = request.GET.get("name", "")\n    return HttpResponse(f"<h1>Hello {name}</h1>")',
    # Good fix: Django autoescape
    'def render_{n}(request):\n    from django.utils.html import escape\n    name = escape(request.GET.get("name", ""))\n    return HttpResponse(f"<h1>Hello {name}</h1>")',
    # Bad fix: remove script tags
    'def render_{n}(request):\n    import re\n    name = re.sub(r"<script[^>]*>.*?</script>", "", request.GET.get("name", ""), flags=re.DOTALL)\n    return HttpResponse(f"<h1>Hello {name}</h1>")',
    "Django's escape() function encodes < > & \" ' as HTML entities, preventing all XSS vectors.",
    "Regex-based script tag removal fails against XSS without script tags (event handlers, javascript: URLs, SVG, etc.)."),

# ══════════════════════════════════════════════════════════════
# Command Injection DPO pairs
# ══════════════════════════════════════════════════════════════
add("python", "CWE-78",
    "def ping_{n}(hostname):\n    return os.system(\"ping -c 4 \" + hostname)",
    # Good fix: subprocess with list
    "def ping_{n}(hostname):\n    import subprocess\n    return subprocess.run([\"ping\", \"-c\", \"4\", hostname], capture_output=True)",
    # Bad fix: shell escaping
    "def ping_{n}(hostname):\n    import shlex\n    safe = shlex.quote(hostname)\n    return os.system(\"ping -c 4 \" + safe)",
    "subprocess.run() with argument list avoids shell entirely - no shell injection possible.",
    "shlex.quote() can be bypassed with certain shell features (command substitution $(), newlines, etc.)."),

add("go", "CWE-78",
    'func Ping_{n}(host string) {\n  cmd := exec.Command("ping", "-c", "4", host)\n  out, _ := cmd.Output()\n  fmt.Println(string(out))\n}',
    # Good fix: input validation
    'func Ping_{n}(host string) {\n  if strings.ContainsAny(host, ";|&$`\\\\") { log.Fatal("Invalid host") }\n  cmd := exec.Command("ping", "-c", "4", host)\n  out, _ := cmd.Output()\n  fmt.Println(string(out))\n}',
    # Bad fix: flag-based attack (trusting host unreachable)
    'func Ping_{n}(host string) {\n  cmd := exec.Command("ping", "-c", "4", host)\n  out, _ := cmd.Output()\n  fmt.Println(string(out))\n}',
    "Input validation blocks shell metacharacters and dangerous flag injection.",
    "Even with exec.Command argument separation, 'host' can contain flags like -o ProxyCommand=... that execute commands."),

# ══════════════════════════════════════════════════════════════
# Path Traversal DPO pairs
# ══════════════════════════════════════════════════════════════
add("python", "CWE-22",
    "def read_file_{n}(filename):\n    path = \"/var/data/\" + filename\n    return open(path).read()",
    # Good fix: canonicalize + prefix check
    "def read_file_{n}(filename):\n    import os\n    safe = os.path.realpath(\"/var/data/\" + filename)\n    if not safe.startswith(\"/var/data/\"):\n        raise ValueError(\"Invalid path\")\n    return open(safe).read()",
    # Bad fix: just strip ..
    "def read_file_{n}(filename):\n    safe = filename.replace(\"..\", \"\")\n    path = \"/var/data/\" + safe\n    return open(path).read()",
    "os.path.realpath() resolves all symlinks and .. sequences before checking prefix, making traversal impossible.",
    "Replacing .. is trivially bypassed (e.g., ....// becomes ../ after replacement, or using URL-encoded variants)."),

add("java", "CWE-22",
    'public String readFile_{n}(String filename) throws Exception {\n  return new String(Files.readAllBytes(Paths.get("/var/data/" + filename)));\n}',
    # Good fix: normalize + validate
    'public String readFile_{n}(String filename) throws Exception {\n  Path path = Paths.get("/var/data/", filename).normalize();\n  if (!path.startsWith("/var/data/")) throw new SecurityException("Invalid path");\n  return new String(Files.readAllBytes(path));\n}',
    # Bad fix: blacklist
    'public String readFile_{n}(String filename) throws Exception {\n  if (filename.contains("..")) throw new SecurityException("No traversal");\n  return new String(Files.readAllBytes(Paths.get("/var/data/" + filename)));\n}',
    "Path.normalize() resolves .. sequences, then prefix check ensures base directory constraint.",
    "Blacklisting .. fails against null bytes, symlinks, absolute paths (/etc/passwd), or encoded sequences."),

# ══════════════════════════════════════════════════════════════
# SSRF DPO pairs
# ══════════════════════════════════════════════════════════════
add("python", "CWE-918",
    "def fetch_url_{n}(url):\n    import requests\n    return requests.get(url).text",
    # Good fix: allowlist
    "def fetch_url_{n}(url):\n    import requests\n    from urllib.parse import urlparse\n    parsed = urlparse(url)\n    if parsed.hostname not in (\"api.example.com\", \"api.example.org\"):\n        raise ValueError(\"Blocked URL\")\n    return requests.get(url, timeout=10).text",
    # Bad fix: block localhost
    "def fetch_url_{n}(url):\n    import requests\n    if \"localhost\" in url or \"127.0.0.1\" in url:\n        raise ValueError(\"Blocked\")\n    return requests.get(url).text",
    "Allowlist approach only permits known-safe domains, preventing SSRF to any unapproved destination.",
    "Blocking localhost is insufficient - metadata service (169.254.169.254), internal IP ranges (10.x, 172.16-31.x, 192.168.x), DNS rebinding attacks bypass it."),

# ══════════════════════════════════════════════════════════════
# Deserialization DPO pairs
# ══════════════════════════════════════════════════════════════
add("python", "CWE-502",
    "def load_data_{n}(data):\n    import pickle\n    return pickle.loads(data)",
    # Good fix: use safe format
    "def load_data_{n}(data):\n    import json\n    return json.loads(data)",
    # Bad fix: add allowlist to pickle
    "def load_data_{n}(data):\n    import pickle\n    class RestrictedUnpickler(pickle.Unpickler):\n        def find_class(self, module, name):\n            allowed = {\"builtins\": [\"int\", \"str\", \"list\", \"dict\", \"tuple\"]}\n            if module in allowed and name in allowed[module]:\n                return super().find_class(module, name)\n            raise pickle.UnpicklingError(\"Blocked\")\n    return RestrictedUnpickler(io.BytesIO(data)).load()",
    "JSON is a safe serialization format that does not support code execution.",
    "Custom Unpickler allowlists are notoriously hard to secure - bypasses exist via indirect gadgets in allowed modules."),

# ══════════════════════════════════════════════════════════════
# XXE DPO pairs
# ══════════════════════════════════════════════════════════════
add("java", "CWE-611",
    'public Document parseXML_{n}(String xml) throws Exception {\n  DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();\n  DocumentBuilder builder = factory.newDocumentBuilder();\n  return builder.parse(new InputSource(new StringReader(xml)));\n}',
    # Good fix: disable XXE
    'public Document parseXML_{n}(String xml) throws Exception {\n  DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();\n  factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);\n  factory.setFeature("http://xml.org/sax/features/external-general-entities", false);\n  DocumentBuilder builder = factory.newDocumentBuilder();\n  return builder.parse(new InputSource(new StringReader(xml)));\n}',
    # Bad fix: entity expansion limit only
    'public Document parseXML_{n}(String xml) throws Exception {\n  DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();\n  factory.setExpandEntityReferences(false);\n  DocumentBuilder builder = factory.newDocumentBuilder();\n  return builder.parse(new InputSource(new StringReader(xml)));\n}',
    "Disabling DOCTYPE declarations and external entities completely prevents XXE and Billion Laughs.",
    "Disabling entity expansion still allows external entity loading for file reading/SSRF."),

# ══════════════════════════════════════════════════════════════
# Hardcoded Credentials DPO pairs
# ══════════════════════════════════════════════════════════════
add("python", "CWE-798",
    'def connect_{n}():\n    return mysql.connector.connect(user="admin", password="password123!", host="localhost", database="prod")',
    # Good fix: environment variable
    'def connect_{n}():\n    import os\n    return mysql.connector.connect(\n        user=os.environ["DB_USER"],\n        password=os.environ["DB_PASSWORD"],\n        host=os.environ["DB_HOST"],\n        database=os.environ["DB_NAME"]\n    )',
    # Bad fix: obfuscation
    'def connect_{n}():\n    pwd = "".join(chr(ord(c) - 1) for c in "qbtbtxpe!2025!")\n    return mysql.connector.connect(user="admin", password=pwd, host="localhost", database="prod")',
    "Environment variables keep secrets out of source code, enable rotation without redeployment, and follow 12-factor app principles.",
    "Obfuscation (ROT, base64, etc.) is NOT security - determined attacker can reverse it, and it's still in source control."),

# ══════════════════════════════════════════════════════════════
# NoSQL Injection DPO pairs
# ══════════════════════════════════════════════════════════════
add("python", "CWE-943",
    'def login_{n}(username, password):\n    return list(db.users.find({\'$where\': \'this.username == "\' + username + \'"\'}))',
    # Good fix: avoid $where
    'def login_{n}(username, password):\n    return list(db.users.find({"username": username, "password": password}))',
    # Bad fix: escape quotes
    'def login_{n}(username, password):\n    safe_user = username.replace(\'"\', \'\\\\"\');\n    return list(db.users.find({\'$where\': \'this.username == "\' + safe_user + \'"\'}))',
    "Direct field matching eliminates the $where injection vector entirely.",
    "Escaping quotes in $where is insufficient - JavaScript injection via comparison operators, regex, or function calls still works."),

# ══════════════════════════════════════════════════════════════
# Prototype Pollution DPO pairs
# ══════════════════════════════════════════════════════════════
add("javascript", "CWE-1321",
    'function merge_{n}(target, source) {\n  for (const key in source) {\n    target[key] = source[key];\n  }\n  return target;\n}',
    # Good fix: block prototype keys
    'function merge_{n}(target, source) {\n  for (const key in source) {\n    if (key === "__proto__" || key === "constructor" || key === "prototype") continue;\n    if (Object.prototype.hasOwnProperty.call(source, key)) {\n      target[key] = source[key];\n    }\n  }\n  return target;\n}',
    # Bad fix: shallow clone
    'function merge_{n}(target, source) {\n  return {...target, ...source};\n}',
    "Explicitly blocking dangerous keys and checking hasOwnProperty prevents prototype pollution.",
    "Spread operator still copies __proto__ on nested merge if source is parsed from JSON (JSON.parse preserves __proto__ as regular key)."),


# ══════════════════════════════════════════════════════════════
# Generate samples
# ══════════════════════════════════════════════════════════════
TARGET_PER_TEMPLATE = 500

samples = []
existing_fps = set()
counts = Counter()
cwe_counts = Counter()
lang_counts = Counter()

print(f"Generating {len(DPO_PAIRS) * TARGET_PER_TEMPLATE} DPO pairs from {len(DPO_PAIRS)} templates...")

for lang, cwe, vuln, good, bad, reason_good, reason_bad in DPO_PAIRS:
    for var in range(TARGET_PER_TEMPLATE):
        uid = rng.randint(10000, 99999)
        # Use {n} for unique IDs (template functions should have _{n})
        vcode = vuln.replace("{n}", str(uid))
        gcode = good.replace("{n}", str(uid))
        bcode = bad.replace("{n}", str(uid))

        # DPO format: chosen (good) and rejected (bad)
        fp_v = hashlib.md5(vcode.encode()).hexdigest()
        if fp_v in existing_fps:
            continue
        existing_fps.add(fp_v)

        sample = {
            "vulnerable_code": vcode,
            "patched_code": gcode,
            "patch_alternative": bcode,
            "cwe": cwe,
            "language": lang,
            "source": "dpo_pairs",
            "is_vulnerable": True,
            "dpo_type": "fix_quality",
            "dpo_chosen": gcode,
            "dpo_rejected": bcode,
            "chosen_label": "secure",
            "rejected_label": "insecure_fix",
            "chosen_explanation": reason_good,
            "rejected_explanation": reason_bad,
            "severity": "high",
            "fingerprint": fp_v,
            "sample_type": "dpo_pair",
        }
        samples.append(sample)
        cwe_counts[cwe] += 1
        lang_counts[lang] += 1

    print(f"  {cwe} ({lang}): {TARGET_PER_TEMPLATE} pairs")

out_file = OUT / "dpo_pairs.jsonl"
with open(out_file, "w") as f:
    for s in samples:
        f.write(json.dumps(s, ensure_ascii=False) + "\n")

print(f"\n=== Summary ===")
print(f"Total DPO pairs: {len(samples)}")
print(f"Saved to: {out_file}")
print(f"\nBy CWE:")
for c, n in sorted(cwe_counts.items(), key=lambda x: -x[1]):
    print(f"  {c}: {n}")
print(f"\nBy Language:")
for l, n in sorted(lang_counts.items(), key=lambda x: -x[1]):
    print(f"  {l}: {n}")
