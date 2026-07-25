"""
RakshakAI — Dataset generation and loading.

Generates diverse code vulnerability samples with augmentation.
"""
import random
import hashlib
import csv
from pathlib import Path
from typing import Optional
from collections import Counter

import torch
from torch.utils.data import Dataset

VULNERABILITY_CLASSES = [
    "CLEAN",
    "SQL_INJECTION", "XSS", "CSRF", "PATH_TRAVERSAL", "COMMAND_INJECTION",
    "HARDCODED_SECRET", "INSECURE_DESERIALIZATION", "OPEN_REDIRECT",
    "WEAK_CRYPTO", "JWT_VULNERABILITY", "LDAP_INJECTION", "XXE_INJECTION",
    "SSTI", "REDOS", "NULL_DEREFERENCE", "MEMORY_LEAK", "RACE_CONDITION",
    "BUFFER_OVERFLOW", "EMPTY_CATCH", "INFINITE_LOOP",
]

NUM_CLASSES = len(VULNERABILITY_CLASSES)
LABEL2ID = {l: i for i, l in enumerate(VULNERABILITY_CLASSES)}
ID2LABEL = {i: l for l, i in LABEL2ID.items()}

SEVERITY_MAP = {
    "SQL_INJECTION": "critical", "XSS": "critical", "COMMAND_INJECTION": "critical",
    "SSTI": "critical", "INSECURE_DESERIALIZATION": "critical", "PATH_TRAVERSAL": "critical",
    "LDAP_INJECTION": "critical", "XXE_INJECTION": "critical", "JWT_VULNERABILITY": "critical",
    "BUFFER_OVERFLOW": "critical", "CSRF": "warning", "OPEN_REDIRECT": "warning",
    "HARDCODED_SECRET": "warning", "WEAK_CRYPTO": "warning", "RACE_CONDITION": "warning",
    "MEMORY_LEAK": "warning", "NULL_DEREFERENCE": "warning", "REDOS": "warning",
    "EMPTY_CATCH": "info", "INFINITE_LOOP": "info", "CLEAN": "clean",
}

CWE_MAP = {
    "SQL_INJECTION": "CWE-89", "XSS": "CWE-79", "COMMAND_INJECTION": "CWE-78",
    "PATH_TRAVERSAL": "CWE-22", "HARDCODED_SECRET": "CWE-798", "WEAK_CRYPTO": "CWE-327",
    "SSTI": "CWE-94", "INSECURE_DESERIALIZATION": "CWE-502",
}


# ── Augmentation ──────────────────────────────────────

VARS = ["data", "input", "value", "user", "item", "record", "entry", "payload", "content", "param", "result", "output"]
FUNCS = ["process", "handle", "execute", "run", "parse", "validate", "check", "load", "fetch", "compute"]
SUFFIXES = ["_1", "_2", "_in", "_raw", "_tmp", "_buf", ""]
PREFIXES = ["my_", "user_", "input_", "raw_", ""]


def mutate_code(code: str, seed: int) -> str:
    """Apply random mutations to code for data augmentation."""
    rng = random.Random(seed)
    # Variable renaming
    for _ in range(rng.randint(0, 3)):
        old = rng.choice(VARS)
        new = rng.choice([v + rng.choice(SUFFIXES) for v in VARS])
        code = code.replace(old, new, 1)
    # Whitespace changes
    if rng.random() < 0.3:
        lines = code.split("\n")
        code = "\n".join("  " * rng.randint(0, 2) + l for l in lines)
    # Comment addition
    if rng.random() < 0.2 and "#" not in code and "//" not in code:
        comments = ["# unsafe", "# FIXME", "# TODO: sanitize", "# user input", "// potential issue"]
        code += "  " + rng.choice(comments)
    # String quote style
    if rng.random() < 0.3:
        code = code.replace('"', "'").replace("'", '"', 1) if '"' in code else code
    return code


# ── Vulnerability templates (expanded) ────────────────

TEMPLATES = {
    "SQL_INJECTION": {
        "python": [
            'query = "SELECT * FROM users WHERE id = " + user_id',
            'cursor.execute("SELECT * FROM users WHERE name = \'" + username + "\'")',
            'db.query("SELECT * FROM items WHERE " + filter_param)',
            'sql = f"SELECT * FROM users WHERE email = \'{email}\'"',
            'conn.execute("DELETE FROM posts WHERE id = " + str(post_id))',
            'rows = db.select("SELECT * FROM products WHERE category = " + cat)',
            'cur.execute("UPDATE users SET pass = \'" + new_pw + "\' WHERE id = " + uid)',
            'db.run("INSERT INTO logs VALUES(\'" + msg + "\', \'" + level + "\')")',
            'query = f"SELECT {fields} FROM {table} WHERE id = {uid}"',
            'cursor.execute("SELECT * FROM users WHERE id = \'" + request.GET["id"] + "\'")',
            "cursor.execute(f'SELECT * FROM users WHERE id = {uid}')",
            "conn.execute(f'DELETE FROM posts WHERE id = {post_id}')",
            "cur.execute(f'UPDATE users SET name = \\'{name}\\' WHERE id = {uid}')",
            'rows = db.query(f"SELECT * FROM items WHERE category = {cat}")',
            'db.run(f"INSERT INTO logs VALUES(\'{msg}\', \'{level}\')")',
            'query = f"SELECT * FROM {table}"',
            "cursor.execute(f'SELECT * FROM users WHERE name = \\'{username}\\'')",
            "res = db.select(f'SELECT * FROM products WHERE id = {pid}')",
            'cursor.execute("SELECT * FROM users WHERE id = {}".format(user_id))',
            'query = "SELECT * FROM users WHERE name = \'%s\'" % username',
            'conn.execute("DELETE FROM posts WHERE id = %s" % post_id)',
            'cur.execute("SELECT * FROM users WHERE name = \'%s\' AND pass = \'%s\'" % (user, pw))',
        ],
        "javascript": [
            'db.query("SELECT * FROM users WHERE id = " + req.params.id)',
            'const query = `SELECT * FROM products WHERE id = ${productId}`',
            'connection.query("SELECT * FROM users WHERE name = \'" + name + "\'")',
            'pool.query("UPDATE items SET price = " + amount)',
            'const sql = `INSERT INTO users VALUES(\'${email}\', \'${pass}\')`',
            'client.query("DELETE FROM orders WHERE id = " + order_id, callback)',
            'db.query(`SELECT * FROM users WHERE id = ${uid}`)',
            'connection.query(`SELECT name FROM items WHERE id = ${itemId}`)',
            'pool.query(`UPDATE products SET price = ${amount} WHERE id = ${pid}`)',
            'const result = await db.query(`SELECT * FROM orders WHERE user_id = ${userId}`)',
            'client.query(`DELETE FROM sessions WHERE id = ${sessionId}`)',
        ],
        "java": [
            'String q = "SELECT * FROM users WHERE id = " + userId;',
            'String query = "SELECT * FROM users WHERE name = \'" + name + "\'";',
            'jdbcTemplate.query("SELECT * FROM items WHERE " + filter, mapper)',
            'Statement stmt = conn.createStatement();\nResultSet rs = stmt.executeQuery("SELECT * FROM products WHERE id = " + productId);',
        ],
        "php": [
            '$result = mysqli_query($conn, "SELECT * FROM users WHERE id = " . $_GET["id"]);',
            '$db->query("SELECT * FROM posts WHERE author = \'" . $author . "\'")',
            '$stmt = $db->prepare("SELECT * FROM items WHERE " . $filter);\n$stmt->execute();',
        ],
    },
    "XSS": {
        "python": [
            'return "<div>" + user_input + "</div>"',
            'Response.write(user_name)',
            'template.render(user_content)',
            'return f"<h1>{title}</h1><p>{body}</p>"',
            'print("<script>" + code + "</script>")',
            'def handle(request):\n    return HttpResponse(user_input)',
            'return render_template("page.html", content=user_html)',
        ],
        "javascript": [
            'document.getElementById("output").innerHTML = userInput',
            'element.innerHTML = req.params.value',
            '$("#div").html(userContent)',
            'render("<span>" + data + "</span>")',
            'document.write(user_name)',
            'el.insertAdjacentHTML("beforeend", unsafeHTML)',
            'ReactDOM.render(htmlContent, container)',
            '$("body").append(userHtml)',
        ],
        "java": [
            'response.getWriter().write(userInput)',
            'out.println("<div>" + name + "</div>")',
        ],
        "php": [
            'echo "<div>" . $_GET["content"] . "</div>"',
            'print $userMessage;',
        ],
    },
    "COMMAND_INJECTION": {
        "python": [
            'os.system("ping " + user_input)',
            'subprocess.call("ls " + directory, shell=True)',
            'os.popen("cat " + filename)',
            'commands.getoutput("rm " + file)',
            'os.execl("sh", "sh", "-c", cmd)',
            'os.popen("cat " + filename).read()',
            'subprocess.Popen("ls -la " + directory, shell=True)',
            'os.system("nslookup " + domain)',
        ],
        "javascript": [
            'exec("ls " + userInput, callback)',
            'child_process.execSync("ping " + req.body.host)',
            'require("child_process").spawn(cmd + " " + arg)',
            'exec("ls -la " + req.query.path)',
            'spawn("sh", ["-c", cmd])',
        ],
        "java": [
            'Runtime.getRuntime().exec("ping " + host)',
            'ProcessBuilder pb = new ProcessBuilder("ls", directory)',
            'Runtime.getRuntime().exec("nslookup " + hostname)',
        ],
    },
    "HARDCODED_SECRET": {
        "python": [
            'API_KEY = "YOUR_STRIPE_KEY_HERE"',
            'password = "admin123"',
            'SECRET_TOKEN = "my-secret-value"',
            'db_password = "Password123"',
            'token = "ghp_xxxxxxxxxxxx"',
            'api_key = "YOUR_STRIPE_API_KEY_HERE"',
            'auth_token = "ghp_abcdefghijklmnopqrstuvwxyz1234567890"',
            'DB_PASSWORD = "SuperSecret123!"',
            'jwt_secret = "my-jwt-secret-key-2024"',
        ],
        "javascript": [
            'const API_KEY = "YOUR_STRIPE_KEY_HERE"',
            'const SECRET = "my-secret-token"',
            'const jwt_secret = "my-super-secret-key-12345"',
            'const AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"',
            'const auth_token = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxx"',
            'const secretKey = "YOUR_STRIPE_KEY_HERE"',
        ],
        "java": [
            'private static final String API_KEY = "sk-abc123"',
            'String password = "admin123"',
            'String awsAccessKey = "AKIAIOSFODNN7EXAMPLE";',
        ],
        "php": ['$apiKey = "YOUR_STRIPE_KEY_HERE"'],
    },
    "PATH_TRAVERSAL": {
        "python": [
            'open("uploads/" + filename)',
            'with open(user_file) as f: return f.read()',
            'filepath = "data/" + request.params.path',
            'open("uploads/" + filename, "r").read()',
            'path = os.path.join("uploads", user_input)\nwith open(path) as f: pass',
            'file = open("reports/" + report_name).read()',
        ],
        "javascript": [
            'fs.readFileSync("uploads/" + filename)',
            'require("fs").createReadStream(userPath)',
            'fs.readFileSync("data/" + userPath)',
        ],
        "java": [
            'new FileInputStream(userFile)',
            'File f = new File(directory + filename)',
            'FileInputStream fis = new FileInputStream(directory + fileName);',
        ],
    },
    "WEAK_CRYPTO": {
        "python": [
            'hashlib.md5(data).hexdigest()',
            'hashlib.sha1(password.encode()).hexdigest()',
            'hashlib.md5(user_input.encode()).hexdigest()',
            'cipher = AES.new(key, AES.MODE_ECF)',
            'hashlib.new("md5", data).hexdigest()',
            'hashlib.new("sha1", password.encode()).hexdigest()',
        ],
        "javascript": [
            'crypto.createHash("md5").update(data).digest("hex")',
            'crypto.createHash("md5").update(password).digest("base64")',
            'crypto.createHash("sha1").update(userData).digest("hex")',
            'crypto.createHash("MD5").update(token).digest("hex")',
            'const hash = crypto.createHmac("md5", key).update(data).digest("hex")',
        ],
        "java": [
            'MessageDigest.getInstance("MD5")',
            'Cipher.getInstance("DES")',
            'MessageDigest.getInstance("SHA-1")',
        ],
    },
    "SSTI": {
        "python": [
            'Template("Hello " + user).render()',
            'render_template_string(user_input)',
        ],
        "javascript": [
            'handlebars.compile(userInput)(data)',
            'ejs.render(userData, options)',
        ],
    },
    "INSECURE_DESERIALIZATION": {
        "python": [
            "pickle.loads(data)",
            'yaml.load(user_data)',
        ],
        "javascript": [
            'unserialize(userInput)',
        ],
        "java": ['ObjectInputStream.readObject()'],
    },
    "JWT_VULNERABILITY": {
        "python": [
            'jwt.decode(token, options={"verify_signature": False})',
        ],
        "javascript": [
            'jwt.verify(token, secret, {algorithms: []})',
        ],
    },
    "REDOS": {
        "javascript": [
            'new RegExp(user_input + "+")',
        ],
        "python": [
            're.compile(user_input + "+$")',
        ],
    },
    "CSRF": {
        "python": [
            '@app.route("/transfer")\ndef transfer(): pass',
        ],
        "javascript": [
            'router.post("/update", handler)',
        ],
        "java": [
            '@PostMapping("/update")\npublic void update() {}',
        ],
    },
    "OPEN_REDIRECT": {
        "python": [
            'return redirect(params.get("next"))',
        ],
        "javascript": [
            'res.redirect(req.query.next)',
        ],
    },
    "NULL_DEREFERENCE": {
        "java": [
            'user.getName()  # no null check',
        ],
        "javascript": [
            'user.name  # might be null',
        ],
    },
    "MEMORY_LEAK": {
        "python": [
            'conn = getConnection()',
            'file = open(path)',
        ],
        "javascript": [
            'const conn = db.connect()',
        ],
        "java": [
            'Connection conn = getConnection()',
        ],
    },
    "EMPTY_CATCH": {
        "python": ["try:\n    pass\nexcept:\n    pass"],
        "javascript": ["} catch(err) {}"],
        "java": ["} catch(Exception e) { }"],
    },
    "BUFFER_OVERFLOW": {
        "c": ["strcpy(dest, userInput)", "gets(userInput)"],
    },
    "RACE_CONDITION": {
        "python": ["if balance >= amount: balance -= amount"],
        "java": ["if (balance >= amount) { balance -= amount; }"],
    },
    "INFINITE_LOOP": {
        "python": ["while True: pass"],
        "javascript": ["while(true) {}"],
    },
    "LDAP_INJECTION": {
        "python": ['ldap.search("dc=example,dc=com", "(uid=" + user + ")")'],
    },
    "XXE_INJECTION": {
        "python": ['etree.fromstring(user_xml)'],
        "java": [
            'DocumentBuilderFactory db = DocumentBuilderFactory.newInstance();\n'
            'Document doc = db.newDocumentBuilder().parse(userXml)'
        ],
    },
}

CLEAN_TEMPLATES = {
    "python": [
        'cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))',
        'element.textContent = sanitizer.escape(userInput)',
        'subprocess.run(["ping", host], check=True)',
        'filepath = os.path.join("uploads", os.path.basename(filename))',
        'hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())',
        'data = json.loads(user_data)',
        'return redirect(url_for("success"))',
        'path = os.path.normpath(os.path.join(BASE_DIR, filename))',
        'stmt = conn.prepare("SELECT * FROM users WHERE id = ?")',
        'result = re.sub(r"[<>\"\']", "", user_input)',
        'secret = os.environ.get("API_KEY")',
        'with open(filepath, "r") as f: contents = f.read()',
        'ip = validate_ip(host)',
        'allowed = ["css", "js", "png"]\nif ext in allowed: pass',
        'quote = conn.escape_string(username)',
        'cur.execute("SELECT * FROM users WHERE id = %s", [uid])',
        'db.query("SELECT * FROM products WHERE id = $1", [product_id])',
        'import bleach\nclean_html = bleach.clean(user_html)',
        'conn.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
        'rows = db.query("SELECT * FROM items WHERE category = %s", [cat])',
        'cur.execute("SELECT name FROM products WHERE id = %s", [pid])',
        'hashlib.sha256(user_input.encode()).hexdigest()',
        'hashlib.sha3_256(data.encode()).hexdigest()',
        'hash = hmac.new(key, msg, hashlib.sha256).hexdigest()',
        'digest = hashlib.sha256(password.encode()).hexdigest()',
        'checksum = hashlib.sha256(data.encode()).hexdigest()',
        'subprocess.run(["ls", "-la", directory], check=True, capture_output=True)',
        'subprocess.run(["git", "clone", url], cwd=workdir)',
        'result = subprocess.run(["npm", "test"], shell=False)',
        'proc = subprocess.Popen(["cat", filename], stdout=subprocess.PIPE)',
        'ret = redirect(url_for("admin.dashboard"))',
        'resp = redirect(location, code=302)',
        'safe = os.path.normpath(os.path.join(UPLOAD_DIR, filepath))',
        'clean = bleach.clean(html_input, tags=["p", "b", "i"])',
        'sanitized = sanitize_html(user_content)',
    ],
    "javascript": [
        'db.query("SELECT * FROM users WHERE id = ?", [userId])',
        'element.textContent = userInput',
        'execFile("ping", [host], callback)',
        'const safePath = path.basename(userPath)',
        'const data = JSON.parse(userData)',
        'res.redirect("/success")',
        'const sanitized = DOMPurify.sanitize(userInput)',
        'const escaped = escapeHtml(userContent)',
        'crypto.createHash("sha256").update(data).digest("hex")',
        'connection.query("SELECT * FROM products WHERE id = $1", [productId])',
        'pool.query("SELECT * FROM users WHERE email = $1", [email])',
        'client.query("UPDATE items SET price = $1 WHERE id = $2", [price, itemId])',
        'const result = await db.query("SELECT * FROM orders WHERE id = $1", [orderId])',
        'crypto.createHash("sha512").update(data).digest("hex")',
        'crypto.createHash("sha3-256").update(buffer).digest("hex")',
        'crypto.createHash("sha384").update(payload).digest("hex")',
        'const clean = DOMPurify.sanitize(userInput)\ndocument.getElementById("out").innerHTML = clean',
        'execFile("git", ["status"], {cwd: repoPath}, callback)',
        'const { spawn } = require("child_process");\nspawn("node", ["app.js"])',
    ],
    "java": [
        'PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?");\nps.setString(1, userId);',
        'ProcessBuilder pb = new ProcessBuilder("ping", host);',
        'response.sendRedirect("/success")',
        'String safe = Encode.forHtml(userInput);',
        'MessageDigest md = MessageDigest.getInstance("SHA-256");',
    ],
    "php": [
        '$stmt = $pdo->prepare("SELECT * FROM users WHERE id = :id");\n$stmt->execute([":id" => $id]);',
        'htmlspecialchars($input, ENT_QUOTES, "UTF-8")',
        'password_hash($pass, PASSWORD_BCRYPT)',
    ],
}


class VulnerabilityDatasetGenerator:
    """Generates diverse, balanced vulnerability detection dataset."""

    def generate(self, num_samples: int = 10000) -> list[dict]:
        samples = []
        vuln_classes = [c for c in VULNERABILITY_CLASSES if c != "CLEAN"]
        class_count = len(vuln_classes)

        # Generate vulnerable samples — balanced per class
        vuln_per_class = max(3, (num_samples // 2) // class_count)
        for vuln_type in vuln_classes:
            langs = TEMPLATES.get(vuln_type, {})
            if not langs:
                continue
            for _ in range(vuln_per_class):
                lang = random.choice(list(langs.keys()))
                code = random.choice(langs[lang])
                code = mutate_code(code, random.randint(0, 2**32))
                samples.append({
                    "code": code,
                    "language": lang,
                    "label": vuln_type,
                    "is_vulnerable": 1,
                })

        # Fill remaining vulnerable slots
        remaining = (num_samples // 2) - len(samples)
        for _ in range(remaining):
            vuln_type = random.choice(vuln_classes)
            langs = TEMPLATES.get(vuln_type, {})
            if not langs:
                continue
            lang = random.choice(list(langs.keys()))
            code = random.choice(langs[lang])
            code = mutate_code(code, random.randint(0, 2**32))
            samples.append({
                "code": code,
                "language": lang,
                "label": vuln_type,
                "is_vulnerable": 1,
            })

        # Generate clean samples
        clean_count = num_samples - len(samples)
        for _ in range(clean_count):
            lang = random.choice(list(CLEAN_TEMPLATES.keys()))
            code = random.choice(CLEAN_TEMPLATES[lang])
            code = mutate_code(code, random.randint(0, 2**32))
            samples.append({
                "code": code,
                "language": lang,
                "label": "CLEAN",
                "is_vulnerable": 0,
            })

        random.shuffle(samples)
        return samples


class CodeDataset(Dataset):
    """PyTorch dataset for vulnerability classification."""

    def __init__(self, samples: list[dict], tokenizer, max_length: int = 256,
                 class_weights: Optional[torch.Tensor] = None):
        self.samples = samples
        self.tokenizer = tokenizer
        self.max_length = max_length
        self.class_weights = class_weights

    def __len__(self):
        return len(self.samples)

    def __getitem__(self, idx):
        sample = self.samples[idx]
        text = f"[{sample['language']}] {sample['code']}"
        input_ids = self.tokenizer.encode(text, self.max_length)
        label_id = LABEL2ID.get(sample["label"], 0)
        return {
            "input_ids": torch.tensor(input_ids, dtype=torch.long),
            "labels": torch.tensor(label_id, dtype=torch.long),
            "attention_mask": torch.tensor(
                [1 if t != self.tokenizer.pad_id else 0 for t in input_ids],
                dtype=torch.long,
            ),
        }

    def get_class_weights(self) -> torch.Tensor:
        """Compute class weights (inverse frequency) for balanced loss."""
        if self.class_weights is not None:
            return self.class_weights
        label_counts = Counter(s["label"] for s in self.samples)
        n = len(self.samples)
        weights = torch.zeros(NUM_CLASSES)
        for label, count in label_counts.items():
            idx = LABEL2ID.get(label, 0)
            weights[idx] = n / (NUM_CLASSES * count) if count > 0 else 1.0
        return weights


def load_csv(path: str) -> list[dict]:
    """Load samples from a CSV file."""
    samples = []
    with open(path) as f:
        reader = csv.DictReader(f)
        for row in reader:
            samples.append({
                "code": row["code"],
                "language": row.get("language", "python"),
                "label": row.get("label", row.get("label", "CLEAN")),
                "is_vulnerable": int(row.get("is_vulnerable", 0)),
            })
    return samples
