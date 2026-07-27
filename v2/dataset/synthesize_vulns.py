"""Generate synthetic vulnerable + fixed code pairs across non-C languages."""
import json, hashlib, random
from pathlib import Path
from collections import Counter

rng = random.Random(42)
OUT = Path("inputs/datasets/extra_vuln")
OUT.mkdir(parents=True, exist_ok=True)
def fp(c): return hashlib.md5((c or "").encode()).hexdigest()

# ── Templates: list of (lang, cwe, vuln_template, fix_template) ──
# Templates use {n} for unique ID, {{ }} for literal braces

TEMPLATES = []

def add(lang, cwe, v_template, f_template):
    TEMPLATES.append((lang, cwe, v_template, f_template))

# ══ PYTHON ══
add("python", "CWE-89",
    "def get_user_{n}(user_id):\n    conn = sqlite3.connect(\"db.sqlite\")\n    cursor = conn.cursor()\n    query = \"SELECT * FROM users WHERE id = \" + user_id\n    cursor.execute(query)\n    return cursor.fetchall()",
    "def get_user_{n}(user_id):\n    conn = sqlite3.connect(\"db.sqlite\")\n    cursor = conn.cursor()\n    query = \"SELECT * FROM users WHERE id = ?\"\n    cursor.execute(query, (user_id,))\n    return cursor.fetchall()")

add("python", "CWE-78",
    "def ping_host_{n}(hostname):\n    result = os.system(\"ping -c 4 \" + hostname)\n    return result",
    "def ping_host_{n}(hostname):\n    import subprocess\n    result = subprocess.run([\"ping\", \"-c\", \"4\", hostname], capture_output=True, text=True)\n    return result.returncode")

add("python", "CWE-22",
    "def read_file_{n}(filename):\n    with open(\"/var/data/\" + filename, \"r\") as f:\n        return f.read()",
    "def read_file_{n}(filename):\n    import os\n    safe_path = os.path.realpath(\"/var/data/\" + filename)\n    if not safe_path.startswith(\"/var/data/\"):\n        raise ValueError(\"Invalid path\")\n    with open(safe_path, \"r\") as f:\n        return f.read()")

add("python", "CWE-79",
    "def render_comment_{n}(request):\n    comment = request.GET.get(\"comment\", \"\")\n    return HttpResponse(f\"<div>{comment}</div>\")",
    "def render_comment_{n}(request):\n    from django.utils.html import escape\n    comment = escape(request.GET.get(\"comment\", \"\"))\n    return HttpResponse(f\"<div>{comment}</div>\")")

add("python", "CWE-502",
    "def load_config_{n}(data):\n    import pickle\n    return pickle.loads(data)",
    "def load_config_{n}(data):\n    import json\n    return json.loads(data)")

add("python", "CWE-918",
    "def fetch_url_{n}(url):\n    import requests\n    resp = requests.get(url)\n    return resp.text",
    "def fetch_url_{n}(url):\n    import requests\n    from urllib.parse import urlparse\n    parsed = urlparse(url)\n    if parsed.hostname in (\"localhost\", \"127.0.0.1\", \"0.0.0.0\") or parsed.hostname.startswith(\"10.\") or parsed.hostname.startswith(\"192.168.\"):\n        raise ValueError(\"Blocked internal URL\")\n    resp = requests.get(url, timeout=10)\n    return resp.text")

add("python", "CWE-943",
    "def login_{n}(username, password):\n    return list(db.users.find({{'$where': 'this.username == \\\"' + username + '\\\" and this.password == \\\"' + password + '\\\"'}}))",
    "def login_{n}(username, password):\n    return list(db.users.find({{\"username\": username, \"password\": password}}))")

# ══ JAVASCRIPT ══
add("javascript", "CWE-79",
    "function render_{n}(req, res) {{\n  const name = req.query.name;\n  res.send(`<h1>Hello ${{name}}</h1>`);\n}}",
    "function render_{n}(req, res) {{\n  const escape = require(\"escape-html\");\n  const name = escape(req.query.name);\n  res.send(`<h1>Hello ${{name}}</h1>`);\n}}")

add("javascript", "CWE-89",
    "function getUser_{n}(id) {{\n  const query = `SELECT * FROM users WHERE id = ${{id}}`;\n  return db.execute(query);\n}}",
    "function getUser_{n}(id) {{\n  const query = \"SELECT * FROM users WHERE id = ?\";\n  return db.execute(query, [id]);\n}}")

add("javascript", "CWE-78",
    "function ping_{n}(host) {{\n  const exec = require(\"child_process\").exec;\n  exec(`ping -c 4 ${{host}}`, (err, out) => console.log(out));\n}}",
    "function ping_{n}(host) {{\n  const exec = require(\"child_process\").execFile;\n  exec(\"ping\", [\"-c\", \"4\", host], (err, out) => console.log(out));\n}}")

add("javascript", "CWE-1321",
    "function merge_{n}(target, source) {{\n  for (const key in source) {{\n    target[key] = source[key];\n  }}\n  return target;\n}}",
    "function merge_{n}(target, source) {{\n  for (const key in source) {{\n    if (key === \"__proto__\" || key === \"constructor\") continue;\n    if (Object.prototype.hasOwnProperty.call(source, key)) {{\n      target[key] = source[key];\n    }}\n  }}\n  return target;\n}}")

add("javascript", "CWE-22",
    "function readFile_{n}(path) {{\n  return fs.readFileSync(`/var/data/${{path}}`, \"utf8\");\n}}",
    "function readFile_{n}(path) {{\n  const path = require(\"path\");\n  const resolved = path.resolve(`/var/data/${{path}}`);\n  if (!resolved.startsWith(\"/var/data/\")) throw new Error(\"Invalid path\");\n  return fs.readFileSync(resolved, \"utf8\");\n}}")

add("javascript", "CWE-918",
    "async function proxy_{n}(req, res) {{\n  const url = req.query.url;\n  const resp = await fetch(url);\n  res.send(await resp.text());\n}}",
    "async function proxy_{n}(req, res) {{\n  const url = req.query.url;\n  const parsed = new URL(url);\n  if (parsed.hostname === \"localhost\" || parsed.hostname === \"127.0.0.1\") {{\n    return res.status(403).send(\"Blocked\");\n  }}\n  const resp = await fetch(url);\n  res.send(await resp.text());\n}}")

# ══ JAVA ══
add("java", "CWE-89",
    "public List<User> getUser_{n}(String id) {{\n  String sql = \"SELECT * FROM users WHERE id = \" + id;\n  return jdbcTemplate.query(sql, new UserRowMapper());\n}}",
    "public List<User> getUser_{n}(String id) {{\n  String sql = \"SELECT * FROM users WHERE id = ?\";\n  return jdbcTemplate.query(sql, new Object[]{{id}}, new UserRowMapper());\n}}")

add("java", "CWE-79",
    "public String render_{n}(String name) {{\n  return \"<h1>Hello \" + name + \"</h1>\";\n}}",
    "public String render_{n}(String name) {{\n  import org.owasp.encoder.Encode;\n  return \"<h1>Hello \" + Encode.forHtml(name) + \"</h1>\";\n}}")

add("java", "CWE-78",
    "public String ping_{n}(String host) throws Exception {{\n  Runtime rt = Runtime.getRuntime();\n  Process pr = rt.exec(\"ping -c 4 \" + host);\n  return readOutput(pr);\n}}",
    "public String ping_{n}(String host) throws Exception {{\n  List<String> cmd = new ArrayList<>(Arrays.asList(\"ping\", \"-c\", \"4\", host));\n  ProcessBuilder pb = new ProcessBuilder(cmd);\n  Process pr = pb.start();\n  return readOutput(pr);\n}}")

add("java", "CWE-22",
    "public String readFile_{n}(String filename) throws Exception {{\n  return new String(Files.readAllBytes(Paths.get(\"/var/data/\" + filename)));\n}}",
    "public String readFile_{n}(String filename) throws Exception {{\n  Path path = Paths.get(\"/var/data/\", filename).normalize();\n  if (!path.startsWith(\"/var/data/\")) throw new SecurityException(\"Invalid path\");\n  return new String(Files.readAllBytes(path));\n}}")

add("java", "CWE-611",
    "public Document parseXML_{n}(String xml) throws Exception {{\n  DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();\n  DocumentBuilder builder = factory.newDocumentBuilder();\n  return builder.parse(new InputSource(new StringReader(xml)));\n}}",
    "public Document parseXML_{n}(String xml) throws Exception {{\n  DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();\n  factory.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true);\n  factory.setFeature(\"http://xml.org/sax/features/external-general-entities\", false);\n  DocumentBuilder builder = factory.newDocumentBuilder();\n  return builder.parse(new InputSource(new StringReader(xml)));\n}}")

add("java", "CWE-502",
    "public Object deserialize_{n}(byte[] data) throws Exception {{\n  ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));\n  return ois.readObject();\n}}",
    "public Object deserialize_{n}(byte[] data) throws Exception {{\n  import io.github.classgraph.ParseException;\n  String json = new String(data, StandardCharsets.UTF_8);\n  return new JSONObject(json);\n}}")

add("java", "CWE-287",
    "public boolean login_{n}(String user, String pass) {{\n  String query = \"SELECT * FROM users WHERE username='\" + user + \"' AND password='\" + pass + \"'\";\n  return jdbcTemplate.queryForRowSet(query).next();\n}}",
    "public boolean login_{n}(String user, String pass) {{\n  String query = \"SELECT * FROM users WHERE username=? AND password=?\";\n  return jdbcTemplate.queryForRowSet(query, user, pass).next();\n}}")

# ══ GO ══
add("go", "CWE-89",
    "func GetUser_{n}(db *sql.DB, id string) (*User, error) {{\n  query := fmt.Sprintf(\"SELECT * FROM users WHERE id = %s\", id)\n  row := db.QueryRow(query)\n  return scanUser(row)\n}}",
    "func GetUser_{n}(db *sql.DB, id string) (*User, error) {{\n  query := \"SELECT * FROM users WHERE id = ?\"\n  row := db.QueryRow(query, id)\n  return scanUser(row)\n}}")

add("go", "CWE-78",
    "func Ping_{n}(host string) {{\n  cmd := exec.Command(\"ping\", \"-c\", \"4\", host)\n  out, _ := cmd.Output()\n  fmt.Println(string(out))\n}}",
    "func Ping_{n}(host string) {{\n  if strings.ContainsAny(host, \";&|$`\\\\\") {{\n    log.Fatal(\"Invalid host\")\n  }}\n  cmd := exec.Command(\"ping\", \"-c\", \"4\", host)\n  out, _ := cmd.Output()\n  fmt.Println(string(out))\n}}")

add("go", "CWE-22",
    "func ReadFile_{n}(path string) ([]byte, error) {{\n  return os.ReadFile(filepath.Join(\"/var/data/\", path))\n}}",
    "func ReadFile_{n}(path string) ([]byte, error) {{\n  abs, _ := filepath.Abs(filepath.Join(\"/var/data/\", path))\n  if !strings.HasPrefix(abs, \"/var/data/\") {{\n    return nil, fmt.Errorf(\"invalid path\")\n  }}\n  return os.ReadFile(abs)\n}}")

add("go", "CWE-918",
    "func FetchURL_{n}(url string) (string, error) {{\n  resp, err := http.Get(url)\n  if err != nil {{\n    return \"\", err\n  }}\n  defer resp.Body.Close()\n  body, _ := io.ReadAll(resp.Body)\n  return string(body), nil\n}}",
    "func FetchURL_{n}(url string) (string, error) {{\n  u, err := url.Parse(url)\n  if err != nil {{\n    return \"\", err\n  }}\n  if u.Hostname() == \"localhost\" || u.Hostname() == \"127.0.0.1\" {{\n    return \"\", fmt.Errorf(\"blocked\")\n  }}\n  resp, err := http.Get(url)\n  if err != nil {{\n    return \"\", err\n  }}\n  defer resp.Body.Close()\n  body, _ := io.ReadAll(resp.Body)\n  return string(body), nil\n}}")

add("go", "CWE-1321",
    "func Merge_{n}(target, source map[string]any) map[string]any {{\n  for k, v := range source {{\n    target[k] = v\n  }}\n  return target\n}}",
    "func Merge_{n}(target, source map[string]any) map[string]any {{\n  for k, v := range source {{\n    if k == \"__proto__\" || k == \"constructor\" {{\n      continue\n    }}\n    target[k] = v\n  }}\n  return target\n}}")

# ══ PHP ══
add("php", "CWE-89",
    "function getUser_{n}($id) {{\n  $query = \"SELECT * FROM users WHERE id = \" . $id;\n  $result = mysqli_query($conn, $query);\n  return mysqli_fetch_all($result);\n}}",
    "function getUser_{n}($id) {{\n  $stmt = $conn->prepare(\"SELECT * FROM users WHERE id = ?\");\n  $stmt->bind_param(\"s\", $id);\n  $stmt->execute();\n  return $stmt->get_result()->fetch_all();\n}}")

add("php", "CWE-79",
    "function render_{n}($name) {{\n  echo \"<h1>Hello \" . $name . \"</h1>\";\n}}",
    "function render_{n}($name) {{\n  echo \"<h1>Hello \" . htmlspecialchars($name, ENT_QUOTES, \"UTF-8\") . \"</h1>\";\n}}")

add("php", "CWE-78",
    "function ping_{n}($host) {{\n  $output = shell_exec(\"ping -c 4 \" . $host);\n  echo $output;\n}}",
    "function ping_{n}($host) {{\n  $sanitized = escapeshellcmd($host);\n  $output = shell_exec(\"ping -c 4 \" . $sanitized);\n  echo $output;\n}}")

add("php", "CWE-98",
    "function loadPage_{n}($page) {{\n  include($page . \".php\");\n}}",
    "function loadPage_{n}($page) {{\n  $allowed = [\"home\", \"about\", \"contact\"];\n  if (!in_array($page, $allowed)) {{\n    die(\"Invalid page\");\n  }}\n  include($page . \".php\");\n}}")

add("php", "CWE-502",
    "function loadData_{n}($data) {{\n  return unserialize($data);\n}}",
    "function loadData_{n}($data) {{\n  return json_decode($data, true);\n}}")

# ══ RUST ══
add("rust", "CWE-78",
    "fn ping_{n}(host: &str) {{\n    let output = std::process::Command::new(\"ping\").arg(\"-c\").arg(\"4\").arg(host).output().unwrap();\n    println!(\"{{}}\", String::from_utf8_lossy(&output.stdout));\n}}",
    "fn ping_{n}(host: &str) {{\n    if host.contains(\";\") || host.contains(\"&\") || host.contains(\"|\") {{\n        eprintln!(\"Invalid host\");\n        return;\n    }}\n    let output = std::process::Command::new(\"ping\").arg(\"-c\").arg(\"4\").arg(host).output().unwrap();\n    println!(\"{{}}\", String::from_utf8_lossy(&output.stdout));\n}}")

add("rust", "CWE-89",
    "fn get_user_{n}(conn: &Connection, id: &str) -> Result<Vec<User>, Error> {{\n    let query = format!(\"SELECT * FROM users WHERE id = {{}}\", id);\n    conn.query(query, &[])\n}}",
    "fn get_user_{n}(conn: &Connection, id: &str) -> Result<Vec<User>, Error> {{\n    conn.query(\"SELECT * FROM users WHERE id = $1\", &[&id])\n}}")

add("rust", "CWE-22",
    "fn read_file_{n}(path: &str) -> String {{\n    std::fs::read_to_string(format!(\"/var/data/{{}}\", path)).unwrap()\n}}",
    "fn read_file_{n}(path: &str) -> String {{\n    use std::path::Path;\n    let base = Path::new(\"/var/data\");\n    let abs = base.join(path).canonicalize().unwrap();\n    if !abs.starts_with(base) {{\n        panic!(\"Path traversal detected\");\n    }}\n    std::fs::read_to_string(abs).unwrap()\n}}")

# ══ CSHARP ══
add("csharp", "CWE-89",
    "public List<User> GetUser_{n}(string id) {{\n  string query = \"SELECT * FROM users WHERE id = \" + id;\n  using SqlCommand cmd = new SqlCommand(query, conn);\n  return ExecuteQuery(cmd);\n}}",
    "public List<User> GetUser_{n}(string id) {{\n  string query = \"SELECT * FROM users WHERE id = @id\";\n  using SqlCommand cmd = new SqlCommand(query, conn);\n  cmd.Parameters.AddWithValue(\"@id\", id);\n  return ExecuteQuery(cmd);\n}}")

add("csharp", "CWE-79",
    "public string Render_{n}(string name) {{\n  return \"<h1>Hello \" + name + \"</h1>\";\n}}",
    "public string Render_{n}(string name) {{\n  return \"<h1>Hello \" + System.Web.HttpUtility.HtmlEncode(name) + \"</h1>\";\n}}")

add("csharp", "CWE-502",
    "public object Deserialize_{n}(string data) {{\n  BinaryFormatter formatter = new BinaryFormatter();\n  using MemoryStream stream = new MemoryStream(Convert.FromBase64String(data));\n  return formatter.Deserialize(stream);\n}}",
    "public object Deserialize_{n}(string data) {{\n  return JsonSerializer.Deserialize<object>(data);\n}}")

add("csharp", "CWE-22",
    "public string ReadFile_{n}(string path) {{\n  return File.ReadAllText(Path.Combine(\"/var/data/\", path));\n}}",
    "public string ReadFile_{n}(string path) {{\n  string fullPath = Path.GetFullPath(Path.Combine(\"/var/data/\", path));\n  if (!fullPath.StartsWith(\"/var/data/\")) throw new SecurityException(\"Invalid path\");\n  return File.ReadAllText(fullPath);\n}}")

# ══ RUBY ══
add("ruby", "CWE-89",
    "def get_user_{n}(id)\n  User.find_by_sql(\"SELECT * FROM users WHERE id = #{id}\")\nend",
    "def get_user_{n}(id)\n  User.where(\"id = ?\", id)\nend")

add("ruby", "CWE-79",
    "def render_{n}(name)\n  \"<h1>Hello #{name}</h1>\"\nend",
    "def render_{n}(name)\n  \"<h1>Hello #{ERB::Util.html_escape(name)}</h1>\"\nend")

add("ruby", "CWE-78",
    "def ping_{n}(host)\n  `ping -c 4 #{host}`\nend",
    "def ping_{n}(host)\n  system(\"ping\", \"-c\", \"4\", host)\nend")

add("ruby", "CWE-502",
    "def load_data_{n}(data)\n  Marshal.load(data)\nend",
    "def load_data_{n}(data)\n  JSON.parse(data)\nend")

# ══ SWIFT ══
add("swift", "CWE-89",
    "func getUser_{n}(_ id: String) -> [User] {{\n  let query = \"SELECT * FROM users WHERE id = \\(id)\"\n  return db.execute(query)\n}}",
    "func getUser_{n}(_ id: String) -> [User] {{\n  let query = \"SELECT * FROM users WHERE id = ?\"\n  return db.execute(query, parameters: [id])\n}}")

add("swift", "CWE-78",
    "func ping_{n}(_ host: String) {{\n  let task = Process()\n  task.executableURL = URL(fileURLWithPath: \"/sbin/ping\")\n  task.arguments = [\"-c\", \"4\", host]\n  try! task.run()\n}}",
    "func ping_{n}(_ host: String) {{\n  let task = Process()\n  task.executableURL = URL(fileURLWithPath: \"/sbin/ping\")\n  let safe = host.replacingOccurrences(of: \"[;&|$`]\", with: \"\", options: .regularExpression)\n  task.arguments = [\"-c\", \"4\", safe]\n  try! task.run()\n}}")

# ══ KOTLIN ══
add("kotlin", "CWE-89",
    "fun getUser_{n}(id: String): List<User> {{\n  val query = \"SELECT * FROM users WHERE id = \$id\"\n  return jdbcTemplate.query(query, UserRowMapper())\n}}",
    "fun getUser_{n}(id: String): List<User> {{\n  val query = \"SELECT * FROM users WHERE id = ?\"\n  return jdbcTemplate.query(query, arrayOf(id), UserRowMapper())\n}}")

add("kotlin", "CWE-78",
    "fun ping_{n}(host: String) {{\n  val process = Runtime.getRuntime().exec(\"ping -c 4 \$host\")\n  process.waitFor()\n}}",
    "fun ping_{n}(host: String) {{\n  val process = ProcessBuilder(\"ping\", \"-c\", \"4\", host).start()\n  process.waitFor()\n}}")

# ══ TYPESCRIPT ══
add("typescript", "CWE-79",
    "function render_{n}(req: Request, res: Response) {{\n  const name = req.query.name as string;\n  res.send(`<h1>Hello ${{name}}</h1>`);\n}}",
    "function render_{n}(req: Request, res: Response) {{\n  import escape from \"escape-html\";\n  const name = escape(req.query.name as string);\n  res.send(`<h1>Hello ${{name}}</h1>`);\n}}")

add("typescript", "CWE-89",
    "async function getUser_{n}(id: string) {{\n  const query = `SELECT * FROM users WHERE id = ${{id}}`;\n  const [rows] = await db.execute(query);\n  return rows;\n}}",
    "async function getUser_{n}(id: string) {{\n  const query = \"SELECT * FROM users WHERE id = ?\";\n  const [rows] = await db.execute(query, [id]);\n  return rows;\n}}")

# ══ SCALA ══
add("scala", "CWE-89",
    "def getUser_{n}(id: String): List[User] = {{\n  val query = s\"SELECT * FROM users WHERE id = $id\"\n  jdbcTemplate.query(query, new UserRowMapper)\n}}",
    "def getUser_{n}(id: String): List[User] = {{\n  val query = \"SELECT * FROM users WHERE id = ?\"\n  jdbcTemplate.query(query, Array(id), new UserRowMapper)\n}}")

# ══ PERL ══
add("perl", "CWE-89",
    "sub get_user_{n} {{\n  my ($id) = @_;\n  my $query = \"SELECT * FROM users WHERE id = $id\";\n  return $dbh->selectall_arrayref($query);\n}}",
    "sub get_user_{n} {{\n  my ($id) = @_;\n  my $sth = $dbh->prepare(\"SELECT * FROM users WHERE id = ?\");\n  $sth->execute($id);\n  return $sth->fetchall_arrayref();\n}}")

add("perl", "CWE-78",
    "sub ping_{n} {{\n  my ($host) = @_;\n  my $output = `ping -c 4 $host`;\n  print $output;\n}}",
    "sub ping_{n} {{\n  my ($host) = @_;\n  use String::ShellQuote;\n  my $safe = shell_quote($host);\n  my $output = `ping -c 4 $safe`;\n  print $output;\n}}")


# ── Generate ─────────────────────────────────────────────
TARGET = 20000
samples = []
existing_fps = set()
counts = Counter()
cwe_counts = Counter()

print(f"Generating {TARGET} samples...")
while len(samples) < TARGET:
    lang, cwe, v_tmpl, f_tmpl = rng.choice(TEMPLATES)
    uid = rng.randint(10000, 99999)
    vcode = v_tmpl.replace("{n}", str(uid))
    fcode = f_tmpl.replace("{n}", str(uid))
    if not vcode or not fcode:
        continue
    fp = hashlib.md5(vcode.encode()).hexdigest()
    if fp in existing_fps:
        continue
    existing_fps.add(fp)
    counts[lang] += 1
    cwe_counts[cwe] += 1
    samples.append({
        "vulnerable_code": vcode,
        "patched_code": fcode,
        "cwe": cwe,
        "language": lang,
        "source": "synthetic_vuln_gen",
        "is_vulnerable": True,
        "explanation": f"Detected {cwe} vulnerability in {lang} code. The vulnerable pattern involves untrusted input being used without proper sanitization or safe API usage.",
        "severity": "high" if rng.random() < 0.6 else "critical" if rng.random() < 0.3 else "medium",
        "fingerprint": fp,
    })

with open(OUT / "synthetic_vulns.jsonl", "w") as f:
    for s in samples:
        f.write(json.dumps(s, ensure_ascii=False) + "\n")

print(f"\nGenerated: {len(samples):,}")
print("\nBy language:")
for l, n in sorted(counts.items(), key=lambda x: -x[1]):
    print(f"  {l}: {n}")
print("\nBy CWE:")
for c, n in sorted(cwe_counts.items(), key=lambda x: -x[1]):
    print(f"  {c}: {n}")
print(f"\nSaved to {OUT / 'synthetic_vulns.jsonl'}")
