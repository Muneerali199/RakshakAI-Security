"""
RakshakAI — Real-world benchmark suite.
Tests the model on code patterns NOT in training templates to detect overfitting.
"""
import sys
import json
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from rakshakai.inference import RakshakInference

BENCHMARKS = {
    "SQL_INJECTION": [
        ("Python f-string SQLi", "python",
         "cursor.execute(f'SELECT * FROM users WHERE id = {uid}')"),
        ("Python db.query concatenation", "python",
         'db.query("SELECT * FROM items WHERE " + filter_param)'),
        ("Python format string SQLi", "python",
         'cursor.execute("SELECT * FROM users WHERE id = {}".format(user_id))'),
        ("JS template literal SQLi", "javascript",
         "connection.query(`SELECT * FROM products WHERE id = ${productId}`)"),
        ("JS concat SQLi", "javascript",
         'pool.query("DELETE FROM orders WHERE id = " + orderId)'),
        ("Java string concat SQLi", "java",
         'String sql = "SELECT * FROM users WHERE name = \'" + userName + "\'";\nStatement stmt = conn.createStatement();\nResultSet rs = stmt.executeQuery(sql);'),
        ("Python % formatting SQLi", "python",
         'cursor.execute("SELECT * FROM users WHERE name = \'%s\'" % username)'),
        ("JS template in exec", "javascript",
         "const sql = `INSERT INTO users VALUES('${email}', '${pass}')`;\ndb.execute(sql)"),
        ("Python tuple concat SQLi", "python",
         'query = "SELECT * FROM users WHERE id = " + str(user_input)\ncur.execute(query)'),
        ("Node pg query injection", "javascript",
         'client.query("SELECT * FROM users WHERE email = " + email)'),
    ],
    "XSS": [
        ("Python innerHTML via template", "python",
         'return f"<div>{user_content}</div>"'),
        ("JS innerHTML assignment", "javascript",
         'document.getElementById("output").innerHTML = userInput'),
        ("JS jQuery html injection", "javascript",
         '$("#container").html(userContent)'),
        ("Python Response.write XSS", "python",
         'def handler(request):\n    return HttpResponse(user_input)'),
        ("Python print XSS", "python",
         'print(f"<script>{user_code}</script>")'),
        ("JS innerHTML event handler", "javascript",
         'element.innerHTML = "<span onclick=\\"alert(\'" + data + "\')\\">click</span>"'),
        ("Java response writer XSS", "java",
         'response.getWriter().write("<div>" + userName + "</div>")'),
    ],
    "COMMAND_INJECTION": [
        ("Python os.system injection", "python",
         'os.system("ping -c 1 " + host)'),
        ("Python subprocess shell injection", "python",
         'subprocess.Popen("ls -la " + directory, shell=True)'),
        ("Python os.popen injection", "python",
         'os.popen("cat " + filename).read()'),
        ("JS exec injection", "javascript",
         'exec("ls -la " + req.query.path)'),
        ("JS spawn injection", "javascript",
         'spawn("sh", ["-c", cmd])'),
        ("Java runtime exec", "java",
         'Runtime.getRuntime().exec("ping " + ipAddress)'),
    ],
    "HARDCODED_SECRET": [
        ("Python API key string", "python",
         'API_KEY = "YOUR_STRIPE_API_KEY_HERE"'),
        ("Python password hardcoded", "python",
         'DB_PASSWORD = "SuperSecret123!"'),
        ("JS secret key", "javascript",
         'const jwt_secret = "my-super-secret-key-12345";'),
        ("Python token variable", "python",
         'auth_token = "ghp_abcdefghijklmnopqrstuvwxyz1234567890"'),
        ("JS AWS key hardcoded", "javascript",
         'const AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE";'),
    ],
    "WEAK_CRYPTO": [
        ("Node.js crypto md5", "javascript",
         'crypto.createHash("md5").update(data).digest("hex")'),
        ("Python hashlib md5", "python",
         'hashlib.md5(password.encode()).hexdigest()'),
        ("Python hashlib sha1", "python",
         'hashlib.sha1(user_input.encode()).hexdigest()'),
        ("Java MD5", "java",
         'MessageDigest.getInstance("MD5")'),
        ("Node crypto sha1", "javascript",
         'crypto.createHash("sha1").update(token).digest("base64")'),
        ("Python DES", "python",
         'from Crypto.Cipher import DES\ncipher = DES.new(key, DES.MODE_ECB)'),
    ],
    "PATH_TRAVERSAL": [
        ("Python open traversal", "python",
         'open("uploads/" + filename, "r").read()'),
        ("JS readFile traversal", "javascript",
         'fs.readFileSync("data/" + userPath)'),
        ("Python filepath join traversal", "python",
         'path = os.path.join("uploads", user_input)\nwith open(path) as f: pass'),
        ("Java FileInputStream traversal", "java",
         'FileInputStream fis = new FileInputStream(directory + fileName);'),
    ],
    "CLEAN": [
        ("Python parameterized SQL", "python",
         'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))'),
        ("Python subprocess no shell", "python",
         'subprocess.run(["ping", host], check=True, capture_output=True)'),
        ("Python path sanitization", "python",
         'safe_path = os.path.join(BASE_DIR, os.path.basename(filename))'),
        ("Python bcrypt hashing", "python",
         'hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())'),
        ("Python SHA256 hashing", "python",
         'hashlib.sha256(data.encode()).hexdigest()'),
        ("JS parameterized query", "javascript",
         'db.query("SELECT * FROM users WHERE id = $1", [userId])'),
        ("JS textContent safe", "javascript",
         'element.textContent = userInput'),
        ("JS execFile safe", "javascript",
         'execFile("ping", ["-c", "1", host], callback)'),
        ("Python prepare statement", "python",
         'stmt = conn.prepare("SELECT * FROM users WHERE id = ?")'),
        ("Python escape string", "python",
         'safe_input = conn.escape_string(user_input)\ncursor.execute("SELECT * FROM users WHERE name = \'" + safe_input + "\'")'),
        ("Python redirect safe", "python",
         'return redirect(url_for("index"))'),
        ("Python normpath safe", "python",
         'filepath = os.path.normpath(os.path.join(UPLOAD_DIR, filename))'),
        ("Java prepared statement", "java",
         'PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?");\nps.setString(1, userId);\nResultSet rs = ps.executeQuery();'),
        ("JS crypto SHA256", "javascript",
         'crypto.createHash("sha256").update(data).digest("hex")'),
        ("Python JSON safe parse", "python",
         'data = json.loads(user_data)'),
        ("JS DOMPurify", "javascript",
         'const clean = DOMPurify.sanitize(userInput)\ndocument.getElementById("out").innerHTML = clean'),
    ],
}

def run_benchmark(model_path: str = None, tokenizer_path: str = None):
    engine = RakshakInference(model_path=model_path, tokenizer_path=tokenizer_path)

    results = {}
    total_correct = 0
    total = 0

    for expected_label, cases in BENCHMARKS.items():
        case_results = []
        for desc, lang, code in cases:
            pred = engine.predict(code, lang)
            correct = pred["label"] == expected_label
            case_results.append({
                "description": desc,
                "expected": expected_label,
                "predicted": pred["label"],
                "confidence": pred["confidence"],
                "correct": correct,
                "top5": pred["top5"],
            })
            if correct:
                total_correct += 1
            total += 1
        results[expected_label] = case_results

    return results, total_correct, total


def print_report(results, total_correct, total):
    print("=" * 70)
    print("RAKSHAKAI — REAL-WORLD BENCHMARK REPORT")
    print("=" * 70)

    by_class = {}
    for label, cases in results.items():
        correct = sum(1 for c in cases if c["correct"])
        by_class[label] = (correct, len(cases))

    print(f"\n{'Class':<25} {'Correct':>8} {'Total':>6} {'Acc%':>8}")
    print("-" * 50)
    for label, (cor, tot) in sorted(by_class.items()):
        pct = 100.0 * cor / tot if tot > 0 else 0
        print(f"{label:<25} {cor:>8} {tot:>6} {pct:>7.1f}%")
    print("-" * 50)
    print(f"{'TOTAL':<25} {total_correct:>8} {total:>6} {100.0*total_correct/total:>7.1f}%")

    print(f"\n{'='*70}")
    print("FAILURES")
    print(f"{'='*70}")
    failures = []
    for label, cases in results.items():
        for c in cases:
            if not c["correct"]:
                failures.append(c)
    if failures:
        for f in failures:
            print(f"\n  [{f['expected']} → {f['predicted']}] (conf: {f['confidence']:.3f})")
            print(f"  Desc: {f['description']}")
            print(f"  Top5: {[(t['label'], t['confidence']) for t in f['top5'][:3]]}")
    else:
        print("  No failures! 100% accuracy!")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", default=None)
    parser.add_argument("--tokenizer", default=None)
    parser.add_argument("--json", action="store_true", help="Output JSON")
    args = parser.parse_args()

    results, correct, total = run_benchmark(args.model, args.tokenizer)

    if args.json:
        print(json.dumps({
            "total_correct": correct,
            "total": total,
            "accuracy": correct / total if total > 0 else 0,
            "results": results,
        }, indent=2))
    else:
        print_report(results, correct, total)

    sys.exit(0 if correct == total else 1)
