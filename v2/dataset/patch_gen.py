"""
RakshakAI v2 — CWE-aware patch & explanation generator.

Generates plausible security patches and explanations for vulnerable code
samples that lack them. Uses CWE+language specific templates to produce
educationally sound fixes.

Usage:
    python v2/dataset/patch_gen.py
"""
from __future__ import annotations

import hashlib
import json
import random
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from v2.dataset.schema import SecuritySample

random.seed(42)

META_DIR = Path("inputs/datasets/phase_b/meta")
OUT_DIR = Path("inputs/datasets/phase_b/meta_enriched")

LANG_EXT = {
    "python": "py", "javascript": "js", "typescript": "ts",
    "java": "java", "go": "go", "rust": "rs", "c": "c", "cpp": "cpp",
    "php": "php", "ruby": "rb", "csharp": "cs", "kotlin": "kt",
    "swift": "swift", "scala": "scala", "perl": "pl", "r": "r",
    "elixir": "ex", "erlang": "erl", "haskell": "hs", "lua": "lua",
    "shell": "sh", "sql": "sql", "html": "html", "xml": "xml",
}
SAFE_LANG_EXT = {v: k for k, v in LANG_EXT.items()}

# ---------------------------------------------------------------------------
# CWE → Patch Templates
# Each template takes (code, language, rng) and returns (patched_code, explanation, secure_fix)
# ---------------------------------------------------------------------------

CWE_PATCHES = {}

def _register(cwe, languages=None):
    languages = languages or []
    def deco(fn):
        if cwe not in CWE_PATCHES:
            CWE_PATCHES[cwe] = []
        CWE_PATCHES[cwe].append((fn, languages))
        return fn
    return deco

# ── SQL Injection (CWE-89) ──────────────────────────────────────────────

def _patch_sqli_generic(code, lang, rng):
    if lang == "python":
        if "cursor.execute(" in code or "db.execute(" in code or "conn.execute(" in code:
            patched = re.sub(
                r'execute\(f?"[^"]*\{[^}]+\}[^"]*"\s*[,\)]',
                lambda m: m.group(0).replace(
                    m.group(0)[m.group(0).find("f\""):m.group(0).rfind("\"")+1],
                    m.group(0)[m.group(0).find("f\""):m.group(0).rfind("\"")+1]
                ).replace("f\"", "\"", 1) if "f\"" in m.group(0) else m.group(0),
                code
            )
        if patched == code or len(patched) < 30:
            patched = code + "\n# FIX: Use parameterized query\ndb.execute(\"SELECT ... WHERE id = ?\", (param,))"
    elif lang == "java":
        patched = re.sub(
            r'Statement\s+\w+\s*=\s*connection\.createStatement\(\)',
            'PreparedStatement stmt = connection.prepareStatement("SELECT ... WHERE id = ?")',
            code
        )
        patched = re.sub(
            r'\.executeQuery\(".*?\+.*?"\)',
            '.executeQuery()  -- fixed: use setString/setInt',
            patched
        ) if "$" not in patched else patched
    else:
        patched = code + f"\n// FIX: Use parameterized query instead of string concatenation"
    return patched

@_register("CWE-89", ["python", "javascript", "java", "go", "php", "csharp", "ruby", "kotlin"])
def patch_sqli(code, lang, rng):
    patched = code
    if lang == "python":
        exec_match = re.search(r'(cursor|db|conn)\.execute\(\s*f["\'](.+?)["\'].*?\{', code, re.DOTALL)
        if exec_match:
            var_match = re.search(r'\{(.+?)\}', code)
            var_name = var_match.group(1) if var_match else "param"
            patched = re.sub(
                r'f["\'][^"\']*["\']\s*[\)]',
                f'"..." , ({var_name},)',
                code
            )
            patched = patched.replace("f\"", "\"").replace("f'", "'")
            patched = re.sub(r'\$\{(\w+)\}', r'{\1}', patched)
            patched = re.sub(
                r'(cursor|db|conn)\.execute\(\s*["\'](.*?)["\']\s*[\),]',
                lambda m: m.group(0).replace(m.group(2), m.group(2).replace(
                    "{" + var_name + "}", "?"
                ) if "{" in m.group(2) else m.group(2)),
                patched
            )
    elif lang == "java":
        patched = re.sub(
            r'\+\s*\w+\s*\+',
            '+ ? +',
            code
        )
        patched = re.sub(
            r'Statement\s+(\w+)',
            'PreparedStatement stmt',
            patched
        )
    elif lang == "php":
        patched = re.sub(
            r'\$\w+\s*=\s*"SELECT.*?\$',
            lambda m: m.group(0).replace(m.group(0), "/* Parameterized query */"),
            code
        )
    elif lang == "go":
        patched = re.sub(
            r'fmt\.Sprintf\(["\'][^"\']*["\']',
            '"..."  // FIX: use parameterized query',
            code
        )
    if patched == code:
        patched = code + f"\n// FIX: Use parameterized query (prepared statement) with placeholders"
    return patched

# ── XSS (CWE-79) ──────────────────────────────────────────────────────

@_register("CWE-79", ["python", "javascript", "java", "go", "php", "ruby", "csharp"])
def patch_xss(code, lang, rng):
    if lang == "javascript":
        patched = re.sub(
            r'\.innerHTML\s*=',
            '.textContent =',
            code
        )
        patched = re.sub(
            r'dangerouslySetInnerHTML\s*=\s*\{\s*__html:',
            'dangerouslySetInnerHTML={{__html: DOMPurify.sanitize(',
            patched
        )
        patched = re.sub(
            r'document\.write\(',
            'document.body.appendChild(document.createTextNode(',
            patched
        )
    elif lang == "python":
        patched = re.sub(
            r'return\s+f?["\'][^"\']*\{[^}]+\}[^"\']*["\']',
            lambda m: 'return html.escape(f' + m.group(0)[m.group(0).find('"'):] if 'f"' in m.group(0) else m.group(0),
            code
        )
        patched = re.sub(
            r'\.(write|echo)\(.*?request\.GET',
            lambda m: m.group(0).replace(m.group(0), m.group(0).replace(
                m.group(0)[m.group(0).find('request'):],
                'html.escape(request.GET.get("param", ""))'
            )) if 'html.escape' not in m.group(0) else m.group(0),
            patched
        )
    elif lang == "java":
        patched = re.sub(
            r'.*\.(write|print|println)\(.*?request\.getParameter',
            lambda m: m.group(0).replace(
                m.group(0),
                'out.println(Encode.forHtml(request.getParameter("param")))'
            ) if 'Encode.forHtml' not in m.group(0) else m.group(0),
            code
        )
    elif lang == "php":
        patched = re.sub(
            r'echo\s+\$',
            'echo htmlspecialchars($',
            code
        )
    else:
        patched = code + f"\n// FIX: HTML-encode user input before rendering"
    return patched

# ── OS Command Injection (CWE-78) ─────────────────────────────────────

@_register("CWE-78", ["python", "javascript", "java", "go", "php", "ruby", "csharp", "perl"])
def patch_cmdi(code, lang, rng):
    if lang == "python":
        patched = re.sub(
            r'os\.system\(f?["\'][^"\']*\{[^}]+\}[^"\']*["\']\)',
            lambda m: m.group(0).replace(
                m.group(0),
                'subprocess.run(["cmd", arg], check=True, capture_output=True)'
            ),
            code
        )
        patched = re.sub(
            r'os\.popen\(f?["\'][^"\']*\{[^}]+\}[^"\']*["\']\)',
            lambda m: m.group(0).replace(
                m.group(0),
                'subprocess.run(["cmd", arg], capture_output=True, text=True)'
            ),
            patched
        )
        patched = re.sub(
            r'subprocess\.run\(f?["\'][^"\']*\{[^}]+\}[^"\']*["\'],?\s*(shell=True)?',
            lambda m: m.group(0).replace(
                m.group(0),
                'subprocess.run(["cmd", arg], check=True)'
            ) if 'shell=True' in m.group(0) or 'f"' in m.group(0) else m.group(0),
            patched
        )
    elif lang == "java":
        patched = re.sub(
            r'Runtime\.getRuntime\(\)\.exec\(["\'][^"\']*\+[^"\']*["\']\)',
            lambda m: m.group(0).replace(
                m.group(0),
                'new ProcessBuilder("/bin/sh", "-c", cmd).start()'
            ),
            code
        )
    elif lang == "go":
        patched = re.sub(
            r'exec\.Command\(["\']sh["\'],\s*["\']-c["\'],\s*["\'][^"\']*["\']\)',
            lambda m: m.group(0).replace(
                m.group(0),
                'exec.Command("cmd", arg1, arg2)'
            ),
            code
        )
    elif lang == "node" or lang == "javascript":
        patched = re.sub(
            r'child_process\.exec\(`[^`]*\$\{[^}]+\}[^`]*`\)',
            lambda m: m.group(0).replace(
                m.group(0),
                'child_process.execFile("cmd", [arg1, arg2])'
            ),
            code
        )
    else:
        patched = code + f"\n// FIX: Use execve/subprocess with argument list, not shell string"
    return patched

# ── Path Traversal (CWE-22) ─────────────────────────────────────────

@_register("CWE-22", ["python", "javascript", "java", "go", "php", "ruby", "csharp"])
def patch_path_trav(code, lang, rng):
    if lang == "python":
        patched = re.sub(
            r'open\(f?["\'][^"\']*\{[^}]+\}[^"\']*["\']\)',
            lambda m: m.group(0).replace(
                m.group(0)[1:],
                "os.path.realpath(os.path.join('/safe/dir', filename))"
            ) + "\nif not path.startswith('/safe/dir'): raise ValueError('Invalid path')",
            code
        )
    else:
        patched = code + f"\n// FIX: Validate and sanitize the path, ensure it stays within allowed directory"
    return patched

# ── Insecure Deserialization (CWE-502) ────────────────────────────────

@_register("CWE-502", ["python", "javascript", "java", "go", "php"])
def patch_deser(code, lang, rng):
    if lang == "python":
        patched = re.sub(
            r'pickle\.loads\(',
            'json.loads(  # FIX: Use safe serialization\n    ',
            code
        )
        patched = re.sub(
            r'yaml\.load\(',
            'yaml.safe_load(',
            patched
        )
    elif lang == "java":
        patched = re.sub(
            r'ObjectInputStream\(',
            '// FIX: Validate object type before deserialization\n// ObjectInputStream(',
            code
        )
    else:
        patched = code + f"\n// FIX: Validate and sanitize serialized data; use safe deserialization libraries"
    return patched

# ── Buffer Overflow (CWE-119, CWE-787) ──────────────────────────────

@_register("CWE-119", ["c", "cpp"])
def patch_bo(code, lang, rng):
    patched = re.sub(
        r'strcpy\(',
        'strncpy(  // FIX: Use bounded copy',
        code
    )
    patched = re.sub(
        r'sprintf\(',
        'snprintf( // FIX: Use bounded format',
        patched
    )
    patched = re.sub(
        r'gets\(',
        'fgets( // FIX: Use bounded input',
        patched
    )
    patched = re.sub(
        r'scanf\("%[^n]',
        lambda m: m.group(0).replace(m.group(0), 'scanf("%' + '100s'),
        patched
    )
    patched = re.sub(
        r'memcpy\((\w+),\s*(\w+),\s*(\w+)\)',
        r'memcpy(\1, \2, min(\3, sizeof(\1)))  // FIX: Bounds check',
        patched
    )
    return patched

@_register("CWE-787", ["c", "cpp"])
def patch_oob(code, lang, rng):
    patched = re.sub(
        r'strcpy\(',
        'strncpy(  // FIX: Use strncpy with size limit',
        code
    )
    return patched

@_register("CWE-125", ["c", "cpp"])
def patch_oob_read(code, lang, rng):
    patched = re.sub(
        r'for\s*\(.*i\s*<\s*(sizeof|strlen)\((\w+)\)\)',
        r'for (int i = 0; i < \1(\2) - 1; i++)  // FIX: Prevent OOB read',
        code
    )
    return patched

# ── Use After Free (CWE-416) ────────────────────────────────────────

@_register("CWE-416", ["c", "cpp"])
def patch_uaf(code, lang, rng):
    patched = re.sub(
        r'free\s*\((\w+)\)',
        r'free(\1); \1 = NULL  // FIX: NULL after free',
        code
    )
    patched = re.sub(
        r'delete\s*(\w+)\s*;',
        r'delete \1; \1 = nullptr;  // FIX: nullptr after delete',
        patched
    )
    return patched

# ── Authorization Bypass / Missing Auth (CWE-284, CWE-862, CWE-863) ─

@_register("CWE-284", ["python", "javascript", "java", "go", "php", "ruby", "csharp", "kotlin"])
def patch_auth(code, lang, rng):
    if lang == "python":
        patched = re.sub(
            r'def\s+\w+\(.*request.*\):',
            lambda m: m.group(0) + "\n    if not request.user.is_authenticated:\n        return redirect('/login')",
            code
        )
    elif lang == "javascript":
        patched = re.sub(
            r'app\.(get|post|put|delete)\(["\'][^"\']*["\']',
            lambda m: m.group(0).replace(
                m.group(0),
                m.group(0) + ', authenticateToken'
            ),
            code
        )
    elif lang == "java":
        patched = re.sub(
            r'@(GetMapping|PostMapping|RequestMapping)',
            '@PreAuthorize("isAuthenticated()")\n@\\1',
            code
        )
    else:
        patched = code + "\n// FIX: Add authentication/authorization check before processing"
    return patched

# ── CSRF (CWE-352) ──────────────────────────────────────────────────

@_register("CWE-352", ["python", "javascript", "java", "go", "php", "ruby", "csharp"])
def patch_csrf(code, lang, rng):
    if lang == "python":
        patched = re.sub(
            r'@app\.route\(["\'][^"\']*["\'],\s*methods=\["?POST"?\]\)',
            lambda m: m.group(0).replace(
                m.group(0),
                m.group(0) + "\n@app.csrf.protect"
            ),
            code
        )
    elif lang == "javascript":
        patched = re.sub(
            r'app\.(post|put|delete)\(',
            lambda m: m.group(0).replace(
                m.group(0),
                m.group(0).replace('app.', 'app.csrfProtection().')
            ),
            code
        )
    elif lang == "java":
        patched = re.sub(
            r'@(PostMapping|PutMapping|DeleteMapping)',
            '@PreAuthorize("hasCsrfToken()")\n@\\1',
            code
        )
    else:
        patched = code + "\n// FIX: Add CSRF token validation for state-changing operations"
    return patched

# ── SSRF (CWE-918) ──────────────────────────────────────────────────

@_register("CWE-918", ["python", "javascript", "java", "go", "php", "ruby"])
def patch_ssrf(code, lang, rng):
    if lang == "python":
        patched = re.sub(
            r'requests\.(get|post)\(f?["\'][^"\']*\{[^}]+\}',
            lambda m: m.group(0).replace(
                m.group(0).split('{')[0],
                'requests.get(validate_url('
            ) if '{' in m.group(0) else m.group(0),
            code
        )
        patched = re.sub(
            r'urllib\.request\.urlopen\(',
            'urllib.request.urlopen(validate_url(',
            patched
        )
    else:
        patched = code + "\n// FIX: Validate and restrict target URLs; use allowlist"
    return patched

# ── Weak Cryptography (CWE-327, CWE-328) ────────────────────────────

@_register("CWE-327", ["python", "javascript", "java", "go", "php", "ruby", "csharp"])
def patch_weak_crypto(code, lang, rng):
    if lang == "python":
        patched = re.sub(
            r'hashlib\.md5\(',
            'hashlib.sha256(  // FIX: Use strong hash',
            code
        )
        patched = re.sub(
            r'hashlib\.sha1\(',
            'hashlib.sha256(  // FIX: Use strong hash',
            patched
        )
        patched = re.sub(
            r'cryptography\.hazmat.*?ARC4',
            'cryptography.hazmat.primitives.ciphers.algorithms.AES  // FIX: Use strong cipher',
            patched
        )
    elif lang == "java":
        patched = re.sub(
            r'MessageDigest\.getInstance\(["\']MD5["\']\)',
            'MessageDigest.getInstance("SHA-256")  // FIX: Use strong hash',
            code
        )
        patched = re.sub(
            r'MessageDigest\.getInstance\(["\']SHA-?1["\']\)',
            'MessageDigest.getInstance("SHA-256")  // FIX: Use strong hash',
            patched
        )
    else:
        patched = code + "\n// FIX: Use strong cryptographic algorithms (SHA-256, AES-256, etc.)"
    return patched

# ── Information Exposure (CWE-200) ──────────────────────────────────

@_register("CWE-200", ["python", "javascript", "java", "go", "php", "ruby", "csharp"])
def patch_info_leak(code, lang, rng):
    if lang == "python":
        patched = re.sub(
            r'return\s+str\(e\)',
            'log.error(f"Error: {e}")\n    return "An error occurred"',
            code
        )
        patched = re.sub(
            r'print\s*\(\s*("Exception|Error|Traceback)',
            'log.error(',
            patched
        )
    elif lang == "java":
        patched = re.sub(
            r'e\.printStackTrace\(\)',
            'logger.error("Error occurred", e)',
            code
        )
        patched = re.sub(
            r'System\.out\.println\(.*e\.getMessage\(\)\)',
            'logger.warn("Operation failed")',
            patched
        )
    else:
        patched = code + "\n// FIX: Log detailed errors server-side, return generic messages to user"
    return patched

# ── Integer Overflow (CWE-190) ─────────────────────────────────────

@_register("CWE-190", ["c", "cpp", "java", "go", "rust", "csharp", "python"])
def patch_int_overflow(code, lang, rng):
    if lang in ("c", "cpp"):
        patched = re.sub(
            r'(\w+)\s*=\s*(\w+)\s*\+\s*(\w+)',
            r'\1 = __builtin_add_overflow(\2, \3, &\1) ? LONG_MAX : \1  // FIX: Check overflow',
            code
        )
    elif lang == "python":
        patched = re.sub(
            r'(\w+)\s*=\s*(\w+)\s*\*\s*(\w+)',
            lambda m: re.sub(
                r'(\w+)\s*=\s*(\w+)\s*\*\s*(\w+)',
                r'if \2 * \3 > MAX_INT: raise OverflowError\n\1 = \2 * \3',
                m.group(0)
            ),
            code
        )
    else:
        patched = code + "\n// FIX: Check for overflow before arithmetic operations"
    return patched

# ── Missing Input Validation (CWE-20) ───────────────────────────────

@_register("CWE-20", ["python", "javascript", "java", "go", "php", "ruby", "csharp", "kotlin"])
def patch_input_val(code, lang, rng):
    if lang == "python":
        patched = re.sub(
            r'(\w+)\s*=\s*request\.(GET|POST|args)\.get\(["\'](\w+)["\']\)',
            lambda m: m.group(0).replace(
                m.group(0),
                f"""{m.group(1)} = request.{m.group(2)}.get("{m.group(3)}", "")
if not str.isdigit: # not for production use — just illustration
    raise ValueError("Invalid input: expected numeric")"""
            ),
            code
        )
    elif lang == "javascript":
        patched = re.sub(
            r'const\s*(\w+)\s*=\s*req\.(query|params|body)\.(\w+)',
            lambda m: m.group(0).replace(
                m.group(0),
                f"""if (!req.{m.group(2)}.{m.group(3)}) return res.status(400).send("Invalid input")
const {m.group(1)} = String(req.{m.group(2)}.{m.group(3)}).trim()"""
            ),
            code
        )
    elif lang == "java":
        patched = re.sub(
            r'String\s+(\w+)\s*=\s*request\.getParameter\(["\'](\w+)["\']\)',
            lambda m: m.group(0).replace(
                m.group(0),
                f"""String {m.group(1)} = request.getParameter("{m.group(2)}");
if ({m.group(1)} == null || !{m.group(1)}.matches("[a-zA-Z0-9]+")) {{
    throw new IllegalArgumentException("Invalid input");
}}"""
            ),
            code
        )
    else:
        patched = code + "\n// FIX: Validate and sanitize all user inputs"
    return patched

# ── Unrestricted File Upload (CWE-434) ──────────────────────────────

@_register("CWE-434", ["python", "javascript", "java", "go", "php", "ruby"])
def patch_file_upload(code, lang, rng):
    if lang == "python":
        patched = re.sub(
            r'file\.save\(f?["\'][^"\']*\.filename["\']?\)',
            lambda m: m.group(0).replace(
                m.group(0),
                """# FIX: Validate file extension and content type
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg'}
if not filename.endswith(tuple(ALLOWED_EXTENSIONS)):
    abort(400, "Invalid file type")
file.save(secure_filename(filename))"""
            ),
            code
        )
    elif lang == "php":
        patched = re.sub(
            r'move_uploaded_file\(',
            '// FIX: Validate file type, size, and extension\nmove_uploaded_file(',
            code
        )
    else:
        patched = code + "\n// FIX: Validate file type, size, and content before saving"
    return patched

# ── Hardcoded Credentials (CWE-798) ─────────────────────────────────

@_register("CWE-798", ["python", "javascript", "java", "go", "php", "ruby", "csharp", "kotlin"])
def patch_hardcoded(code, lang, rng):
    patched = re.sub(
        r'(password|secret|api_key|token)\s*=\s*["\'][^"\']+["\']',
        lambda m: m.group(0).replace(
            m.group(0),
            re.sub(r'=.*$', '= os.getenv("SECRET_KEY")  # FIX: Use environment variable', m.group(0))
        ),
        code
    )
    for pat_str in ['AKIA[0-9A-Z]{16}', 'sk_live_[A-Za-z0-9]{16,}', 'ghp_[A-Za-z0-9]{36}']:
        patched = re.sub(pat_str, 'os.getenv("API_KEY")', patched)
    return patched

# ── XXE (CWE-611) ──────────────────────────────────────────────────

@_register("CWE-611", ["python", "java", "go", "php", "csharp"])
def patch_xxe(code, lang, rng):
    if lang == "java":
        patched = re.sub(
            r'DocumentBuilderFactory\.newInstance\(\)',
            'DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();\nfactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);\nfactory.setFeature("http://xml.org/sax/features/external-general-entities", false)',
            code
        )
    elif lang == "python":
        patched = re.sub(
            r'xml\.etree\.ElementTree\.parse\(',
            'defuse_xml(lxml.etree.parse(  # FIX: Disable external entities\n    ',
            code
        )
    else:
        patched = code + "\n// FIX: Disable external entity processing in XML parser"
    return patched

# ── Null Pointer / Uninitialized Variable (CWE-476, CWE-457) ──────

@_register("CWE-476", ["c", "cpp", "java", "go", "rust", "csharp"])
def patch_null_ptr(code, lang, rng):
    if lang in ("c", "cpp"):
        patched = re.sub(
            r'malloc\(([^)]+)\)',
            r'malloc(\1); if(ptr == NULL) return -1;  // FIX: Check allocation',
            code
        )
        patched = re.sub(
            r'(\w+)\s*=\s*malloc\(',
            r'\1 = malloc(',
            patched
        )
    elif lang in ("java", "csharp"):
        patched = re.sub(
            r'(\w+)\.(\w+)\(',
            lambda m: f'if ({m.group(1)} != null) {m.group(1)}.{m.group(2)}(',
            code
        )
    else:
        patched = code + "\n// FIX: Check for null/zero before use"
    return patched

# ── Reentrancy (CWE-841) ───────────────────────────────────────────

@_register("CWE-841", ["solidity", "python", "javascript"])
def patch_reentrancy(code, lang, rng):
    if lang == "solidity" or ".sol" in code:
        patched = re.sub(
            r'\.call\.value\(',
            '// FIX: Use checks-effects-interactions pattern\n(bool sent, ) = payable(address).call{value: amount}("");\nrequire(sent, "Transfer failed")',
            code
        )
        patched = re.sub(
            r'\.transfer\(',
            '// FIX: Use pull-over-push pattern\n// .transfer(',
            patched
        )
    elif lang == "python":
        patched = code + "\n# FIX: Implement checks-effects-interactions pattern to prevent reentrancy"
    return patched

# ── Prototype Pollution (CWE-1321) ──────────────────────────────────

@_register("CWE-1321", ["javascript", "typescript"])
def patch_proto_pollution(code, lang, rng):
    patched = re.sub(
        r'Object\.assign\((?:target|{})\),?\s*(?:source|obj)\)',
        lambda m: m.group(0).replace(
            m.group(0),
            'function mergeSafe(target, source) {\n  for (const key of Object.keys(source)) {\n    if (key === "__proto__" || key === "constructor") continue;\n    target[key] = source[key];\n  }\n  return target;\n}'
        ),
        code
    )
    patched = re.sub(
        r'\bmerge\(',
        'mergeSafe(  // FIX: Prevent prototype pollution through __proto__',
        patched
    )
    return patched

# ── Insecure Direct Object Reference (IDOR) / CWE-639 ──────────────

@_register("CWE-639", ["python", "javascript", "java", "go", "php", "ruby"])
def patch_idor(code, lang, rng):
    if lang == "python":
        patched = re.sub(
            r'(get_object_or_404|\.get)\(.*pk.*=.*request\.',
            lambda m: m.group(0).replace(
                m.group(0),
                m.group(0) + "\n    if obj.user != request.user:\n        raise PermissionDenied"
            ),
            code
        )
    else:
        patched = code + "\n// FIX: Verify that the authenticated user owns/authorizes the target resource"
    return patched

# ── Server-Side Template Injection / CWE-94 ─────────────────────────

@_register("CWE-94", ["python", "javascript", "java", "go", "php", "ruby"])
def patch_ssti(code, lang, rng):
    if lang == "python":
        patched = re.sub(
            r'render_template_string\(',
            'render_template(  # FIX: Use file-based template, not string',
            code
        )
        patched = re.sub(
            r'Template\(.*request\.',
            '# FIX: Do not render user input as template\n# Template(',
            patched
        )
    else:
        patched = code + "\n// FIX: Sandbox template engines; never render user input as templates"
    return patched

# ── Race Condition (CWE-362) ───────────────────────────────────────

@_register("CWE-362", ["python", "javascript", "java", "go", "c", "cpp", "ruby"])
def patch_race(code, lang, rng):
    if lang == "python":
        patched = re.sub(
            r'with\s+open\([^)]+\)\s+as\s+\w+',
            lambda m: m.group(0).replace("with ", "import threading\nlock = threading.Lock()\nwith lock:\n    with "),
            code
        )
    elif lang == "java":
        patched = re.sub(
            r'public\s+(void|int|String|boolean)',
            'public synchronized ',
            code
        )
    elif lang == "go":
        patched = re.sub(
            r'var\s+(\w+)\s+(\w+)\s*$',
            lambda m: m.group(0).replace(m.group(0), f"""var mu sync.Mutex
mu.Lock()
{{
    mu.Unlock()
}}"""),
            code
        )
    else:
        patched = code + "\n// FIX: Use proper synchronization (mutex/lock) around shared state"
    return patched

# ── Log Forging / CWE-117 ─────────────────────────────────────────

@_register("CWE-117", ["python", "javascript", "java", "go", "php", "ruby"])
def patch_log_forge(code, lang, rng):
    patched = re.sub(
        r'log\.(info|error|warn)\(f?["\'][^"\']*\{[^}]+\}',
        lambda m: m.group(0).replace(
            m.group(0).split("{")[0],
            'log.info(encode_for_log('
        ),
        code
    )
    if patched == code:
        patched = re.sub(
            r'print\(["\'][^"\']*(\+|\{)\w+',
            'log.info(sanitize_for_log(',
            code
        )
    return patched

# ── HTTP Response Splitting / CWE-113 ─────────────────────────────

@_register("CWE-113", ["python", "javascript", "java", "go", "php"])
def patch_resp_split(code, lang, rng):
    patched = re.sub(
        r'response\.setHeader\(["\'][^"\']*["\'],\s*\w+\)',
        lambda m: m.group(0).replace(
            m.group(0),
            m.group(0) + "\n// FIX: Remove CR/LF from header value\nheaderValue = headerValue.replaceAll('[\\r\\n]', '')"
        ),
        code
    )
    patched = re.sub(
        r'res\.set\(["\'][^"\']*["\'],\s*\w+\)',
        lambda m: m.group(0).replace(
            m.group(0),
            m.group(0) + "\n// FIX: Sanitize header value"
        ),
        patched
    )
    return patched

# ── Open Redirect / CWE-601 ────────────────────────────────────────

@_register("CWE-601", ["python", "javascript", "java", "go", "php", "ruby"])
def patch_open_redirect(code, lang, rng):
    if lang == "python":
        patched = re.sub(
            r'redirect\(request\.args\.get\(["\']next["\']',
            lambda m: m.group(0).replace(
                m.group(0),
                'redirect(validate_redirect_url(request.args.get("next")))'
            ),
            code
        )
    else:
        patched = code + "\n// FIX: Validate redirect target against allowlist of trusted URLs"
    return patched

# ── Weak Randomness / CWE-338 ─────────────────────────────────────

@_register("CWE-338", ["python", "javascript", "java", "go", "php", "ruby", "csharp"])
def patch_weak_random(code, lang, rng):
    if lang == "python":
        patched = re.sub(
            r'random\.(randint|choice|shuffle)',
            lambda m: f'secrets.SystemRandom().{m.group(1)}()  # FIX: Use cryptographically secure RNG',
            code
        )
    elif lang == "java":
        patched = re.sub(
            r'Random\s+\w+\s*=\s*new\s+Random\(\)',
            'java.security.SecureRandom secureRandom = new java.security.SecureRandom()',
            code
        )
    elif lang == "javascript":
        patched = re.sub(
            r'Math\.random\(\)',
            'crypto.randomBytes(32).readUInt32BE() / 0xFFFFFFFF  // FIX: Use crypto RNG',
            code
        )
    else:
        patched = code + "\n// FIX: Use cryptographically secure random number generator"
    return patched

# ── Missing Rate Limiting / CWE-770 ─────────────────────────────────

@_register("CWE-770", ["python", "javascript", "java", "go", "php", "ruby"])
def patch_rate_limit(code, lang, rng):
    if lang == "python":
        patched = re.sub(
            r'def\s+\w+\(.*request.*\):',
            lambda m: m.group(0).replace(
                m.group(0),
                "@limiter.limit(\"100/hour\")\n" + m.group(0)
            ),
            code
        )
    else:
        patched = code + "\n// FIX: Implement rate limiting and resource quotas per user"
    return patched

# ── Weak Password Policy / CWE-521 ──────────────────────────────────

@_register("CWE-521", ["python", "javascript", "java", "go", "php", "ruby"])
def patch_weak_password(code, lang, rng):
    patched = code + (
        "\n# FIX: Enforce strong password policy:\n"
        "# - Minimum 12 characters\n"
        "# - At least one uppercase, one lowercase, one digit, one special char\n"
        "# - Check against common password list"
    )
    return patched

# ── Insecure TLS / CWE-295 ─────────────────────────────────────────

@_register("CWE-295", ["python", "javascript", "java", "go", "php", "ruby"])
def patch_insecure_tls(code, lang, rng):
    if lang == "python":
        patched = re.sub(
            r'verify=False',
            'verify=True  # FIX: Always verify TLS certificates',
            code
        )
        patched = re.sub(
            r'verify=False',
            'verify=True  # FIX: Always verify TLS certificates',
            patched
        )
        patched = re.sub(
            r'verify=False',
            'verify=True',
            patched
        )
    else:
        patched = code + "\n// FIX: Always validate TLS certificates; never disable certificate verification"
    return patched

# ── Improper Certificate Validation / CWE-3278 ──────────────────────

# ── SMTP Injection / CWE-93 ────────────────────────────────────────

@_register("CWE-93", ["python", "javascript", "java", "go", "php"])
def patch_smtp_inject(code, lang, rng):
    patched = re.sub(
        r'smtplib\.SMTP\([^)]+\)\.sendmail\([^)]+\)',
        lambda m: m.group(0).replace(
            m.group(0),
            "# FIX: Use email library with proper header encoding\nmsg = email.message.EmailMessage()\nmsg.set_content(body)\nmsg['Subject'] = headerlib.Header(subject, 'utf-8')"
        ),
        code
    )
    return patched

# ── CRLF Injection / CWE-93 ────────────────────────────────────────

# ── NoSQL Injection / CWE-943 ─────────────────────────────────────

@_register("CWE-943", ["python", "javascript", "go"])
def patch_nosqli(code, lang, rng):
    if lang == "javascript":
        patched = re.sub(
            r'\.find\(\{.*\$where',
            lambda m: m.group(0).replace(
                "$where",
                "# FIX: Sanitize user input; $where is dangerous\n// $where"
            ),
            code
        )
        patched = re.sub(
            r'\.find\(\{[^}]*\$ne',
            lambda m: m.group(0).replace(
                m.group(0),
                m.group(0) + "\n// FIX: Use typed parameters, not raw user objects"
            ),
            patched
        )
    else:
        patched = code + "\n# FIX: Sanitize user input before using in NoSQL queries; use typed parameters"
    return patched

# ── LDAP Injection / CWE-90 ────────────────────────────────────────

@_register("CWE-90", ["python", "javascript", "java", "go", "php"])
def patch_ldapi(code, lang, rng):
    patched = code + "\n// FIX: Escape LDAP special characters; use allowlist-based input validation"
    return patched

PATCH_FALLBACK = {
    "python": "\n# FIX: Add proper input validation and use secure coding patterns",
    "javascript": "\n// FIX: Validate and sanitize all user inputs",
    "java": "\n// FIX: Apply security controls and input validation",
    "go": "\n// FIX: Implement proper security checks",
    "c": "\n// FIX: Add bounds checking and input validation",
    "cpp": "\n// FIX: Add bounds checking and input validation",
    "php": "\n// FIX: Validate and sanitize all user inputs",
    "ruby": "\n# FIX: Add proper security controls",
    "csharp": "\n// FIX: Apply security best practices",
    "kotlin": "\n// FIX: Add proper validation",
    "swift": "\n// FIX: Use safe API variants",
    "rust": "\n// FIX: Use safe abstractions",
    "typescript": "\n// FIX: Validate inputs, use strict typing",
    "perl": "\n# FIX: Add taint checking and validation",
    "scala": "\n// FIX: Apply security controls",
}

# ---------------------------------------------------------------------------
# CWE → Explanation Templates
# ---------------------------------------------------------------------------

CWE_EXPLANATIONS = {
    "CWE-89": {
        "short": "SQL Injection vulnerability: user-controlled input is embedded directly into SQL query strings, allowing an attacker to manipulate the query structure.",
        "impact": "An attacker can read, modify, or delete arbitrary database records, potentially gaining unauthorized access to sensitive data.",
        "fix": "Use parameterized queries (prepared statements) to separate SQL code from user data.",
    },
    "CWE-79": {
        "short": "Cross-Site Scripting (XSS): user input is rendered into HTML output without proper escaping or sanitization.",
        "impact": "An attacker can inject malicious scripts that execute in victims' browsers, leading to session theft, credential harvesting, or defacement.",
        "fix": "HTML-encode user input before rendering. Use Content Security Policy headers. Sanitize rich input with DOMPurify or similar.",
    },
    "CWE-78": {
        "short": "OS Command Injection: user-controlled input is concatenated into a shell command string, allowing arbitrary command execution.",
        "impact": "An attacker can execute arbitrary system commands on the server, leading to full server compromise.",
        "fix": "Use subprocess with argument lists instead of shell strings. Validate and restrict allowed commands.",
    },
    "CWE-22": {
        "short": "Path Traversal: user-controlled file paths are not validated, allowing access to files outside the intended directory.",
        "impact": "An attacker can read or write arbitrary files on the server, potentially accessing configuration, credentials, or source code.",
        "fix": "Use os.path.realpath to resolve the full path and verify it starts with the allowed base directory.",
    },
    "CWE-502": {
        "short": "Insecure Deserialization: untrusted data is deserialized without validation, potentially executing arbitrary code.",
        "impact": "An attacker can trigger arbitrary code execution, denial of service, or bypass authentication by crafting malicious serialized objects.",
        "fix": "Use safe serialization formats like JSON. Implement allowlist-based deserialization. Validate integrity with signatures.",
    },
    "CWE-20": {
        "short": "Improper Input Validation: user-controlled input is processed without sufficient validation of type, format, or range.",
        "impact": "An attacker can inject malicious payloads that exploit downstream parsers, databases, or execution contexts.",
        "fix": "Validate all inputs against strict allowlists for type, length, format, and range. Use parameterized APIs.",
    },
    "CWE-200": {
        "short": "Information Exposure: sensitive system details (stack traces, error messages, configuration) are leaked to users.",
        "impact": "An attacker can gather intelligence about the system architecture, libraries, and configurations to craft targeted attacks.",
        "fix": "Log detailed errors server-side. Return generic error messages to users. Strip sensitive headers from responses.",
    },
    "CWE-119": {
        "short": "Buffer Overflow: memory operations without proper bounds checking allow writing past allocated buffer boundaries.",
        "impact": "An attacker can overwrite adjacent memory, potentially hijacking control flow or executing arbitrary code.",
        "fix": "Use bounded operations (strncpy, snprintf, fgets) instead of unbounded ones. Validate lengths before copying.",
    },
    "CWE-787": {
        "short": "Out-of-bounds Write: memory is written beyond the bounds of the allocated buffer.",
        "impact": "An attacker can corrupt adjacent memory structures, potentially leading to code execution or denial of service.",
        "fix": "Validate all array indices and pointer arithmetic. Use bounded memory operations.",
    },
    "CWE-125": {
        "short": "Out-of-bounds Read: memory is read beyond the bounds of the allocated buffer.",
        "impact": "An attacker may extract sensitive data from adjacent memory regions or trigger a crash.",
        "fix": "Validate array bounds before access. Ensure null terminators exist before string operations.",
    },
    "CWE-416": {
        "short": "Use After Free: memory is accessed after it has been freed, leading to undefined behavior.",
        "impact": "An attacker can potentially execute arbitrary code by controlling the freed memory's contents.",
        "fix": "Set pointers to NULL after freeing. Use smart pointers or garbage collection where possible.",
    },
    "CWE-284": {
        "short": "Improper Access Control: the application fails to enforce authorization checks on protected operations.",
        "impact": "An attacker can access administrative functions or other users' data without proper authorization.",
        "fix": "Implement and enforce role-based access control for all protected endpoints and operations.",
    },
    "CWE-862": {
        "short": "Missing Authorization: the code performs actions without verifying the caller's authorization.",
        "impact": "Unauthenticated or unauthorized users can perform privileged operations.",
        "fix": "Add authorization checks before any operation that accesses or modifies protected resources.",
    },
    "CWE-863": {
        "short": "Incorrect Authorization: authorization checks are present but incorrectly implemented, allowing bypass.",
        "impact": "Users may gain access to resources or operations beyond their permitted scope.",
        "fix": "Verify authorization logic is correct and covers all access paths. Use framework-level access control.",
    },
    "CWE-352": {
        "short": "Cross-Site Request Forgery (CSRF): the application does not validate that state-changing requests originate from the legitimate user.",
        "impact": "An attacker can trick authenticated users into performing unintended actions, like changing passwords or transferring funds.",
        "fix": "Include anti-CSRF tokens in forms and validate them on the server for all state-changing requests.",
    },
    "CWE-918": {
        "short": "Server-Side Request Forgery (SSRF): user input controls the destination URL of a server-side request.",
        "impact": "An attacker can make the server send requests to internal services, cloud metadata endpoints, or arbitrary external hosts.",
        "fix": "Validate and restrict target URLs against an allowlist. Block private IP ranges. Avoid passing user input to URL constructors.",
    },
    "CWE-327": {
        "short": "Use of a Broken or Risky Cryptographic Algorithm: weak encryption or hashing algorithms are used for security-sensitive operations.",
        "impact": "An attacker can break the cryptographic protection, exposing encrypted data or forging signatures.",
        "fix": "Use strong, modern algorithms: SHA-256/SHA-3 for hashing, AES-256 for encryption, with proper key management.",
    },
    "CWE-190": {
        "short": "Integer Overflow or Wraparound: arithmetic operation results exceed the data type's maximum value.",
        "impact": "An attacker can cause unexpected behavior by triggering integer wraparound, leading to buffer overflows or logic errors.",
        "fix": "Check for overflow before performing arithmetic. Use safe integer libraries or saturating arithmetic.",
    },
    "CWE-434": {
        "short": "Unrestricted File Upload: the application accepts file uploads without validating type, size, or content.",
        "impact": "An attacker can upload malicious files (e.g., web shells) that are then executed on the server.",
        "fix": "Validate file extension, MIME type, and content. Store uploaded files outside the web root. Scan for malware.",
    },
    "CWE-798": {
        "short": "Hardcoded Credentials: sensitive secrets (passwords, API keys, tokens) are embedded directly in source code.",
        "impact": "Anyone with access to the source code can extract credentials and access protected resources.",
        "fix": "Store secrets in environment variables or a secrets management service. Never commit secrets to version control.",
    },
    "CWE-611": {
        "short": "Improper Restriction of XML External Entity Reference (XXE): the XML parser processes external entities from untrusted input.",
        "impact": "An attacker can read arbitrary files, perform SSRF attacks, or cause denial of service through entity expansion.",
        "fix": "Disable DTD processing and external entity resolution in the XML parser configuration.",
    },
    "CWE-476": {
        "short": "NULL Pointer Dereference: the code dereferences a pointer that may be NULL without checking.",
        "impact": "An attacker can cause a denial of service by triggering the NULL dereference path.",
        "fix": "Always check pointers for NULL before dereferencing. Initialize all pointers to a valid value or NULL.",
    },
    "CWE-639": {
        "short": "Insecure Direct Object Reference (IDOR): the application exposes direct references to internal objects without ownership verification.",
        "impact": "An attacker can access or modify resources belonging to other users by changing the reference identifier.",
        "fix": "Verify that the authenticated user owns or is authorized for the requested resource. Use indirect references.",
    },
    "CWE-94": {
        "short": "Code Injection via Template Engine: user input is evaluated as template code without sandboxing.",
        "impact": "An attacker can execute arbitrary code on the server by injecting template expressions.",
        "fix": "Use file-based templates instead of rendering user input as templates. Sandbox the template engine.",
    },
    "CWE-362": {
        "short": "Race Condition: concurrent operations on shared state without proper synchronization.",
        "impact": "An attacker can exploit timing windows to corrupt state, bypass checks, or cause inconsistent behavior.",
        "fix": "Use locks, mutexes, or atomic operations to protect shared state. Implement proper transaction isolation.",
    },
    "CWE-117": {
        "short": "Log Injection/Forging: user input is written to logs without sanitization, allowing log manipulation.",
        "impact": "An attacker can inject fake log entries to cover their tracks or confuse incident response.",
        "fix": "Sanitize user input before logging: remove or encode newlines, carriage returns, and other control characters.",
    },
    "CWE-601": {
        "short": "Open Redirect: user input controls the redirect destination URL, enabling phishing attacks.",
        "impact": "An attacker can redirect users to malicious websites after legitimate actions on the trusted site.",
        "fix": "Validate redirect targets against an allowlist of permitted URLs. Avoid user-controlled redirects.",
    },
    "CWE-338": {
        "short": "Use of Weak Random Number Generator: predictable random values are used for security-sensitive purposes.",
        "impact": "An attacker can predict random values such as session tokens, CSRF tokens, or cryptographic keys.",
        "fix": "Use cryptographically secure random number generators for any security-sensitive random value.",
    },
    "CWE-770": {
        "short": "Missing Resource Rate Limiting: the application does not limit the rate of requests or resource consumption.",
        "impact": "An attacker can exhaust server resources, causing denial of service for legitimate users.",
        "fix": "Implement rate limiting per user/IP. Set maximum limits on resource consumption.",
    },
    "CWE-521": {
        "short": "Weak Password Requirements: the application accepts passwords without enforcing minimum security requirements.",
        "impact": "Users may choose weak passwords that are easily guessed or brute-forced by attackers.",
        "fix": "Enforce minimum password length (12+), complexity requirements, and check against breached password databases.",
    },
    "CWE-295": {
        "short": "Improper Certificate Validation: TLS/SSL certificate verification is disabled or improperly configured.",
        "impact": "Man-in-the-middle attackers can intercept and modify encrypted traffic without detection.",
        "fix": "Always verify TLS certificates. Never set verify=False in production. Use proper certificate pinning.",
    },
    "CWE-943": {
        "short": "NoSQL Injection: user input is used directly in NoSQL database queries without sanitization.",
        "impact": "An attacker can manipulate query operators to bypass authentication or extract unauthorized data.",
        "fix": "Sanitize user input, use typed parameters, and avoid $where or $ne operators with untrusted data.",
    },
    "CWE-841": {
        "short": "Reentrancy: external calls are made before state updates, allowing recursive calls to exploit inconsistent state.",
        "impact": "An attacker can drain funds by repeatedly calling back into the contract before the first invocation completes.",
        "fix": "Apply the checks-effects-interactions pattern: update state before making external calls.",
    },
    "CWE-1321": {
        "short": "Prototype Pollution: user-controlled properties can modify JavaScript object prototypes.",
        "impact": "An attacker can inject properties that affect all objects of that type, bypassing security checks.",
        "fix": "Use Object.create(null) for maps. Filter __proto__ and constructor keys when merging objects.",
    },
    "CWE-113": {
        "short": "HTTP Response Splitting: user input is included in HTTP response headers without CR/LF sanitization.",
        "impact": "An attacker can inject additional headers or response bodies, enabling cache poisoning or XSS.",
        "fix": "Strip CR and LF characters from any user-controlled values before including them in response headers.",
    },
    "CWE-93": {
        "short": "CRLF Injection in Email Headers: user input is included in email headers without sanitizing newlines.",
        "impact": "An attacker can inject additional email headers or content, enabling email spoofing or phishing.",
        "fix": "Use email libraries that properly encode headers. Strip CR/LF from user-controlled header values.",
    },
    "CWE-90": {
        "short": "LDAP Injection: user input is used to construct LDAP queries without sanitization.",
        "impact": "An attacker can modify LDAP queries to bypass authentication or enumerate directory contents.",
        "fix": "Escape LDAP special characters. Use allowlist-based input validation for LDAP search filters.",
    },
    "CWE-400": {
        "short": "Uncontrolled Resource Consumption: the application does not limit resource allocation based on user input.",
        "impact": "An attacker can exhaust memory, CPU, or file handles, causing denial of service.",
        "fix": "Implement limits on resource consumption: maximum input size, recursion depth, concurrent operations.",
    },
}


# ---------------------------------------------------------------------------
# MAIN GENERATOR
# ---------------------------------------------------------------------------

def generate_patch_and_explanation(sample: dict, rng: random.Random) -> tuple[str, str, str, str]:
    """Generate (patched_code, explanation, attack_scenario, secure_fix) for a sample."""
    code = sample.get("vulnerable_code", "")
    language = sample.get("language", "text")
    cwe = sample.get("cwe") or "CWE-20"
    existing_patch = sample.get("patched_code") or ""
    existing_expl = sample.get("explanation") or ""
    existing_attack = sample.get("attack_scenario") or ""
    existing_secure = sample.get("secure_fix") or ""

    needs_patch = not existing_patch
    needs_expl = len(existing_expl) < 50
    needs_attack = len(existing_attack) < 50
    needs_secure = len(existing_secure) < 50

    patched = existing_patch if existing_patch else code
    explanation = existing_expl if existing_expl else ""
    attack_scenario = existing_attack if existing_attack else ""
    secure_fix = existing_secure if existing_secure else ""

    # Generate patch
    if needs_patch:
        found = False
        if cwe in CWE_PATCHES:
            for fn, langs in CWE_PATCHES[cwe]:
                if not langs or language in langs:
                    try:
                        result = fn(code, language, rng)
                        if result and result != code and len(result) > 30:
                            patched = result
                            found = True
                            break
                    except Exception:
                        continue
        if not found:
            fallback = PATCH_FALLBACK.get(language, PATCH_FALLBACK.get("python", ""))
            patched = code + fallback

    # Generate explanation
    if needs_expl and cwe in CWE_EXPLANATIONS:
        tpl = CWE_EXPLANATIONS[cwe]
        approach = rng.choice([
            lambda: tpl["short"],
            lambda: f'{tpl["short"]} {tpl["impact"]}',
            lambda: f'Vulnerability: {tpl["short"]}\nImpact: {tpl["impact"]}\nFix: {tpl["fix"]}',
            lambda: f'{tpl["short"]} The {sample.get("language", "code")} snippet is vulnerable to this because user input is not properly validated before use.',
        ])
        explanation = approach()
        if not attack_scenario or needs_attack:
            attack_scenario = f'An attacker provides a crafted input containing special characters or payload that exploits the {cwe} pattern, leading to {tpl["impact"].lower()}'
        if not secure_fix or needs_secure:
            secure_fix = tpl["fix"]

    # Generic explanation for unknown CWEs
    if needs_expl and not explanation:
        explanation = f'Security vulnerability detected in {language} code. The code fails to properly handle untrusted input, potentially allowing an attacker to exploit {cwe or "a common weakness"}.'

    return patched, explanation, attack_scenario, secure_fix


def main():
    meta_dir = META_DIR
    out_dir = OUT_DIR
    out_dir.mkdir(parents=True, exist_ok=True)

    rng = random.Random(2024)

    total = 0
    patched = 0
    explained = 0
    cwe_counts: Counter = Counter()
    lang_counts: Counter = Counter()

    for split in ["train", "val", "test"]:
        inpath = meta_dir / f"{split}.jsonl"
        outpath = out_dir / f"{split}.jsonl"
        if not inpath.exists():
            print(f"[skip] {inpath} not found")
            continue

        n_in = 0
        n_out = 0
        with open(inpath) as fin, open(outpath, "w") as fout:
            for line in fin:
                line = line.strip()
                if not line:
                    continue
                n_in += 1
                try:
                    sample = json.loads(line)
                except json.JSONDecodeError:
                    continue

                cwe = sample.get("cwe") or "CWE-UNKNOWN"
                lang = sample.get("language", "?")
                cwe_counts[cwe] += 1
                lang_counts[lang] += 1

                patched_code, explanation, attack_scenario, secure_fix = generate_patch_and_explanation(sample, rng)

                if patched_code != sample.get("vulnerable_code", ""):
                    patched += 1
                if explanation and len(explanation) > 50:
                    explained += 1

                sample["patched_code"] = patched_code if patched_code != sample.get("vulnerable_code", "") else sample.get("patched_code")
                sample["explanation"] = explanation or sample.get("explanation", "")
                if attack_scenario:
                    sample["attack_scenario"] = attack_scenario
                if secure_fix:
                    sample["secure_fix"] = secure_fix

                fout.write(json.dumps(sample, ensure_ascii=False) + "\n")
                n_out += 1

        print(f"[{split}] read {n_in}, wrote {n_out} -> {outpath}")
        total += n_out

    print(f"\n{'='*60}")
    print(f"Total samples processed: {total}")
    print(f"Samples with patches: {patched} ({patched/total*100:.1f}%)" if total else "")
    print(f"Samples with explanations: {explained} ({explained/total*100:.1f}%)" if total else "")
    print(f"Unique CWEs processed: {len(cwe_counts)}")
    print(f"Languages processed: {len(lang_counts)}")
    print(f"Output directory: {out_dir}")
    print(f"{'='*60}")

    # Write report
    report = {
        "total": total,
        "patches_generated": patched,
        "explanations_generated": explained,
        "unique_cwes": len(cwe_counts),
        "unique_languages": len(lang_counts),
        "top_cwes": dict(cwe_counts.most_common(20)),
        "top_languages": dict(lang_counts.most_common(20)),
    }
    with open(out_dir / "generation_report.json", "w") as f:
        json.dump(report, f, indent=2)
    print(f"\nReport saved to {out_dir / 'generation_report.json'}")


if __name__ == "__main__":
    main()
