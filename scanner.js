#!/usr/bin/env node
/**
 * RakshakAI — multi-language vulnerability scanner.
 * Supports 20+ languages with regex-based detection + CWE mapping.
 */
const fs = require("fs");
const path = require("path");

// ── Supported Languages ────────────────────────────────────────────
const LANGS = {
  ".py": "python", ".js": "javascript", ".ts": "typescript",
  ".jsx": "javascript", ".tsx": "typescript", ".java": "java",
  ".go": "go", ".rs": "rust", ".c": "c", ".cpp": "cpp",
  ".h": "c", ".hpp": "cpp", ".rb": "ruby", ".php": "php",
  ".cs": "csharp", ".swift": "swift", ".kt": "kotlin",
  ".scala": "scala", ".sol": "solidity", ".vue": "vue",
  ".pl": "perl", ".pm": "perl", ".ex": "elixir",
  ".exs": "elixir", ".erl": "erlang", ".hs": "haskell",
  ".r": "r", ".m": "matlab", ".mm": "objectivec",
  ".yml": "yaml", ".yaml": "yaml", ".dockerfile": "dockerfile",
  ".json": "json",
};

const IGNORE_DIRS = new Set([
  "node_modules", ".git", "__pycache__", "venv", ".venv",
  "dist", "build", ".next", ".nuxt", "target", "vendor",
  ".cache", ".opencode", ".tox", "env", ".env",
  "bower_components", "jspm_packages",
]);

// ── CWE / Severity Mapping ────────────────────────────────────────
const SEVERITY = {
  SQL_INJECTION: "critical", XSS: "critical", COMMAND_INJECTION: "critical",
  SSTI: "critical", INSECURE_DESERIALIZATION: "critical", LDAP_INJECTION: "critical",
  XXE_INJECTION: "critical", BUFFER_OVERFLOW: "critical", PATH_TRAVERSAL: "high",
  HARDCODED_SECRET: "high", WEAK_CRYPTO: "medium", CSRF: "medium",
  OPEN_REDIRECT: "medium", JWT_VULNERABILITY: "high", SSRF: "high",
  INSECURE_DIRECT_OBJECT_REF: "medium", SECURITY_MISCONFIG: "medium",
  XPATH_INJECTION: "critical", WEAK_PASSWORD: "medium",
  SSRF_INJECTION: "high", DOCKER_SECURITY: "high", K8S_SECURITY: "high",
  DEPENDENCY_VULN: "high",
};

const CWE = {
  SQL_INJECTION: "CWE-89", XSS: "CWE-79", COMMAND_INJECTION: "CWE-78",
  PATH_TRAVERSAL: "CWE-22", HARDCODED_SECRET: "CWE-798", WEAK_CRYPTO: "CWE-327",
  SSTI: "CWE-1336", INSECURE_DESERIALIZATION: "CWE-502",
  LDAP_INJECTION: "CWE-90", XXE_INJECTION: "CWE-611",
  BUFFER_OVERFLOW: "CWE-120", CSRF: "CWE-352", OPEN_REDIRECT: "CWE-601",
  JWT_VULNERABILITY: "CWE-347", SSRF: "CWE-918",
  INSECURE_DIRECT_OBJECT_REF: "CWE-639", SECURITY_MISCONFIG: "CWE-16",
  XPATH_INJECTION: "CWE-643", WEAK_PASSWORD: "CWE-521",
  SSRF_INJECTION: "CWE-918", DOCKER_SECURITY: "CWE-1220", K8S_SECURITY: "CWE-250",
  DEPENDENCY_VULN: "CWE-1104",
};

// ── Patterns: [regex, label, message] ─────────────────────────────
// Patterns are grouped by language context to reduce false positives.
// Each pattern has an optional language filter.

function p(regex, label, message, langs = null) {
  return { regex, label, message, langs };
}

const PATTERNS = [
  // ═══════════════════════════════════════════════════════════════
  //  SQL INJECTION — All languages
  // ═══════════════════════════════════════════════════════════════
  p(/execute\([^)]*(?:["'`][^"'`]*["'`]\s*[+%]|f["'])/gi, "SQL_INJECTION", "SQL injection via string concatenation in execute()"),
  p(/query\([^)]*(?:["'`][^"'`]*["'`]\s*[+%]|f["'])/gi, "SQL_INJECTION", "SQL injection via query string concatenation"),
  p(/cursor\.execute\s*\(\s*f["']/i, "SQL_INJECTION", "SQL injection via f-string in cursor.execute()"),
  p(/db\.execute\s*\(\s*["'`][^"'`]*\{/i, "SQL_INJECTION", "SQL injection via formatted string in db.execute()"),
  p(/db\.query\s*\(\s*`[^`]*\$\{/i, "SQL_INJECTION", "SQL injection via template literal in db.query()"),
  p(/query\s*=.*\+\s*(?:user|input|name|id|param|get|request)/i, "SQL_INJECTION", "SQL injection via user input concatenation"),
  p(/\$conn->query\s*\(\s*["'][^"']*\$/i, "SQL_INJECTION", "SQL injection via PHP string interpolation"),
  p(/f["'][^"']*SELECT[^"']*["']\s*[.%]/i, "SQL_INJECTION", "SQL injection via f-string/percent formatting"),
  p(/session\.execute\s*\(.*\+|session\.execute\s*\(f["']/i, "SQL_INJECTION", "NoSQL/SQL injection in session.execute()"),

  // ═══════════════════════════════════════════════════════════════
  //  OS COMMAND INJECTION — scoped to actual command execution
  // ═══════════════════════════════════════════════════════════════
  p(/os\.system\s*\(/i, "COMMAND_INJECTION", "os.system() allows shell injection", ["python"]),
  p(/os\.popen\s*\(/i, "COMMAND_INJECTION", "os.popen() allows shell injection", ["python"]),
  p(/subprocess\.[a-z]+\s*\(.*shell\s*=\s*True/i, "COMMAND_INJECTION", "subprocess with shell=True allows injection", ["python"]),
  p(/subprocess\.call\s*\(.*\+/i, "COMMAND_INJECTION", "subprocess.call() with string concatenation", ["python"]),
  p(/Runtime\.getRuntime\(\)\.exec\s*\(/i, "COMMAND_INJECTION", "Java Runtime.exec() allows command injection", ["java"]),
  p(/ProcessBuilder\s*\(.*\+/i, "COMMAND_INJECTION", "ProcessBuilder with concatenation allows injection", ["java"]),
  p(/exec\s*\([^)]*\)\s*(?:;|\n|$)/g, "COMMAND_INJECTION", "exec() on user-controlled input may allow injection", ["javascript", "typescript", "php"]),
  p(/child_process\.exec\s*\(/i, "COMMAND_INJECTION", "child_process.exec() allows shell injection", ["javascript", "typescript"]),
  p(/execSync\s*\(/i, "COMMAND_INJECTION", "execSync() allows shell injection", ["javascript", "typescript"]),
  p(/shell_exec\s*\(/i, "COMMAND_INJECTION", "shell_exec() allows shell injection", ["php"]),
  p(/system\s*\(.*\$.*\)/i, "COMMAND_INJECTION", "system() with variable allows injection", ["php"]),
  p(/(?:exec|execSync|spawn|execFile)\s*\(\s*`[^`]*\$\{/i, "COMMAND_INJECTION", "Shell command via template literal in exec/spawn", ["javascript", "typescript"]),
  p(/os\.exec\s*\(/i, "COMMAND_INJECTION", "os.exec() allows command injection", ["go"]),
  p(/exec\.Command\s*\(/i, "COMMAND_INJECTION", "exec.Command with user input", ["go"]),

  // ═══════════════════════════════════════════════════════════════
  //  HARDCODED SECRETS — All languages
  // ═══════════════════════════════════════════════════════════════
  p(/(?:password|passwd)\s*[=:]\s*["'`][^"'`\s]{4,}["'`]/gi, "HARDCODED_SECRET", "Hardcoded password detected"),
  p(/(?:api[_-]?key|apikey)\s*[=:]\s*["'`][A-Za-z0-9_-]{8,}["'`]/gi, "HARDCODED_SECRET", "Hardcoded API key detected"),
  p(/(?:secret|secret_key)\s*[=:]\s*["'`][^"'`\s]{8,}["'`]/gi, "HARDCODED_SECRET", "Hardcoded secret detected"),
  p(/-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----/, "HARDCODED_SECRET", "Embedded private key detected"),
  p(/['"`](?:sk[-_]|pk[-_]|ghp_|gho_|ghu_|ghs_|ghr_)[A-Za-z0-9_-]{20,}['"`]/g, "HARDCODED_SECRET", "Hardcoded API credential/token"),
  p(/AKIA[0-9A-Z]{16}/g, "HARDCODED_SECRET", "Hardcoded AWS Access Key ID"),
  p(/['"`](?:eyJ)[A-Za-z0-9_-]{10,}(?:\.[A-Za-z0-9_-]{10,}){2}['"`]/g, "HARDCODED_SECRET", "Hardcoded JWT token"),
  p(/token\s*[=:]\s*["'`][A-Za-z0-9_-]{16,}["'`]/gi, "HARDCODED_SECRET", "Hardcoded authentication token"),

  // ═══════════════════════════════════════════════════════════════
  //  XSS (Cross-Site Scripting)
  // ═══════════════════════════════════════════════════════════════
  p(/\.innerHTML\s*=\s*["'`][^"'`]*\+/g, "XSS", "innerHTML with concatenation leads to XSS", ["javascript", "typescript"]),
  p(/document\.write\s*\([^)]*\+/gi, "XSS", "document.write() with concatenated input", ["javascript", "typescript"]),
  p(/\.html\(\s*\$/g, "XSS", "jQuery .html() with unsanitized input", ["javascript", "typescript"]),
  p(/dangerouslySetInnerHTML/i, "XSS", "dangerouslySetInnerHTML bypasses React XSS protection", ["javascript", "typescript"]),
  p(/v-html\s*=/i, "XSS", "v-html directive renders raw HTML in Vue", ["javascript", "typescript"]),
  p(/response\.write\s*\(.*\+/gi, "XSS", "response.write() with concatenated user input", ["javascript", "typescript"]),
  p(/\|\s*safe\b/i, "XSS", "|safe filter disables HTML escaping in Django/Jinja", ["python"]),

  // ═══════════════════════════════════════════════════════════════
  //  PATH TRAVERSAL
  // ═══════════════════════════════════════════════════════════════
  p(/open\([^)]*\+\s*(?:user|input|file|path|name|filename)/gi, "PATH_TRAVERSAL", "User input in file open() allows path traversal"),
  p(/readFile(?:Sync)?\s*\([^)]*\+\s*(?:user|input|file|path|name)/gi, "PATH_TRAVERSAL", "User input in file read allows path traversal"),
  p(/writeFile(?:Sync)?\s*\([^)]*\+\s*(?:user|input|file|path|name)/gi, "PATH_TRAVERSAL", "User input in file write allows path traversal"),
  p(/join\(\s*["'`][^"'`]*["'`]\s*,\s*(?:user|input|file|name|filename)/gi, "PATH_TRAVERSAL", "User-controlled path in file join"),
  p(/(?:file_get_contents|fopen|fwrite|file_put_contents)\s*\([^)]*\$/i, "PATH_TRAVERSAL", "User input in PHP file operations", ["php"]),

  // ═══════════════════════════════════════════════════════════════
  //  WEAK CRYPTOGRAPHY
  // ═══════════════════════════════════════════════════════════════
  p(/\bmd5\s*\(/gi, "WEAK_CRYPTO", "MD5 is vulnerable to collision attacks"),
  p(/\bsha1\s*\(|\bsha\b.*1/gi, "WEAK_CRYPTO", "SHA-1 is deprecated and collision-prone"),
  p(/\bhashlib\.md5\b/gi, "WEAK_CRYPTO", "Replace MD5 with SHA-256 or better", ["python"]),
  p(/\bDES_CBC\b|\bDES_ECB\b/i, "WEAK_CRYPTO", "DES encryption is deprecated and insecure"),
  p(/\bAES\/ECB\b/i, "WEAK_CRYPTO", "AES-ECB mode is insecure (deterministic, no IV)", ["java", "csharp"]),
  p(/\bRSA\/ECB\b/i, "WEAK_CRYPTO", "RSA-ECB padding mode is insecure"),
  p(/\bCrypto\.MD5\b/i, "WEAK_CRYPTO", "MD5 via CryptoJS is collision-vulnerable"),
  p(/MessageDigest\.getInstance\s*\(\s*["']MD5["']/i, "WEAK_CRYPTO", "Java MD5 MessageDigest — use SHA-256", ["java"]),
  p(/\.getBytes\s*\(\)\s*;\s*[\s\S]{0,50}MessageDigest/i, "WEAK_CRYPTO", "Weak hashing via MessageDigest", ["java"]),

  // ═══════════════════════════════════════════════════════════════
  //  BUFFER OVERFLOW — C/C++ specific
  // ═══════════════════════════════════════════════════════════════
  p(/strcpy\s*\(/g, "BUFFER_OVERFLOW", "strcpy() is unsafe — use strncpy() or strlcpy()", ["c", "cpp"]),
  p(/strcat\s*\(/g, "BUFFER_OVERFLOW", "strcat() is unsafe — use strncat()", ["c", "cpp"]),
  p(/gets\s*\(/g, "BUFFER_OVERFLOW", "gets() has no bounds checking — use fgets()", ["c", "cpp"]),
  p(/sprintf\s*\([^,]*,[^,]*(?:%s|%[0-9]+\$)/g, "BUFFER_OVERFLOW", "sprintf with %s can overflow", ["c", "cpp"]),
  p(/scanf\s*\([^)]*%s/g, "BUFFER_OVERFLOW", "scanf %s has no bounds checking", ["c", "cpp"]),
  p(/memcpy\s*\([^)]*,\s*[^,]+,\s*sizeof\s+/g, "BUFFER_OVERFLOW", "memcpy with sizeof may overflow", ["c", "cpp"]),

  // ═══════════════════════════════════════════════════════════════
  //  SSTI (Server-Side Template Injection)
  // ═══════════════════════════════════════════════════════════════
  p(/\.render\s*\([^)]*\+(?:user|input|name|query|param)/gi, "SSTI", "Template injection via string concatenation in render()"),
  p(/\.render\([^)]*request/gi, "SSTI", "Potential SSTI with request input in render()"),
  p(/Template\s*\([^)]*\+/gi, "SSTI", "Template string concatenation may lead to SSTI", ["python"]),
  p(/\{\{.*[\(\)].*\}\}/g, "SSTI", "Potential Jinja2 template injection expression"),

  // ═══════════════════════════════════════════════════════════════
  //  INSECURE DESERIALIZATION
  // ═══════════════════════════════════════════════════════════════
  p(/\bpickle\.loads?\s*\(/g, "INSECURE_DESERIALIZATION", "Pickle deserialization can execute arbitrary code", ["python"]),
  p(/\byaml\.load\s*\(/gi, "INSECURE_DESERIALIZATION", "yaml.load() is unsafe — use yaml.safe_load()", ["python"]),
  p(/\bJSON\.parse\s*\([^)]*(?:user|input|data|request)/gi, "INSECURE_DESERIALIZATION", "Unsafe JSON.parse of untrusted data", ["javascript", "typescript"]),
  p(/\beval\s*\(\s*JSON/gi, "INSECURE_DESERIALIZATION", "eval() with JSON input is dangerous"),
  p(/unserialize\s*\(/i, "INSECURE_DESERIALIZATION", "unserialize() with user input is dangerous", ["php"]),
  p(/Marshal\.deserialize/i, "INSECURE_DESERIALIZATION", "Marshal.deserialize allows arbitrary object creation", ["ruby"]),

  // ═══════════════════════════════════════════════════════════════
  //  XXE (XML External Entity)
  // ═══════════════════════════════════════════════════════════════
  p(/etree\.parse\s*\(/i, "XXE_INJECTION", "XML parsing without entity resolution disabled", ["python"]),
  p(/xml\.dom/i, "XXE_INJECTION", "XML DOM parsing may be vulnerable to XXE", ["python"]),
  p(/SAXParser/i, "XXE_INJECTION", "SAX parser without XXE protection", ["java"]),
  p(/XMLReader/i, "XXE_INJECTION", "XMLReader without XXE protection", ["php"]),
  p(/libxml/i, "XXE_INJECTION", "libxml without external entity disabling", ["php"]),
  p(/DocumentBuilderFactory\.newInstance/i, "XXE_INJECTION", "XML parser without XXE protection", ["java"]),

  // ═══════════════════════════════════════════════════════════════
  //  CSRF
  // ═══════════════════════════════════════════════════════════════
  p(/@csrf\.exempt/i, "CSRF", "CSRF protection disabled on endpoint", ["python"]),
  p(/csrf\.except/i, "CSRF", "CSRF protection exception", ["python"]),

  // ═══════════════════════════════════════════════════════════════
  //  OPEN REDIRECT
  // ═══════════════════════════════════════════════════════════════
  p(/redirect\s*\([^)]*(?:user|input|url|next|return|redirect)/gi, "OPEN_REDIRECT", "Open redirect via user-controlled URL"),
  p(/res\.redirect\s*\([^)]*(?:req\.query|req\.param)/gi, "OPEN_REDIRECT", "Open redirect via request parameter", ["javascript", "typescript"]),

  // ═══════════════════════════════════════════════════════════════
  //  SSRF (Server-Side Request Forgery)
  // ═══════════════════════════════════════════════════════════════
  p(/requests?\.(?:get|post|put|delete)\s*\([^)]*\+\s*(?:user|input|url)/gi, "SSRF", "User-controlled URL in server-side request"),
  p(/fetch\s*\([^)]*\+\s*(?:user|input|url)/gi, "SSRF", "User-controlled URL in fetch()", ["javascript", "typescript"]),
  p(/http\.get\s*\([^)]*\+\s*(?:user|input|url)/gi, "SSRF", "User-controlled URL in HTTP GET", ["go"]),

  // ═══════════════════════════════════════════════════════════════
  //  JWT / AUTH ISSUES
  // ═══════════════════════════════════════════════════════════════
  p(/jwt\.verify\s*\([^)]*null/gi, "JWT_VULNERABILITY", "JWT verification with null secret"),
  p(/jwt\.decode\s*\([^)]*(?!.*verify)/gi, "JWT_VULNERABILITY", "JWT decode without verification"),
  p(/algorithm:\s*["']none["']/i, "JWT_VULNERABILITY", "JWT algorithm 'none' allows forged tokens"),
  p(/expiresIn:\s*["']\d{1,3}["']/i, "JWT_VULNERABILITY", "JWT expiry set too short or invalid"),

  // ═══════════════════════════════════════════════════════════════
  //  SMARTCONTRACT / SOLIDITY
  // ═══════════════════════════════════════════════════════════════
  p(/\.call\s*\{value.*\}\s*\(/i, "BUFFER_OVERFLOW", "Reentrancy vulnerability: external call before state update", ["solidity"]),
  p(/tx\.origin/i, "SECURITY_MISCONFIG", "tx.origin is vulnerable to phishing attacks — use msg.sender", ["solidity"]),
  p(/\.call\s*\{value/i, "SECURITY_MISCONFIG", "Unchecked external call — always check return value", ["solidity"]),
  p(/pragma\s+solidity\s+\^/i, "SECURITY_MISCONFIG", "Floating pragma allows unpredictable compiler versions", ["solidity"]),
  p(/selfdestruct\s*\(/i, "SECURITY_MISCONFIG", "selfdestruct enables contract self-destruction", ["solidity"]),
  p(/\bnow\b/i, "SECURITY_MISCONFIG", "Using block.timestamp/now — miners can manipulate", ["solidity"]),

  // ═══════════════════════════════════════════════════════════════
  //  LDAP INJECTION
  // ═══════════════════════════════════════════════════════════════
  p(/ldap_search\s*\([^)]*\+/gi, "LDAP_INJECTION", "LDAP search with string concatenation"),
  p(/ldap_bind\s*\([^)]*\+/gi, "LDAP_INJECTION", "LDAP bind with string concatenation"),

  // ═══════════════════════════════════════════════════════════════
  //  INSECURE DIRECT OBJECT REFERENCE
  // ═══════════════════════════════════════════════════════════════
  p(/\.findById\s*\([^)]*(?:req\.param|request\.get)/gi, "INSECURE_DIRECT_OBJECT_REF", "Direct object reference without ownership check"),
  p(/\.find\([^)]*(?:req\.param|request\.get)/gi, "INSECURE_DIRECT_OBJECT_REF", "Direct database lookup without access control"),

  // ═══════════════════════════════════════════════════════════════
  //  SECURITY MISCONFIGURATION
  // ═══════════════════════════════════════════════════════════════
  p(/debug\s*=\s*True\b/i, "SECURITY_MISCONFIG", "Debug mode enabled in production exposes stack traces"),
  p(/CORS_ORIGIN_ALLOW_ALL\s*=\s*True/i, "SECURITY_MISCONFIG", "CORS allows all origins", ["python"]),
  p(/Access-Control-Allow-Origin:\s*\*/i, "SECURITY_MISCONFIG", "CORS configured with wildcard origin"),
  p(/NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*0/i, "SECURITY_MISCONFIG", "SSL/TLS verification disabled", ["javascript", "typescript"]),
  p(/rejectUnauthorized\s*:\s*false/i, "SECURITY_MISCONFIG", "SSL/TLS certificate validation disabled"),
  p(/verify\s*=\s*False\b/i, "SECURITY_MISCONFIG", "SSL certificate verification disabled", ["python"]),
  p(/process\.env\.NODE_TLS_REJECT_UNAUTHORIZED/i, "SECURITY_MISCONFIG", "TLS rejection disabled via environment", ["javascript", "typescript"]),

  // ═══════════════════════════════════════════════════════════════
  //  PERMISSIONS / INSECURE FILE PERMS
  // ═══════════════════════════════════════════════════════════════
  p(/chmod\s*\([^)]*0o?777/i, "SECURITY_MISCONFIG", "World-writable permissions (777) on files"),
  p(/umask\s*\(.*0\b/i, "SECURITY_MISCONFIG", "umask(0) creates world-writable files"),

  // ═══════════════════════════════════════════════════════════════
  //  XPATH INJECTION
  // ═══════════════════════════════════════════════════════════════
  p(/xpath\.evaluate\s*\([^)]*\+/gi, "XPATH_INJECTION", "XPath query built via concatenation"),
  p(/\.xpath\s*\([^)]*\+\s*(?:user|input|name)/gi, "XPATH_INJECTION", "User-controlled XPath expression"),

  // ═══════════════════════════════════════════════════════════════
  //  DOCKER SECURITY — Dockerfile patterns
  // ═══════════════════════════════════════════════════════════════
  p(/^FROM\s+\S+:latest\s*$/gim, "DOCKER_SECURITY", "Docker 'latest' tag is ambiguous — pin a specific version", ["dockerfile"]),
  p(/^FROM\s+\S+:\S*[a-z]+\S*$/gim, "DOCKER_SECURITY", "Using mutable tag — pin to immutable digest or semver", ["dockerfile"]),
  p(/^USER\s+root\s*$/gim, "DOCKER_SECURITY", "Container runs as root — use non-root user", ["dockerfile"]),
  p(/^ADD\s+/gim, "DOCKER_SECURITY", "ADD pulls remote archives — use COPY instead", ["dockerfile"]),
  p(/apt-get\s+update\b.*&&\s*apt-get\s+install\b(?!.*&&\s*rm\s)/gi, "DOCKER_SECURITY", "apt-get without cleanup leaves cache — add rm -rf /var/lib/apt/lists/*", ["dockerfile"]),
  p(/pip\s+install\b(?!.*--no-cache-dir)/gi, "DOCKER_SECURITY", "pip without --no-cache-dir increases image size", ["dockerfile"]),
  p(/npm\s+install\b(?!.*--only=prod|.*ci)/gi, "DOCKER_SECURITY", "npm install without --only=prod includes dev dependencies", ["dockerfile"]),
  p(/ENV\s+(?:NODE_ENV|FLASK_ENV|DJANGO_SETTINGS_MODULE)\s*=\s*development/i, "DOCKER_SECURITY", "Development environment vars baked into production image", ["dockerfile"]),
  p(/EXPOSE\s+\d+/g, "DOCKER_SECURITY", "Consider limiting exposed ports — only expose necessary services", ["dockerfile"]),
  p(/--no-install-recommends/gi, "DOCKER_SECURITY", "Consider adding --no-install-recommends to reduce bloat", ["dockerfile"]),
  p(/ARG\s+(?:API_KEY|SECRET|PASSWORD|TOKEN|CREDENTIAL)/gi, "DOCKER_SECURITY", "Build args may leak secrets into image history", ["dockerfile"]),

  // ═══════════════════════════════════════════════════════════════
  //  KUBERNETES SECURITY — YAML manifest patterns
  // ═══════════════════════════════════════════════════════════════
  p(/privileged:\s*true/i, "K8S_SECURITY", "Privileged container — grants all capabilities", ["yaml"]),
  p(/hostNetwork:\s*true/i, "K8S_SECURITY", "Host network mode — container can access host network namespace", ["yaml"]),
  p(/hostPID:\s*true/i, "K8S_SECURITY", "Host PID namespace — container can see host processes", ["yaml"]),
  p(/hostIPC:\s*true/i, "K8S_SECURITY", "Host IPC namespace — container can access host IPC", ["yaml"]),
  p(/runAsUser:\s*0/i, "K8S_SECURITY", "Container runs as root (UID 0) — use non-root user", ["yaml"]),
  p(/allowPrivilegeEscalation:\s*true/i, "K8S_SECURITY", "Privilege escalation allowed — set to false", ["yaml"]),
  p(/readOnlyRootFilesystem:\s*false/i, "K8S_SECURITY", "Root filesystem is writable — set to true", ["yaml"]),
  p(/capabilities:\s*[\s\S]*?ADD\s/i, "K8S_SECURITY", "Extra capabilities added — drop all and add only needed", ["yaml"]),
  p(/hostPath:/i, "K8S_SECURITY", "HostPath volume — limits pod mobility and risks host access", ["yaml"]),
  p(/serviceAccountName:\s*default/i, "K8S_SECURITY", "Using default service account — create least-privilege account", ["yaml"]),
  p(/automountServiceAccountToken:\s*true/i, "K8S_SECURITY", "Service account token auto-mounted — set to false if unused", ["yaml"]),
  p(/securityContext:\s*[\s\S]*?runAsNonRoot:\s*false/i, "K8S_SECURITY", "runAsNonRoot disabled — container may run as root", ["yaml"]),

  // ═══════════════════════════════════════════════════════════════
  //  DEPENDENCY VULNERABILITIES — package.json, requirements.txt
  // ═══════════════════════════════════════════════════════════════
  p(/"express"\s*:\s*["']\^?[0-3]\./i, "DEPENDENCY_VULN", "Express < 4.x may have known vulnerabilities — upgrade to 4.x+", ["json"]),
  p(/"lodash"\s*:\s*["']\^?4\.17\.(?:0|[1-9]\d{0,1}|[12]\d|3[0-9]|4[0-8])\b/i, "DEPENDENCY_VULN", "lodash < 4.17.49 has prototype pollution vulnerability", ["json"]),
  p(/"axios"\s*:\s*["']\^?0\.(?:1\d|2[0-4])\./i, "DEPENDENCY_VULN", "axios < 0.25.0 has SSRF vulnerability", ["json"]),
  p(/"jsonwebtoken"\s*:\s*["']\^?[0-8]\./i, "DEPENDENCY_VULN", "jsonwebtoken < 9.x has JWT verification bypass vulnerabilities", ["json"]),
  p(/"react"\s*:\s*["']\^?1[4-6]\./i, "DEPENDENCY_VULN", "React 14-16 uses legacy lifecycle methods — upgrade to 18+", ["json"]),
  p(/"moment"\s*:\s*["']\^?2\.2[0-9]\./i, "DEPENDENCY_VULN", "moment.js is legacy — consider using date-fns or Temporal", ["json"]),
  p(/Django\s*[<>=]+\s*[0-2]\./i, "DEPENDENCY_VULN", "Django < 3.x has known vulnerabilities — upgrade to 4.x+"),
  p(/Flask\s*[<>=]+\s*[0-1]\./i, "DEPENDENCY_VULN", "Flask < 2.x lacks security improvements — upgrade to 2.x+"),
  p(/requests\s*[<>=]+\s*[0-1]\./i, "DEPENDENCY_VULN", "requests < 2.x may have SSL verification issues"),
  p(/cryptography\s*[<>=]+\s*[0-2]\./i, "DEPENDENCY_VULN", "cryptography < 3.x has known vulnerabilities — upgrade to 35+"),
  p(/"passport"\s*:\s*["']\^?0\./i, "DEPENDENCY_VULN", "passport 0.x may have session issues — upgrade to 1.x+", ["json"]),
  p(/"mongoose"\s*:\s*["']\^?[0-5]\./i, "DEPENDENCY_VULN", "mongoose < 6.x has prototype pollution risks — upgrade", ["json"]),
  p(/"debug"\s*:\s*["']\^?[0-2]\./i, "DEPENDENCY_VULN", "debug < 3.x may leak sensitive information", ["json"]),
  p(/"shelljs"\s*:\s*["']\^?0\.[0-7]\./i, "DEPENDENCY_VULN", "shelljs < 0.8.5 has command injection vulnerability", ["json"]),
  p(/Pillow\s*[<>=]+\s*[0-8]\./i, "DEPENDENCY_VULN", "Pillow < 9.x has multiple DoS vulnerabilities"),
  p(/paramiko\s*[<>=]+\s*[0-2]\./i, "DEPENDENCY_VULN", "paramiko < 2.8 has auth bypass vulnerability"),
  p(/urllib3\s*[<>=]+\s*1\.2[0-5]\./i, "DEPENDENCY_VULN", "urllib3 < 1.26.5 has SSL certificate validation issue"),
];

// ── Scan Logic ─────────────────────────────────────────────────────
function getLang(filePath) {
  const ext = path.extname(filePath).toLowerCase();
  if (LANGS[ext]) return LANGS[ext];
  const base = path.basename(filePath).toLowerCase();
  if (base === "dockerfile" || base.startsWith("dockerfile.")) return "dockerfile";
  if (base === "docker-compose.yml" || base === "docker-compose.yaml") return "yaml";
  if (base === "requirements.txt" || base === "Pipfile" || base === "Pipfile.lock") return "python";
  if (base === "package.json" || base === "package-lock.json" || base === "yarn.lock") return "json";
  return null;
}

function scanFile(filePath) {
  const lang = getLang(filePath);
  if (!lang) return [];

  const basename = path.basename(filePath);
  if (IGNORE_DIRS.has(basename)) return [];
  const parentDir = path.basename(path.dirname(filePath));
  if (IGNORE_DIRS.has(parentDir)) return [];

  let content;
  try {
    content = fs.readFileSync(filePath, "utf-8");
  } catch {
    return [];
  }

  const lines = content.split("\n");
  const findings = [];
  const seenKeys = new Set();

  for (let i = 0; i < lines.length; i++) {
    for (const { regex, label, message, langs } of PATTERNS) {
      if (langs && !langs.includes(lang)) continue;
      regex.lastIndex = 0;
      if (regex.test(lines[i])) {
        const key = `${label}:${message}`;
        if (!seenKeys.has(key)) {
          seenKeys.add(key);
          findings.push({
            line: i + 1,
            message,
            severity: SEVERITY[label] || "info",
            category: label,
            cweId: CWE[label] || "CWE-000",
            language: lang,
          });
        }
      }
    }
  }

  return findings;
}

function collectSourceFiles(rootDir, maxFiles = 10000) {
  const files = [];
  const queue = [path.resolve(rootDir)];
  while (queue.length > 0 && files.length < maxFiles) {
    const dir = queue.shift();
    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      if (entry.name.startsWith(".")) continue;
      const fullPath = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (!IGNORE_DIRS.has(entry.name)) {
          queue.push(fullPath);
        }
      } else if (entry.isFile()) {
        if (getLang(fullPath)) {
          files.push(fullPath);
        }
      }
    }
  }
  return files;
}

function scanProject(rootDir, onProgress) {
  const files = collectSourceFiles(rootDir);
  const results = [];

  for (let i = 0; i < files.length; i++) {
    const filePath = files[i];
    const relPath = path.relative(rootDir, filePath);
    const issues = scanFile(filePath);
    if (issues.length > 0) {
      results.push({ file: relPath, issues });
    }
    if (onProgress) {
      onProgress({ current: i + 1, total: files.length, file: relPath, issues: issues.length });
    }
  }

  const totalIssues = results.reduce((sum, r) => sum + r.issues.length, 0);
  const bySeverity = {};
  for (const r of results) {
    for (const issue of r.issues) {
      const s = issue.severity || "info";
      bySeverity[s] = (bySeverity[s] || 0) + 1;
    }
  }

  return {
    filesScanned: files.length,
    filesWithIssues: results.length,
    totalIssues,
    bySeverity,
    results,
  };
}

module.exports = { scanProject, scanFile, collectSourceFiles, getLang, LANGS };

if (require.main === module) {
  const target = process.argv[2] || ".";
  console.log(`Scanning ${target}...`);

  if (fs.existsSync(target) && fs.statSync(target).isFile()) {
    const issues = scanFile(target);
    const file = path.basename(target);
    console.log(`\nFiles scanned: ${issues.length > 0 ? 1 : 0}`);
    console.log(`Files with issues: ${issues.length > 0 ? 1 : 0}`);
    console.log(`Total issues: ${issues.length}`);
    const bySeverity = {};
    for (const issue of issues) {
      bySeverity[issue.severity] = (bySeverity[issue.severity] || 0) + 1;
    }
    console.log(`By severity:`, bySeverity);
    for (const issue of issues) {
      console.log(`\n  ${file}:`);
      console.log(`    L${issue.line} [${issue.severity}] ${issue.cweId} — ${issue.message}`);
    }
  } else {
    const result = scanProject(target);
    console.log(`\nFiles scanned: ${result.filesScanned}`);
    console.log(`Files with issues: ${result.filesWithIssues}`);
    console.log(`Total issues: ${result.totalIssues}`);
    console.log(`By severity:`, result.bySeverity);
    for (const r of result.results) {
      console.log(`\n${r.file}:`);
      for (const issue of r.issues) {
        console.log(`  L${issue.line} [${issue.severity}] ${issue.cweId} — ${issue.message}`);
      }
    }
  }
}
