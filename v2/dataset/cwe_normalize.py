"""
RakshakAI v2 — CWE label canonicalization.

Maps any of:
  - "CWE-89"
  - "SQL Injection"
  - "SQLi"
  - "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')"
  - free-text CVE descriptions

to the canonical "CWE-XXX" MITRE identifier.
"""
from __future__ import annotations

import re
from functools import lru_cache

# A compact but high-coverage name↔id table. Extended at runtime if the
# MITRE CWEC catalog is available locally (v2/inputs/cwec.xml).
NAME_TO_ID: dict[str, str] = {
    "sql injection": "CWE-89",
    "sqli": "CWE-89",
    "sql command injection": "CWE-89",
    "improper neutralization of special elements used in an sql command": "CWE-89",
    "xss": "CWE-79",
    "cross-site scripting": "CWE-79",
    "improper neutralization of input during web page generation": "CWE-79",
    "command injection": "CWE-78",
    "os command injection": "CWE-78",
    "improper neutralization of special elements used in an os command": "CWE-78",
    "code injection": "CWE-94",
    "improper control of generation of code": "CWE-94",
    "ssti": "CWE-94",
    "server-side template injection": "CWE-94",
    "path traversal": "CWE-22",
    "directory traversal": "CWE-22",
    "improper limitation of a pathname to a restricted directory": "CWE-22",
    "weak crypto": "CWE-327",
    "use of a broken or risky cryptographic algorithm": "CWE-327",
    "insecure hash": "CWE-327",
    "insecure deserialization": "CWE-502",
    "deserialization of untrusted data": "CWE-502",
    "hardcoded credentials": "CWE-798",
    "use of hard-coded credentials": "CWE-798",
    "hardcoded secret": "CWE-798",
    "hardcoded password": "CWE-798",
    "api key in source": "CWE-798",
    "ssrf": "CWE-918",
    "server-side request forgery": "CWE-918",
    "xxe": "CWE-611",
    "xml external entity reference": "CWE-611",
    "improper restriction of xml external entity reference": "CWE-611",
    "open redirect": "CWE-601",
    "url redirection to untrusted site": "CWE-601",
    "unsafe deserialization": "CWE-502",
    "buffer overflow": "CWE-120",
    "stack buffer overflow": "CWE-121",
    "heap buffer overflow": "CWE-122",
    "out-of-bounds write": "CWE-787",
    "out-of-bounds read": "CWE-125",
    "use after free": "CWE-416",
    "double free": "CWE-415",
    "integer overflow": "CWE-190",
    "race condition": "CWE-362",
    "concurrent execution using shared resource with improper synchronization": "CWE-362",
    "toctou": "CWE-367",
    "time-of-check time-of-use": "CWE-367",
    "missing authentication": "CWE-306",
    "missing authorization": "CWE-862",
    "improper authentication": "CWE-287",
    "improper authorization": "CWE-285",
    "csrf": "CWE-352",
    "cross-site request forgery": "CWE-352",
    "jwt": "CWE-347",
    "improper verification of cryptographic signature": "CWE-347",
    "insecure random": "CWE-338",
    "use of cryptographically weak pseudo-random number generator": "CWE-338",
    "cleartext transmission": "CWE-319",
    "cleartext transmission of sensitive information": "CWE-319",
    "missing encryption": "CWE-311",
    "missing encryption of sensitive data": "CWE-311",
    "insecure direct object reference": "CWE-639",
    "idor": "CWE-639",
    "authorization bypass": "CWE-862",
    "missing function level access control": "CWE-862",
    "improper input validation": "CWE-20",
    "improper neutralization": "CWE-707",
    "improper error handling": "CWE-209",
    "information exposure through error message": "CWE-209",
    "regular expression dos": "CWE-1333",
    "redos": "CWE-1333",
    "unrestricted file upload": "CWE-434",
    "improper limitation of upload": "CWE-434",
    "zip slip": "CWE-22",
}

_ID_RE = re.compile(r"\bCWE-(\d{1,4})\b", re.IGNORECASE)


@lru_cache(maxsize=8192)
def canonical_cwe(label: str | None) -> str:
    if not label:
        return "CWE-UNKNOWN"
    s = str(label).strip()

    # Direct CWE-XXX present
    m = _ID_RE.search(s)
    if m:
        return f"CWE-{m.group(1)}"

    # Free text → lookup
    key = re.sub(r"[\"'\(\)\.,]", " ", s.lower())
    key = re.sub(r"\s+", " ", key).strip()

    if key in NAME_TO_ID:
        return NAME_TO_ID[key]

    # Substring match for compound names
    for k, v in NAME_TO_ID.items():
        if k in key:
            return v
    return "CWE-UNKNOWN"
