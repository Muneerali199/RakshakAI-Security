"""
RakshakAI — FastAPI inference server.
"""
import json
import time
import logging
from pathlib import Path
from typing import List, Optional

import argparse

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("rakshakai")

app = FastAPI(title="RakshakAI", version="0.2.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
MODEL_DIR = Path("models/rakshakai-v1/")

# Try loading model
engine = None
ENGINE_MODE = "mock"
CONFIDENCE_THRESHOLD = 0.75

ID2LABEL_FALLBACK = {
    str(i): name for i, name in enumerate([
        "SQL_INJECTION", "XSS", "COMMAND_INJECTION", "HARDCODED_SECRET",
        "PATH_TRAVERSAL", "WEAK_CRYPTO", "SSTI", "INSECURE_DESERIALIZATION",
        "JWT_VULNERABILITY", "REDOS", "CSRF", "OPEN_REDIRECT",
        "NULL_DEREFERENCE", "MEMORY_LEAK", "EMPTY_CATCH", "BUFFER_OVERFLOW",
        "RACE_CONDITION", "INFINITE_LOOP", "LDAP_INJECTION", "XXE_INJECTION",
        "CLEAN",
    ])
}

import os as _os
_FORCE_MOCK = _os.environ.get("RAKSHAK_MOCK", "0") == "1"

if _FORCE_MOCK:
    logger.info("RAKSHAK_MOCK=1 — using mock engine for predictable demo results")
else:
    try:
        from rakshakai.inference import RakshakInference
        engine = RakshakInference()
        ENGINE_MODE = "lightweight"
        logger.info(f"RakshakAI loaded ({engine.model.count_params()['total']:,} params)")
    except Exception as e:
        logger.warning(f"Model not available: {e}")
        logger.info("Falling back to mock engine")

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
    "SSTI": "CWE-1336", "INSECURE_DESERIALIZATION": "CWE-502",
    "LDAP_INJECTION": "CWE-90", "XXE_INJECTION": "CWE-611",
    "BUFFER_OVERFLOW": "CWE-120", "CSRF": "CWE-352", "OPEN_REDIRECT": "CWE-601",
    "JWT_VULNERABILITY": "CWE-347",
}
OWASP_MAP = {
    "SQL_INJECTION": "A03:2021 – Injection",
    "XSS": "A03:2021 – Injection",
    "COMMAND_INJECTION": "A03:2021 – Injection",
    "SSTI": "A03:2021 – Injection",
    "LDAP_INJECTION": "A03:2021 – Injection",
    "XXE_INJECTION": "A05:2021 – XXE",
    "HARDCODED_SECRET": "A07:2021 – Identification & Auth Failures",
    "WEAK_CRYPTO": "A02:2021 – Cryptographic Failures",
    "PATH_TRAVERSAL": "A01:2021 – Broken Access Control",
    "INSECURE_DESERIALIZATION": "A08:2021 – Software & Data Integrity Failures",
    "BUFFER_OVERFLOW": "A06:2021 – Vulnerable Components",
    "CSRF": "A01:2021 – Broken Access Control",
    "OPEN_REDIRECT": "A01:2021 – Broken Access Control",
    "JWT_VULNERABILITY": "A07:2021 – Identification & Auth Failures",
}
REMEDIATION_MAP = {
    "SQL_INJECTION": {
        "description": "Use parameterized queries instead of string concatenation. This separates SQL code from data, preventing malicious input from altering query structure.",
        "example": "cursor.execute(\"SELECT * FROM users WHERE id = %s\", (user_id,))",
    },
    "COMMAND_INJECTION": {
        "description": "Avoid os.system() and subprocess shell=True. Use subprocess.run() with a list of arguments instead of a shell string.",
        "example": "subprocess.run([\"ls\", \"-la\", user_input])",
    },
    "HARDCODED_SECRET": {
        "description": "Store secrets in environment variables or a secrets manager. Never hardcode credentials in source code.",
        "example": "api_key = os.environ[\"API_KEY\"]\npassword = os.environ[\"DB_PASSWORD\"]",
    },
    "XSS": {
        "description": "Use DOMPurify to sanitize user input before rendering. Never insert unsanitized user data directly into the DOM.",
        "example": "import DOMPurify from 'dompurify'\ndocument.getElementById('output').innerHTML = DOMPurify.sanitize(userInput)",
    },
    "PATH_TRAVERSAL": {
        "description": "Validate and sanitize file paths. Use os.path.realpath() to resolve symlinks and ensure the resolved path is within an allowed directory.",
        "example": "safe_dir = os.path.realpath(\"/var/www/\")\nfilepath = os.path.realpath(os.path.join(safe_dir, filename))\nif not filepath.startswith(safe_dir): raise ValueError(\"Path traversal\")\nwith open(filepath, \"r\") as f: return f.read()",
    },
    "WEAK_CRYPTO": {
        "description": "Replace MD5/SHA1 with a strong hash like SHA-256 or bcrypt for passwords.",
        "example": "import hashlib\nhash = hashlib.sha256(password.encode()).hexdigest()",
    },
}


class ScanRequest(BaseModel):
    code: str
    language: str
    filename: Optional[str] = "unknown"


class Remediation(BaseModel):
    description: str = ""
    example: Optional[str] = None


class Issue(BaseModel):
    line: int
    message: str
    severity: str
    description: str = ""
    category: str = ""
    cweId: Optional[str] = None
    owaspCategory: Optional[str] = None
    confidence: float = 0.0
    remediation: Optional[Remediation] = None


class ScanResponse(BaseModel):
    issues: List[Issue]
    language: str
    total_issues: int
    scan_time_ms: float


def mock_predict(code: str):
    code_lower = code.lower()
    if "select" in code_lower and ("+" in code_lower or 'f"' in code_lower or "${" in code_lower):
        return "SQL_INJECTION", 0.95
    if "os.system" in code_lower or "exec(" in code_lower:
        return "COMMAND_INJECTION", 0.92
    if "password =" in code_lower or "api_key" in code_lower or "secret" in code_lower:
        return "HARDCODED_SECRET", 0.88
    if "innerhtml" in code_lower or ("<html" in code_lower and "+" in code_lower):
        return "XSS", 0.91
    if "open(" in code_lower and "+" in code_lower and ("../" in code_lower or "/var/" in code_lower or "filename" in code_lower):
        return "PATH_TRAVERSAL", 0.87
    if "md5" in code_lower or "sha1" in code_lower:
        return "WEAK_CRYPTO", 0.85
    return "CLEAN", 0.99


def scan_code_by_lines(code: str, language: str, window_size: int = 5):
    lines = code.split("\n")
    issues = []
    seen = set()

    for i in range(0, len(lines), max(1, window_size // 2)):
        snippet = "\n".join(lines[i:i + window_size])
        if len(snippet.strip()) < 5:
            continue

        if engine:
            result = engine.predict(snippet, language)
            label, confidence = result["label"], result["confidence"]
        else:
            label, confidence = mock_predict(snippet)

        if label == "CLEAN" or confidence < CONFIDENCE_THRESHOLD:
            continue
        if label in seen:
            continue
        seen.add(label)

        severity = SEVERITY_MAP.get(label, "info")
        remediation = REMEDIATION_MAP.get(label)
        desc = remediation["description"] if remediation else ""
        fix_example = remediation["example"] if remediation else None

        issues.append(Issue(
            line=i + 1,
            message=f"{label.replace('_', ' ').title()} Detected",
            severity=severity,
            description=desc,
            category=label,
            cweId=CWE_MAP.get(label, "CWE-000"),
            owaspCategory=OWASP_MAP.get(label),
            confidence=round(confidence, 3),
            remediation=Remediation(
                description=desc,
                example=fix_example,
            ) if remediation else None,
        ))
    return issues


async def _scan(request: ScanRequest):
    try:
        start = time.time()
        issues = scan_code_by_lines(request.code, request.language)
        elapsed = round((time.time() - start) * 1000, 2)
        return ScanResponse(issues=issues, language=request.language,
                           total_issues=len(issues), scan_time_ms=elapsed)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/ml/scan", response_model=ScanResponse)
async def scan(request: ScanRequest):
    return await _scan(request)

@app.post("/api/scan", response_model=ScanResponse)
async def scan_api(request: ScanRequest):
    return await _scan(request)


@app.get("/ml/health")
async def health():
    return {"status": "ok", "engine": ENGINE_MODE,
            "labels": len(ID2LABEL_FALLBACK), "version": "0.2.0"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="RakshakAI server")
    parser.add_argument("--port", type=int, default=3000, help="Port to listen on")
    args = parser.parse_args()
    logger.info(f"RakshakAI server starting on :{args.port} (engine: {ENGINE_MODE})")
    uvicorn.run(app, host="0.0.0.0", port=args.port)
