"""
RakshakAI v2 — common helpers for the Phase 2.5 dataset importers.

Every source importer produces a list[SecuritySample] and writes them
to ``v2/inputs/datasets/raw/<source>.jsonl`` for the cleaning pipeline
to consume.  Helpers in this module handle:

* polite HTTP fetching (UA, retry, timeout)
* streaming JSONL file writes
* language detection from filename / extension
* severity normalization (CVSS → label)
* CWE extraction from free text

Importers must remain *offline-tolerant* — if a download fails they
should log the error and exit non-zero, never silently write empty
files.
"""
from __future__ import annotations

import hashlib
import json
import re
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, Iterator, Optional

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from v2.dataset.schema import SecuritySample, write_jsonl  # noqa: E402


# Polite UA identifies us to GitHub, NVD, etc.
UA = "RakshakAI-v2-dataset-importer/1.0 (+https://github.com/anomalyco/rakshak-ai)"
RAW_DIR = Path("v2/inputs/datasets/raw")


# ─── HTTP helpers ───────────────────────────────────────────────────

def fetch(url: str, *, timeout: int = 30, max_retries: int = 3,
          headers: Optional[dict] = None) -> bytes:
    """Fetch ``url`` with a polite UA and a retry loop."""
    hdrs = {"User-Agent": UA, "Accept": "*/*"}
    if headers:
        hdrs.update(headers)
    last_err: Optional[Exception] = None
    for attempt in range(max_retries):
        try:
            req = urllib.request.Request(url, headers=hdrs)
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.read()
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as e:
            last_err = e
            wait = 2 ** attempt
            print(f"  [fetch] {url}  attempt {attempt+1}/{max_retries}  failed: {e!r}  retry in {wait}s",
                  file=sys.stderr)
            time.sleep(wait)
    raise RuntimeError(f"failed to fetch {url}: {last_err!r}")


def fetch_json(url: str, **kw):
    return json.loads(fetch(url, **kw).decode("utf-8", errors="replace"))


def fetch_text(url: str, **kw) -> str:
    return fetch(url, **kw).decode("utf-8", errors="replace")


def fetch_jsonl(url: str, **kw) -> Iterator[dict]:
    """Fetch a JSONL file and yield each line as a dict."""
    text = fetch_text(url, **kw)
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            yield json.loads(line)
        except json.JSONDecodeError:
            continue


# ─── Language detection ──────────────────────────────────────────────

EXT_LANG = {
    ".py":  "python",     ".pyw": "python",  ".pyi": "python",
    ".js":  "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".jsx": "javascript", ".ts":  "typescript", ".tsx": "typescript",
    ".java": "java",
    ".rb":  "ruby",
    ".php": "php",        ".phtml": "php",
    ".go":  "go",
    ".rs":  "rust",
    ".c":   "c",          ".h":   "c",
    ".cpp": "cpp",        ".cc":  "cpp",       ".cxx": "cpp", ".hpp": "cpp",
    ".cs":  "csharp",
    ".swift": "swift",
    ".kt":  "kotlin",     ".kts": "kotlin",
    ".scala": "scala",
    ".pl":  "perl",
    ".sh":  "shell",      ".bash": "shell",
}

LANG_BY_PATH_TOKEN = [
    (re.compile(r"\b(node|node_modules|express|react|next|nest)", re.I), "javascript"),
    (re.compile(r"\b(rails|ruby|sinatra|gemfile)", re.I), "ruby"),
    (re.compile(r"\b(laravel|symfony|wordpress|wp-|drupal|joomla)", re.I), "php"),
    (re.compile(r"\b(django|flask|fastapi|pipfile|pyproject|setup\.py|requirements\.txt)", re.I), "python"),
    (re.compile(r"\b(spring|maven|gradle|hibernate|tomcat)", re.I), "java"),
    (re.compile(r"\b(cargo|rust|crate)", re.I), "rust"),
    (re.compile(r"\b(golang|go\.mod|go\.sum)", re.I), "go"),
]


def detect_language(path: str, hint: Optional[str] = None) -> str:
    """Detect language from a file path.  ``hint`` wins if it is a known
    whitelisted language."""
    if hint and hint.lower() in {
        "python", "javascript", "typescript", "java", "ruby", "php",
        "go", "rust", "c", "cpp", "csharp", "swift", "kotlin", "scala",
        "shell", "perl", "html", "sql",
    }:
        return hint.lower()
    p = path.lower()
    for ext, lang in EXT_LANG.items():
        if p.endswith(ext):
            return lang
    for rx, lang in LANG_BY_PATH_TOKEN:
        if rx.search(p):
            return lang
    return "unknown"


# ─── CWE normalization ──────────────────────────────────────────────

CWE_RE = re.compile(r"CWE-?(\d+)", re.I)


def normalize_cwe(cwe: Optional[str]) -> Optional[str]:
    """Normalize a CWE identifier to ``CWE-<n>`` form, or None."""
    if not cwe:
        return None
    m = CWE_RE.search(str(cwe))
    if not m:
        return None
    return f"CWE-{int(m.group(1))}"


def cwe_to_severity(cwe: Optional[str]) -> str:
    """Heuristic severity from a CWE class.  Conservative — defaults to
    ``high`` when we don't know."""
    cwe = (cwe or "").upper()
    critical = {
        "CWE-94", "CWE-78", "CWE-502", "CWE-798", "CWE-287",
        "CWE-22",  # path traversal can be RCE
    }
    high = {
        "CWE-89", "CWE-79", "CWE-918", "CWE-611", "CWE-918",
        "CWE-347", "CWE-352", "CWE-862", "CWE-863",
    }
    medium = {
        "CWE-327", "CWE-328", "CWE-330", "CWE-200", "CWE-1333",
        "CWE-639", "CWE-601", "CWE-209",
    }
    if cwe in critical:
        return "critical"
    if cwe in high:
        return "high"
    if cwe in medium:
        return "medium"
    return "high"


def cvss_to_severity(score: Optional[float]) -> str:
    if score is None:
        return "high"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "high"


# ─── Code-safety filters ────────────────────────────────────────────

HARM_PATTERNS = [
    re.compile(r"AKIA[0-9A-Z]{16}"),                   # AWS access key
    re.compile(r"AIza[0-9A-Za-z\-_]{35}"),             # GCP API key
    re.compile(r"sk-[A-Za-z0-9]{32,}"),                # OpenAI key
    re.compile(r"ghp_[A-Za-z0-9]{30,}"),               # GitHub PAT
    re.compile(r"xox[abprs]-[A-Za-z0-9-]{10,}"),       # Slack token
    re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),  # email
]


def is_harmful(text: str) -> bool:
    return any(p.search(text) for p in HARM_PATTERNS)


# ─── Fingerprinting & dedup ────────────────────────────────────────

def fingerprint(text: str) -> str:
    """Stable hash of a code body, used to dedup across sources."""
    norm = re.sub(r"\s+", " ", text or "").strip()
    return hashlib.sha256(norm.encode("utf-8")).hexdigest()[:16]


# ─── Import run helper ────────────────────────────────────────────

@dataclass
class ImportStats:
    source: str
    requested: int = 0
    built: int = 0
    skipped_harmful: int = 0
    skipped_no_cwe: int = 0
    skipped_no_code: int = 0
    skipped_too_short: int = 0
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "requested": self.requested,
            "built": self.built,
            "skipped_harmful": self.skipped_harmful,
            "skipped_no_cwe": self.skipped_no_cwe,
            "skipped_no_code": self.skipped_no_code,
            "skipped_too_short": self.skipped_too_short,
            "error": self.error,
        }


def write_samples(source: str, samples: Iterable[SecuritySample],
                  stats: ImportStats) -> Path:
    out = RAW_DIR / f"{source}.jsonl"
    out.parent.mkdir(parents=True, exist_ok=True)
    n = write_jsonl(out, list(samples))
    print(f"  [{source}] wrote {n} samples to {out}")
    return out


def run_importer(name: str, fn: Callable[[ImportStats], Iterator[SecuritySample]]
                 ) -> tuple[Path, ImportStats]:
    """Run an importer function and persist its output.

    ``fn`` is a generator that yields SecuritySample.  It must NOT
    raise — bad records should be reported via the ImportStats object
    passed in.
    """
    stats = ImportStats(source=name)
    samples: list[SecuritySample] = []
    try:
        for s in fn(stats):
            samples.append(s)
            stats.built += 1
    except Exception as e:
        stats.error = repr(e)
        print(f"  [{name}] ERROR: {e!r}", file=sys.stderr)
    path = write_samples(name, samples, stats)
    print(f"  [{name}] stats: {stats.to_dict()}")
    return path, stats
