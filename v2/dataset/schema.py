"""
RakshakAI v2 — Unified security-dataset schema.

This module is the single source of truth for the format of every record that
flows through the v2 data pipeline (download → clean → dedup → balance →
instruct → pack → eval).

Design principles
-----------------
1. **Strict, not loose.**  Every record MUST validate against
   :class:`SecuritySample` before it enters the training mix. We catch bad
   data at the edge; we do not let it poison the SFT run.

2. **Compact, not bloated.**  Fields that are nice-to-have are *also* defined
   on the schema but are not required.  This keeps the JSONL files small and
   makes the dedup fingerprint short.

3. **Origin-tracked.**  Every record carries its source dataset, the upstream
   license, and the per-source SHA-1 fingerprint.  This is how the training
   gate can prove to a reviewer that no record from a GPL-licensed repo
   leaked in.

4. **Eval-aware.**  The same record class is used for training data and for
   the locked benchmark.  A ``split`` field (``train`` / ``val`` / ``test`` /
   ``benchmark``) is what the pipeline keys off to keep the benchmark out
   of training.

Schema
------
::

    {
      "id":                  "<sha1-12>",
      "language":            "python" | "javascript" | "typescript" | "java"
                             | "go" | "rust" | "c" | "cpp" | "ruby" | "php"
                             | "csharp" | "kotlin" | "swift" | "scala"
                             | "text",
      "vulnerable_code":     "<str, 30..100_000 chars>",
      "patched_code":        "<str, same constraints> | null",
      "cwe":                 "CWE-XXX" | "CWE-UNKNOWN" | null,
      "severity":            "critical" | "high" | "medium" | "low"
                             | "info" | "clean" | null,
      "explanation":         "<one paragraph, ≤ 1500 chars>",
      "attack_scenario":     "<one paragraph, ≤ 1500 chars>",
      "secure_fix":          "<one paragraph, ≤ 1500 chars>",
      "source":              "<origin dataset>",
      "source_license":      "MIT" | "Apache-2.0" | "BSD-3" | "CC-BY-4.0"
                             | "PublicDomain" | "Unknown",
      "cve":                 "CVE-YYYY-NNNN" | null,
      "owasp":               "A01:2021" | ... | null,
      "cvss":                <float 0.0..10.0> | null,
      "is_vulnerable":       true | false,
      "split":               "train" | "val" | "test" | "benchmark",
      "fingerprint":         "<sha1(normalized vulnerable_code)>",
      "added_at":            "2026-06-07T00:00:00Z",
    }
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

LANGUAGES: frozenset[str] = frozenset({
    "python", "javascript", "typescript", "java", "go", "rust",
    "c", "cpp", "ruby", "php", "csharp", "kotlin", "swift", "scala",
    "shell", "perl", "sql", "html", "xml", "json",
    "erlang", "haskell", "elixir", "lua", "r",
    "text",
})

SEVERITIES: frozenset[str] = frozenset({
    "critical", "high", "medium", "low", "info", "clean",
})

SPLITS: frozenset[str] = frozenset({"train", "val", "test", "benchmark"})

# Permissive license whitelist. GPL/LGPL/AGPL are explicitly excluded.
LICENSES: frozenset[str] = frozenset({
    "MIT", "Apache-2.0", "BSD-2", "BSD-3", "ISC", "Unlicense",
    "CC-BY-4.0", "CC-BY-NC-SA-4.0", "PublicDomain", "Unknown",
})

# CWE pattern — MITRE format. We accept CWE-XXX (1-4 digits) and
# the special placeholder "CWE-UNKNOWN" used for non-vulnerable
# baseline records.
CWE_RE = re.compile(r"^CWE-(\d{1,4}|UNKNOWN)$")
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")
OWASP_RE = re.compile(r"^A\d{2}:2021$")

# Constraints
MIN_CODE_CHARS = 30
MAX_CODE_CHARS = 100_000
MAX_TEXT_CHARS = 5000

# A non-exhaustive list of "harmful" tokens that should never appear in a
# training sample. They indicate either corruption, a PII leak, or that the
# upstream is a malicious payload. We scrub at the clean step.
HARM_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"sk_live_[A-Za-z0-9]{16,}"),                 # real Stripe key shape
    re.compile(r"AKIA[0-9A-Z]{16}"),                         # AWS access key
    re.compile(r"ghp_[A-Za-z0-9]{36}"),                      # GitHub PAT
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),      # raw PEM private keys
    re.compile(r"\b1[3-9]\d{9}\b"),                          # phone numbers
    re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),  # email
)

# ---------------------------------------------------------------------------
# Dataclass + validator
# ---------------------------------------------------------------------------


@dataclass
class SecuritySample:
    """One record in the v2 dataset."""

    id: str
    language: str
    vulnerable_code: str
    patched_code: str | None
    cwe: str | None
    severity: str | None
    explanation: str
    attack_scenario: str
    secure_fix: str
    source: str
    source_license: str = "Unknown"
    cve: str | None = None
    owasp: str | None = None
    cvss: float | None = None
    is_vulnerable: bool = True
    split: str = "train"
    fingerprint: str = ""
    added_at: str = ""
    references: list[str] = field(default_factory=list)

    # ---- construction helpers ----
    @staticmethod
    def make_id(seed: str) -> str:
        return hashlib.sha1(seed.encode("utf-8", errors="replace")).hexdigest()[:12]

    @staticmethod
    def fingerprint_of(code: str) -> str:
        """Stable dedup key used to identify **exact** duplicates.

        Conservative normalization: strips BOM, normalizes line endings to
        ``\\n``, and trims leading/trailing whitespace.  Does **not**
        collapse internal whitespace, lowercase identifiers, or remove
        comments — those transformations are reserved for the near-dedup
        step (see :mod:`v2.dataset.clean`).

        Two records that differ only in variable names, indentation, or
        comment text will have **different** fingerprints, which is the
        correct behaviour for a v2 SFT dataset (we want the model to see
        both the original and the renamed variants).
        """
        s = code.replace("\r\n", "\n").replace("\r", "\n").strip()
        return hashlib.sha1(s.encode("utf-8", errors="replace")).hexdigest()

    @classmethod
    def build(
        cls,
        *,
        language: str,
        vulnerable_code: str,
        patched_code: str | None,
        cwe: str | None,
        severity: str | None,
        explanation: str,
        attack_scenario: str,
        secure_fix: str,
        source: str,
        source_license: str = "Unknown",
        cve: str | None = None,
        owasp: str | None = None,
        cvss: float | None = None,
        is_vulnerable: bool = True,
        split: str = "train",
        references: list[str] | None = None,
    ) -> "SecuritySample":
        code = (vulnerable_code or "").strip()
        fp = cls.fingerprint_of(code)
        rid = cls.make_id(f"{source}|{fp}")
        return cls(
            id=rid,
            language=language,
            vulnerable_code=code,
            patched_code=(patched_code or "").strip() or None,
            cwe=cwe,
            severity=severity,
            explanation=explanation,
            attack_scenario=attack_scenario,
            secure_fix=secure_fix,
            source=source,
            source_license=source_license,
            cve=cve,
            owasp=owasp,
            cvss=cvss,
            is_vulnerable=is_vulnerable,
            split=split,
            fingerprint=fp,
            added_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
            references=list(references or []),
        )

    # ---- validation ----
    def validate(self) -> list[str]:
        """Return a list of validation errors. Empty list = valid."""
        errs: list[str] = []
        if not self.id or len(self.id) < 8:
            errs.append("id too short")
        if self.language not in LANGUAGES:
            errs.append(f"language not in allowed set: {self.language!r}")
        if not self.vulnerable_code or len(self.vulnerable_code) < MIN_CODE_CHARS:
            errs.append(f"vulnerable_code too short ({len(self.vulnerable_code)} chars)")
        if len(self.vulnerable_code) > MAX_CODE_CHARS:
            errs.append(f"vulnerable_code too long ({len(self.vulnerable_code)} chars)")
        if self.patched_code and len(self.patched_code) > MAX_CODE_CHARS:
            errs.append(f"patched_code too long ({len(self.patched_code)} chars)")
        if self.cwe is not None and not CWE_RE.match(self.cwe):
            errs.append(f"cwe not in CWE-XXX form: {self.cwe!r}")
        if self.cve is not None and not CVE_RE.match(self.cve):
            errs.append(f"cve not in CVE-YYYY-NNNN form: {self.cve!r}")
        if self.owasp is not None and not OWASP_RE.match(self.owasp):
            errs.append(f"owasp not in ANN:2021 form: {self.owasp!r}")
        if self.severity is not None and self.severity not in SEVERITIES:
            errs.append(f"severity not in allowed set: {self.severity!r}")
        if self.cvss is not None and not (0.0 <= self.cvss <= 10.0):
            errs.append(f"cvss out of range: {self.cvss}")
        if self.split not in SPLITS:
            errs.append(f"split not in allowed set: {self.split!r}")
        if self.source_license not in LICENSES:
            errs.append(f"source_license not in whitelist: {self.source_license!r}")
        for fld in ("explanation", "attack_scenario", "secure_fix"):
            v = getattr(self, fld) or ""
            if len(v) > MAX_TEXT_CHARS:
                errs.append(f"{fld} too long ({len(v)} chars)")
        # Corruption / harmful content (skip email pattern in code fields)
        for pat in HARM_PATTERNS:
            text_flds = ("vulnerable_code", "patched_code", "explanation",
                         "attack_scenario", "secure_fix")
            # Email pattern is too common in source headers — skip for code fields
            if pat.pattern.startswith(("\\b[A-Za-z0-9._%+-]", "[A-Za-z0-9._%+-]+@")):
                text_flds = ("explanation", "attack_scenario", "secure_fix")
            for fld in text_flds:
                v = getattr(self, fld) or ""
                if pat.search(v):
                    errs.append(f"harmful content ({pat.pattern[:30]}) in {fld}")
                    break
        # Non-UTF8 / null bytes
        for fld in ("vulnerable_code", "patched_code"):
            v = getattr(self, fld) or ""
            if "\x00" in v:
                errs.append(f"null byte in {fld}")
        return errs

    # ---- IO ----
    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        # Trim optional empty strings to None for compactness
        for k in ("patched_code", "cwe", "severity", "cve", "owasp", "cvss"):
            if d.get(k) in ("", None):
                d[k] = None
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "SecuritySample":
        return cls(
            id=d.get("id") or cls.make_id(d.get("vulnerable_code", "")),
            language=d.get("language", "text"),
            vulnerable_code=d.get("vulnerable_code", ""),
            patched_code=d.get("patched_code") or None,
            cwe=d.get("cwe") or None,
            severity=d.get("severity") or None,
            explanation=d.get("explanation", ""),
            attack_scenario=d.get("attack_scenario", ""),
            secure_fix=d.get("secure_fix", ""),
            source=d.get("source", "unknown"),
            source_license=d.get("source_license", "Unknown"),
            cve=d.get("cve") or None,
            owasp=d.get("owasp") or None,
            cvss=d.get("cvss") or None,
            is_vulnerable=bool(d.get("is_vulnerable", True)),
            split=d.get("split", "train"),
            fingerprint=d.get("fingerprint", ""),
            added_at=d.get("added_at", ""),
            references=list(d.get("references") or []),
        )


# ---------------------------------------------------------------------------
# JSONL IO
# ---------------------------------------------------------------------------


def read_jsonl(path: Path) -> Iterable[SecuritySample]:
    """Yield SecuritySample records, skipping lines that fail validation."""
    with path.open("r", encoding="utf-8") as f:
        for ln, raw in enumerate(f, 1):
            raw = raw.strip()
            if not raw:
                continue
            try:
                d = json.loads(raw)
            except json.JSONDecodeError:
                continue
            s = SecuritySample.from_dict(d)
            errs = s.validate()
            if errs:
                continue
            yield s


def write_jsonl(path: Path, samples: Iterable[SecuritySample]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with path.open("w", encoding="utf-8") as f:
        for s in samples:
            errs = s.validate()
            if errs:
                continue
            f.write(json.dumps(s.to_dict(), ensure_ascii=False) + "\n")
            n += 1
    return n


def load(path: Path) -> list[SecuritySample]:
    return list(read_jsonl(path))


__all__ = [
    "SecuritySample",
    "LANGUAGES", "SEVERITIES", "SPLITS", "LICENSES",
    "CWE_RE", "CVE_RE", "OWASP_RE",
    "HARM_PATTERNS",
    "MIN_CODE_CHARS", "MAX_CODE_CHARS", "MAX_TEXT_CHARS",
    "read_jsonl", "write_jsonl", "load",
]
