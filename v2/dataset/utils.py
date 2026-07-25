"""Dataset prep utilities: iter JSONL safely, language detect, text sanitize."""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any, Iterator

# lazy-import so this module loads without langdetect installed in CI
_langdetect_mod = None


def _langdetect():
    global _langdetect_mod
    if _langdetect_mod is None:
        try:
            import langdetect
            _langdetect_mod = langdetect
        except Exception:  # noqa: BLE001
            _langdetect_mod = False
    return _langdetect_mod or None


_PRINTABLE_RE = re.compile(r"[--￿\n\r\t]")


def safe_read_text(s: Any) -> str:
    if s is None:
        return ""
    if isinstance(s, bytes):
        try:
            s = s.decode("utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            return ""
    if not isinstance(s, str):
        s = str(s)
    s = s.replace("", " ")
    s = re.sub(r"[\x00-\x08\x0b-\x0c\x0e-\x1f\x7f]", " ", s)
    return s


def detect_language(code: str) -> str | None:
    ld = _langdetect()
    if ld is None:
        return None
    try:
        snippet = code[:4000]
        return ld.detect(snippet)
    except Exception:  # noqa: BLE001
        return None


def iter_jsonl(path: Path) -> Iterator[dict]:
    if not path.is_file():
        return
    if path.suffix == ".jsonl" or path.suffix == ".ndjson":
        with path.open("r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    continue
    elif path.suffix == ".json":
        try:
            data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        except json.JSONDecodeError:
            return
        if isinstance(data, list):
            yield from (x for x in data if isinstance(x, dict))
        elif isinstance(data, dict):
            yield data


def write_jsonl(path: Path, items: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for it in items:
            f.write(json.dumps(it, ensure_ascii=False) + "\n")


def sha_short(s: str, n: int = 12) -> str:
    return hashlib.sha1(s.encode("utf-8")).hexdigest()[:n]
