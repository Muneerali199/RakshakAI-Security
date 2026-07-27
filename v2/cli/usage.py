"""Usage tracking — daily limits, plan enforcement, usage reset."""
from __future__ import annotations
import json
import os
import time
from pathlib import Path
from datetime import date

USAGE_DIR = Path.home() / ".rakshak"
USAGE_FILE = USAGE_DIR / "usage.json"

FREE_LIMITS = {
    "ai_scans": -1,
    "regex_scans": -1,
    "models": "all",
}

PRO_LIMITS = {
    "ai_scans": -1,
    "regex_scans": -1,
    "models": "all",
}


def _today() -> str:
    return date.today().isoformat()


def _load_usage() -> dict:
    if USAGE_FILE.exists():
        try:
            return json.loads(USAGE_FILE.read_text())
        except (json.JSONDecodeError, OSError):
            pass
    return {
        "date": _today(),
        "ai_scans": 0,
        "regex_scans": 0,
        "last_reset": time.time(),
    }


def _save_usage(data: dict):
    USAGE_DIR.mkdir(parents=True, exist_ok=True)
    USAGE_FILE.write_text(json.dumps(data, indent=2))


def _ensure_today(data: dict):
    if data.get("date") != _today():
        data["date"] = _today()
        data["ai_scans"] = 0
        data["regex_scans"] = 0
        data["last_reset"] = time.time()


def increment_ai_scan() -> tuple[bool, int, int]:
    """Increment AI scan count. Returns (allowed, used, limit)."""
    data = _load_usage()
    _ensure_today(data)
    data["ai_scans"] = data.get("ai_scans", 0) + 1
    _save_usage(data)
    used = data["ai_scans"]
    limit = FREE_LIMITS["ai_scans"]
    return used <= limit, used, limit


def increment_regex_scan() -> tuple[bool, int, int]:
    """Increment regex scan count. Returns (allowed, used, limit)."""
    data = _load_usage()
    _ensure_today(data)
    data["regex_scans"] = data.get("regex_scans", 0) + 1
    _save_usage(data)
    used = data["regex_scans"]
    limit = FREE_LIMITS["regex_scans"]
    return used <= limit, used, limit


def get_usage() -> dict:
    """Get current usage stats."""
    data = _load_usage()
    _ensure_today(data)
    return {
        "date": data["date"],
        "ai_scans": {
            "used": data.get("ai_scans", 0),
            "limit": FREE_LIMITS["ai_scans"],
            "remaining": max(0, FREE_LIMITS["ai_scans"] - data.get("ai_scans", 0)),
        },
        "regex_scans": {
            "used": data.get("regex_scans", 0),
            "limit": FREE_LIMITS["regex_scans"],
            "remaining": max(0, FREE_LIMITS["regex_scans"] - data.get("regex_scans", 0)),
        },
    }


def check_ai_scan_allowed() -> tuple[bool, str]:
    """Check if AI scan is allowed. Returns (allowed, reason)."""
    limit = FREE_LIMITS["ai_scans"]
    if limit == -1:
        return True, "Unlimited AI scans remaining"
    
    data = _load_usage()
    _ensure_today(data)
    used = data.get("ai_scans", 0)
    if used >= limit:
        remaining_secs = max(0, 86400 - (time.time() - data.get("last_reset", 0)))
        return False, f"Daily AI scan limit reached ({limit}/{limit}). Resets in {int(remaining_secs // 3600)}h {int((remaining_secs % 3600) // 60)}m"
    remaining = limit - used
    return True, f"{remaining}/{limit} AI scans remaining today"


def check_regex_scan_allowed() -> tuple[bool, str]:
    """Check if regex scan is allowed. Returns (allowed, reason)."""
    limit = FREE_LIMITS["regex_scans"]
    if limit == -1:
        return True, "Unlimited regex scans remaining"
        
    data = _load_usage()
    _ensure_today(data)
    used = data.get("regex_scans", 0)
    if used >= limit:
        return False, f"Daily regex scan limit reached ({limit}/{limit})"
    remaining = limit - used
    return True, f"{remaining}/{limit} regex scans remaining today"


def reset_usage():
    """Force reset today's usage."""
    data = _load_usage()
    data["date"] = _today()
    data["ai_scans"] = 0
    data["regex_scans"] = 0
    data["last_reset"] = time.time()
    _save_usage(data)


def format_usage_bar(used: int, limit: int, width: int = 20) -> str:
    """Format a usage bar like ████░░░░░░ 5/10."""
    if limit <= 0:
        return "─" * width + f" unlimited"
    ratio = min(1.0, used / limit)
    filled = int(ratio * width)
    bar = "█" * filled + "░" * (width - filled)
    return f"{bar} {used}/{limit}"
