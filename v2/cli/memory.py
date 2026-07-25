"""Persistent session memory — SQLite-backed, searchable across sessions.

What no other CLI does: remembers every analysis, every finding,
every conversation. Ask "what did we find in that file last week?"
and it answers instantly.
"""
from __future__ import annotations
import hashlib
import json
import os
import sqlite3
import threading
from datetime import datetime
from pathlib import Path
from typing import Optional

MEMORY_DIR = os.path.expanduser("~/.rakshak/memory")
DB_PATH = os.path.join(MEMORY_DIR, "memory.db")
_local = threading.local()


def _get_db() -> sqlite3.Connection:
    """Get thread-local database connection."""
    if not hasattr(_local, "conn") or _local.conn is None:
        os.makedirs(MEMORY_DIR, exist_ok=True)
        _local.conn = sqlite3.connect(DB_PATH)
        _local.conn.row_factory = sqlite3.Row
        _init_db(_local.conn)
    return _local.conn


def _init_db(conn: sqlite3.Connection):
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            started_at TEXT NOT NULL,
            ended_at TEXT,
            model TEXT,
            dir TEXT,
            summary TEXT
        );
        CREATE TABLE IF NOT EXISTS analyses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id INTEGER NOT NULL,
            timestamp TEXT NOT NULL,
            file_path TEXT,
            language TEXT,
            cwe TEXT,
            severity TEXT,
            model TEXT,
            query_hash TEXT,
            query TEXT,
            response TEXT,
            structured JSON,
            duration_ms INTEGER,
            FOREIGN KEY (session_id) REFERENCES sessions(id)
        );
        CREATE TABLE IF NOT EXISTS cache (
            query_hash TEXT PRIMARY KEY,
            response TEXT,
            model TEXT,
            cached_at TEXT NOT NULL,
            hits INTEGER DEFAULT 1
        );
        CREATE TABLE IF NOT EXISTS feedback (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            analysis_id INTEGER NOT NULL,
            verdict TEXT NOT NULL CHECK(verdict IN ('confirmed', 'dismissed')),
            note TEXT,
            timestamp TEXT NOT NULL,
            FOREIGN KEY (analysis_id) REFERENCES analyses(id)
        );
        CREATE INDEX IF NOT EXISTS idx_analyses_file ON analyses(file_path);
        CREATE INDEX IF NOT EXISTS idx_analyses_cwe ON analyses(cwe);
        CREATE INDEX IF NOT EXISTS idx_analyses_session ON analyses(session_id);
        CREATE INDEX IF NOT EXISTS idx_feedback_analysis ON feedback(analysis_id);
        CREATE INDEX IF NOT EXISTS idx_feedback_verdict ON feedback(verdict);
    """)
    conn.commit()


def start_session(model: str, directory: str) -> int:
    conn = _get_db()
    cur = conn.execute(
        "INSERT INTO sessions (started_at, model, dir) VALUES (?, ?, ?)",
        (datetime.utcnow().isoformat(), model, directory),
    )
    conn.commit()
    return cur.lastrowid


def end_session(session_id: int):
    conn = _get_db()
    conn.execute(
        "UPDATE sessions SET ended_at = ? WHERE id = ?",
        (datetime.utcnow().isoformat(), session_id),
    )
    conn.commit()


def record_analysis(
    session_id: int,
    file_path: str = "",
    language: str = "",
    cwe: str = "",
    severity: str = "",
    model: str = "",
    query_hash: str = "",
    query: str = "",
    response: str = "",
    structured: Optional[dict] = None,
    duration_ms: int = 0,
) -> int:
    conn = _get_db()
    cur = conn.execute(
        """INSERT INTO analyses
           (session_id, timestamp, file_path, language, cwe, severity, model,
            query_hash, query, response, structured, duration_ms)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            session_id,
            datetime.utcnow().isoformat(),
            file_path,
            language,
            cwe,
            severity,
            model,
            query_hash,
            query,
            response,
            json.dumps(structured) if structured else None,
            duration_ms,
        ),
    )
    conn.commit()
    return cur.lastrowid


def get_cached(query_hash: str, model: str) -> Optional[str]:
    conn = _get_db()
    row = conn.execute(
        "SELECT response FROM cache WHERE query_hash = ? AND model = ?",
        (query_hash, model),
    ).fetchone()
    if row:
        conn.execute(
            "UPDATE cache SET hits = hits + 1 WHERE query_hash = ? AND model = ?",
            (query_hash, model),
        )
        conn.commit()
        return row["response"]
    return None


def set_cached(query_hash: str, response: str, model: str):
    conn = _get_db()
    conn.execute(
        """INSERT OR REPLACE INTO cache (query_hash, response, model, cached_at)
           VALUES (?, ?, ?, ?)""",
        (query_hash, response, model, datetime.utcnow().isoformat()),
    )
    conn.commit()


def search_analyses(query: str, limit: int = 20) -> list[dict]:
    """Search across all analyses with full-text search-like matching."""
    conn = _get_db()
    like = f"%{query}%"
    rows = conn.execute(
        """SELECT a.*, s.model as session_model, s.started_at as session_start
           FROM analyses a
           JOIN sessions s ON a.session_id = s.id
           WHERE a.file_path LIKE ? OR a.cwe LIKE ? OR a.query LIKE ?
              OR a.response LIKE ? OR a.severity LIKE ?
           ORDER BY a.timestamp DESC LIMIT ?""",
        (like, like, like, like, like, limit),
    ).fetchall()
    return [dict(r) for r in rows]


def get_file_history(file_path: str, limit: int = 10) -> list[dict]:
    """Get all analyses for a specific file across sessions."""
    conn = _get_db()
    rows = conn.execute(
        """SELECT a.*, s.started_at as session_start
           FROM analyses a
           JOIN sessions s ON a.session_id = s.id
           WHERE a.file_path = ?
           ORDER BY a.timestamp DESC LIMIT ?""",
        (file_path, limit),
    ).fetchall()
    return [dict(r) for r in rows]


def get_stats() -> dict:
    conn = _get_db()
    stats = {}
    stats["sessions"] = conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
    stats["analyses"] = conn.execute("SELECT COUNT(*) FROM analyses").fetchone()[0]
    stats["cache_entries"] = conn.execute("SELECT COUNT(*) FROM cache").fetchone()[0]
    stats["cache_hits"] = conn.execute("SELECT SUM(hits) FROM cache").fetchone()[0] or 0
    stats["files_scanned"] = conn.execute(
        "SELECT COUNT(DISTINCT file_path) FROM analyses WHERE file_path != ''"
    ).fetchone()[0]
    # Top CWEs
    rows = conn.execute(
        "SELECT cwe, COUNT(*) as cnt FROM analyses WHERE cwe != '' GROUP BY cwe ORDER BY cnt DESC LIMIT 10"
    ).fetchall()
    stats["top_cwes"] = [{"cwe": r[0], "count": r[1]} for r in rows]
    # Feedback stats
    fb = conn.execute("SELECT COUNT(*) FROM feedback").fetchone()[0]
    confirmed = conn.execute("SELECT COUNT(*) FROM feedback WHERE verdict = 'confirmed'").fetchone()[0]
    dismissed = conn.execute("SELECT COUNT(*) FROM feedback WHERE verdict = 'dismissed'").fetchone()[0]
    stats["feedback_total"] = fb
    stats["feedback_confirmed"] = confirmed
    stats["feedback_dismissed"] = dismissed
    stats["precision"] = round(confirmed / fb, 3) if fb else None
    # Cost stats
    cost_rows = conn.execute(
        """SELECT model, COUNT(*) as cnt, SUM(duration_ms) as total_ms, AVG(duration_ms) as avg_ms
           FROM analyses GROUP BY model"""
    ).fetchall()
    stats["model_usage"] = [
        {"model": r[0], "count": r[1], "total_ms": r[2] or 0, "avg_ms": round(r[3] or 0)}
        for r in cost_rows
    ]
    return stats


def confirm_finding(analysis_id: int, note: str = "") -> int:
    """Mark a finding as confirmed (true positive). Returns feedback id."""
    conn = _get_db()
    cur = conn.execute(
        "INSERT INTO feedback (analysis_id, verdict, note, timestamp) VALUES (?, 'confirmed', ?, ?)",
        (analysis_id, note, datetime.utcnow().isoformat()),
    )
    conn.commit()
    return cur.lastrowid


def dismiss_finding(analysis_id: int, note: str = "") -> int:
    """Mark a finding as dismissed (false positive). Returns feedback id."""
    conn = _get_db()
    cur = conn.execute(
        "INSERT INTO feedback (analysis_id, verdict, note, timestamp) VALUES (?, 'dismissed', ?, ?)",
        (analysis_id, note, datetime.utcnow().isoformat()),
    )
    conn.commit()
    return cur.lastrowid


def get_feedback_for_analysis(analysis_id: int) -> list[dict]:
    """Get all feedback for a specific analysis."""
    conn = _get_db()
    rows = conn.execute(
        "SELECT * FROM feedback WHERE analysis_id = ? ORDER BY timestamp DESC",
        (analysis_id,),
    ).fetchall()
    return [dict(r) for r in rows]


def get_dismissed_cwes() -> list[dict]:
    """Get CWEs that have been dismissed, for learning false-positive patterns."""
    conn = _get_db()
    rows = conn.execute(
        """SELECT a.cwe, COUNT(*) as dismiss_count, GROUP_CONCAT(DISTINCT a.file_path) as files
           FROM feedback f
           JOIN analyses a ON f.analysis_id = a.id
           WHERE f.verdict = 'dismissed' AND a.cwe != ''
           GROUP BY a.cwe
           ORDER BY dismiss_count DESC"""
    ).fetchall()
    return [{"cwe": r[0], "dismiss_count": r[1], "files": r[2]} for r in rows]


# ── Content Hash Caching ──────────────────────────────────────

def get_cached_scan(file_path: str, content_hash: str, model: str = "") -> Optional[dict]:
    """Return cached scan result if file content unchanged (within 7 days).

    Uses `analyses` table with query_hash matching content_hash.
    Returns deserialized structured data if found, None otherwise.
    """
    conn = _get_db()
    if model:
        row = conn.execute(
            """SELECT structured FROM analyses
               WHERE file_path = ? AND query_hash = ? AND model = ?
                 AND timestamp > datetime('now', '-7 days')
               ORDER BY timestamp DESC LIMIT 1""",
            (file_path, content_hash, model),
        ).fetchone()
    else:
        row = conn.execute(
            """SELECT structured FROM analyses
               WHERE file_path = ? AND query_hash = ?
                 AND timestamp > datetime('now', '-7 days')
               ORDER BY timestamp DESC LIMIT 1""",
            (file_path, content_hash),
        ).fetchone()
    if row and row["structured"]:
        try:
            return json.loads(row["structured"])
        except (json.JSONDecodeError, TypeError):
            pass
    return None


def cache_scan_result(
    file_path: str,
    content_hash: str,
    model: str,
    result: dict,
    duration_ms: int = 0,
    session_id: int = 0,
):
    """Cache a scan result for later reuse.

    Stores in both analyses table (for history) and cache table (for quick lookup).
    """
    from datetime import datetime
    conn = _get_db()
    structured = json.dumps(result)
    conn.execute(
        """INSERT OR REPLACE INTO cache (query_hash, response, model, cached_at)
           VALUES (?, ?, ?, ?)""",
        (content_hash, structured, model, datetime.utcnow().isoformat()),
    )
    if session_id and file_path:
        cwe = ""
        sev = ""
        vulns = result.get("vulnerabilities", [])
        if vulns:
            cwe = vulns[0].get("cwe", "")
            sev = vulns[0].get("severity", "")
        conn.execute(
            """INSERT INTO analyses
               (session_id, timestamp, file_path, language, cwe, severity, model,
                query_hash, query, response, structured, duration_ms)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                session_id,
                datetime.utcnow().isoformat(),
                file_path,
                Path(file_path).suffix[1:] if file_path else "",
                cwe,
                sev,
                model,
                content_hash,
                f"scan {file_path}",
                structured,
                structured,
                duration_ms,
            ),
        )
    conn.commit()
