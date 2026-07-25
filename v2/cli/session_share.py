"""Session sharing - upload and share scan sessions via unique URLs.

Example:
    session_id = memory.start_session(...)
    url = upload_session(session_id)
    # => "https://rakshak.ai/s/abc123xyz"
"""
from __future__ import annotations
import os
import json
import hashlib
import requests
from typing import Optional
from pathlib import Path


# Session storage endpoint (can be self-hosted or use rakshak.ai)
SHARE_ENDPOINT = os.getenv("RAKSHAK_SHARE_ENDPOINT", "https://rakshak.ai/api/share")


def upload_session(session_id: int, db_path: str = None) -> Optional[str]:
    """Upload session to share endpoint and return public URL.
    
    Args:
        session_id: Session ID from memory.start_session()
        db_path: Path to SQLite database (defaults to ~/.rakshak.db)
    
    Returns:
        Public URL like "https://rakshak.ai/s/abc123xyz" or None if failed
    """
    import sqlite3
    
    if db_path is None:
        db_path = os.path.expanduser("~/.rakshak.db")
    
    if not os.path.exists(db_path):
        return None
    
    try:
        # Fetch session data from database
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        
        # Get session info
        cur.execute("""
            SELECT * FROM sessions WHERE id = ?
        """, (session_id,))
        session = cur.fetchone()
        
        if not session:
            conn.close()
            return None
        
        # Get all analyses for this session
        cur.execute("""
            SELECT * FROM analyses WHERE session_id = ? ORDER BY timestamp ASC
        """, (session_id,))
        analyses = [dict(row) for row in cur.fetchall()]
        
        conn.close()
        
        # Build shareable payload
        payload = {
            "session": dict(session),
            "analyses": analyses,
            "version": "v3",
        }
        
        # Generate deterministic hash
        payload_str = json.dumps(payload, sort_keys=True)
        hash_id = hashlib.sha256(payload_str.encode()).hexdigest()[:12]
        
        # Upload to share endpoint
        response = requests.post(
            SHARE_ENDPOINT,
            json={"id": hash_id, "data": payload},
            timeout=10,
        )
        
        if response.status_code == 200 or response.status_code == 201:
            result = response.json()
            return result.get("url", f"https://rakshak.ai/s/{hash_id}")
        else:
            return None
    
    except Exception as e:
        print(f"Upload failed: {e}")
        return None


def save_session_local(session_id: int, output_file: str, db_path: str = None) -> bool:
    """Save session as JSON file locally (offline sharing).
    
    Args:
        session_id: Session ID
        output_file: Path to save JSON file
        db_path: Path to SQLite database
    
    Returns:
        True if successful
    """
    import sqlite3
    
    if db_path is None:
        db_path = os.path.expanduser("~/.rakshak.db")
    
    if not os.path.exists(db_path):
        return False
    
    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        
        # Get session
        cur.execute("SELECT * FROM sessions WHERE id = ?", (session_id,))
        session = dict(cur.fetchone())
        
        # Get analyses
        cur.execute("SELECT * FROM analyses WHERE session_id = ? ORDER BY timestamp ASC", (session_id,))
        analyses = [dict(row) for row in cur.fetchall()]
        
        conn.close()
        
        # Write to file
        with open(output_file, 'w') as f:
            json.dump({
                "session": session,
                "analyses": analyses,
                "version": "v3",
            }, f, indent=2, default=str)
        
        return True
    
    except Exception:
        return False


def load_shared_session(url_or_id: str) -> Optional[dict]:
    """Load a shared session by URL or ID.
    
    Args:
        url_or_id: Either full URL or just the hash ID
    
    Returns:
        Session data dict or None
    """
    # Extract ID from URL if needed
    if url_or_id.startswith("http"):
        hash_id = url_or_id.split("/")[-1]
    else:
        hash_id = url_or_id
    
    try:
        response = requests.get(
            f"{SHARE_ENDPOINT.replace('/share', '')}/s/{hash_id}",
            timeout=10,
        )
        
        if response.status_code == 200:
            return response.json()
        else:
            return None
    
    except Exception:
        return None


def export_for_github(session_id: int, db_path: str = None) -> str:
    """Export session as GitHub-friendly markdown report.
    
    Args:
        session_id: Session ID
        db_path: Path to SQLite database
    
    Returns:
        Markdown string
    """
    import sqlite3
    from datetime import datetime
    
    if db_path is None:
        db_path = os.path.expanduser("~/.rakshak.db")
    
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    
    # Get session
    cur.execute("SELECT * FROM sessions WHERE id = ?", (session_id,))
    session = dict(cur.fetchone())
    
    # Get analyses
    cur.execute("""
        SELECT * FROM analyses WHERE session_id = ? ORDER BY timestamp ASC
    """, (session_id,))
    analyses = [dict(row) for row in cur.fetchall()]
    
    conn.close()
    
    # Build markdown
    md = f"""# RakshakAI Scan Report

**Session ID:** {session_id}  
**Started:** {session['started_at']}  
**Model:** {session['model']}  
**Directory:** {session['working_directory']}  

## Summary

- **Total Analyses:** {len(analyses)}
- **Vulnerabilities Found:** {sum(1 for a in analyses if a.get('cwe'))}
- **Files Scanned:** {len(set(a['file_path'] for a in analyses if a.get('file_path')))}

## Findings

"""
    
    # Group by severity
    by_severity = {}
    for analysis in analyses:
        if not analysis.get('cwe'):
            continue
        
        severity = analysis.get('severity', 'unknown')
        if severity not in by_severity:
            by_severity[severity] = []
        by_severity[severity].append(analysis)
    
    for severity in ['critical', 'high', 'medium', 'low']:
        if severity not in by_severity:
            continue
        
        md += f"\n### {severity.upper()} ({len(by_severity[severity])})\n\n"
        
        for analysis in by_severity[severity]:
            file_path = analysis.get('file_path', 'unknown')
            cwe = analysis.get('cwe', 'CWE-???')
            
            md += f"- **{cwe}** in `{file_path}`\n"
    
    md += "\n---\n*Generated by [RakshakAI](https://github.com/yourusername/RakshakAI)*\n"
    
    return md


# CLI usage
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python session_share.py upload <session_id>")
        print("  python session_share.py save <session_id> <output.json>")
        print("  python session_share.py export <session_id> <output.md>")
        sys.exit(1)
    
    command = sys.argv[1]
    
    if command == "upload":
        session_id = int(sys.argv[2])
        url = upload_session(session_id)
        if url:
            print(f"✓ Session uploaded: {url}")
        else:
            print("✗ Upload failed")
            sys.exit(1)
    
    elif command == "save":
        session_id = int(sys.argv[2])
        output_file = sys.argv[3]
        if save_session_local(session_id, output_file):
            print(f"✓ Session saved to {output_file}")
        else:
            print("✗ Save failed")
            sys.exit(1)
    
    elif command == "export":
        session_id = int(sys.argv[2])
        output_file = sys.argv[3]
        md = export_for_github(session_id)
        with open(output_file, 'w') as f:
            f.write(md)
        print(f"✓ Report exported to {output_file}")
