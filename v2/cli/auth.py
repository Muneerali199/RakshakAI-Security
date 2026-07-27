"""Auth module — token management, web login flow, session storage."""
from __future__ import annotations
import json
import os
import time
import threading
import webbrowser
from pathlib import Path
from dataclasses import dataclass
from typing import Optional
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from datetime import datetime

AUTH_DIR = Path.home() / ".rakshak"
AUTH_FILE = AUTH_DIR / "auth.json"
AUTH_SERVER_PORT = int(os.environ.get("RAKSHAK_AUTH_PORT", "8888"))
AUTH_SERVER_HOST = os.environ.get("RAKSHAK_AUTH_HOST", f"http://localhost:{AUTH_SERVER_PORT}")


@dataclass
class AuthState:
    email: str = ""
    token: str = ""
    refresh_token: str = ""
    logged_in: bool = False
    login_time: float = 0.0
    plan: str = "free"

    def save(self):
        AUTH_DIR.mkdir(parents=True, exist_ok=True)
        AUTH_DIR.chmod(0o700)
        AUTH_FILE.write_text(json.dumps({
            "email": self.email,
            "token": self.token,
            "refresh_token": self.refresh_token,
            "login_time": self.login_time,
            "plan": self.plan,
        }, indent=2))
        AUTH_FILE.chmod(0o600)

    def load(self) -> bool:
        if AUTH_FILE.exists():
            try:
                data = json.loads(AUTH_FILE.read_text())
                self.email = data.get("email", "")
                self.token = data.get("token", "")
                self.refresh_token = data.get("refresh_token", "")
                self.login_time = data.get("login_time", 0)
                self.plan = data.get("plan", "free")
                self.logged_in = bool(self.token)
            except (json.JSONDecodeError, KeyError):
                self.clear()
            return self.logged_in
        return False

    def clear(self):
        self.email = ""
        self.token = ""
        self.refresh_token = ""
        self.logged_in = False
        self.login_time = 0
        self.plan = "free"
        if AUTH_FILE.exists():
            AUTH_FILE.unlink()

    @property
    def elapsed(self) -> str:
        if not self.login_time:
            return "—"
        delta = time.time() - self.login_time
        if delta < 60:
            return f"{int(delta)}s"
        if delta < 3600:
            return f"{int(delta // 60)}m"
        if delta < 86400:
            return f"{int(delta // 3600)}h"
        return f"{int(delta // 86400)}d"


auth_state = AuthState()
_auth_server_instance: Optional[HTTPServer] = None


class _CallbackHandler(BaseHTTPRequestHandler):
    token_result: list[str] = []

    def do_GET(self):
        qs = parse_qs(urlparse(self.path).query)
        if "token" in qs:
            self.token_result.append(qs["token"][0])
            self._respond(200, "<html><body><h2>✓ Logged in! You can close this window.</h2></body></html>")
        elif "error" in qs:
            self._respond(400, f"<html><body><h2>Login failed: {qs['error'][0]}</h2></body></html>")
        else:
            self._respond(200, "<html><body><h2>Waiting for login... Close this window and try again.</h2></body></html>")

    def _respond(self, code: int, body: str):
        self.send_response(code)
        self.send_header("Content-type", "text/html; charset=utf-8")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body.encode())

    def log_message(self, fmt, *args):
        pass


def start_callback_server(port: int = 0) -> tuple[HTTPServer, int]:
    """Start a local callback server to receive the auth token."""
    global _auth_server_instance
    _CallbackHandler.token_result.clear()
    server = HTTPServer(("127.0.0.1", port or 0), _CallbackHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    _auth_server_instance = server
    return server, port


def stop_callback_server():
    global _auth_server_instance
    if _auth_server_instance:
        _auth_server_instance.shutdown()
        _auth_server_instance = None


def login_flow(timeout: int = 120) -> Optional[str]:
    """Open browser to auth server login page, wait for callback token."""
    server, port = start_callback_server()
    callback_url = f"http://127.0.0.1:{port}/"
    login_url = f"{AUTH_SERVER_HOST}/login?redirect={callback_url}"
    webbrowser.open(login_url)

    for _ in range(timeout):
        if _CallbackHandler.token_result:
            token = _CallbackHandler.token_result[0]
            stop_callback_server()
            return token
        time.sleep(1)

    stop_callback_server()
    return None


def login_token(token: str) -> bool:
    """Manually set an auth token (paste from web UI)."""
    user_info = fetch_user_info(token)
    if not user_info:
        return False
    auth_state.email = user_info.get("email", "")
    auth_state.token = token
    auth_state.logged_in = True
    auth_state.login_time = time.time()
    auth_state.plan = user_info.get("plan", "free")
    auth_state.save()
    return True


def fetch_user_info(token: str) -> Optional[dict]:
    """Fetch user info from the auth server."""
    import requests as req
    try:
        r = req.get(f"{AUTH_SERVER_HOST}/api/me", headers={"Authorization": f"Bearer {token}"}, timeout=10)
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return None
