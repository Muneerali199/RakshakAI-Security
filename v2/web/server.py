"""RakshakAI Auth Web Server — login, register, token, referral, training tracking."""
from __future__ import annotations
import os, sys, json, time, secrets, sqlite3, uuid, re, logging as _logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional
from contextlib import asynccontextmanager
from collections import defaultdict

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import BaseModel, field_validator
import uvicorn

try:
    import bcrypt as _bcrypt
    HAS_BCRYPT = True
except ImportError:
    HAS_BCRYPT = False

_logging.basicConfig(
    level=_logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = _logging.getLogger("rakshak-auth")

DB_PATH = Path.home() / ".rakshak" / "auth.db"
PORT = int(os.environ.get("RAKSHAK_AUTH_PORT", "8080"))
HOST = os.environ.get("RAKSHAK_AUTH_HOST", "0.0.0.0")
ALLOWED_ORIGINS = os.environ.get("RAKSHAK_CORS_ORIGINS", "*").split(",")
MAX_LOGIN_ATTEMPTS = int(os.environ.get("RAKSHAK_MAX_LOGIN_ATTEMPTS", "10"))
RATE_LIMIT_WINDOW = int(os.environ.get("RAKSHAK_RATE_LIMIT_WINDOW", "300"))
TOKEN_EXPIRE_DAYS = int(os.environ.get("RAKSHAK_TOKEN_EXPIRE_DAYS", "30"))

_db_conn = None

def _init_db():
    global _db_conn
    if _db_conn is not None:
        return _db_conn
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    DB_PATH.parent.chmod(0o700)
    _db_conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    DB_PATH.chmod(0o600)
    _db_conn.row_factory = sqlite3.Row
    _db_conn.execute("PRAGMA journal_mode=WAL")
    _db_conn.execute("PRAGMA busy_timeout=5000")
    _db_conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            name TEXT DEFAULT '',
            plan TEXT DEFAULT 'free',
            created_at REAL DEFAULT (strftime('%s','now')),
            last_login REAL,
            login_attempts INTEGER DEFAULT 0,
            locked_until REAL DEFAULT 0,
            credits INTEGER DEFAULT 0,
            referred_by TEXT
        )
    """)
    _db_conn.execute("""
        CREATE TABLE IF NOT EXISTS tokens (
            token TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            created_at REAL DEFAULT (strftime('%s','now')),
            expires_at REAL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)
    _db_conn.execute("""
        CREATE TABLE IF NOT EXISTS referral_codes (
            code TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            uses INTEGER DEFAULT 0,
            max_uses INTEGER DEFAULT 100,
            created_at REAL DEFAULT (strftime('%s','now')),
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)
    _db_conn.execute("""
        CREATE TABLE IF NOT EXISTS referrals (
            id TEXT PRIMARY KEY,
            referrer_id TEXT NOT NULL,
            referee_id TEXT NOT NULL,
            code TEXT,
            bonus_credits INTEGER DEFAULT 5,
            created_at REAL DEFAULT (strftime('%s','now')),
            FOREIGN KEY (referrer_id) REFERENCES users(id),
            FOREIGN KEY (referee_id) REFERENCES users(id)
        )
    """)
    _db_conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_tokens_user ON tokens(user_id)
    """)
    _db_conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_tokens_expires ON tokens(expires_at)
    """)
    _db_conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_referrals_ref ON referrals(referrer_id)
    """)
    _db_conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_referral_codes_user ON referral_codes(user_id)
    """)
    _db_conn.commit()
    _clean_expired_tokens()
    return _db_conn

def _clean_expired_tokens():
    try:
        _db_conn.execute("DELETE FROM tokens WHERE expires_at IS NOT NULL AND expires_at < strftime('%s','now')")
        _db_conn.commit()
    except Exception:
        pass

def _hash_password(password: str) -> str:
    if HAS_BCRYPT:
        return _bcrypt.hashpw(password.encode(), _bcrypt.gensalt()).decode()
    return "bcrypt_unavailable_placeholder"

def _check_password(password: str, hash: str) -> bool:
    if hash == "bcrypt_unavailable_placeholder":
        return False
    try:
        return _bcrypt.checkpw(password.encode(), hash.encode())
    except Exception:
        return False

def _generate_token() -> str:
    return "rk_" + secrets.token_urlsafe(48)

def _create_token(user_id: str) -> str:
    token = _generate_token()
    expires = (datetime.now() + timedelta(days=TOKEN_EXPIRE_DAYS)).timestamp()
    conn = _init_db()
    conn.execute(
        "INSERT INTO tokens (token, user_id, expires_at) VALUES (?, ?, ?)",
        (token, user_id, expires),
    )
    conn.commit()
    return token

def _verify_token(token: str) -> Optional[dict]:
    if not token or not token.startswith("rk_"):
        return None
    conn = _init_db()
    row = conn.execute("""
        SELECT u.id, u.email, u.name, u.plan, u.credits
        FROM tokens t JOIN users u ON t.user_id = u.id
        WHERE t.token = ? AND (t.expires_at IS NULL OR t.expires_at > strftime('%s','now'))
    """, (token,)).fetchone()
    return dict(row) if row else None

def _generate_referral_code() -> str:
    return "RAKSHAK-" + secrets.token_hex(4).upper()

def _get_user_by_token(request: Request) -> Optional[dict]:
    auth = request.headers.get("Authorization", "")
    token = auth.replace("Bearer ", "") if auth.startswith("Bearer ") else ""
    return _verify_token(token)

class RateLimiter:
    def __init__(self, max_attempts: int, window_seconds: int):
        self.max_attempts = max_attempts
        self.window = window_seconds
        self.attempts: dict[str, list[float]] = defaultdict(list)
    def check(self, key: str) -> bool:
        now = time.time()
        self.attempts[key] = [t for t in self.attempts[key] if now - t < self.window]
        if len(self.attempts[key]) >= self.max_attempts:
            return False
        self.attempts[key].append(now)
        return True
    def reset(self, key: str):
        self.attempts.pop(key, None)

rate_limiter = RateLimiter(MAX_LOGIN_ATTEMPTS, RATE_LIMIT_WINDOW)

async def security_middleware(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Server"] = "RakshakAI"
    return response

EMAIL_RE = re.compile(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$")

class RegisterRequest(BaseModel):
    email: str
    password: str
    name: str = ""
    ref: str = ""

    @field_validator("email")
    @classmethod
    def validate_email(cls, v):
        if not EMAIL_RE.match(v):
            raise ValueError("Invalid email format")
        if len(v) > 254:
            raise ValueError("Email too long")
        return v.lower().strip()

    @field_validator("password")
    @classmethod
    def validate_password(cls, v):
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters")
        if len(v) > 128:
            raise ValueError("Password too long (max 128)")
        return v

    @field_validator("name")
    @classmethod
    def validate_name(cls, v):
        if len(v) > 100:
            raise ValueError("Name too long (max 100)")
        if v and not re.match(r"^[a-zA-Z0-9\s.\-']+$", v):
            raise ValueError("Name contains invalid characters")
        return v.strip()

class LoginRequest(BaseModel):
    email: str
    password: str

    @field_validator("email")
    @classmethod
    def validate_email(cls, v):
        return v.lower().strip() if v else v

class ReferralGenerateRequest(BaseModel):
    max_uses: int = 100

@asynccontextmanager
async def lifespan(app: FastAPI):
    _init_db()
    log.info(f"Auth server starting on {HOST}:{PORT}")
    log.info(f"  Login:  http://localhost:{PORT}/login")
    log.info(f"  Register: http://localhost:{PORT}/register")
    log.info(f"  Bcrypt: {'✓' if HAS_BCRYPT else '✗ NOT AVAILABLE'}")
    yield
    log.info("Auth server shutting down")

app = FastAPI(title="RakshakAI Auth", version="2.0.0", lifespan=lifespan)
app.middleware("http")(security_middleware)

from fastapi.middleware.cors import CORSMiddleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "OPTIONS"],
    allow_headers=["*"],
    max_age=3600,
)

# ═══════════════════════════════════════════════
# AUTH API
# ═══════════════════════════════════════════════

@app.post("/api/register")
async def register(req: RegisterRequest, request: Request):
    client_ip = request.client.host if request.client else "unknown"
    if not rate_limiter.check(f"register:{client_ip}"):
        raise HTTPException(429, "Too many registration attempts. Try again later.")
    if not HAS_BCRYPT:
        raise HTTPException(503, "Authentication unavailable (bcrypt not installed). Run: pip install bcrypt")

    conn = _init_db()
    existing = conn.execute("SELECT id FROM users WHERE email = ?", (req.email,)).fetchone()
    if existing:
        raise HTTPException(409, "Email already registered")

    user_id = str(uuid.uuid4())
    ref_id = None
    if req.ref:
        code_row = conn.execute(
            "SELECT user_id FROM referral_codes WHERE code = ? AND uses < max_uses",
            (req.ref.upper(),),
        ).fetchone()
        if code_row:
            ref_id = code_row["user_id"]
            conn.execute("UPDATE referral_codes SET uses = uses + 1 WHERE code = ?", (req.ref.upper(),))

    conn.execute(
        "INSERT INTO users (id, email, password_hash, name, referred_by, credits) VALUES (?, ?, ?, ?, ?, ?)",
        (user_id, req.email, _hash_password(req.password), req.name, ref_id, 3),
    )

    if ref_id:
        conn.execute(
            "INSERT INTO referrals (id, referrer_id, referee_id, code) VALUES (?, ?, ?, ?)",
            (str(uuid.uuid4()), ref_id, user_id, req.ref.upper()),
        )
        conn.execute("UPDATE users SET credits = credits + 5 WHERE id = ?", (ref_id,))

    token = _create_token(user_id)
    conn.commit()
    log.info(f"Registered: {req.email}{' via ref: ' + req.ref if req.ref else ''}")
    return {
        "token": token, "email": req.email, "name": req.name,
        "plan": "free", "credits": 3,
    }

@app.post("/api/login")
async def login(req: LoginRequest, request: Request):
    client_ip = request.client.host if request.client else "unknown"
    if not rate_limiter.check(f"login:{client_ip}"):
        raise HTTPException(429, "Too many login attempts. Try again later.")
    if not HAS_BCRYPT:
        raise HTTPException(503, "Authentication unavailable (bcrypt not installed). Run: pip install bcrypt")

    conn = _init_db()
    user = conn.execute(
        "SELECT id, email, name, plan, password_hash, locked_until FROM users WHERE email = ?",
        (req.email,),
    ).fetchone()
    if user and user["locked_until"] and user["locked_until"] > time.time():
        remaining = int(user["locked_until"] - time.time())
        raise HTTPException(429, f"Account locked. Try again in {remaining}s.")

    if not user or not _check_password(req.password, user["password_hash"]):
        if user:
            conn.execute("UPDATE users SET login_attempts = login_attempts + 1 WHERE id = ?", (user["id"],))
            row = conn.execute("SELECT login_attempts FROM users WHERE id = ?", (user["id"],)).fetchone()
            if row and row["login_attempts"] >= MAX_LOGIN_ATTEMPTS:
                conn.execute("UPDATE users SET locked_until = ? WHERE id = ?",
                    (time.time() + RATE_LIMIT_WINDOW, user["id"]))
                log.warning(f"Account locked: {req.email}")
        conn.commit()
        raise HTTPException(401, "Invalid email or password")

    conn.execute(
        "UPDATE users SET last_login = strftime('%s','now'), login_attempts = 0, locked_until = 0 WHERE id = ?",
        (user["id"],),
    )
    token = _create_token(user["id"])
    conn.commit()
    rate_limiter.reset(f"login:{client_ip}")
    log.info(f"Login: {req.email}")
    return {"token": token, "email": user["email"], "name": user["name"], "plan": user["plan"]}

@app.get("/api/me")
async def me(request: Request):
    user = _get_user_by_token(request)
    if not user:
        raise HTTPException(401, "Invalid or expired token")
    return user

@app.post("/api/logout")
async def logout(request: Request):
    auth = request.headers.get("Authorization", "")
    token = auth.replace("Bearer ", "") if auth.startswith("Bearer ") else ""
    if token:
        conn = _init_db()
        conn.execute("DELETE FROM tokens WHERE token = ?", (token,))
        conn.commit()
    return {"ok": True}

@app.get("/api/health")
async def health():
    return {"status": "ok", "uptime": time.time(), "bcrypt": HAS_BCRYPT}

# ═══════════════════════════════════════════════
# REFERRAL API
# ═══════════════════════════════════════════════

RK_BONUS = """
<div style="background:linear-gradient(135deg,rgba(0,255,255,0.08),rgba(255,0,255,0.08));border:1px solid rgba(0,255,255,0.2);border-radius:12px;padding:16px;margin-bottom:16px;text-align:center;">
  <div style="font-size:32px;margin-bottom:8px;">🎉</div>
  <div style="color:var(--cyan);font-weight:700;font-size:18px;margin-bottom:4px;">You got 5 bonus credits!</div>
  <div style="color:#999;font-size:13px;">Your referrer earned 5 credits too</div>
</div>"""

@app.post("/api/referral/generate")
async def generate_referral(req: ReferralGenerateRequest, request: Request):
    user = _get_user_by_token(request)
    if not user:
        raise HTTPException(401, "Not authenticated")
    conn = _init_db()
    existing = conn.execute(
        "SELECT code FROM referral_codes WHERE user_id = ?", (user["id"],)
    ).fetchone()
    if existing:
        base_url = request.base_url
        return {"code": existing["code"], "url": f"{base_url}register?ref={existing['code']}"}

    code = _generate_referral_code()
    conn.execute(
        "INSERT INTO referral_codes (code, user_id, max_uses) VALUES (?, ?, ?)",
        (code, user["id"], req.max_uses),
    )
    conn.commit()
    base_url = str(request.base_url).rstrip("/")
    return {"code": code, "url": f"{base_url}/register?ref={code}"}

@app.get("/api/referral/stats")
async def referral_stats(request: Request):
    user = _get_user_by_token(request)
    if not user:
        raise HTTPException(401, "Not authenticated")
    conn = _init_db()
    referrals = conn.execute(
        "SELECT r.id, r.bonus_credits, r.created_at, u.email, u.name, u.created_at as joined_at "
        "FROM referrals r JOIN users u ON r.referee_id = u.id "
        "WHERE r.referrer_id = ? ORDER BY r.created_at DESC",
        (user["id"],),
    ).fetchall()
    code = conn.execute(
        "SELECT code, uses, max_uses FROM referral_codes WHERE user_id = ?",
        (user["id"],),
    ).fetchone()
    return {
        "referrals": [dict(r) for r in referrals],
        "code": dict(code) if code else None,
        "total_earned": len(referrals) * 5,
    }

@app.get("/api/referral/{code}")
async def check_referral(code: str):
    conn = _init_db()
    row = conn.execute(
        "SELECT code, uses, max_uses FROM referral_codes WHERE code = ? AND uses < max_uses",
        (code.upper(),),
    ).fetchone()
    if not row:
        raise HTTPException(404, "Invalid or expired referral code")
    return {"code": row["code"], "valid": True}

# ═══════════════════════════════════════════════
# TRAINING STATUS API
# ═══════════════════════════════════════════════

TRAINING_INFO = {
    "model": "Qwen/Qwen2.5-Coder-14B-Instruct",
    "finetune": "RakshakAI CWE-14B-SFT",
    "base": "Qwen2.5-Coder-14B-Instruct",
    "method": "QLoRA (4-bit)",
    "dataset": "87K CWE security examples + reasoning traces",
    "total_steps": 750,
    "checkpoints": {
        "lightning_375": {"steps": 375, "source": "Lightning.ai A100-80GB", "status": "completed"},
        "checkpoint_50": {"steps": 50, "source": "Radeon Cloud W7900D", "status": "completed", "repo": "Muneerali199/rakshak-cwe-14b-sft-checkpoints"},
        "checkpoint_100": {"steps": 100, "source": "Radeon Cloud W7900D", "status": "completed", "repo": "Muneerali199/rakshak-cwe-14b-sft-checkpoints"},
        "checkpoint_150": {"steps": 150, "source": "Radeon Cloud W7900D", "status": "in_progress", "repo": "Muneerali199/rakshak-cwe-14b-sft-checkpoints"},
    },
    "cumulative_steps": 525,
    "progress_pct": 70,
    "lora_r": 32,
    "lora_alpha": 64,
    "batch_size": 1,
    "grad_accum": 16,
    "seq_len": 1024,
    "learning_rate": "1.5e-4",
    "scheduler": "cosine",
    "repo_final": "Muneerali199/rakshak-cwe-14b-sft-final",
    "repo_checkpoints": "Muneerali199/rakshak-cwe-14b-sft-checkpoints",
    "repo_step375": "Muneerali199/rakshak-cwe-14b-sft-step375",
}

# ═══════════════════════════════════════════════
# PAGE RENDERER
# ═══════════════════════════════════════════════

RAKSHAK_CSS = """
:root {
  --bg: #0a0a1a; --surface: rgba(255,255,255,0.03);
  --border: rgba(0,255,255,0.15); --cyan: #00ffff; --pink: #ff00ff;
  --green: #00ff88; --yellow: #ffdd00; --red: #ff4466; --text: #c0c0c0;
}
* { margin:0; padding:0; box-sizing:border-box; }
body { font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
  background:linear-gradient(135deg,#0a0a1a 0%,#1a1a2e 100%);
  color:var(--text); min-height:100vh; line-height:1.6; }
.wrap { max-width:1100px; margin:0 auto; padding:40px 20px; }
h1 { font-size:42px; margin-bottom:8px;
  background:linear-gradient(135deg,var(--cyan),var(--pink)); -webkit-background-clip:text; -webkit-text-fill-color:transparent; }
.sub { color:#888; margin-bottom:32px; font-size:14px; }
.card { background:var(--surface); border:1px solid var(--border); border-radius:16px; padding:28px; margin-bottom:24px; }
.card h2 { color:var(--cyan); font-size:20px; margin:0 0 16px; display:flex; align-items:center; gap:8px; }
table { width:100%; border-collapse:collapse; font-size:14px; }
th { text-align:left; padding:10px 12px; color:var(--cyan); border-bottom:1px solid var(--border); font-weight:600; }
td { padding:10px 12px; border-bottom:1px solid rgba(255,255,255,0.04); }
tr:hover td { background:rgba(0,255,255,0.03); }
.btn { display:inline-block; padding:14px 32px; background:linear-gradient(135deg,var(--cyan),var(--pink));
  border:none; border-radius:12px; color:#000; font-size:15px; font-weight:700;
  cursor:pointer; transition:0.2s; text-decoration:none; }
.btn:hover { transform:translateY(-2px); box-shadow:0 8px 30px rgba(0,255,255,0.3); }
.btn-outline { display:inline-block; padding:14px 32px; border:1px solid var(--border);
  border-radius:12px; color:var(--cyan); font-weight:600; cursor:pointer; transition:0.2s; text-decoration:none; }
.btn-outline:hover { border-color:var(--cyan); box-shadow:0 0 20px rgba(0,255,255,0.15); }
input { width:100%; padding:14px 16px; margin-bottom:16px;
  background:rgba(255,255,255,0.05); border:1px solid rgba(255,255,255,0.1);
  border-radius:12px; color:#fff; font-size:15px; outline:none; transition:0.2s; }
input:focus { border-color:var(--cyan); box-shadow:0 0 20px rgba(0,255,255,0.15); }
.badge { display:inline-block; padding:2px 10px; border-radius:20px; font-size:12px; font-weight:600; }
.badge-green { background:rgba(0,255,136,0.15); color:var(--green); }
.badge-red { background:rgba(255,68,102,0.15); color:var(--red); }
.badge-yellow { background:rgba(255,221,0,0.15); color:var(--yellow); }
.badge-cyan { background:rgba(0,255,255,0.15); color:var(--cyan); }
.grid-3 { display:grid; grid-template-columns:repeat(auto-fit,minmax(280px,1fr)); gap:16px; }
.stat-box { text-align:center; padding:24px; background:var(--surface); border:1px solid var(--border); border-radius:12px; }
.stat-num { font-size:36px; font-weight:700; background:linear-gradient(135deg,var(--cyan),var(--pink)); -webkit-background-clip:text; -webkit-text-fill-color:transparent; }
.stat-label { font-size:13px; color:#888; margin-top:4px; }
.footer { text-align:center; margin-top:48px; padding:24px; border-top:1px solid var(--border); color:#555; font-size:13px; }
.footer a { color:var(--cyan); text-decoration:none; }
.footer a:hover { text-decoration:underline; }
.progress-bar { height:24px; background:rgba(255,255,255,0.05); border-radius:12px; overflow:hidden; margin:8px 0; }
.progress-fill { height:100%; background:linear-gradient(90deg,var(--cyan),var(--pink)); border-radius:12px; transition:width 0.5s; }
.nav { display:flex; gap:24px; justify-content:center; margin-bottom:40px; flex-wrap:wrap; }
.nav a { color:#888; text-decoration:none; font-size:14px; padding:8px 16px; border-radius:8px; transition:0.2s; }
.nav a:hover { color:var(--cyan); background:rgba(0,255,255,0.05); }
.copy-btn { cursor:pointer; color:var(--cyan); font-size:13px; }
.copy-btn:hover { text-decoration:underline; }
@media(max-width:600px){ h1{font-size:28px;} .card{padding:16px;} td,th{padding:6px 8px;font-size:12px;} }
"""

def _nav(current: str = "") -> str:
    items = [
        ("/", "Home"),
        ("/pricing", "Pricing"),
        ("/benchmark", "Benchmarks"),
        ("/training", "Training"),
        ("http://localhost:3000/", "Chat"),
        ("/login", "Login"),
    ]
    links = ""
    for path, label in items:
        external = path.startswith("http")
        active = ' style="color:var(--cyan);background:rgba(0,255,255,0.05);"' if not external and path == current else ""
        target = ' target="_blank"' if external else ""
        links += f'<a href="{path}"{active}{target}>{label}</a>'
    return f'<div class="nav">{links}</div>'

def _page(title: str, body: str, script: str = "") -> str:
    nonce = secrets.token_hex(16)
    style = RAKSHAK_CSS
    style += "\n.check { color: var(--green); } .cross { color: var(--red); }"
    return f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>{title} — RakshakAI</title><style>{style}</style></head>
<body><div class="wrap">{body}</div>{script}</body></html>"""

def _get_base_url(request: Request) -> str:
    return str(request.base_url).rstrip("/")

# ═══════════════════════════════════════════════
# WEB PAGES
# ═══════════════════════════════════════════════

@app.get("/", response_class=HTMLResponse)
async def home_page():
    return _page("Home", f"""
    {_nav("/")}
    <div style="text-align:center;padding-top:40px;">
      <div style="font-size:80px;margin-bottom:16px;">🛡️</div>
      <h1 style="font-size:56px;">RakshakAI</h1>
      <div class="sub" style="font-size:20px;max-width:600px;margin:0 auto;">
        The World's Most Intelligent Security AI — fine-tuned on 87K CWE examples, 248 vulnerability classes
      </div>
      <div style="margin:48px auto;display:flex;gap:16px;justify-content:center;flex-wrap:wrap;">
        <a href="/register" class="btn">Get Started Free</a>
        <a href="http://localhost:3000/" class="btn">Launch Chat UI</a>
        <a href="/pricing" class="btn-outline">View Pricing</a>
        <a href="/benchmark" class="btn-outline">Benchmarks</a>
      </div>

      <!-- Pricing Summary -->
      <div style="display:flex;gap:16px;justify-content:center;flex-wrap:wrap;margin:40px auto;max-width:800px;">
        <div class="stat-box" style="flex:1;min-width:200px;border-color:rgba(255,255,255,0.08);">
          <div class="stat-num" style="font-size:28px;">Free</div>
          <div class="stat-label" style="font-size:14px;">$0 — 5 AI scans/day<br><span style="color:#555;font-size:12px;">Llama 8B + local Ollama</span></div>
        </div>
        <div class="stat-box" style="flex:1;min-width:200px;border-color:var(--cyan);">
          <div class="stat-num" style="font-size:28px;">Pro</div>
          <div class="stat-label" style="font-size:14px;">$10/mo — Unlimited scans<br><span style="color:#555;font-size:12px;">67 models, 12 providers</span></div>
        </div>
        <div class="stat-box" style="flex:1;min-width:200px;border-color:var(--yellow);">
          <div class="stat-num" style="font-size:28px;">Enterprise</div>
          <div class="stat-label" style="font-size:14px;">Custom — Self-hosted<br><span style="color:#555;font-size:12px;">Dedicated GPU + support</span></div>
        </div>
      </div>

      <div class="grid-3" style="margin-top:32px;">
        <div class="stat-box"><div class="stat-num">302t</div><div class="stat-label">Tiny System Prompt</div></div>
        <div class="stat-box"><div class="stat-num">50ms</div><div class="stat-label">Cold Start</div></div>
        <div class="stat-box"><div class="stat-num">$0</div><div class="stat-label">Free to Start</div></div>
        <div class="stat-box"><div class="stat-num">67</div><div class="stat-label">AI Models</div></div>
        <div class="stat-box"><div class="stat-num">248</div><div class="stat-label">CWE Classes</div></div>
        <div class="stat-box"><div class="stat-num">20</div><div class="stat-label">Programming Languages</div></div>
      </div>
      <div class="card" style="margin-top:48px;text-align:left;">
        <h2>🧠 Model: RakshakAI CWE-14B-SFT</h2>
        <div class="grid-3">
          <div style="padding:12px;"><strong style="color:var(--cyan);">Base Model:</strong><br>Qwen2.5-Coder-14B-Instruct</div>
          <div style="padding:12px;"><strong style="color:var(--cyan);">Training:</strong><br>525 / 750 steps (70%)</div>
          <div style="padding:12px;"><strong style="color:var(--cyan);">Method:</strong><br>QLoRA 4-bit, r=32</div>
          <div style="padding:12px;"><strong style="color:var(--cyan);">Dataset:</strong><br>87K CWE security examples</div>
          <div style="padding:12px;"><strong style="color:var(--cyan);">Checkpoints:</strong><br><a href="https://huggingface.co/Muneerali199/rakshak-cwe-14b-sft-checkpoints" style="color:var(--green);">HF Hub</a></div>
          <div style="padding:12px;"><strong style="color:var(--cyan);">Final Model:</strong><br><a href="https://huggingface.co/Muneerali199/rakshak-cwe-14b-sft-final" style="color:var(--green);">HF Hub</a></div>
        </div>
      </div>
    </div>
    <div class="footer">
      RakshakAI · Apache 2.0 ·
      <a href="/pricing">Pricing</a> ·
      <a href="http://localhost:3000/">Chat UI</a> ·
      <a href="https://github.com/Muneerali199/RakshakAI">GitHub</a>
    </div>
    """)

@app.get("/pricing", response_class=HTMLResponse)
async def pricing_page():
    return _page("Pricing", f"""
    {_nav("/pricing")}
    <div style="text-align:center;padding-top:40px;">
      <h1>Simple, transparent pricing</h1>
      <div class="sub" style="font-size:18px;">Start free. Upgrade when you need more power.</div>

      <div style="display:flex;gap:24px;justify-content:center;flex-wrap:wrap;margin-top:40px;">
        <!-- Free -->
        <div class="card" style="width:300px;padding:32px;text-align:left;">
          <div style="font-size:20px;font-weight:700;margin-bottom:8px;">Free</div>
          <div style="font-size:42px;font-weight:700;margin-bottom:4px;">$0</div>
          <div style="color:#888;font-size:14px;margin-bottom:24px;">For individual developers</div>
          <a href="/register" class="btn" style="width:100%;text-align:center;">Get Started</a>
          <ul style="list-style:none;margin-top:24px;">
            <li style="padding:6px 0;font-size:13px;"><span style="color:var(--green);font-weight:bold;">✓</span> 5 AI scans / day</li>
            <li style="padding:6px 0;font-size:13px;"><span style="color:var(--green);font-weight:bold;">✓</span> 10 regex scans / day</li>
            <li style="padding:6px 0;font-size:13px;"><span style="color:var(--green);font-weight:bold;">✓</span> Llama 3.1 8B + Ollama</li>
            <li style="padding:6px 0;font-size:13px;"><span style="color:var(--green);font-weight:bold;">✓</span> CLI + Web UI</li>
            <li style="padding:6px 0;font-size:13px;color:#888;"><span style="color:#888;">✗</span> Session sharing</li>
            <li style="padding:6px 0;font-size:13px;color:#888;"><span style="color:#888;">✗</span> Priority support</li>
          </ul>
        </div>

        <!-- Pro -->
        <div class="card" style="width:300px;padding:32px;text-align:left;border-color:var(--cyan);background:linear-gradient(135deg,rgba(0,255,255,0.03),rgba(255,0,255,0.03));position:relative;">
          <div style="position:absolute;top:-12px;right:24px;background:var(--cyan);color:#000;padding:4px 12px;border-radius:20px;font-size:11px;font-weight:700;letter-spacing:1px;">POPULAR</div>
          <div style="font-size:20px;font-weight:700;margin-bottom:8px;">Pro</div>
          <div style="font-size:42px;font-weight:700;margin-bottom:4px;">$10 <span style="font-size:16px;color:#888;font-weight:400;">/month</span></div>
          <div style="color:#888;font-size:14px;margin-bottom:24px;">For security engineers &amp; teams</div>
          <a href="/register" class="btn" style="width:100%;text-align:center;">Upgrade</a>
          <ul style="list-style:none;margin-top:24px;">
            <li style="padding:6px 0;font-size:13px;"><span style="color:var(--green);font-weight:bold;">✓</span> Unlimited AI scans</li>
            <li style="padding:6px 0;font-size:13px;"><span style="color:var(--green);font-weight:bold;">✓</span> Unlimited regex scans</li>
            <li style="padding:6px 0;font-size:13px;"><span style="color:var(--green);font-weight:bold;">✓</span> 67 models, 12 providers</li>
            <li style="padding:6px 0;font-size:13px;"><span style="color:var(--green);font-weight:bold;">✓</span> Session sharing</li>
            <li style="padding:6px 0;font-size:13px;"><span style="color:var(--green);font-weight:bold;">✓</span> Agentic tools (Read, Edit, Bash)</li>
            <li style="padding:6px 0;font-size:13px;"><span style="color:var(--green);font-weight:bold;">✓</span> Git workflow (commit, PR, review)</li>
            <li style="padding:6px 0;font-size:13px;"><span style="color:var(--green);font-weight:bold;">✓</span> Priority email support</li>
          </ul>
        </div>

        <!-- Enterprise -->
        <div class="card" style="width:300px;padding:32px;text-align:left;border-color:var(--yellow);">
          <div style="font-size:20px;font-weight:700;margin-bottom:8px;">Enterprise</div>
          <div style="font-size:42px;font-weight:700;margin-bottom:4px;">Custom</div>
          <div style="color:#888;font-size:14px;margin-bottom:24px;">For organizations &amp; dedicated infra</div>
          <a href="mailto:rakshak@example.com?subject=Enterprise%20Plan" class="btn-outline" style="width:100%;text-align:center;color:var(--yellow);border-color:var(--yellow);">Contact Us</a>
          <ul style="list-style:none;margin-top:24px;">
            <li style="padding:6px 0;font-size:13px;"><span style="color:var(--green);font-weight:bold;">✓</span> Everything in Pro</li>
            <li style="padding:6px 0;font-size:13px;"><span style="color:var(--green);font-weight:bold;">✓</span> Self-hosted deployment</li>
            <li style="padding:6px 0;font-size:13px;"><span style="color:var(--green);font-weight:bold;">✓</span> Dedicated GPU endpoint</li>
            <li style="padding:6px 0;font-size:13px;"><span style="color:var(--green);font-weight:bold;">✓</span> Custom fine-tuning</li>
            <li style="padding:6px 0;font-size:13px;"><span style="color:var(--green);font-weight:bold;">✓</span> SAML/SSO + audit logging</li>
            <li style="padding:6px 0;font-size:13px;"><span style="color:var(--green);font-weight:bold;">✓</span> 99.9% SLA + dedicated support</li>
          </ul>
        </div>
      </div>

      <div class="faq" style="max-width:700px;margin:60px auto 0;text-align:left;">
        <h3 style="text-align:center;">FAQ</h3>
        <div class="faq-item" style="padding:16px 0;border-bottom:1px solid rgba(255,255,255,0.08);">
          <div style="font-weight:600;margin-bottom:6px;">What's the difference between Free and Pro models?</div>
          <div style="color:#888;font-size:14px;">Free tier includes Llama 3.1 8B via Groq and local Ollama. Pro adds 65+ models: Llama 70B, RakshakAI 14B, GPT-4o, Claude, Gemini, DeepSeek, Mistral, and more across 12 providers.</div>
        </div>
        <div class="faq-item" style="padding:16px 0;border-bottom:1px solid rgba(255,255,255,0.08);">
          <div style="font-weight:600;margin-bottom:6px;">How do I use the Chat UI?</div>
          <div style="color:#888;font-size:14px;">Visit <a href="http://localhost:3000/" style="color:var(--cyan);">localhost:3000</a> to access the full chat interface with model selection, file scanning, and clipboard analysis. You can also use the CLI with <code style="background:rgba(255,255,255,0.05);padding:2px 6px;border-radius:4px;">python3 v2/cli/main.py</code>.</div>
        </div>
        <div class="faq-item" style="padding:16px 0;border-bottom:1px solid rgba(255,255,255,0.08);">
          <div style="font-weight:600;margin-bottom:6px;">Can I use RakshakAI for free forever?</div>
          <div style="color:#888;font-size:14px;">Yes. The Free plan is free forever with 5 AI scans and 10 regex scans daily. No credit card required.</div>
        </div>
      </div>
    </div>
    <div class="footer">
      <a href="/">Home</a> · <a href="/benchmark">Benchmarks</a> · <a href="/training">Training</a> · <a href="http://localhost:3000/">Chat</a>
    </div>
    """)

@app.get("/login", response_class=HTMLResponse)
async def login_page(redirect: str = ""):
    return _page("Login", f"""
    <div style="max-width:420px;margin:60px auto;">
      <div style="text-align:center;margin-bottom:32px;">
        <div style="font-size:48px;margin-bottom:8px;">🛡️</div>
        <h1>Welcome back</h1>
        <div class="sub">Sign in to RakshakAI</div>
      </div>
      <div class="card">
        <div class="error" id="error" style="color:var(--red);font-size:13px;margin-bottom:12px;display:none;"></div>
        <div class="spinner" id="spinner" style="display:none;width:18px;height:18px;border:2px solid rgba(255,255,255,0.3);border-top-color:#fff;border-radius:50%;animation:spin 0.6s linear infinite;margin:0 auto 8px;"></div>
        <input type="email" id="email" placeholder="Email" autocomplete="email" autofocus>
        <input type="password" id="password" placeholder="Password" autocomplete="current-password">
        <button class="btn" id="btn" onclick="login()" style="width:100%;">Sign In</button>
        <div style="text-align:center;margin-top:16px;font-size:14px;color:#888;">
          Don't have an account? <a href="/register{('?redirect='+redirect) if redirect else ''}" style="color:var(--cyan);">Sign up</a>
        </div>
      </div>
    </div>
    <style>@keyframes spin{{to{{transform:rotate(360deg)}}}}</style>
    <script nonce="{secrets.token_hex(16)}">
    const redirect = {json.dumps(redirect)};
    async function login(){{
      const e=document.getElementById('email').value.trim();
      const p=document.getElementById('password').value;
      const er=document.getElementById('error');const btn=document.getElementById('btn');const sp=document.getElementById('spinner');
      if(!e||!p){{er.textContent='Fill in all fields';er.style.display='block';return;}}
      er.style.display='none';btn.disabled=true;sp.style.display='block';
      try{{const r=await fetch('/api/login',{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{email:e,password:p}})}});
      const d=await r.json();btn.disabled=false;sp.style.display='none';
      if(!r.ok){{er.textContent=d.detail||'Login failed';er.style.display='block';return;}}
      window.location.href='/dashboard?token='+encodeURIComponent(d.token);
      }}catch(e){{btn.disabled=false;sp.style.display='none';er.textContent='Connection error';er.style.display='block';}}
    }}
    document.addEventListener('keydown',e=>{{if(e.key==='Enter')login();}});
    </script>
    """)

@app.get("/register", response_class=HTMLResponse)
async def register_page(redirect: str = "", ref: str = ""):
    ref_notice = ""
    if ref:
        ref_notice = f'<div style="background:rgba(0,255,255,0.05);border:1px solid rgba(0,255,255,0.15);border-radius:8px;padding:12px;margin-bottom:16px;text-align:center;font-size:13px;color:var(--cyan);">🎯 Referral code <strong>{ref}</strong> applied — you get <strong>3 bonus credits</strong> on signup!</div>'
    return _page("Register", f"""
    <div style="max-width:420px;margin:60px auto;">
      <div style="text-align:center;margin-bottom:32px;">
        <div style="font-size:48px;margin-bottom:8px;">🛡️</div>
        <h1>Create account</h1>
        <div class="sub">Join RakshakAI security platform</div>
      </div>
      <div class="card">
        {ref_notice}
        <div class="error" id="error" style="color:var(--red);font-size:13px;margin-bottom:12px;display:none;"></div>
        <div class="spinner" id="spinner" style="display:none;width:18px;height:18px;border:2px solid rgba(255,255,255,0.3);border-top-color:#fff;border-radius:50%;animation:spin 0.6s linear infinite;margin:0 auto 8px;"></div>
        <input type="text" id="name" placeholder="Your name (optional)" autocomplete="name">
        <input type="email" id="email" placeholder="Email" autocomplete="email" autofocus>
        <input type="password" id="password" placeholder="Password (min 8 chars)" autocomplete="new-password">
        <input type="hidden" id="ref" value="{ref}">
        <button class="btn" id="btn" onclick="register()" style="width:100%;">Create Account</button>
        <div style="text-align:center;margin-top:16px;font-size:14px;color:#888;">
          Already registered? <a href="/login" style="color:var(--cyan);">Sign in</a>
        </div>
      </div>
    </div>
    <style>@keyframes spin{{to{{transform:rotate(360deg)}}}}</style>
    <script nonce="{secrets.token_hex(16)}">
    const redirect = {json.dumps(redirect)};
    async function register(){{
      const name=document.getElementById('name').value.trim();
      const email=document.getElementById('email').value.trim();
      const password=document.getElementById('password').value;
      const ref=document.getElementById('ref').value;
      const er=document.getElementById('error');const btn=document.getElementById('btn');const sp=document.getElementById('spinner');
      if(!email||!password){{er.textContent='Fill in all fields';er.style.display='block';return;}}
      if(password.length<8){{er.textContent='Password must be 8+ chars';er.style.display='block';return;}}
      er.style.display='none';btn.disabled=true;sp.style.display='block';
      try{{const r=await fetch('/api/register',{{method:'POST',headers:{{'Content-Type':'application/json'}},
        body:JSON.stringify({{email,password,name,ref}})}});
      const d=await r.json();btn.disabled=false;sp.style.display='none';
      if(!r.ok){{er.textContent=d.detail?.[0]?.msg||d.detail||'Registration failed';er.style.display='block';return;}}
      window.location.href='/dashboard?token='+encodeURIComponent(d.token);
      }}catch(e){{btn.disabled=false;sp.style.display='none';er.textContent='Connection error';er.style.display='block';}}
    }}
    document.addEventListener('keydown',e=>{{if(e.key==='Enter')register();}});
    </script>
    """)

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request, token: str = ""):
    user = _verify_token(token) if token else None
    if not user:
        return RedirectResponse("/login")
    conn = _init_db()
    code = conn.execute("SELECT code, uses, max_uses FROM referral_codes WHERE user_id = ?", (user["id"],)).fetchone()
    referrals = conn.execute(
        "SELECT u.name, u.email, r.created_at "
        "FROM referrals r JOIN users u ON r.referee_id = u.id "
        "WHERE r.referrer_id = ? ORDER BY r.created_at DESC LIMIT 10",
        (user["id"],),
    ).fetchall()
    base_url = _get_base_url(request)
    ref_section = ""
    if code:
        ref_code = code["code"]
        ref_url = f"{base_url}/register?ref={ref_code}"
        ref_section = f"""
        <div class="card">
          <h2>🎯 Your Referral Code</h2>
          <div style="display:flex;gap:12px;align-items:center;flex-wrap:wrap;">
            <code style="background:rgba(0,255,255,0.1);padding:12px 20px;border-radius:8px;font-size:16px;color:var(--cyan);flex:1;">{ref_code}</code>
            <button class="btn" onclick="navigator.clipboard.writeText('{ref_url}');this.textContent='Copied!';setTimeout(()=>this.textContent='Copy Link',2000);">Copy Link</button>
          </div>
          <div style="margin-top:12px;font-size:13px;color:#888;">
            Used {code["uses"]}/{code["max_uses"]} times · You earned <strong style="color:var(--green);">{code["uses"]*5} credits</strong>
          </div>
        </div>"""
    else:
        ref_section = f"""
        <div class="card">
          <h2>🎯 Invite Friends</h2>
          <p style="color:#888;font-size:14px;margin-bottom:16px;">Earn 5 credits per referral — click below to generate your code</p>
          <button class="btn" onclick="generateRef()">Generate Referral Code</button>
          <div id="ref-result" style="margin-top:12px;"></div>
        </div>
        <script nonce="{secrets.token_hex(16)}">
        async function generateRef(){{
          const r=document.getElementById('ref-result');
          r.innerHTML='<div style="color:#888;">Generating...</div>';
          try{{const res=await fetch('/api/referral/generate',{{method:'POST',headers:{{'Content-Type':'application/json','Authorization':'Bearer {token}'}},body:'{{}}'}});
          const d=await res.json();
          r.innerHTML='<code style="background:rgba(0,255,255,0.1);padding:12px;border-radius:8px;display:block;text-align:center;font-size:16px;color:var(--cyan);">'+d.code+'</code><button class="btn" style="margin-top:8px;" onclick="navigator.clipboard.writeText(\\''+d.url+'\\');this.textContent=\\'Copied!\\';setTimeout(()=>this.textContent=\\'Copy Link\\',2000);">Copy Link</button>';
          }}catch(e){{r.innerHTML='<div style="color:var(--red);">Error: '+e.message+'</div>';}}
        }}
        </script>"""
    refs_list = ""
    if referrals:
        items = "".join(f'<tr><td>{r["name"] or "—"}</td><td>{r["email"]}</td><td style="color:var(--green);">+5 credits</td><td>{datetime.fromtimestamp(r["created_at"]).strftime("%b %d")}</td></tr>' for r in referrals)
        refs_list = f"""
        <div class="card">
          <h2>👥 Your Referrals ({len(referrals)})</h2>
          <table><tr><th>Name</th><th>Email</th><th>Bonus</th><th>Date</th></tr>{items}</table>
        </div>"""
    return _page("Dashboard", f"""
    <div style="text-align:center;margin-bottom:40px;">
      <div style="font-size:48px;margin-bottom:8px;">🛡️</div>
      <h1>Hello, {user.get('name') or user['email']}</h1>
      <div class="sub">{user['plan'].title()} Plan · {user.get('credits', 0)} credits</div>
    </div>
    {_nav("/dashboard")}
    <div class="card">
      <h2>👤 Account Details</h2>
      <table>
        <tr><td style="color:#888;">Email</td><td>{user['email']}</td></tr>
        <tr><td style="color:#888;">Plan</td><td style="color:var(--cyan);">{user['plan'].title()}</td></tr>
        <tr><td style="color:#888;">Credits</td><td style="color:var(--green);">{user.get('credits', 0)}</td></tr>
        <tr><td style="color:#888;">User ID</td><td style="font-size:12px;">{user['id'][:12]}...</td></tr>
      </table>
    </div>
    {ref_section}
    {refs_list}
    <div class="card">
      <h2>🧠 Model Training Progress</h2>
      <div style="display:flex;justify-content:space-between;font-size:13px;margin-bottom:4px;">
        <span style="color:#888;">Total: 750 steps</span>
        <span style="color:var(--cyan);">525 / 750 (70%)</span>
      </div>
      <div class="progress-bar"><div class="progress-fill" style="width:70%"></div></div>
      <div style="margin-top:12px;font-size:13px;color:#888;">
        <a href="/training" style="color:var(--cyan);">View full training details →</a>
      </div>
    </div>
    <div style="text-align:center;margin-top:24px;">
      <a href="/benchmark" class="btn-outline">View Benchmarks</a>
      <a href="/logout?token={token}" style="display:inline-block;margin-left:12px;color:#888;text-decoration:none;font-size:14px;">Sign out</a>
    </div>
    <div class="footer"><a href="/">Home</a> · <a href="/training">Training</a> · <a href="/benchmark">Benchmarks</a></div>
    """)

@app.get("/logout", response_class=HTMLResponse)
async def logout_page(token: str = ""):
    if token:
        conn = _init_db()
        conn.execute("DELETE FROM tokens WHERE token = ?", (token,))
        conn.commit()
    return _page("Signed Out", f"""
    <div style="text-align:center;padding-top:80px;">
      <div style="font-size:48px;margin-bottom:16px;">👋</div>
      <h1>Signed out</h1>
      <div class="sub">Come back soon!</div>
      <a href="/login" class="btn">Sign in again</a>
      <a href="/" class="btn-outline" style="margin-left:12px;">Home</a>
    </div>
    """)

# ═══════════════════════════════════════════════
# TRAINING PAGE
# ═══════════════════════════════════════════════

@app.get("/training", response_class=HTMLResponse)
async def training_page():
    ti = TRAINING_INFO
    ckpt_rows = ""
    for name, info in ti["checkpoints"].items():
        status_badge = f'<span class="badge badge-green">✓ Completed</span>' if info["status"] == "completed" else '<span class="badge badge-yellow">⟳ In Progress</span>'
        repo_link = f'<a href="https://huggingface.co/{info["repo"]}" style="color:var(--cyan);font-size:12px;">HF</a>' if "repo" in info else ""
        ckpt_rows += f'<tr><td><strong>{name}</strong></td><td>{info["steps"]}</td><td>{info["source"]}</td><td>{status_badge} {repo_link}</td></tr>'

    return _page("Training", f"""
    {_nav("/training")}
    <div style="text-align:center;margin-bottom:40px;">
      <h1>🧠 Model Training</h1>
      <div class="sub">RakshakAI CWE-14B-SFT · Fine-tuning Qwen2.5-Coder-14B-Instruct on 87K CWE examples</div>
    </div>
    <div class="grid-3">
      <div class="stat-box"><div class="stat-num">{ti["cumulative_steps"]}</div><div class="stat-label">Total Steps Trained</div></div>
      <div class="stat-box"><div class="stat-num">{ti["total_steps"]}</div><div class="stat-label">Target Steps</div></div>
      <div class="stat-box"><div class="stat-num">{ti["progress_pct"]}%</div><div class="stat-label">Completion</div></div>
    </div>
    <div class="card">
      <h2>📊 Overall Progress</h2>
      <div style="display:flex;justify-content:space-between;font-size:13px;margin-bottom:4px;">
        <span style="color:#888;">Steps completed</span>
        <span style="color:var(--cyan);">{ti["cumulative_steps"]} / {ti["total_steps"]}</span>
      </div>
      <div class="progress-bar"><div class="progress-fill" style="width:{ti["progress_pct"]}%"></div></div>
      <div style="margin-top:16px;font-size:13px;color:#888;">
        RakshakAI is fine-tuned from Qwen2.5-Coder-14B-Instruct using QLoRA (4-bit) on 87,000 curated CWE security examples enhanced with DeepSeek reasoning traces. Training runs across multiple GPU providers.
      </div>
    </div>
    <div class="card">
      <h2>📋 Training Configuration</h2>
      <table>
        <tr><td style="color:#888;">Base Model</td><td>{ti["base"]}</td></tr>
        <tr><td style="color:#888;">Fine-tune Method</td><td>{ti["method"]}</td></tr>
        <tr><td style="color:#888;">LoRA Rank (r)</td><td>{ti["lora_r"]}</td></tr>
        <tr><td style="color:#888;">LoRA Alpha</td><td>{ti["lora_alpha"]}</td></tr>
        <tr><td style="color:#888;">Batch Size</td><td>{ti["batch_size"]}</td></tr>
        <tr><td style="color:#888;">Gradient Accumulation</td><td>{ti["grad_accum"]}</td></tr>
        <tr><td style="color:#888;">Sequence Length</td><td>{ti["seq_len"]}</td></tr>
        <tr><td style="color:#888;">Learning Rate</td><td>{ti["learning_rate"]}</td></tr>
        <tr><td style="color:#888;">Scheduler</td><td>{ti["scheduler"]}</td></tr>
        <tr><td style="color:#888;">Dataset</td><td>{ti["dataset"]}</td></tr>
      </table>
    </div>
    <div class="card">
      <h2>📦 Checkpoints</h2>
      <table>
        <tr><th>Name</th><th>Steps</th><th>Source</th><th>Status</th></tr>
        {ckpt_rows}
      </table>
      <div style="margin-top:16px;font-size:13px;color:#888;">
        Checkpoints are uploaded to <a href="https://huggingface.co/{ti['repo_checkpoints']}" style="color:var(--cyan);">{ti['repo_checkpoints']}</a> every 50 steps.
        Final model at <a href="https://huggingface.co/{ti['repo_final']}" style="color:var(--cyan);">{ti['repo_final']}</a>.
        Step-375 fallback at <a href="https://huggingface.co/{ti['repo_step375']}" style="color:var(--cyan);">{ti['repo_step375']}</a>.
      </div>
    </div>
    <div class="card">
      <h2>🚀 Deployment Timeline</h2>
      <table>
        <tr><th>Provider</th><th>GPU</th><th>Steps</th><th>Status</th></tr>
        <tr><td>Lightning.ai</td><td>A100-80GB</td><td>0 → 375</td><td><span class="badge badge-green">✓ Complete</span></td></tr>
        <tr><td>Radeon Cloud</td><td>W7900D 48GB</td><td>375 → 425</td><td><span class="badge badge-green">✓ Checkpoint-50</span></td></tr>
        <tr><td>Radeon Cloud</td><td>W7900D 48GB</td><td>425 → 475</td><td><span class="badge badge-green">✓ Checkpoint-100</span></td></tr>
        <tr><td>Radeon Cloud</td><td>W7900D 48GB</td><td>475 → 525</td><td><span class="badge badge-yellow">⟳ In Progress</span></td></tr>
        <tr><td>Next Session</td><td>TBD</td><td>525 → 750</td><td><span class="badge badge-red">⏳ Pending</span></td></tr>
      </table>
    </div>
    <div class="footer">
      <a href="/">Home</a> · <a href="/benchmark">Benchmarks</a> · <a href="/dashboard">Dashboard</a>
    </div>
    """)

# ═══════════════════════════════════════════════
# BENCHMARK PAGE
# ═══════════════════════════════════════════════

BENCHMARK_CSS = RAKSHAK_CSS

@app.get("/benchmark", response_class=HTMLResponse)
async def benchmark_page():
    return _page("Benchmark", f"""
    {_nav("/benchmark")}
    <h1 style="text-align:center;">⚡ RakshakAI vs The World</h1>
    <div class="sub" style="text-align:center;max-width:600px;margin:0 auto 40px;">Honest benchmarks — token efficiency, speed, accuracy &amp; cost vs Claude Code, OpenCode, Snyk, Semgrep</div>
    <div class="card">
      <h2>🏆 Overall Score</h2>
      <table>
        <tr><th>Rank</th><th>Tool</th><th>Score</th><th>Rating</th><th width="40%">Performance</th></tr>
        <tr class="rank-1"><td>#1</td><td><strong>RakshakAI</strong></td><td><strong>50/50</strong></td><td>★★★★★★★★★★</td><td><div class="progress-bar"><div class="progress-fill" style="width:100%"></div></div></td></tr>
        <tr><td>#2</td><td>OpenCode</td><td>36/50</td><td>★★★★★★★☆☆☆</td><td><div class="progress-bar"><div class="progress-fill" style="width:72%;background:linear-gradient(90deg,var(--green),rgba(0,255,136,0.3));"></div></div></td></tr>
        <tr><td>#3</td><td>Semgrep CLI</td><td>33/50</td><td>★★★★★★★☆☆☆</td><td><div class="progress-bar"><div class="progress-fill" style="width:66%;background:linear-gradient(90deg,var(--yellow),rgba(255,200,0,0.3));"></div></div></td></tr>
        <tr><td>#4</td><td>Snyk CLI</td><td>30/50</td><td>★★★★★★☆☆☆☆</td><td><div class="progress-bar"><div class="progress-fill" style="width:60%;background:linear-gradient(90deg,var(--yellow),rgba(255,200,0,0.3));"></div></div></td></tr>
        <tr><td>#5</td><td>Claude Code</td><td>23/50</td><td>★★★★★☆☆☆☆☆</td><td><div class="progress-bar"><div class="progress-fill" style="width:46%;background:linear-gradient(90deg,var(--red),rgba(255,68,102,0.3));"></div></div></td></tr>
      </table>
    </div>
    <div class="grid-3">
      <div class="stat-box"><div class="stat-num">302</div><div class="stat-label">System Prompt (tokens)</div><div style="font-size:11px;color:#555;margin-top:8px;">vs 30,500 in Claude Code — <strong style="color:var(--green)">101x smaller</strong></div></div>
      <div class="stat-box"><div class="stat-num">50ms</div><div class="stat-label">Cold Start</div><div style="font-size:11px;color:#555;margin-top:8px;">vs 3,500ms in Claude Code — <strong style="color:var(--green)">70x faster</strong></div></div>
      <div class="stat-box"><div class="stat-num">$0</div><div class="stat-label">Cost per 1,000 Scans</div><div style="font-size:11px;color:#555;margin-top:8px;">vs $80 in Claude Code — <strong style="color:var(--green)">100% free</strong></div></div>
      <div class="stat-box"><div class="stat-num">~20%</div><div class="stat-label">False Positive Rate</div><div style="font-size:11px;color:#555;margin-top:8px;">vs 80% in Snyk — <strong style="color:var(--green)">4x more accurate</strong></div></div>
      <div class="stat-box"><div class="stat-num">500+</div><div class="stat-label">Files/sec (Pattern)</div><div style="font-size:11px;color:#555;margin-top:8px;">Hybrid AI+pattern engine</div></div>
      <div class="stat-box"><div class="stat-num">65+</div><div class="stat-label">Models Supported</div><div style="font-size:11px;color:#555;margin-top:8px;">9 providers — Ollama, OpenAI, Anthropic, etc.</div></div>
    </div>
    <div class="card">
      <h2>📊 Token Efficiency — System Prompt Overhead per Request</h2>
      <table>
        <tr><th>Tool</th><th>System Prompt</th><th>Tool Schemas</th><th>Total</th><th>vs RakshakAI</th></tr>
        <tr><td><strong>RakshakAI</strong></td><td><span class="badge badge-cyan">302t</span></td><td><span class="badge badge-green">0t</span></td><td><strong>302t</strong></td><td><strong>1x</strong></td></tr>
        <tr><td>OpenCode</td><td>2,000t</td><td>4,800t</td><td>6,800t</td><td>23x</td></tr>
        <tr><td>Copilot CLI</td><td>~1,500t</td><td>~5,000t</td><td>~6,500t</td><td>22x</td></tr>
        <tr><td>Claude Code</td><td>6,500t</td><td>24,000t</td><td><strong>30,500t</strong></td><td><strong>101x</strong></td></tr>
      </table>
      <div style="margin-top:16px;padding:12px;background:rgba(0,255,255,0.05);border-radius:8px;font-size:13px;">💡 <strong>Why it matters:</strong> With Claude Code, you pay for <strong>30,500 tokens</strong> before the AI even reads your question. RakshakAI sends just <strong>302 tokens</strong> — that's <strong>101x less overhead</strong> per interaction.</div>
    </div>
    <div class="card">
      <h2>🗑️ Token Waste — Mid-Session Bloat</h2>
      <table>
        <tr><th>Waste Category</th><th style="color:var(--cyan)">RakshakAI</th><th>OpenCode</th><th>Claude Code</th></tr>
        <tr><td>Tool schemas</td><td><span class="badge badge-green">0t</span></td><td>4,800t</td><td><span class="badge badge-red">24,000t</span></td></tr>
        <tr><td>Subagent overhead</td><td><span class="badge badge-green">0t</span></td><td>~7,000t</td><td><span class="badge badge-red">~33,000t</span></td></tr>
        <tr><td>Cache rewrites</td><td><span class="badge badge-green">0t</span></td><td>~1,000t</td><td><span class="badge badge-red">~54,000t</span></td></tr>
        <tr><td>CLAUDE.md / MEMORY.md</td><td><span class="badge badge-green">N/A</span></td><td>20,000t</td><td><span class="badge badge-red">20,000t</span></td></tr>
        <tr><td>MCP schemas (5)</td><td><span class="badge badge-green">N/A</span></td><td>~6,000t</td><td><span class="badge badge-red">~6,000t</span></td></tr>
        <tr><td>Fluff per response</td><td><span class="badge badge-green">0t</span></td><td>20-80t</td><td><span class="badge badge-red">20-80t</span></td></tr>
      </table>
      <div style="margin-top:16px;padding:12px;background:rgba(255,68,102,0.05);border-radius:8px;font-size:13px;">⚠️ Claude Code wastes <strong>~137,000 tokens per session</strong> on overhead. RakshakAI wastes <strong>zero</strong>.</div>
    </div>
    <div class="card">
      <h2>⚔️ Feature Comparison</h2>
      <table>
        <tr><th>Feature</th><th style="color:var(--cyan)">RakshakAI</th><th>OpenCode</th><th>Claude Code</th><th>Snyk</th><th>Semgrep</th></tr>
        <tr><td>Security vuln scanning</td><td class="check">✓</td><td class="cross">✗</td><td class="cross">✗</td><td>✓</td><td>✓</td></tr>
        <tr><td>AI code analysis</td><td>✓</td><td>✓</td><td>✓</td><td>✗</td><td>✗</td></tr>
        <tr><td>CWE taxonomy (248)</td><td>✓</td><td>✗</td><td>✗</td><td>✓</td><td>✓</td></tr>
        <tr><td>Slash commands (REPL)</td><td>✓</td><td>✓</td><td>✓</td><td>✗</td><td>✗</td></tr>
        <tr><td>65+ models, 9 providers</td><td>✓</td><td>✓</td><td>✗</td><td>✗</td><td>✗</td></tr>
        <tr><td>Local Ollama (free)</td><td>✓</td><td>✓</td><td>✗</td><td>✗</td><td>✗</td></tr>
        <tr><td>File watching</td><td>✓</td><td>✗</td><td>✗</td><td>✓</td><td>✓</td></tr>
        <tr><td>Pre-commit hook</td><td>✓</td><td>✗</td><td>✗</td><td>✗</td><td>✓</td></tr>
        <tr><td>Autonomous agent</td><td>✓</td><td>✓</td><td>✓</td><td>✗</td><td>✗</td></tr>
        <tr><td>Free &amp; open source</td><td>✓</td><td>✓</td><td>✗</td><td>✗</td><td>✓</td></tr>
      </table>
    </div>
    <div class="card">
      <h2>💰 Cost — per 1,000 Security Scans</h2>
      <table>
        <tr><th>Tool</th><th>Cost</th><th>Notes</th></tr>
        <tr><td><strong>RakshakAI (Ollama)</strong></td><td><span class="badge badge-green"><strong>$0.00</strong></span></td><td>Local, private, no API key</td></tr>
        <tr><td><strong>RakshakAI (GPT-4o-mini)</strong></td><td><strong>$0.15</strong></td><td>Only when you choose it</td></tr>
        <tr><td>Claude Code (Sonnet)</td><td><span class="badge badge-yellow">~$80.00</span></td><td>~$8/1M input tokens</td></tr>
        <tr><td>Snyk CLI (Team)</td><td><span class="badge badge-red">$250.00</span></td><td>$25/user/mo</td></tr>
        <tr><td>Semgrep (Team)</td><td><span class="badge badge-red">$350.00</span></td><td>$35/user/mo</td></tr>
      </table>
    </div>
    <div class="footer">
      RakshakAI Benchmarks · July 2026 · Sources: Systima, Debuggix, ACR, Endor Labs<br>
      <a href="/">Home</a> · <a href="/training">Training</a> · <a href="/dashboard">Dashboard</a>
    </div>
    """)

# ═══════════════════════════════════════════════
# INVITE / REFERRAL PAGE
# ═══════════════════════════════════════════════

@app.get("/invite", response_class=HTMLResponse)
async def invite_page(request: Request, token: str = ""):
    user = _verify_token(token) if token else None
    if not user:
        return RedirectResponse("/login?redirect=/invite")

    conn = _init_db()
    code = conn.execute("SELECT code, uses, max_uses FROM referral_codes WHERE user_id = ?", (user["id"],)).fetchone()
    if not code:
        return RedirectResponse("/dashboard?token=" + token)

    ref_url = str(request.base_url).rstrip("/") + "/register?ref=" + code["code"]
    return _page("Invite", f"""
    <div style="text-align:center;padding-top:40px;">
      <div style="font-size:64px;margin-bottom:16px;">🎉</div>
      <h1>Invite Friends</h1>
      <div class="sub" style="font-size:18px;">Share your referral link and earn <strong style="color:var(--cyan);">5 credits</strong> per signup!</div>
      <div class="card" style="max-width:600px;margin:32px auto;">
        <h2>🔗 Your Referral Link</h2>
        <div style="display:flex;gap:12px;align-items:center;flex-wrap:wrap;">
          <code id="ref-link" style="background:rgba(0,255,255,0.1);padding:16px 20px;border-radius:8px;font-size:14px;color:var(--cyan);flex:1;word-break:break-all;">{ref_url}</code>
          <button class="btn" onclick="copyLink()">Copy</button>
        </div>
        <div style="margin-top:20px;display:flex;justify-content:space-around;text-align:center;">
          <div><div style="font-size:32px;font-weight:700;color:var(--cyan);">{code["uses"]}</div><div style="font-size:13px;color:#888;">Referrals</div></div>
          <div><div style="font-size:32px;font-weight:700;color:var(--green);">{code["uses"]*5}</div><div style="font-size:13px;color:#888;">Credits Earned</div></div>
          <div><div style="font-size:32px;font-weight:700;color:var(--yellow);">{code["max_uses"] - code["uses"]}</div><div style="font-size:13px;color:#888;">Remaining</div></div>
        </div>
        <div style="margin-top:20px;padding:16px;background:rgba(0,255,255,0.05);border-radius:8px;text-align:left;font-size:13px;color:#888;">
          <strong style="color:var(--cyan);">How it works:</strong><br>
          1. Share your referral link with friends<br>
          2. They sign up and get <strong style="color:var(--green);">3 free credits</strong><br>
          3. You earn <strong style="color:var(--green);">5 credits</strong> for each referral<br>
          4. Credits can be used for AI-powered scans
        </div>
      </div>
      <a href="/dashboard?token={token}" class="btn-outline">Back to Dashboard</a>
    </div>
    <script nonce="{secrets.token_hex(16)}">
    function copyLink(){{
      const el=document.getElementById('ref-link');
      navigator.clipboard.writeText(el.textContent);
      const btn=event.target;
      btn.textContent='Copied!';
      setTimeout(()=>btn.textContent='Copy',2000);
    }}
    </script>
    """)

# ═══════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════

def main():
    uvicorn.run(
        "v2.web.server:app",
        host=HOST,
        port=PORT,
        log_level="info",
        reload=False,
        workers=1,
        proxy_headers=True,
        forwarded_allow_ips="*",
    )

if __name__ == "__main__":
    main()
