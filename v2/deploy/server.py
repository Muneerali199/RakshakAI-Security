"""
RakshakAI v2 — production FastAPI server with multi-provider support.

Providers:
    - ollama: Local models via Ollama (free, private)
    - groq: Groq cloud API (fast, free tier)
    - fireworks: Fireworks AI (paid, fast)
    - nebius: Nebius AI (paid)
    - huggingface: HF Inference API (free tier)

Run:
    cd /Users/macbook/Desktop/RakshakAI && python -m v2.deploy.server
"""
from __future__ import annotations

import json
import logging
import os
import time
from contextlib import asynccontextmanager
from pathlib import Path as _Path
from dotenv import load_dotenv
load_dotenv(_Path(__file__).resolve().parent.parent.parent / ".env")
from typing import Any, Literal

import requests
import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

log = logging.getLogger("rakshakai-v2")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

MAX_MODEL_LEN = 8192
TEMPERATURE = 0.0
MAX_TOKENS = 1500

SYSTEM_PROMPT = (
    "You are RakshakAI, a security code analyzer. "
    "Given source code, respond with a JSON object:\n"
    "{\n"
    '  "vulnerability": "<short name>",\n'
    '  "cwe": "CWE-<number>",\n'
    '  "severity": "critical|high|medium|low|info",\n'
    '  "confidence": <0.0-1.0>,\n'
    '  "root_cause": "<why>",\n'
    '  "attack_scenario": "<how exploited>",\n'
    '  "secure_fix": "<how to fix>",\n'
    '  "references": ["<links>"]\n'
    "}\n"
    "If no vulnerability, return {\"vulnerability\": null, \"confidence\": 0}\n"
    "Output ONLY valid JSON, no markdown."
)

FIX_PROMPT_TEMPLATE = (
    "You are a security code fixer. The following {lang} code has a vulnerability.\n\n"
    "VULNERABILITY: {vuln}\n"
    "CWE: {cwe}\n"
    "ROOT CAUSE: {root_cause}\n\n"
    "VULNERABLE CODE:\n```{lang}\n{code}\n```\n\n"
    "Return ONLY a JSON object:\n"
    '{{"patched_code": "<the complete fixed file>", "explanation": "<brief fix explanation>"}}\n\n'
    "Rules:\n"
    "- Output ONLY valid JSON, no markdown\n"
    "- patched_code must be the COMPLETE fixed file, not a snippet\n"
    "- Preserve original code structure and style"
)


# ──────────────────────────────────────────────────────
#  Provider implementations
# ──────────────────────────────────────────────────────

def _groq_chat(messages: list[dict], model: str = "llama-3.3-70b-versatile") -> str:
    import os
    api_key = os.environ.get("GROQ_API_KEY", "")
    if not api_key:
        raise RuntimeError("GROQ_API_KEY not set")
    r = requests.post(
        "https://api.groq.com/openai/v1/chat/completions",
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        json={"model": model, "messages": messages, "temperature": TEMPERATURE, "max_tokens": MAX_TOKENS},
        timeout=60,
    )
    r.raise_for_status()
    return r.json()["choices"][0]["message"]["content"]


def _fireworks_chat(messages: list[dict], model: str = "accounts/fireworks/models/llama-v3p3-70b-instruct") -> str:
    import os
    api_key = os.environ.get("FIREWORKS_API_KEY", "")
    if not api_key:
        raise RuntimeError("FIREWORKS_API_KEY not set")
    r = requests.post(
        "https://api.fireworks.ai/inference/v1/chat/completions",
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        json={"model": model, "messages": messages, "temperature": TEMPERATURE, "max_tokens": MAX_TOKENS},
        timeout=60,
    )
    r.raise_for_status()
    return r.json()["choices"][0]["message"]["content"]


def _nebius_chat(messages: list[dict], model: str = "Qwen/Qwen3-32B") -> str:
    import os
    api_key = os.environ.get("NEBIUS_API_KEY", "")
    if not api_key:
        raise RuntimeError("NEBIUS_API_KEY not set")
    r = requests.post(
        "https://api.studio.nebius.com/v1/chat/completions",
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        json={"model": model, "messages": messages, "temperature": TEMPERATURE, "max_tokens": MAX_TOKENS},
        timeout=60,
    )
    r.raise_for_status()
    return r.json()["choices"][0]["message"]["content"]


def _ollama_chat(messages: list[dict], model: str = "qwen2.5-coder:7b") -> str:
    r = requests.post(
        "http://localhost:11434/api/chat",
        json={"model": model, "messages": messages, "stream": False, "options": {"temperature": TEMPERATURE, "num_predict": MAX_TOKENS}},
        timeout=120,
    )
    r.raise_for_status()
    return r.json()["message"]["content"]


def _huggingface_chat(messages: list[dict], model: str = "Qwen/Qwen3-8B") -> str:
    import os
    api_key = os.environ.get("HF_TOKEN", os.environ.get("HUGGINGFACE_TOKEN", ""))
    if not api_key:
        raise RuntimeError("HF_TOKEN not set")
    r = requests.post(
        f"https://api-inference.huggingface.co/models/{model}",
        headers={"Authorization": f"Bearer {api_key}"},
        json={"messages": messages, "temperature": TEMPERATURE, "max_tokens": MAX_TOKENS},
        timeout=60,
    )
    r.raise_for_status()
    return r.json()["choices"][0]["message"]["content"]


PROVIDERS = {
    "ollama": {"fn": _ollama_chat, "models": [
        {"id": "qwen2.5-coder:1.5b", "name": "Qwen 2.5 Coder 1.5B (Local, Fast)", "speed": "fast"},
        {"id": "qwen2.5-coder:7b", "name": "Qwen 2.5 Coder 7B (Local, Best)", "speed": "medium"},
    ]},
    "groq": {"fn": _groq_chat, "models": [
        {"id": "llama-3.3-70b-versatile", "name": "Llama 3.3 70B", "speed": "fast"},
        {"id": "llama-3.1-8b-instant", "name": "Llama 3.1 8B", "speed": "fast"},
        {"id": "gemma2-9b-it", "name": "Gemma 2 9B", "speed": "fast"},
    ]},
    "fireworks": {"fn": _fireworks_chat, "models": [
        {"id": "accounts/fireworks/models/llama-v3p3-70b-instruct", "name": "Llama 3.3 70B", "speed": "fast"},
        {"id": "accounts/fireworks/models/deepseek-v3", "name": "DeepSeek V3", "speed": "fast"},
        {"id": "accounts/fireworks/models/qwen3-235b-a22b", "name": "Qwen 3 235B", "speed": "slow"},
    ]},
    "nebius": {"fn": _nebius_chat, "models": [
        {"id": "Qwen/Qwen3-32B", "name": "Qwen 3 32B", "speed": "fast"},
        {"id": "Qwen/Qwen3-30B-A3B-Instruct-2507", "name": "Qwen 3 30B (MoE, Fast)", "speed": "fast"},
        {"id": "moonshotai/Kimi-K2.7-Code", "name": "Kimi K2.7 Code", "speed": "medium"},
        {"id": "meta-llama/Llama-3.3-70B-Instruct", "name": "Llama 3.3 70B", "speed": "medium"},
        {"id": "deepseek-ai/DeepSeek-V4-Pro", "name": "DeepSeek V4 Pro", "speed": "medium"},
        {"id": "zai-org/GLM-5.2", "name": "GLM 5.2", "speed": "medium"},
        {"id": "Qwen/Qwen3.5-397B-A17B", "name": "Qwen 3.5 397B (Best)", "speed": "slow"},
        {"id": "nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B", "name": "Nemotron 3 Nano", "speed": "fast"},
        {"id": "MiniMaxAI/MiniMax-M3", "name": "MiniMax M3", "speed": "medium"},
    ]},
    "huggingface": {"fn": _huggingface_chat, "models": [
        {"id": "Qwen/Qwen3-8B", "name": "Qwen 3 8B", "speed": "fast"},
        {"id": "Qwen/Qwen3-14B", "name": "Qwen 3 14B", "speed": "medium"},
        {"id": "meta-llama/Llama-3.3-70B-Instruct", "name": "Llama 3.3 70B", "speed": "slow"},
    ]},
}

# ──────────────────────────────────────────────────────
#  State & helpers
# ──────────────────────────────────────────────────────

def _normalize(obj: dict) -> dict:
    """Normalize LLM output to standard Finding schema."""
    sev = str(obj.get("severity", "info")).lower().strip()
    if sev not in ("critical", "high", "medium", "low", "info"):
        sev = "info"
    conf = obj.get("confidence", 0)
    if isinstance(conf, str):
        try:
            conf = float(conf)
        except (ValueError, TypeError):
            conf = 0
    refs = obj.get("references", [])
    if isinstance(refs, str):
        refs = [r.strip() for r in refs.split(",") if r.strip()]
    return {
        "vulnerability": obj.get("vulnerability"),
        "cwe": obj.get("cwe"),
        "severity": sev,
        "confidence": max(0.0, min(1.0, float(conf))),
        "root_cause": obj.get("root_cause"),
        "attack_scenario": obj.get("attack_scenario"),
        "secure_fix": obj.get("secure_fix"),
        "references": refs if isinstance(refs, list) else [],
        "patched_code": obj.get("patched_code"),
    }


def _call_llm(user_msg: str, provider: str = "ollama", model: str | None = None) -> tuple[dict, float]:
    """Route to provider, return (parsed_json, latency_seconds)."""
    if provider not in PROVIDERS:
        provider = "ollama"
    info = PROVIDERS[provider]
    fn = info["fn"]
    if model is None:
        model = info["models"][0]["id"]
    messages = [{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": user_msg}]
    t0 = time.time()
    text = fn(messages, model=model).strip()
    dt = time.time() - t0
    # Clean markdown fences
    if text.startswith("```"):
        text = text.strip("`")
        if "\n" in text:
            text = text.split("\n", 1)[1]
        if text.endswith("```"):
            text = text[:-3]
    try:
        obj = json.loads(text)
    except json.JSONDecodeError:
        obj = {"raw": text, "parse_error": True}
    return obj, dt


def _build_user_for_scan(req: "ScanRequest") -> str:
    extra = f"\n\nContext:\n```\n{req.context}\n```" if req.context else ""
    return (
        f"Analyze this {req.language} code for security vulnerabilities.{extra}\n\n"
        f"```{req.language}\n{req.code}\n```"
    )


# ──────────────────────────────────────────────────────
#  Request / Response schemas
# ──────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    code: str = Field(..., min_length=1, max_length=200_000)
    language: str = Field("python")
    filename: str | None = None
    context: str | None = None
    provider: str | None = Field(None, description="ollama|groq|fireworks|nebius|huggingface")
    model: str | None = Field(None, description="Model ID for the chosen provider")


class ReviewRequest(BaseModel):
    diff: str = Field(..., min_length=1, max_length=200_000)
    language: str = Field("python")
    filename: str | None = None
    provider: str | None = None
    model: str | None = None


class GenerateRequest(BaseModel):
    prompt: str = Field(..., min_length=1, max_length=10_000)
    language: str = Field("python")
    provider: str | None = None
    model: str | None = None


class FixRequest(BaseModel):
    code: str = Field(..., min_length=1, max_length=200_000)
    language: str = Field("python")
    vulnerability: str = Field("", description="What the vulnerability is")
    cwe: str = Field("", description="CWE ID like CWE-78")
    root_cause: str = Field("", description="Why it's vulnerable")
    filename: str | None = None
    provider: str | None = None
    model: str | None = None


class BatchScanRequest(BaseModel):
    items: list[ScanRequest] = Field(..., min_length=1, max_length=64)


class Finding(BaseModel):
    vulnerability: str | None
    cwe: str | None
    severity: Literal["critical", "high", "medium", "low", "info", None] = None
    confidence: float = 0
    root_cause: str | None = None
    attack_scenario: str | None = None
    secure_fix: str | None = None
    references: list[str] = []
    patched_code: str | None = None


class ScanResponse(BaseModel):
    finding: Finding
    engine: str
    latency_ms: float


class VersionInfo(BaseModel):
    engine: str
    providers: list[str]
    default_provider: str


# ──────────────────────────────────────────────────────
#  FastAPI app
# ──────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    yield

app = FastAPI(
    title="RakshakAI v2",
    version="2.0.0",
    description="Security code analyzer with multi-provider LLM support.",
    lifespan=lifespan,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ──────────────────────────────────────────────────────
#  Routes
# ──────────────────────────────────────────────────────

@app.get("/v2/health")
async def health() -> dict:
    available = []
    import os
    if os.environ.get("GROQ_API_KEY"):
        available.append("groq")
    if os.environ.get("FIREWORKS_API_KEY"):
        available.append("fireworks")
    if os.environ.get("NEBIUS_API_KEY"):
        available.append("nebius")
    if os.environ.get("HF_TOKEN") or os.environ.get("HUGGINGFACE_TOKEN"):
        available.append("huggingface")
    # Check Ollama
    try:
        r = requests.get("http://localhost:11434/api/tags", timeout=2)
        if r.status_code == 200:
            available.append("ollama")
    except Exception:
        pass
    return {
        "status": "ok",
        "providers_available": available,
        "default_provider": "ollama" if "ollama" in available else (available[0] if available else "none"),
    }


@app.get("/v2/providers")
async def list_providers() -> dict:
    """List all providers and their models."""
    result = {}
    for name, info in PROVIDERS.items():
        result[name] = {
            "models": info["models"],
            "available": _check_provider(name),
        }
    return result


def _check_provider(name: str) -> bool:
    import os
    if name == "ollama":
        try:
            r = requests.get("http://localhost:11434/api/tags", timeout=2)
            return r.status_code == 200
        except Exception:
            return False
    if name == "groq":
        return bool(os.environ.get("GROQ_API_KEY"))
    if name == "fireworks":
        return bool(os.environ.get("FIREWORKS_API_KEY"))
    if name == "nebius":
        return bool(os.environ.get("NEBIUS_API_KEY"))
    if name == "huggingface":
        return bool(os.environ.get("HF_TOKEN") or os.environ.get("HUGGINGFACE_TOKEN"))
    return False


@app.get("/v2/version")
async def version() -> VersionInfo:
    return VersionInfo(
        engine="multi-provider",
        providers=list(PROVIDERS.keys()),
        default_provider="ollama",
    )


@app.post("/v2/scan", response_model=ScanResponse)
async def scan_code(req: ScanRequest) -> ScanResponse:
    provider = req.provider or "ollama"
    user_msg = _build_user_for_scan(req)
    obj, dt = _call_llm(user_msg, provider=provider, model=req.model)
    return ScanResponse(
        finding=_normalize(obj),
        engine=f"v2-{provider}",
        latency_ms=dt * 1000,
    )


@app.post("/v2/review", response_model=ScanResponse)
async def review_diff(req: ReviewRequest) -> ScanResponse:
    provider = req.provider or "ollama"
    user_msg = (
        f"Review this {req.language} diff for security issues.\n\n"
        f"```diff\n{req.diff}\n```"
    )
    obj, dt = _call_llm(user_msg, provider=provider, model=req.model)
    return ScanResponse(
        finding=_normalize(obj),
        engine=f"v2-{provider}",
        latency_ms=dt * 1000,
    )


@app.post("/v2/generate", response_model=ScanResponse)
async def generate_secure(req: GenerateRequest) -> ScanResponse:
    provider = req.provider or "ollama"
    user_msg = (
        f"Write a secure {req.language} implementation for the following requirement. "
        f"Follow security best practices. Output the code in a JSON object field "
        f"called `patched_code`.\n\nRequirement:\n{req.prompt}"
    )
    obj, dt = _call_llm(user_msg, provider=provider, model=req.model)
    return ScanResponse(
        finding=_normalize(obj),
        engine=f"v2-{provider}",
        latency_ms=dt * 1000,
    )


@app.post("/v2/fix")
async def fix_vulnerability(req: FixRequest) -> dict:
    provider = req.provider or "ollama"
    user_msg = FIX_PROMPT_TEMPLATE.format(
        lang=req.language,
        vuln=req.vulnerability,
        cwe=req.cwe,
        root_cause=req.root_cause,
        code=req.code,
    )
    obj, dt = _call_llm(user_msg, provider=provider, model=req.model)
    return {
        "patched_code": obj.get("patched_code", ""),
        "explanation": obj.get("explanation", obj.get("secure_fix", "")),
        "latency_ms": dt * 1000,
        "provider": provider,
    }


@app.post("/v2/batch")
async def batch_scan(req: BatchScanRequest) -> list[ScanResponse]:
    if not req.items:
        raise HTTPException(status_code=400, detail="empty batch")
    provider = req.items[0].provider or "ollama"
    responses: list[ScanResponse] = []
    for it in req.items:
        user_msg = _build_user_for_scan(it)
        obj, dt = _call_llm(user_msg, provider=provider, model=it.model)
        responses.append(ScanResponse(
            finding=_normalize(obj),
            engine=f"v2-{provider}",
            latency_ms=dt * 1000,
        ))
    return responses


# ─── Notion Integration ───
try:
    from v2.api.notion import router as notion_router
    app.include_router(notion_router)
except ImportError:
    pass


if __name__ == "__main__":
    uvicorn.run("v2.deploy.server:app", host="0.0.0.0", port=8080, reload=True, workers=1)
