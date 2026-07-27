"""Multi-model abstraction layer — supports OpenAI, Anthropic, Ollama, DeepSeek, Rakshak, custom.
Streaming chat, function calling, token tracking."""
from __future__ import annotations
import json, os, time, threading, concurrent.futures
from dataclasses import dataclass, field
from typing import Callable, Any, Optional
from openai import OpenAI

NVIDIA_KEY = os.environ.get("NVIDIA_NIM_KEY", "")
HF_TOKEN = os.environ.get("HF_TOKEN", "")
OPENAI_KEY = os.environ.get("OPENAI_API_KEY", "")
ANTHROPIC_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
NEBIUS_KEY = os.environ.get("NEBIUS_API_KEY", "")
FIREWORKS_KEY = os.environ.get("FIREWORKS_API_KEY", "")
TOGETHER_KEY = os.environ.get("TOGETHER_API_KEY", "")
GROQ_KEY = os.environ.get("GROQ_API_KEY", "")
OPENROUTER_KEY = os.environ.get("OPENROUTER_API_KEY", "")
GOOGLE_KEY = os.environ.get("GOOGLE_API_KEY", "")
DEEPSEEK_KEY = os.environ.get("DEEPSEEK_API_KEY", "")
MISTRAL_KEY = os.environ.get("MISTRAL_API_KEY", "")
XAI_KEY = os.environ.get("XAI_API_KEY", "")
PERPLEXITY_KEY = os.environ.get("PERPLEXITY_API_KEY", "")
DEEPINFRA_KEY = os.environ.get("DEEPINFRA_API_KEY", "")
AIML_KEY = os.environ.get("AIML_API_KEY", "")
OLLAMA_URL = os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434")

RAKSHAKAI_INFER_URL = os.environ.get(
    "RAKSHAKAI_INFER_URL",
    "https://alimuneerali245--chat-completions.modal.run",
)

FUNCTION_CALLING_MODELS = {"deepseek", "llama", "gpt-4o", "gpt-4o-mini"}


@dataclass
class LLMConfig:
    name: str
    provider: str
    model: str
    api_key: str = ""
    base_url: str = ""
    max_tokens: int = 4096
    temperature: float = 0.3
    supports_streaming: bool = True
    supports_tools: bool = True

    @property
    def client(self) -> OpenAI:
        key = self.api_key
        if not key:
            if self.provider == "openai":
                key = OPENAI_KEY
            elif self.provider == "nebius":
                key = NEBIUS_KEY
            elif self.provider == "fireworks":
                key = FIREWORKS_KEY
            elif self.provider == "together":
                key = TOGETHER_KEY
            elif self.provider == "groq":
                key = GROQ_KEY
        if not key and self.provider not in ("ollama", "modal"):
            key = NVIDIA_KEY
        return OpenAI(api_key=key, base_url=self.base_url)

    def is_direct_endpoint(self) -> bool:
        return self.provider == "modal"


def count_tokens(text: str) -> int:
    """Quick token estimate (~4 chars per token)."""
    return len(text) // 4


def trim_messages(messages: list[dict], max_tokens: int = 6000) -> list[dict]:
    """Trim conversation to fit within token budget."""
    system_msgs = [m for m in messages if m["role"] == "system"]
    other = [m for m in messages if m["role"] != "system"]

    total = sum(count_tokens(m.get("content", "")) for m in system_msgs)
    trimmed = list(system_msgs)

    for m in reversed(other):
        msg_tokens = count_tokens(m.get("content", ""))
        if total + msg_tokens > max_tokens:
            break
        trimmed.insert(len(system_msgs), m)
        total += msg_tokens

    # Always keep last user message
    if other and other[-1] not in trimmed:
        if trimmed and trimmed[0]["role"] == "system":
            trimmed.append(other[-1])
        else:
            trimmed = system_msgs + [other[-1]]

    return trimmed


def _build_registry():
    """Build the full model registry with all providers."""
    models = {}

    # ── Local ──
    models["ollama"] = LLMConfig(name="Ollama Local", provider="ollama", model="llama3.2", base_url=OLLAMA_URL, api_key="")

    # ── Groq ──
    groq_base = "https://api.groq.com/openai/v1/"

    # ── RakshakAI ──
    models["rakshak"] = LLMConfig(name="RakshakAI v3 (legacy)", provider="modal", model="Muneerali199/rakshak-cwe-v3", base_url=RAKSHAKAI_INFER_URL, api_key=HF_TOKEN, supports_streaming=False, supports_tools=False)
    models["rakshak-14b"] = LLMConfig(name="RakshakAI 14B (Modal)", provider="modal", model="Muneerali199/rakshak-cwe-14b-sft-step375", base_url="https://alimuneerali245--rakshak-api-rakshakmodel-analyze-endpoint.modal.run", api_key=HF_TOKEN, supports_streaming=False, supports_tools=False)
    models["rakshak-14b-groq"] = LLMConfig(name="RakshakAI 14B (via Groq)", provider="groq", model="llama-3.3-70b-versatile", base_url=groq_base, api_key=GROQ_KEY, supports_streaming=True, supports_tools=True)

    # ── NVIDIA NIM ──
    models["deepseek"] = LLMConfig(name="DeepSeek V4 Pro", provider="nvidia", model="deepseek-ai/deepseek-v4-pro", base_url="https://integrate.api.nvidia.com/v1", api_key=NVIDIA_KEY)
    models["llama"] = LLMConfig(name="Llama-3.1-70B", provider="nvidia", model="meta/llama-3.1-70b-instruct", base_url="https://integrate.api.nvidia.com/v1", api_key=NVIDIA_KEY)
    models["mistral-nvidia"] = LLMConfig(name="Mistral Large", provider="nvidia", model="mistralai/mistral-large", base_url="https://integrate.api.nvidia.com/v1", api_key=NVIDIA_KEY)

    # ── Nebius AI Studio ──
    nebius_base = "https://api.studio.nebius.ai/v1/"
    models["nebius-llama-70b"] = LLMConfig(name="Llama 3.1 70B", provider="nebius", model="meta-llama/Meta-Llama-3.1-70B-Instruct", base_url=nebius_base, api_key=NEBIUS_KEY)
    models["nebius-llama-8b"] = LLMConfig(name="Llama 3.1 8B", provider="nebius", model="meta-llama/Meta-Llama-3.1-8B-Instruct", base_url=nebius_base, api_key=NEBIUS_KEY)
    models["nebius-qwen-72b"] = LLMConfig(name="Qwen 2.5 72B", provider="nebius", model="Qwen/Qwen2.5-72B-Instruct", base_url=nebius_base, api_key=NEBIUS_KEY)
    models["nebius-qwen-32b"] = LLMConfig(name="Qwen 2.5 32B", provider="nebius", model="Qwen/Qwen2.5-32B-Instruct", base_url=nebius_base, api_key=NEBIUS_KEY)
    models["nebius-mixtral"] = LLMConfig(name="Mixtral 8x22B", provider="nebius", model="mistralai/Mixtral-8x22B-Instruct-v0.1", base_url=nebius_base, api_key=NEBIUS_KEY)
    models["nebius-deepseek"] = LLMConfig(name="DeepSeek V2.5", provider="nebius", model="DeepSeek/DeepSeek-V2.5", base_url=nebius_base, api_key=NEBIUS_KEY)

    # ── Fireworks AI (200+ models available) ──
    fw_base = "https://api.fireworks.ai/inference/v1/"
    models["fw-kimi-k2"] = LLMConfig(name="Kimi K2 Instruct", provider="fireworks", model="accounts/fireworks/models/kimi-k2-instruct", base_url=fw_base, api_key=FIREWORKS_KEY)
    models["fw-deepseek-v4-pro"] = LLMConfig(name="DeepSeek V4 Pro", provider="fireworks", model="accounts/fireworks/models/deepseek-v4-pro", base_url=fw_base, api_key=FIREWORKS_KEY)
    models["fw-deepseek-v4-flash"] = LLMConfig(name="DeepSeek V4 Flash", provider="fireworks", model="accounts/fireworks/models/deepseek-v4-flash", base_url=fw_base, api_key=FIREWORKS_KEY)
    models["fw-llama-3.3-70b"] = LLMConfig(name="Llama 3.3 70B", provider="fireworks", model="accounts/fireworks/models/llama-v3p3-70b-instruct", base_url=fw_base, api_key=FIREWORKS_KEY)
    models["fw-llama-70b"] = LLMConfig(name="Llama 3.1 70B", provider="fireworks", model="accounts/fireworks/models/llama-v3p1-70b-instruct", base_url=fw_base, api_key=FIREWORKS_KEY)
    models["fw-llama-8b"] = LLMConfig(name="Llama 3.1 8B", provider="fireworks", model="accounts/fireworks/models/llama-v3p1-8b-instruct", base_url=fw_base, api_key=FIREWORKS_KEY)
    models["fw-qwen-3.5-122b"] = LLMConfig(name="Qwen 3.5 122B", provider="fireworks", model="accounts/fireworks/models/qwen3p5-122b-a10b", base_url=fw_base, api_key=FIREWORKS_KEY)
    models["fw-qwen-3.5-27b"] = LLMConfig(name="Qwen 3.5 27B", provider="fireworks", model="accounts/fireworks/models/qwen3p5-27b", base_url=fw_base, api_key=FIREWORKS_KEY)
    models["fw-qwen-3.6-plus"] = LLMConfig(name="Qwen 3.6 Plus", provider="fireworks", model="accounts/fireworks/models/qwen3p6-plus", base_url=fw_base, api_key=FIREWORKS_KEY)
    models["fw-qwen-72b"] = LLMConfig(name="Qwen 2.5 72B", provider="fireworks", model="accounts/fireworks/models/qwen2p5-72b-instruct", base_url=fw_base, api_key=FIREWORKS_KEY)
    models["fw-glm-5"] = LLMConfig(name="GLM-5", provider="fireworks", model="accounts/fireworks/models/glm-5", base_url=fw_base, api_key=FIREWORKS_KEY)
    models["fw-minimax-m3"] = LLMConfig(name="MiniMax M3", provider="fireworks", model="accounts/fireworks/models/minimax-m3", base_url=fw_base, api_key=FIREWORKS_KEY)
    models["fw-gemma-4-31b"] = LLMConfig(name="Gemma 4 31B", provider="fireworks", model="accounts/fireworks/models/gemma-4-31b-it", base_url=fw_base, api_key=FIREWORKS_KEY)
    models["fw-mixtral"] = LLMConfig(name="Mixtral 8x22B", provider="fireworks", model="accounts/fireworks/models/mixtral-8x22b-instruct", base_url=fw_base, api_key=FIREWORKS_KEY)
    models["fw-deepseek-v3"] = LLMConfig(name="DeepSeek V3", provider="fireworks", model="accounts/fireworks/models/deepseek-v3", base_url=fw_base, api_key=FIREWORKS_KEY)
    models["fw-phi-4"] = LLMConfig(name="Phi-4 14B", provider="fireworks", model="accounts/fireworks/models/phi-4", base_url=fw_base, api_key=FIREWORKS_KEY)

    # ── Together AI ──
    together_base = "https://api.together.xyz/v1/"
    models["tg-llama-70b"] = LLMConfig(name="Llama 3.1 70B Turbo", provider="together", model="meta-llama/Meta-Llama-3.1-70B-Instruct-Turbo", base_url=together_base, api_key=TOGETHER_KEY)
    models["tg-llama-8b"] = LLMConfig(name="Llama 3.1 8B Turbo", provider="together", model="meta-llama/Meta-Llama-3.1-8B-Instruct-Turbo", base_url=together_base, api_key=TOGETHER_KEY)
    models["tg-qwen-72b"] = LLMConfig(name="Qwen 2.5 72B Turbo", provider="together", model="Qwen/Qwen2.5-72B-Instruct-Turbo", base_url=together_base, api_key=TOGETHER_KEY)
    models["tg-deepseek"] = LLMConfig(name="DeepSeek V3", provider="together", model="deepseek-ai/DeepSeek-V3", base_url=together_base, api_key=TOGETHER_KEY)
    models["tg-mixtral"] = LLMConfig(name="Mixtral 8x22B", provider="together", model="mistralai/Mixtral-8x22B-Instruct-v0.1", base_url=together_base, api_key=TOGETHER_KEY)

    # ── Groq ──
    models["groq-llama-70b"] = LLMConfig(name="Llama 3.3 70B", provider="groq", model="llama-3.3-70b-versatile", base_url=groq_base, api_key=GROQ_KEY)
    models["groq-llama-8b"] = LLMConfig(name="Llama 3.1 8B", provider="groq", model="llama-3.1-8b-instant", base_url=groq_base, api_key=GROQ_KEY)
    models["groq-mixtral"] = LLMConfig(name="Mixtral 8x7B", provider="groq", model="mixtral-8x7b-32768", base_url=groq_base, api_key=GROQ_KEY)
    models["groq-gemma"] = LLMConfig(name="Gemma 2 9B", provider="groq", model="gemma2-9b-it", base_url=groq_base, api_key=GROQ_KEY)
    models["groq-deepseek"] = LLMConfig(name="DeepSeek R1 Distill", provider="groq", model="deepseek-r1-distill-llama-70b", base_url=groq_base, api_key=GROQ_KEY)

    # ── OpenAI ──
    models["gpt-4o-mini"] = LLMConfig(name="GPT-4o Mini", provider="openai", model="gpt-4o-mini", base_url="https://api.openai.com/v1")
    models["gpt-4o"] = LLMConfig(name="GPT-4o", provider="openai", model="gpt-4o", base_url="https://api.openai.com/v1")

    # ── Anthropic ──
    models["claude"] = LLMConfig(name="Claude Haiku", provider="anthropic", model="claude-3-haiku-20240307", supports_tools=False)
    models["claude-sonnet"] = LLMConfig(name="Claude Sonnet", provider="anthropic", model="claude-3-5-sonnet-20241022", supports_tools=False)

    # ── OpenRouter (gateway to 200+ models) ──
    or_base = "https://openrouter.ai/api/v1"
    models["or-gpt-4o"] = LLMConfig(name="GPT-4o", provider="openai", model="openai/gpt-4o", base_url=or_base, api_key=OPENROUTER_KEY)
    models["or-gpt-4o-mini"] = LLMConfig(name="GPT-4o Mini", provider="openai", model="openai/gpt-4o-mini", base_url=or_base, api_key=OPENROUTER_KEY)
    models["or-claude-sonnet"] = LLMConfig(name="Claude Sonnet", provider="openai", model="anthropic/claude-3-5-sonnet-20241022", base_url=or_base, api_key=OPENROUTER_KEY)
    models["or-claude-haiku"] = LLMConfig(name="Claude Haiku", provider="openai", model="anthropic/claude-3-5-haiku-20241022", base_url=or_base, api_key=OPENROUTER_KEY)
    models["or-deepseek-v3"] = LLMConfig(name="DeepSeek V3", provider="openai", model="deepseek/deepseek-chat", base_url=or_base, api_key=OPENROUTER_KEY)
    models["or-llama-70b"] = LLMConfig(name="Llama 3.1 70B", provider="openai", model="meta-llama/llama-3.1-70b-instruct", base_url=or_base, api_key=OPENROUTER_KEY)
    models["or-llama-8b"] = LLMConfig(name="Llama 3.1 8B", provider="openai", model="meta-llama/llama-3.1-8b-instruct", base_url=or_base, api_key=OPENROUTER_KEY)
    models["or-mixtral"] = LLMConfig(name="Mixtral 8x22B", provider="openai", model="mistralai/mixtral-8x22b-instruct", base_url=or_base, api_key=OPENROUTER_KEY)
    models["or-gemini-2-flash"] = LLMConfig(name="Gemini 2.0 Flash", provider="openai", model="google/gemini-2.0-flash-001", base_url=or_base, api_key=OPENROUTER_KEY)
    models["or-qwen-72b"] = LLMConfig(name="Qwen 2.5 72B", provider="openai", model="qwen/qwen-2.5-72b-instruct", base_url=or_base, api_key=OPENROUTER_KEY)
    models["or-phi-4"] = LLMConfig(name="Phi-4 14B", provider="openai", model="microsoft/phi-4", base_url=or_base, api_key=OPENROUTER_KEY)
    models["or-llama-3.2-3b"] = LLMConfig(name="Llama 3.2 3B", provider="openai", model="meta-llama/llama-3.2-3b-instruct", base_url=or_base, api_key=OPENROUTER_KEY)

    # ── Google Gemini (OpenAI-compatible endpoint) ──
    gemini_base = "https://generativelanguage.googleapis.com/v1beta/openai/"
    models["gemini-2-flash"] = LLMConfig(name="Gemini 2.0 Flash", provider="openai", model="gemini-2.0-flash", base_url=gemini_base, api_key=GOOGLE_KEY)
    models["gemini-2-flash-lite"] = LLMConfig(name="Gemini 2.0 Flash Lite", provider="openai", model="gemini-2.0-flash-lite", base_url=gemini_base, api_key=GOOGLE_KEY)
    models["gemini-1.5-pro"] = LLMConfig(name="Gemini 1.5 Pro", provider="openai", model="gemini-1.5-pro", base_url=gemini_base, api_key=GOOGLE_KEY)
    models["gemini-1.5-flash"] = LLMConfig(name="Gemini 1.5 Flash", provider="openai", model="gemini-1.5-flash", base_url=gemini_base, api_key=GOOGLE_KEY)

    # ── DeepSeek Native API ──
    ds_base = "https://api.deepseek.com/v1"
    models["ds-chat"] = LLMConfig(name="DeepSeek V3 Chat", provider="openai", model="deepseek-chat", base_url=ds_base, api_key=DEEPSEEK_KEY)
    models["ds-reasoner"] = LLMConfig(name="DeepSeek R1 Reasoner", provider="openai", model="deepseek-reasoner", base_url=ds_base, api_key=DEEPSEEK_KEY)

    # ── Mistral AI ──
    ms_base = "https://api.mistral.ai/v1"
    models["ms-large"] = LLMConfig(name="Mistral Large 2", provider="openai", model="mistral-large-latest", base_url=ms_base, api_key=MISTRAL_KEY)
    models["ms-small"] = LLMConfig(name="Mistral Small", provider="openai", model="mistral-small-latest", base_url=ms_base, api_key=MISTRAL_KEY)
    models["ms-codestral"] = LLMConfig(name="Codestral", provider="openai", model="codestral-latest", base_url=ms_base, api_key=MISTRAL_KEY)

    # ── xAI Grok ──
    xai_base = "https://api.x.ai/v1"
    models["grok-2"] = LLMConfig(name="Grok 2", provider="openai", model="grok-2", base_url=xai_base, api_key=XAI_KEY)

    # ── Perplexity ──
    pplx_base = "https://api.perplexity.ai"
    models["pplx-sonar"] = LLMConfig(name="Sonar Pro", provider="openai", model="sonar-pro", base_url=pplx_base, api_key=PERPLEXITY_KEY)
    models["pplx-sonar-deep"] = LLMConfig(name="Sonar Deep", provider="openai", model="sonar-deep", base_url=pplx_base, api_key=PERPLEXITY_KEY)

    # ── DeepInfra ──
    di_base = "https://api.deepinfra.com/v1/openai"
    models["di-llama-70b"] = LLMConfig(name="Llama 3.1 70B", provider="openai", model="meta-llama/Meta-Llama-3.1-70B-Instruct", base_url=di_base, api_key=DEEPINFRA_KEY)
    models["di-llama-8b"] = LLMConfig(name="Llama 3.1 8B", provider="openai", model="meta-llama/Meta-Llama-3.1-8B-Instruct", base_url=di_base, api_key=DEEPINFRA_KEY)
    models["di-mixtral"] = LLMConfig(name="Mixtral 8x22B", provider="openai", model="mistralai/Mixtral-8x22B-Instruct-v0.1", base_url=di_base, api_key=DEEPINFRA_KEY)
    models["di-qwen-72b"] = LLMConfig(name="Qwen 2.5 72B", provider="openai", model="Qwen/Qwen2.5-72B-Instruct", base_url=di_base, api_key=DEEPINFRA_KEY)
    models["di-deepseek"] = LLMConfig(name="DeepSeek V3", provider="openai", model="deepseek-ai/DeepSeek-V3", base_url=di_base, api_key=DEEPINFRA_KEY)

    # ── AI/ML API ──
    aiml_base = "https://api.aimlapi.com/v1"
    models["aiml-gpt-4o"] = LLMConfig(name="GPT-4o", provider="openai", model="gpt-4o", base_url=aiml_base, api_key=AIML_KEY)
    models["aiml-gpt-4o-mini"] = LLMConfig(name="GPT-4o Mini", provider="openai", model="gpt-4o-mini", base_url=aiml_base, api_key=AIML_KEY)
    models["aiml-claude-sonnet"] = LLMConfig(name="Claude Sonnet", provider="openai", model="anthropic/claude-3-5-sonnet-20241022", base_url=aiml_base, api_key=AIML_KEY)
    models["aiml-llama-70b"] = LLMConfig(name="Llama 3.1 70B", provider="openai", model="meta-llama/Meta-Llama-3.1-70B-Instruct", base_url=aiml_base, api_key=AIML_KEY)
    models["aiml-deepseek"] = LLMConfig(name="DeepSeek V3", provider="openai", model="deepseek-ai/DeepSeek-V3", base_url=aiml_base, api_key=AIML_KEY)

    return models


@dataclass
class ModelRegistry:
    models: dict[str, LLMConfig] = field(default_factory=_build_registry)
    active: str = ""

    def get(self, name: str | None = None) -> LLMConfig:
        key = name or self.active
        if key in self.models:
            return self.models[key]
        first = self.auto_select()
        return self.models.get(first, next(iter(self.models.values())))

    def set_active(self, name: str) -> bool:
        if name in self.models:
            self.active = name
            return True
        return False

    def add_custom(self, name: str, model: str, base_url: str, api_key: str, provider: str = "custom"):
        self.models[name] = LLMConfig(name=name, provider=provider, model=model, base_url=base_url, api_key=api_key)

    def auto_select(self) -> str:
        """Pick the first model with an available API key, or 'ollama' as fallback."""
        for name, cfg in self.models.items():
            if cfg.api_key and len(cfg.api_key) > 4:
                return name
        return "ollama"

    def list(self) -> list[str]:
        return list(self.models.keys())

    def supports_function_calling(self, name: str | None = None) -> bool:
        key = name or self.active
        cfg = self.get(key)
        return cfg.supports_tools and key in FUNCTION_CALLING_MODELS


registry = ModelRegistry()


def _direct_chat(cfg, messages, max_tokens, temperature) -> str:
    """Make a direct POST to a custom endpoint (no /chat/completions suffix)."""
    import requests as req
    try:
        r = req.post(cfg.base_url, json={
            "messages": messages, "max_tokens": max_tokens, "temperature": temperature,
        }, timeout=(30, 600))
        data = r.json()
        return data.get("choices", [{}])[0].get("message", {}).get("content", "")
    except Exception as e:
        return f"[ERROR: {e}]"


async def _stream_ollama(cfg, messages, max_tokens, on_token):
    """Stream from Ollama API (local)."""
    import httpx
    async with httpx.AsyncClient(timeout=300) as client:
        async with client.stream("POST", f"{cfg.base_url}/api/chat", json={
            "model": cfg.model, "messages": messages,
            "stream": True, "options": {"num_predict": max_tokens},
        }) as resp:
            full = ""
            async for line in resp.aiter_lines():
                if line.strip():
                    try:
                        data = json.loads(line)
                        if data.get("done"):
                            break
                        content = data.get("message", {}).get("content", "")
                        if content:
                            full += content
                            if on_token:
                                on_token(content)
                    except json.JSONDecodeError:
                        pass
            return full


async def _stream_anthropic(cfg, messages, max_tokens, on_token):
    """Stream from Anthropic Claude API."""
    from anthropic import AsyncAnthropic
    client = AsyncAnthropic(api_key=cfg.api_key or ANTHROPIC_KEY)
    system = ""
    chat_msgs = []
    for m in messages:
        if m["role"] == "system":
            system += m.get("content", "") + "\n"
        else:
            chat_msgs.append({"role": m["role"], "content": m.get("content", "")})
    full = ""
    async with client.messages.stream(
        model=cfg.model, max_tokens=max_tokens,
        system=system.strip() or None,
        messages=chat_msgs,
    ) as stream:
        async for text in stream.text_stream:
            full += text
            if on_token:
                on_token(text)
    return full


def stream_chat(
    messages: list[dict],
    cfg: LLMConfig | None = None,
    on_token: Callable[[str], None] | None = None,
    max_tokens: int = 4096,
) -> str:
    """Streaming chat — renders tokens via on_token callback."""
    cfg = cfg or registry.get()
    if cfg.is_direct_endpoint():
        full = _direct_chat(cfg, messages, max_tokens, cfg.temperature)
        if on_token:
            on_token(full)
        return full

    # Ollama
    if cfg.provider == "ollama":
        try:
            import httpx
            import asyncio
            return asyncio.run(_stream_ollama(cfg, messages, max_tokens, on_token))
        except Exception as e:
            err = f"[Ollama error: {e}. Is Ollama running? Start it: ollama serve]"
            if on_token:
                on_token(err)
            return err

    # Anthropic
    if cfg.provider == "anthropic":
        try:
            from anthropic import AsyncAnthropic
            import asyncio
            return asyncio.run(_stream_anthropic(cfg, messages, max_tokens, on_token))
        except ImportError:
            err = "[anthropic package not installed. Run: pip install anthropic]"
            if on_token:
                on_token(err)
            return err
        except Exception as e:
            err = f"[Anthropic error: {e}]"
            if on_token:
                on_token(err)
            return err

    # Standard OpenAI-compatible
    client = cfg.client
    full = ""
    try:
        if cfg.supports_streaming:
            stream = client.chat.completions.create(
                model=cfg.model, messages=messages,
                max_tokens=max_tokens, temperature=cfg.temperature, stream=True,
            )
            for chunk in stream:
                delta = chunk.choices[0].delta.content or ""
                if delta:
                    full += delta
                    if on_token:
                        on_token(delta)
        else:
            r = client.chat.completions.create(
                model=cfg.model, messages=messages,
                max_tokens=max_tokens, temperature=cfg.temperature, stream=False,
            )
            full = r.choices[0].message.content or ""
            if on_token:
                on_token(full)
    except Exception as e:
        full = f"[ERROR: {e}]"
        if on_token:
            on_token(full)
    return full


def chat_with_tools(
    messages: list[dict],
    cfg: LLMConfig | None = None,
    tools: list[dict] | None = None,
    max_tokens: int = 4096,
) -> dict:
    """Non-streaming chat with optional function calling (tools).

    Returns:
        {"role": "assistant", "content": ..., "tool_calls": [...]}
    """
    cfg = cfg or registry.get()
    if cfg.is_direct_endpoint():
        content = _direct_chat(cfg, messages, max_tokens, cfg.temperature)
        return {"role": "assistant", "content": content}

    client = cfg.client
    kwargs = dict(model=cfg.model, messages=messages, max_tokens=max_tokens, temperature=cfg.temperature)
    if tools:
        kwargs["tools"] = tools
    try:
        r = client.chat.completions.create(**kwargs, stream=False)
        msg = r.choices[0].message
        result = {"role": "assistant", "content": msg.content or ""}
        if msg.tool_calls:
            result["tool_calls"] = [
                {"id": tc.id, "type": "function",
                 "function": {"name": tc.function.name, "arguments": tc.function.arguments}}
                for tc in msg.tool_calls
            ]
            if not result["content"]:
                result["content"] = ""
        return result
    except Exception as e:
        return {"role": "assistant", "content": f"[ERROR: {e}]"}


def parallel_chat(
    messages: list[dict],
    model_names: list[str],
    on_token: Callable[[str, str], None] | None = None,
    max_tokens: int = 4096,
) -> dict[str, str]:
    """Run multiple models in parallel on the same prompt."""
    results = {}
    lock = threading.Lock()

    def run_model(name: str):
        cfg = registry.get(name)
        if not cfg:
            return name, "[INVALID MODEL]"
        text = stream_chat(messages, cfg, max_tokens=max_tokens)
        return name, text

    with concurrent.futures.ThreadPoolExecutor(max_workers=len(model_names)) as ex:
        futures = {ex.submit(run_model, name): name for name in model_names}
        for fut in concurrent.futures.as_completed(futures):
            name, text = fut.result()
            results[name] = text
    return results


def chat_sync(messages: list[dict], cfg: LLMConfig | None = None, max_tokens: int = 4096) -> str:
    """Non-streaming chat for internal use."""
    return stream_chat(messages, cfg, max_tokens=max_tokens)
