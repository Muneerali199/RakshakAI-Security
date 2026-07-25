"""Context Compaction — sliding window compression for long conversations.
Like Claude Code's compact.ts — auto-compresses when approaching limits."""
from __future__ import annotations
import json
import time
from typing import Optional
from v2.cli.llm import registry, chat_sync


def estimate_tokens(text: str) -> int:
    """Rough token estimate (4 chars per token)."""
    return len(text) // 4


def should_compact(messages: list[dict], budget: int = 8000) -> bool:
    """Check if conversation exceeds token budget."""
    total = sum(estimate_tokens(m.get("content", "")) for m in messages)
    return total > budget


def compact_conversation(
    messages: list[dict],
    model: str = "groq-llama-8b",
    target_tokens: int = 4000,
) -> list[dict]:
    """Compress conversation by summarizing older messages.

    Strategy (same as Claude Code):
    1. Keep system prompt untouched
    2. Keep last 3 exchanges intact
    3. Summarize everything before that into a single summary message
    """
    if not messages or len(messages) < 4:
        return messages

    # Keep system prompt (first message) and last 3 exchanges
    keep: list[dict] = []
    summary_candidates: list[dict] = []

    system = None
    if messages and messages[0]["role"] == "system":
        system = messages[0]
        messages = messages[1:]

    # Keep last 3 exchanges (up to 6 messages)
    if len(messages) > 6:
        summary_candidates = messages[:-6]
        keep = messages[-6:]
    else:
        keep = messages

    if not summary_candidates:
        result = [system] + keep if system else keep
        return result

    # Summarize old messages
    summary_msgs = [
        {
            "role": "system",
            "content": "Summarize the following conversation concisely while preserving "
                       "all decisions, file paths, vulnerability findings, and action items.",
        },
        {
            "role": "user",
            "content": "\n".join(
                f"[{m['role']}]: {m['content'][:500]}"
                for m in summary_candidates
            ),
        },
    ]

    try:
        cfg = registry.get(model)
        summary_text = chat_sync(summary_msgs, cfg)
        summary_msg = {
            "role": "system",
            "content": f"[Compacted summary of previous conversation]\n{summary_text[:1500]}",
        }
    except Exception:
        # If summarization fails, just keep recent messages
        summary_msg = {
            "role": "system",
            "content": f"[Previous conversation truncated — {len(summary_candidates)} messages dropped]",
        }

    result = []
    if system:
        result.append(system)
    result.append(summary_msg)
    result.extend(keep)

    return result


def get_context_report(messages: list[dict], budget: int = 8000) -> dict:
    """Return context usage report (like Claude Code's /context)."""
    total_tokens = sum(estimate_tokens(m.get("content", "")) for m in messages)
    msg_count = len(messages)

    breakdown = []
    for i, m in enumerate(messages):
        t = estimate_tokens(m.get("content", ""))
        role_display = {"system": "sys", "user": "usr", "assistant": "ast"}.get(m["role"], m["role"])
        label = f"{role_display}[{i}]"
        breakdown.append({"index": i, "role": m["role"], "tokens": t, "label": label})

    return {
        "total_tokens": total_tokens,
        "budget": budget,
        "usage_pct": round(total_tokens / budget * 100, 1) if budget else 0,
        "message_count": msg_count,
        "needs_compaction": total_tokens > budget,
        "compactable_tokens": max(0, total_tokens - 1500),
        "breakdown": breakdown,
    }
