"""Cost & Token Tracker — per-session and cumulative usage.
Like Claude Code's cost-tracker.ts with dollar estimates."""
from __future__ import annotations
import json
import time
import os
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional

COST_FILE = Path.home() / ".rakshak" / "costs.json"

# Cost per 1M tokens (USD) — approximate
MODEL_COSTS = {
    "groq-llama-8b": {"input": 0.18, "output": 0.18},
    "groq-llama-70b": {"input": 0.59, "output": 0.79},
    "rakshak-14b": {"input": 0.30, "output": 0.30},
    "gpt-4o-mini": {"input": 0.15, "output": 0.60},
    "deepseek": {"input": 0.14, "output": 0.28},
    "default": {"input": 0.50, "output": 1.50},
}


@dataclass
class UsageRecord:
    model: str
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0
    duration_ms: int = 0
    timestamp: float = 0.0

    @property
    def cost(self) -> float:
        rates = MODEL_COSTS.get(self.model, MODEL_COSTS["default"])
        input_cost = (self.input_tokens / 1_000_000) * rates["input"]
        output_cost = (self.output_tokens / 1_000_000) * rates["output"]
        return round(input_cost + output_cost, 6)


@dataclass
class SessionCosts:
    records: list[UsageRecord] = field(default_factory=list)
    session_start: float = 0.0

    @property
    def total_cost(self) -> float:
        return round(sum(r.cost for r in self.records), 6)

    @property
    def total_input_tokens(self) -> int:
        return sum(r.input_tokens for r in self.records)

    @property
    def total_output_tokens(self) -> int:
        return sum(r.output_tokens for r in self.records)

    @property
    def model_breakdown(self) -> dict[str, dict]:
        breakdown = {}
        for r in self.records:
            if r.model not in breakdown:
                breakdown[r.model] = {
                    "calls": 0, "input_tokens": 0, "output_tokens": 0, "cost": 0.0,
                }
            breakdown[r.model]["calls"] += 1
            breakdown[r.model]["input_tokens"] += r.input_tokens
            breakdown[r.model]["output_tokens"] += r.output_tokens
            breakdown[r.model]["cost"] += r.cost
        for v in breakdown.values():
            v["cost"] = round(v["cost"], 6)
        return breakdown

    def add_record(self, record: UsageRecord):
        self.records.append(record)
        _save_cumulative(self)


_session_costs = SessionCosts()
_all_time_costs: list[UsageRecord] = []


def _load_cumulative() -> list[dict]:
    if COST_FILE.exists():
        try:
            return json.loads(COST_FILE.read_text())
        except (json.JSONDecodeError, OSError):
            return []
    return []


def _save_cumulative(session: SessionCosts):
    COST_FILE.parent.mkdir(parents=True, exist_ok=True)
    all_records = _load_cumulative()
    for r in session.records:
        all_records.append({
            "model": r.model,
            "input_tokens": r.input_tokens,
            "output_tokens": r.output_tokens,
            "cost": r.cost,
            "timestamp": r.timestamp or time.time(),
        })
    # Keep last 10000 records
    all_records = all_records[-10000:]
    COST_FILE.write_text(json.dumps(all_records, indent=2))


def track_usage(
    model: str,
    input_tokens: int = 0,
    output_tokens: int = 0,
    duration_ms: int = 0,
):
    """Track a single API call's usage."""
    record = UsageRecord(
        model=model,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        duration_ms=duration_ms,
        timestamp=time.time(),
    )
    _session_costs.add_record(record)


def get_session_costs() -> SessionCosts:
    return _session_costs


def get_cumulative_stats() -> dict:
    records = _load_cumulative()
    if not records:
        return {"total_calls": 0, "total_cost": 0, "by_model": {}}

    total_cost = sum(r.get("cost", 0) for r in records)
    by_model = {}
    for r in records:
        m = r.get("model", "unknown")
        if m not in by_model:
            by_model[m] = {"calls": 0, "cost": 0.0}
        by_model[m]["calls"] += 1
        by_model[m]["cost"] += r.get("cost", 0)

    return {
        "total_calls": len(records),
        "total_cost": round(total_cost, 4),
        "by_model": {k: {"calls": v["calls"], "cost": round(v["cost"], 4)} for k, v in by_model.items()},
    }


def reset_session():
    global _session_costs
    _session_costs = SessionCosts()
