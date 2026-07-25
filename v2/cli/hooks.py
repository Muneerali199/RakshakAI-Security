"""Hook System — lifecycle events for automation.
Like Claude Code's hooks system with pre/post event chains."""
from __future__ import annotations
import os
import subprocess
import json
import time
from pathlib import Path
from typing import Callable, Any, Optional
from dataclasses import dataclass, field
from enum import Enum


class HookEvent(Enum):
    PRE_TOOL = "pre_tool"
    POST_TOOL = "post_tool"
    PRE_COMMIT = "pre_commit"
    POST_COMMIT = "post_commit"
    PRE_SCAN = "pre_scan"
    POST_SCAN = "post_scan"
    SESSION_START = "session_start"
    SESSION_END = "session_end"
    PRE_MODEL = "pre_model"
    POST_MODEL = "post_model"
    ON_ERROR = "on_error"
    ON_COMPACT = "on_compact"


@dataclass
class Hook:
    event: HookEvent
    name: str
    handler: Optional[Callable] = None
    command: Optional[str] = None
    timeout: int = 30
    enabled: bool = True
    metadata: dict[str, Any] = field(default_factory=dict)


class HookRegistry:
    """Central hook registry — tools and commands can register listeners."""

    def __init__(self):
        self._hooks: dict[HookEvent, list[Hook]] = {event: [] for event in HookEvent}

    def register(self, hook: Hook):
        if hook.event not in HookEvent:
            raise ValueError(f"Unknown event: {hook.event}")
        self._hooks[hook.event].append(hook)

    def unregister(self, event: HookEvent, name: str):
        self._hooks[event] = [h for h in self._hooks[event] if h.name != name]

    def trigger(self, event: HookEvent, context: Optional[dict] = None) -> list[dict]:
        results = []
        for hook in self._hooks[event]:
            if not hook.enabled:
                continue
            result = {"hook": hook.name, "event": event.value, "success": True}
            t0 = time.time()
            try:
                if hook.handler:
                    hook_result = hook.handler(context or {})
                    if hook_result is not None:
                        result["result"] = hook_result
                elif hook.command:
                    r = subprocess.run(
                        hook.command,
                        shell=True,
                        capture_output=True,
                        text=True,
                        timeout=hook.timeout,
                    )
                    result["stdout"] = r.stdout[:500]
                    result["stderr"] = r.stderr[:200]
                    result["exit_code"] = r.returncode
                    result["success"] = r.returncode == 0
            except subprocess.TimeoutExpired:
                result["success"] = False
                result["error"] = f"Timeout ({hook.timeout}s)"
            except Exception as e:
                result["success"] = False
                result["error"] = str(e)
            result["duration_ms"] = int((time.time() - t0) * 1000)
            results.append(result)
        return results

    def list_hooks(self, event: Optional[HookEvent] = None) -> list[dict]:
        if event:
            return [
                {"event": e.value, "name": h.name, "enabled": h.enabled}
                for e in [event]
                for h in self._hooks[e]
            ]
        return [
            {"event": e.value, "name": h.name, "enabled": h.enabled}
            for e, hooks in self._hooks.items()
            for h in hooks
        ]

    def load_from_file(self, path: Optional[str] = None):
        """Load hooks from a JSON config file."""
        p = Path(path or ".rakshakai/hooks.json")
        if not p.exists():
            return
        try:
            data = json.loads(p.read_text())
            for event_name, hooks_list in data.items():
                try:
                    event = HookEvent(event_name)
                except ValueError:
                    continue
                for h in hooks_list:
                    self.register(Hook(
                        event=event,
                        name=h.get("name", f"{event_name}_{len(self._hooks[event])}"),
                        command=h.get("command"),
                        timeout=h.get("timeout", 30),
                        enabled=h.get("enabled", True),
                    ))
        except (json.JSONDecodeError, OSError):
            pass


hooks = HookRegistry()
