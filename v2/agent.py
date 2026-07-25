"""Fast autonomous agent — cached prompts, robust parsing, streaming, retry."""
from __future__ import annotations
import json, re, time, hashlib
from typing import Optional, Callable, Any
from dataclasses import dataclass, field
from enum import Enum

from v2.cli.llm import registry, stream_chat, chat_sync
from v2.cli.compactor import should_compact, compact_conversation, estimate_tokens
from v2.cli.cost_tracker import track_usage
from v2.cli.hooks import hooks, Hook, HookEvent
from v2.cli.system_prompt import build_system_prompt


class AgentMode(Enum):
    AUTONOMOUS = "autonomous"
    INTERACTIVE = "interactive"
    PASSIVE = "passive"


TOOL_SCHEMAS = {
    "file_ops": {
        "desc": "Read, write, list, and search files in the codebase.",
        "actions": {
            "read_file": {"path": "str: file path"},
            "write_file": {"path": "str: file path", "content": "str: content to write"},
            "list_files": {"directory": "str: dir path", "pattern": "str: glob (default '*')"},
            "search_in_files": {"directory": "str", "pattern": "str: regex", "file_pattern": "str: glob (default '*.py')"},
        },
    },
    "shell": {
        "desc": "Execute shell commands (git, npm, python, ls, cat, etc.).",
        "actions": {
            "execute": {"command": "str: shell command", "timeout": "int: seconds (default 30)", "cwd": "str: working dir (optional)"},
        },
    },
    "web_search": {
        "desc": "Search the web via DuckDuckGo.",
        "actions": {
            "search": {"query": "str: search query", "limit": "int: max results (default 5)"},
        },
    },
    "http": {
        "desc": "Make HTTP requests to APIs.",
        "actions": {
            "request": {"method": "str: GET/POST/PUT/DELETE", "url": "str: full URL", "headers": "dict (optional)", "data": "dict (optional)", "timeout": "int (default 30)"},
        },
    },
    "github": {
        "desc": "Search repos, get repo info, list issues.",
        "actions": {
            "search_repos": {"q": "str: search query", "limit": "int (default 10)"},
            "get_repo": {"owner": "str", "repo": "str"},
            "list_issues": {"owner": "str", "repo": "str", "state": "str: open/closed/all"},
        },
    },
}


@dataclass
class AgentAction:
    tool: str
    action: str
    params: dict[str, Any]
    reasoning: str


@dataclass
class AgentObservation:
    success: bool
    result: Any
    error: Optional[str] = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class AgentThought:
    step: int
    thought: str
    action: Optional[AgentAction] = None
    observation: Optional[AgentObservation] = None


class ReActAgent:
    """Fast ReAct agent with cached prompts, robust parsing, streaming."""

    def __init__(
        self,
        mode: AgentMode = AgentMode.INTERACTIVE,
        max_iterations: int = 15,
        tools: Optional[dict[str, Callable]] = None,
        model: str = "deepseek",
        max_retries: int = 2,
        context_budget: int = 8000,
    ):
        self.mode = mode
        self.max_iterations = max_iterations
        self.tools = tools or {}
        self.model = model
        self.max_retries = max_retries
        self.context_budget = context_budget
        self.thought_chain: list[AgentThought] = []
        self.context: dict[str, Any] = {}
        self.conversation: list[dict] = []
        self._prompt_cache: dict[str, str] = {}
        self._tools_schema = self._build_tools_schema()

    def _build_tools_schema(self) -> str:
        if not self.tools:
            return ""
        parts = ["Available tools:"]
        for name, obj in self.tools.items():
            schema = TOOL_SCHEMAS.get(name)
            if schema:
                parts.append(f"\n  {name}: {schema['desc']}")
                for action, params in schema["actions"].items():
                    param_str = ", ".join(f"{k}={v}" for k, v in params.items())
                    parts.append(f"    -> {action}({param_str})")
            else:
                methods = [m for m in dir(obj) if not m.startswith('_') and callable(getattr(obj, m))]
                parts.append(f"\n  {name}: {', '.join(methods)}")
        parts.append("\n\nRespond: ACTION[tool:action](key=value, ...) or DONE")
        return "\n".join(parts)

    def _build_system(self, task: str, step: int, cwd: str) -> str:
        cache_key = f"{cwd}:{step}:{self.model}"
        if cache_key in self._prompt_cache:
            return self._prompt_cache[cache_key]
        history = self._format_history()
        system = build_system_prompt(
            cwd=cwd, include_git=True, include_rakshakai_md=True, include_agents_md=True,
            extra_context=f"""Task: {task[:300]}
Step {step}/{self.max_iterations}
{history}

{self._tools_schema}""",
        )
        self._prompt_cache[cache_key] = system
        if len(self._prompt_cache) > 10:
            self._prompt_cache.clear()
        return system

    def think(
        self,
        task: str,
        context: Optional[dict] = None,
        on_token: Optional[Callable[[str], None]] = None,
    ) -> AgentThought:
        step = len(self.thought_chain) + 1
        cwd = context.get("cwd", ".") if context else "."
        system = self._build_system(task, step, cwd)

        messages = [{"role": "system", "content": system}]
        for msg in self.conversation[-6:]:
            messages.append(msg)

        t0 = time.time()
        cfg = registry.get(self.model)
        if on_token and cfg.supports_streaming:
            thought_text = stream_chat(messages, cfg, on_token=on_token)
        else:
            thought_text = chat_sync(messages, cfg)
        duration = int((time.time() - t0) * 1000)

        track_usage(self.model, input_tokens=estimate_tokens(system), duration_ms=duration)
        action = self._parse_action(thought_text)

        return AgentThought(step=step, thought=thought_text, action=action)

    def act(self, action: AgentAction) -> AgentObservation:
        hooks.trigger(HookEvent.PRE_TOOL, {"tool": action.tool, "action": action.action, "params": action.params})
        if action.tool not in self.tools:
            return AgentObservation(success=False, error=f"Tool '{action.tool}' unavailable. Available: {', '.join(self.tools)}")
        last_error = None
        for attempt in range(self.max_retries):
            try:
                tool_obj = self.tools[action.tool]
                method = getattr(tool_obj, action.action, None)
                if method is None:
                    return AgentObservation(success=False, error=f"Action '{action.action}' not found on tool '{action.tool}'")
                result = method(**action.params)
                obs = AgentObservation(success=True, result=result, metadata={"tool": action.tool, "action": action.action, "attempt": attempt + 1})
                hooks.trigger(HookEvent.POST_TOOL, {"tool": action.tool, "observation": obs})
                return obs
            except TypeError as e:
                last_error = AgentObservation(success=False, error=f"Bad params for {action.action}: {e}")
            except Exception as e:
                last_error = AgentObservation(success=False, error=str(e))
                if attempt < self.max_retries - 1:
                    time.sleep(1)
        return last_error

    def run(
        self,
        task: str,
        context: Optional[dict] = None,
        on_token: Optional[Callable[[str], None]] = None,
    ) -> dict:
        self.thought_chain = []
        self.context = context or {}
        self.conversation = [{"role": "user", "content": task}]
        self._prompt_cache.clear()
        hooks.trigger(HookEvent.SESSION_START, {"task": task, "model": self.model})

        for i in range(self.max_iterations):
            if should_compact(self.conversation, self.context_budget):
                self.conversation = compact_conversation(self.conversation, model=self.model, target_tokens=self.context_budget // 2)
                self._prompt_cache.clear()
                hooks.trigger(HookEvent.ON_COMPACT, {"messages": len(self.conversation)})

            thought = self.think(task, self.context, on_token=on_token)
            self.thought_chain.append(thought)

            if self._is_complete(thought):
                hooks.trigger(HookEvent.SESSION_END, {"success": True, "steps": i + 1})
                return self._build_result(success=True)

            if not thought.action:
                if i < self.max_iterations - 1:
                    retry_msg = "Use ACTION[tool:action](key=value, ...) format. Respond with a tool call."
                    self.conversation.append({"role": "user", "content": retry_msg})
                    continue
                hooks.trigger(HookEvent.SESSION_END, {"success": False, "error": "No action", "steps": i + 1})
                return self._build_result(success=False, error="Agent could not determine next action")

            if self.mode == AgentMode.INTERACTIVE:
                if not self._get_user_permission(thought):
                    hooks.trigger(HookEvent.SESSION_END, {"success": False, "error": "User cancelled", "steps": i + 1})
                    return self._build_result(success=False, error="User cancelled")

            if self.mode != AgentMode.PASSIVE:
                observation = self.act(thought.action)
                thought.observation = observation
                if observation.success:
                    result_text = str(observation.result)[:500]
                else:
                    result_text = f"ERROR: {observation.error}"
                self.conversation.append({"role": "assistant", "content": thought.thought[:300]})
                self.conversation.append({"role": "system", "content": f"Result: {result_text}"})

                # Tool result may have changed project state — clear prompt cache
                self._prompt_cache.clear()

        hooks.trigger(HookEvent.SESSION_END, {"success": False, "error": "Max iterations", "steps": self.max_iterations})
        return self._build_result(success=False, error=f"Max iterations ({self.max_iterations}) reached")

    def _parse_action(self, thought: str) -> Optional[AgentAction]:
        pattern = r'ACTION\[(\w+):(\w+)\]\(([\s\S]*?)\)\s*(?:\n|$)'
        match = re.search(pattern, thought)
        if not match:
            pattern2 = r'ACTION\[(\w+):(\w+)\]\(([\s\S]*?)\)\s*$'
            match = re.search(pattern2, thought)
        if not match:
            return None
        tool, action_name, params_str = match.groups()
        params = self._parse_params(params_str.strip())
        return AgentAction(tool=tool, action=action_name, params=params, reasoning=thought)

    def _parse_params(self, s: str) -> dict[str, Any]:
        if not s:
            return {}
        try:
            data = json.loads(s)
            if isinstance(data, dict):
                return data
        except (json.JSONDecodeError, ValueError):
            pass
        params = {}
        parts = re.split(r',(?=(?:[^"\']*["\'][^"\']*["\'])*[^"\']*$)', s)
        for part in parts:
            part = part.strip()
            if '=' not in part:
                continue
            k, v = part.split('=', 1)
            k = k.strip()
            v = v.strip().strip('"\'')
            if v.isdigit():
                v = int(v)
            elif v.replace('.', '', 1).replace('-', '', 1).isdigit():
                v = float(v)
            elif v.lower() == 'true':
                v = True
            elif v.lower() == 'false':
                v = False
            elif v.lower() == 'none':
                v = None
            params[k] = v
        return params

    def _is_complete(self, thought: AgentThought) -> bool:
        return bool(re.search(r'\bDONE\b', thought.thought.upper()))

    def _format_history(self) -> str:
        if not self.thought_chain:
            return ""
        lines = []
        for t in self.thought_chain[-5:]:
            status = ""
            if t.observation:
                status = " ✓" if t.observation.success else " ✗"
            action_str = ""
            if t.action:
                action_str = f" [{t.action.tool}.{t.action.action}]"
            lines.append(f"#{t.step}{status}{action_str}: {t.thought[:100]}")
        return "\n".join(lines)

    def _get_user_permission(self, thought: AgentThought) -> bool:
        if not thought.action:
            return True
        from rich.prompt import Confirm
        from v2.cli.display import console
        console.print(f"\n[bold cyan]Agent[/] wants to use [bold]{thought.action.tool}.{thought.action.action}[/]")
        if thought.action.params:
            console.print(f"  Params: {thought.action.params}")
        console.print(f"  Reason: {thought.action.reasoning[:200]}\n")
        return Confirm.ask("Allow?")

    def _build_result(self, success: bool, error: Optional[str] = None) -> dict:
        return {
            "success": success,
            "error": error,
            "steps": len(self.thought_chain),
            "thoughts": [
                {
                    "step": t.step,
                    "thought": t.thought,
                    "action": {"tool": t.action.tool, "action": t.action.action, "params": t.action.params} if t.action else None,
                    "success": t.observation.success if t.observation else None,
                    "result_preview": str(t.observation.result)[:100] if t.observation and t.observation.success else None,
                }
                for t in self.thought_chain
            ],
        }
