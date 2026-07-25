"""Multi-agent orchestration — decompose, parallelize, synthesize."""
from __future__ import annotations
import json, time, concurrent.futures
from dataclasses import dataclass
from typing import Any, Optional

from v2.cli.agent import ReActAgent, AgentMode
from v2.cli.llm import chat_sync, registry
from v2.cli.tools import TOOLS


@dataclass
class SubTask:
    id: str
    description: str
    tool_restrictions: str = "all"


@dataclass
class SubAgentResult:
    subtask_id: str
    success: bool
    result: dict
    steps: int
    elapsed_ms: float


class OrchestratorAgent:
    def __init__(self, model: str = "deepseek", max_subagents: int = 5, max_iterations: int = 10):
        self.model = model
        self.max_subagents = max_subagents
        self.max_iterations = max_iterations

    def decompose(self, task: str) -> list[SubTask]:
        prompt = (
            f"Break this task into at most {self.max_subagents} independent parallel subtasks.\n"
            f"Task: {task}\n\n"
            "Return JSON array: [{\"id\":\"...\", \"description\":\"...\", \"tool_restrictions\":\"all\"}]\n"
            "Tools: file_ops (read/write/search), shell, web_search, http, github.\n"
            "Return ONLY the JSON array."
        )
        cfg = registry.get(self.model)
        try:
            text = chat_sync([{"role": "user", "content": prompt}], cfg, max_tokens=2048)
            text = text.strip()
            if "```" in text:
                text = text.split("```")[1]
                if text.startswith("json"):
                    text = text[4:]
            data = json.loads(text)
            if isinstance(data, dict):
                data = [data]
            return [SubTask(**t) for t in data[:self.max_subagents]]
        except Exception:
            return [SubTask(id="main", description=task)]

    def _run_single(self, subtask: SubTask) -> SubAgentResult:
        start = time.time()
        agent = ReActAgent(
            mode=AgentMode.AUTONOMOUS,
            max_iterations=self.max_iterations,
            tools=TOOLS, model=self.model,
        )
        result = agent.run(subtask.description)
        elapsed = (time.time() - start) * 1000
        return SubAgentResult(
            subtask_id=subtask.id,
            success=result.get("success", False),
            result=result,
            steps=result.get("steps", 0),
            elapsed_ms=round(elapsed, 1),
        )

    def run(self, task: str) -> dict:
        subtasks = self.decompose(task)
        n = len(subtasks)
        results: list[SubAgentResult] = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=n) as pool:
            futures = {pool.submit(self._run_single, st): st for st in subtasks}
            for future in concurrent.futures.as_completed(futures):
                st = futures[future]
                try:
                    r = future.result(timeout=300)
                    results.append(r)
                except Exception as e:
                    results.append(SubAgentResult(subtask_id=st.id, success=False, result={"error": str(e)}, steps=0, elapsed_ms=0))
        results.sort(key=lambda r: r.subtask_id)
        thoughts = [{
            "id": r.subtask_id, "success": r.success, "steps": r.steps,
            "elapsed_ms": r.elapsed_ms, "error": r.result.get("error") if not r.success else None,
        } for r in results]
        return {
            "task": task, "subtask_count": n,
            "success_count": sum(1 for r in results if r.success),
            "fail_count": n - sum(1 for r in results if r.success),
            "total_elapsed_ms": round(sum(r.elapsed_ms for r in results), 1),
            "subtask_results": thoughts,
        }


def run_swarm(task: str, model: str = "deepseek", max_agents: int = 5) -> dict:
    return OrchestratorAgent(model=model, max_subagents=max_agents).run(task)
