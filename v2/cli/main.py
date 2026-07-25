#!/usr/bin/env python3
"""RakshakAI v3 — Multi-Model Security CLI."""
from __future__ import annotations
import os, sys, json, time, hashlib, threading, re, shutil, subprocess
from pathlib import Path
from datetime import datetime

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from v2.cli.llm import registry, parallel_chat, chat_sync, stream_chat, chat_with_tools
from v2.cli.display import console, show_banner, show_status, show_error, show_success
from v2.cli.display import Markdown
from v2.cli.display import show_vuln_table, show_parallel_results, show_help, show_stats_table
from v2.cli.display import show_scan_tree, show_diff_view, show_code_comparison
from v2.cli.display import show_model_list, show_history_results, show_session_summary
from v2.cli.display import MODEL_LABELS, MODEL_COLORS, create_scan_progress, interactive_model_selector
from v2.cli.display import show_tool_call, show_tool_result, show_thought_timing, show_tool_error
from v2.cli.display import show_swarm_results
from v2.cli.prompts import get_explain_messages, get_fix_messages, get_system, get_scan_system
from v2.cli.auth import auth_state, login_flow, fetch_user_info, AUTH_SERVER_HOST
import v2.cli.memory as memory
from v2.cli.project_context import build_project_context, load_rakshakai_md, find_project_root
from v2.cli.thinking import ThinkingDisplay, ThinkingPanel
from v2.cli.agentic_tools import ReadTool, EditTool, GlobTool, GrepTool, BashTool, build_openai_tools_v2, dispatch as agentic_dispatch
from v2.cli.permissions import approval, patch_tools_with_approval
from v2.cli.usage import get_usage, check_ai_scan_allowed, increment_ai_scan, format_usage_bar
from v2.cli.cost_tracker import get_session_costs, get_cumulative_stats, track_usage
from v2.cli.compactor import should_compact, compact_conversation, get_context_report
from v2.cli.hooks import hooks, Hook, HookEvent
from v2.cli.git_workflow import (get_status, stage_all, commit, diff,
                                 suggest_commit_message, create_pr, get_log, get_current_diff_for_commit)
from v2.cli.system_prompt import build_system_prompt
patch_tools_with_approval()

HISTORY_FILE = os.path.expanduser("~/.rakshak_history")


def _chat_and_show(model: str, messages: list[dict]) -> str:
    """Send messages, render response with live streaming."""
    from v2.cli.llm import stream_chat
    from v2.cli.display import StreamingPanel
    
    cfg = registry.get(model)
    
    if cfg.supports_streaming:
        # Use streaming for better UX
        with StreamingPanel() as panel:
            response = stream_chat(messages, cfg, on_token=panel.update)
        return response
    else:
        # Fallback to non-streaming
        text = chat_sync(messages, cfg)
        content = text.strip()
        if content:
            console.print(Markdown(content))
        return text


class ModelCompleter:
    COMMANDS = [
        "/help", "/model", "/models", "/parallel",
        "/scan", "/scan-project", "/explain", "/fix",
        "/batch", "/watch", "/watch-stop",
        "/diff", "/precommit", "/test", "/share",
        "/index", "/search",
        "/history", "/log", "/stats", "/dashboard",
        "/confirm", "/dismiss", "/cost",
        "/clear", "/session", "/exit",
        "/agent", "/swarm", "/skills",
        "/login", "/logout", "/whoami",
        "/def", "/refs", "/hover", "/rename",
        "/context", "/resume", "/fork", "/rakshakai.md",
        "/permissions", "/plan",
        "/usage", "/pricing",
        "/init", "/doctor", "/compact",
        "/commit", "/review", "/pr",
    ]

    def get_completions(self, document, complete_event):
        from prompt_toolkit.completion import Completion
        text = document.text_before_cursor
        
        if text.startswith("/") and " " not in text:
            for cmd in self.COMMANDS:
                if cmd.startswith(text):
                    yield Completion(cmd, start_position=-len(text))
        
        elif text.startswith("/model ") or text.startswith("/parallel ") or text.startswith("/agent "):
            prefix = text.split()[-1]
            for name in registry.list():
                if name.startswith(prefix):
                    yield Completion(name, start_position=-len(prefix))
        
        elif any(text.startswith(cmd + " ") for cmd in ["/scan", "/explain", "/log", "/batch", "/watch"]):
            from pathlib import Path
            parts = text.split(maxsplit=1)
            if len(parts) < 2:
                return
            path_prefix = parts[1]
            try:
                if path_prefix:
                    base_path = Path(path_prefix).parent if "/" in path_prefix else Path(".")
                    name_prefix = Path(path_prefix).name
                else:
                    base_path = Path(".")
                    name_prefix = ""
                if base_path.exists() and base_path.is_dir():
                    for item in sorted(base_path.iterdir()):
                        item_name = item.name
                        if item_name.startswith(".") and not name_prefix.startswith("."):
                            continue
                        if item_name.startswith(name_prefix):
                            display_path = str(item.relative_to(".")) if item.is_relative_to(".") else str(item)
                            if item.is_dir():
                                display_path += "/"
                            yield Completion(display_path, start_position=-len(path_prefix), display=item_name + ("/" if item.is_dir() else ""))
            except (OSError, ValueError):
                pass

    async def get_completions_async(self, document, complete_event):
        for c in self.get_completions(document, complete_event):
            yield c



class RakshakREPL:
    def __init__(self):
        self.messages: list[dict] = []
        self.current_dir = os.getcwd()
        self.session_count = 0
        if not registry.active:
            registry.set_active(registry.auto_select())
        self.start_time = time.time()
        self._session_id = memory.start_session(registry.active, self.current_dir)
        self.last_analysis_id: int | None = None
        
        # Lazy init heavy modules (faster startup)
        self._scanner = None
        self._watcher = None
        self._skills = None
        self._agent = None
        self._code_index = None
        self._cached_context = ""
        self._cached_context_model = ""
        self._cached_context_dir = ""

        # Track session stats
        self.files_scanned = 0
        self.vulnerabilities_found = 0
        self.models_used = set([registry.active])

    def _ensure_scanner(self):
        if self._scanner is None:
            from v2.cli.scanner import BatchScanner
            self._scanner = BatchScanner(max_workers=4)
        return self._scanner

    def _ensure_watcher(self):
        if self._watcher is None:
            from v2.cli.watcher import FileWatcher
            self._watcher = FileWatcher(model=registry.active)
        return self._watcher

    def _ensure_agent(self):
        if self._agent is None:
            from v2.cli.tools import TOOLS
            from v2.cli.skills import SkillRegistry
            from v2.cli.agent import ReActAgent, AgentMode
            self._skills = SkillRegistry()
            self._agent = ReActAgent(mode=AgentMode.INTERACTIVE, tools=TOOLS, model=registry.active)
        return self._agent
    
    def _ensure_code_index(self):
        if self._code_index is None:
            from v2.cli.code_index import CodebaseIndex
            self._code_index = CodebaseIndex()
            self._code_index.load()  # Try to load existing index
        return self._code_index

    def _on_watch_notify(self, alert: dict):
        sev = alert.get("severity", "").lower()
        c = "red" if sev in ("critical", "high") else "yellow"
        show_status(f"watch: {os.path.basename(alert['file'])} ({alert['cwe']} [{sev}])", c)

    def _read_file(self, path: str) -> str | None:
        p = Path(path)
        if not p.exists():
            p = Path(self.current_dir) / path
        if p.exists():
            return p.read_text(encoding="utf-8", errors="replace")
        return None

    def _cache_key(self, q: str, m: str) -> str:
        return hashlib.md5(f"{m}:{q}".encode()).hexdigest()[:16]

    def _build_project_context(self) -> str:
        """Build project context string for the LLM — cached until model/dir changes."""
        if (self._cached_context
                and self._cached_context_model == registry.active
                and self._cached_context_dir == self.current_dir):
            return self._cached_context

        from v2.cli.scanner import collect_source_files
        cwd = self.current_dir

        # Use the enhanced project context builder with RAKSHAKAI.md
        try:
            ctx = build_project_context(cwd)
        except Exception:
            ctx = f"Working directory: {cwd}"

        parts = [ctx] if ctx else [f"Working directory: {cwd}"]
        parts.append("")

        # File stats
        try:
            files = collect_source_files(cwd, max_files=200)
            if files:
                exts = {}
                for f in files:
                    ext = Path(f).suffix
                    exts[ext] = exts.get(ext, 0) + 1
                lang_summary = ", ".join(f"{ext}: {n}" for ext, n in sorted(exts.items(), key=lambda x: -x[1])[:8])
                parts.append(f"Source files: {len(files)} ({lang_summary})")
        except Exception:
            pass

        self._cached_context = "\n".join(parts)
        self._cached_context_model = registry.active
        self._cached_context_dir = self.current_dir
        return self._cached_context

    # ── command handlers ──────────────────────────────────

    def _handle_scan(self, args: str) -> bool:
        if not args.strip():
            return show_error("Usage: /scan <file>")
        code = self._read_file(args.strip())
        if code is None:
            return show_error(f"File not found: {args.strip()}")

        # Check AI scan limit for free plan
        if auth_state.plan != "pro":
            allowed, msg = check_ai_scan_allowed()
            if not allowed:
                show_error(f"Daily AI scan limit reached. Upgrade: /pricing")
                console.print(f"[dim]{msg}[/]")
                return False
            show_status(msg, "yellow")

        t0 = time.time()
        with console.status(f"[cyan]Scanning {args.strip()}...", spinner="dots"):
            from v2.cli.scanner import scan_code
            increment_ai_scan()
            result = scan_code(code, language=Path(args.strip()).suffix[1:], model=registry.active)
        
        vulns = result.get("vulnerabilities", [])
        raw = result.get("_raw", "")
        
        # Update stats
        self.files_scanned += 1
        self.vulnerabilities_found += len(vulns)
        
        if vulns:
            show_vuln_table(vulns)
        
        cwe = vulns[0].get("cwe", "") if vulns else ""
        sev = vulns[0].get("severity", "") if vulns else ""
        conf = vulns[0].get("confidence", 0.0) if vulns else 0.0
        aid = memory.record_analysis(
            session_id=self._session_id,
            file_path=os.path.abspath(args.strip()),
            language=Path(args.strip()).suffix[1:],
            cwe=cwe, severity=sev, model=registry.active,
            query_hash=self._cache_key(code, registry.active),
            query=f"scan {args.strip()}", response=raw,
            duration_ms=int((time.time() - t0) * 1000),
        )
        self.last_analysis_id = aid
        
        if vulns:
            console.print(f"\n[dim]Analysis #{aid} • /confirm #{aid} to mark as true positive • /dismiss #{aid} to mark as false positive[/]")
        else:
            console.print(f"\n[dim]Analysis #{aid} • Completed in {(time.time() - t0):.2f}s[/]")
        
        return True

    def _check_ai_limit(self) -> bool:
        """Common AI limit check. Returns True if allowed."""
        if auth_state.plan != "pro":
            allowed, msg = check_ai_scan_allowed()
            if not allowed:
                show_error("Daily AI scan limit reached. See /pricing to upgrade.")
                return False
            show_status(msg, "yellow")
        return True

    def _handle_explain(self, args: str) -> bool:
        if not args.strip():
            return show_error("Usage: /explain <file>")
        code = self._read_file(args.strip())
        if code is None:
            return show_error(f"File not found: {args.strip()}")
        if not self._check_ai_limit():
            return False
        increment_ai_scan()
        show_status(f"Explaining {args.strip()} ...")
        _chat_and_show(registry.active, get_explain_messages(code))
        return True

    def _handle_fix(self, args: str) -> bool:
        if not args.strip():
            return show_error("Usage: /fix <description> [--test]")
        
        # Check for --test flag
        run_tests = "--test" in args
        desc = args.replace("--test", "").strip()
        
        if not self._check_ai_limit():
            return False
        increment_ai_scan()
        show_status(f"Generating fix for: {desc}")
        _chat_and_show(registry.active, get_fix_messages(desc))
        
        # Auto-run tests if requested
        if run_tests:
            return self._handle_test("")
        
        return True
    
    def _handle_test(self, args: str) -> bool:
        """Auto-detect and run tests."""
        from v2.cli.test_runner import TestRunner
        from rich.panel import Panel
        
        show_status("Detecting test framework...", "cyan")
        runner = TestRunner(self.current_dir)
        framework = runner.detect_framework()
        
        if framework.value == "unknown":
            return show_error("No test framework detected. Supported: pytest, jest, cargo, go test, maven, dotnet")
        
        show_status(f"Running {framework.value} tests...", "cyan")
        
        # Parse file filter from args
        file_filter = args.strip() if args.strip() else None
        
        result = runner.run_tests(file_filter=file_filter, verbose=False)
        
        # Display results
        status_icon = "✓" if result.passed else "✗"
        status_color = "green" if result.passed else "red"
        
        summary = (
            f"[{status_color}]{status_icon} {result.tests_run} tests run[/]\n"
            f"[green]✓ {result.tests_passed} passed[/]\n"
            f"[red]✗ {result.tests_failed} failed[/]\n"
            f"[dim]Duration: {result.duration_seconds}s[/]"
        )
        
        console.print(Panel(
            summary,
            title=f"[bold]{framework.value} Test Results[/]",
            border_style=status_color,
            padding=(1, 2),
        ))
        
        # Show output if tests failed
        if not result.passed and result.output:
            from rich.syntax import Syntax
            console.print("\n[bold red]Test Output:[/]")
            console.print(result.output[:2000])  # Truncate long output
            if len(result.output) > 2000:
                console.print("[dim]... output truncated[/]")
        
        return True

    def _handle_scan_project(self, args: str) -> bool:
        """Scan entire project and chat about results."""
        from v2.cli.scanner import collect_source_files
        from v2.cli.prompts import get_project_scan_prompt

        if not self._check_ai_limit():
            return False

        target_dir = args.strip() or self.current_dir
        if not os.path.isdir(target_dir):
            return show_error(f"Directory not found: {target_dir}")

        with console.status("[cyan]Collecting source files...", spinner="dots"):
            files = collect_source_files(target_dir)

        if not files:
            return show_status("No source files found.", "yellow")

        # Scan all files
        from v2.cli.scanner import BatchScanner
        scanner = BatchScanner(max_workers=4)
        results = scanner.scan_files(files, model=registry.active)

        increment_ai_scan()
        self.files_scanned += len(files)
        vuln_count = sum(1 for r in results if r.cwe)
        self.vulnerabilities_found += vuln_count

        smry = scanner.summary()
        summary_line = (
            f"Scanned {smry['scanned']} files • "
            f"{smry['vulnerable']} vulnerable • "
            f"Critical: {smry['critical']} • "
            f"High: {smry['high']} • "
            f"Medium: {smry.get('medium', 0)}"
        )
        show_status(summary_line)

        show_scan_tree([r.to_dict() for r in results])

        # Ask AI to analyze results — feed compact vuln details
        if vuln_count > 0:
            # Build compact vulnerability summary for AI (token-efficient)
            vuln_lines = []
            for r in results[:25]:  # max 25 vulns to keep tokens low
                if r.cwe:
                    fname = Path(r.file).name
                    vuln_lines.append(f"  • {r.cwe} [{r.severity}] — {fname}")
            vuln_block = "\n".join(vuln_lines)
            if len(results) > 25:
                vuln_block += f"\n  ... and {len(results) - 25} more"

            user_msg = (
                f"Scanned {smry['scanned']} files. Found {vuln_count} vulnerabilities:\n"
                f"{vuln_block}\n\n"
                f"Which should I fix first, prioritized by risk?"
            )
            self.messages.append({"role": "user", "content": user_msg})
            response = self._chat_with_react(user_msg, self._build_project_context())

        return True

    def _handle_batch(self, args: str) -> bool:
        from v2.cli.scanner import collect_source_files
        target_dir = args.strip() or "."
        if not os.path.isdir(target_dir):
            return show_error(f"Directory not found: {target_dir}")
        
        with console.status("[cyan]Collecting source files...", spinner="dots"):
            files = collect_source_files(target_dir)
        
        if not files:
            return show_status("No source files found.", "yellow")
        
        # Use rich progress bar
        progress = create_scan_progress()
        results = []
        
        with progress:
            task = progress.add_task(
                "Scanning files",
                total=len(files),
                status=f"0/{len(files)} files"
            )
            
            def on_progress(completed_count):
                progress.update(task, completed=completed_count, status=f"{completed_count}/{len(files)} files")
            
            scanner = self._ensure_scanner()
            scanner.on_progress(on_progress)
            results = scanner.scan_files(files, model=registry.active)
        
        # Update stats
        self.files_scanned += len(files)
        vuln_count = sum(1 for r in results if r.cwe)
        self.vulnerabilities_found += vuln_count
        
        smry = scanner.summary()
        show_status(
            f"Scanned: {smry['scanned']} • Vulnerable: {smry['vulnerable']} • "
            f"Critical: {smry['critical']} • High: {smry['high']} • Errors: {smry['errors']}"
        )
        show_scan_tree([r.to_dict() for r in results])
        return True

    def _handle_watch(self, args: str) -> bool:
        target_dir = args.strip() or "."
        if self._ensure_watcher().is_running:
            return show_status("Watcher already running")
        if not os.path.isdir(target_dir):
            return show_error(f"Directory not found: {target_dir}")
        self._ensure_watcher().on_notify(self._on_watch_notify)
        if self._ensure_watcher().start(os.path.abspath(target_dir)):
            show_status(f"Watching {os.path.abspath(target_dir)}  |  /watch-stop to stop")
        else:
            show_error("Failed to start watcher")
        return True

    def _handle_watch_stop(self, args: str) -> bool:
        if not self._ensure_watcher().is_running:
            return show_status("No watcher running")
        c = self._ensure_watcher().vulnerable_count
        self._ensure_watcher().stop()
        show_status(f"Watcher stopped. {c} vulnerabilities found.")
        return True

    def _handle_diff(self, args: str) -> bool:
        from v2.cli.git_scanner import get_repo, get_diff_files, scan_diff_files
        repo = get_repo(".")
        if not repo:
            return show_error("Not a git repository")
        files = get_diff_files(repo)
        if not files:
            return show_status("No unstaged changes.")
        show_status(f"Scanning {len(files)} changed file(s)...")
        results = scan_diff_files(files, model=registry.active)
        show_status(f"{sum(1 for r in results if r.get('cwe'))} vulns in changes")
        show_scan_tree(results)
        return True

    def _handle_precommit(self, args: str) -> bool:
        from v2.cli.git_scanner import install_precommit_hook, uninstall_precommit_hook, is_hook_installed
        a = args.strip().lower()
        if a == "install":
            show_success("Hook installed") if install_precommit_hook(".") else show_error("Not a git repo")
        elif a == "uninstall":
            show_success("Hook removed") if uninstall_precommit_hook(".") else show_error("Hook not found")
        elif a == "status":
            show_status("Installed" if is_hook_installed(".") else "Not installed")
        else:
            show_error("Usage: /precommit [install|uninstall|status]")
        return True

    def _handle_history(self, args: str) -> bool:
        if not args.strip():
            return show_error("Usage: /history <search term>")
        rows = memory.search_analyses(args.strip(), limit=20)
        show_history_results(rows, args.strip())
        return True

    def _handle_log(self, args: str) -> bool:
        if not args.strip():
            return show_error("Usage: /log <file>")
        p = Path(args.strip())
        if not p.exists():
            p = Path(self.current_dir) / args.strip()
        if not p.exists():
            return show_error(f"File not found: {args.strip()}")
        rows = memory.get_file_history(str(p.resolve()))
        if not rows:
            return show_status(f"No history for {args.strip()}")
        for r in rows:
            ts = (r.get("timestamp") or "")[11:19]
            cwe = r.get("cwe", "") or ""
            sev = r.get("severity", "") or ""
            console.print(f"  [dim]{ts}[/]  {cwe}  {sev}")
        return True

    def _handle_stats(self, args: str) -> bool:
        """Display statistics - use /dashboard for interactive view."""
        arg = args.strip().lower()
        stats = memory.get_stats()
        
        if arg == "dashboard" or arg == "dash":
            # Show interactive dashboard with visualizations
            show_interactive_dashboard(stats)
        else:
            # Show traditional stats table
            show_stats_table(stats)
            console.print("\n[dim]💡 Tip: Use /stats dashboard for interactive visualizations[/]\n")
        
        return True

    def _handle_parallel(self, args: str) -> bool:
        model_names = [p for p in args.strip().split() if p in registry.models] or registry.list()
        if not model_names:
            return show_error(f"Available: {', '.join(registry.list())}")
        
        # Update models used
        self.models_used.update(model_names)
        
        last = next((m["content"] for m in reversed(self.messages) if m["role"] == "user"), None)
        if not last:
            return show_error("No previous query.")
        
        with console.status(f"[cyan]Running {len(model_names)} models in parallel...", spinner="dots"):
            results = parallel_chat([{"role": "user", "content": last}], model_names)
        
        show_parallel_results(results)
        return True

    def _handle_model(self, args: str) -> bool:
        name = args.strip()
        if not name:
            # Show interactive model selector
            selected = interactive_model_selector(registry.models, registry.active)
            if selected and selected != registry.active:
                if registry.set_active(selected):
                    self.models_used.add(selected)
                    show_success(f"Switched to {MODEL_LABELS.get(selected, selected)}")
                    return True
            elif not selected:
                # User cancelled, show current model list
                show_model_list(registry.models, registry.active)
            return True
        
        if registry.set_active(name):
            self.models_used.add(name)
            self._ensure_agent().model = name
            show_success(f"Switched to {MODEL_LABELS.get(name, name)}")
            return True
        else:
            show_error(f"Model '{name}' not found")
            show_model_list(registry.models, registry.active)
            return False

    def _handle_models(self, args: str) -> bool:
        show_model_list(registry.models, registry.active)
        return True

    def _handle_confirm(self, args: str) -> bool:
        aid = args.strip().lstrip("#")
        if not aid.isdigit():
            if self.last_analysis_id:
                aid = str(self.last_analysis_id)
            else:
                return show_error("Usage: /confirm <analysis_id>")
        note = ""
        if " " in aid:
            parts = aid.split(maxsplit=1)
            aid, note = parts[0], parts[1]
        memory.confirm_finding(int(aid), note)
        show_success(f"#{aid} confirmed as true positive")
        return True

    def _handle_dismiss(self, args: str) -> bool:
        aid = args.strip().lstrip("#")
        if not aid.isdigit():
            if self.last_analysis_id:
                aid = str(self.last_analysis_id)
            else:
                return show_error("Usage: /dismiss <analysis_id>")
        note = ""
        if " " in aid:
            parts = aid.split(maxsplit=1)
            aid, note = parts[0], parts[1]
        memory.dismiss_finding(int(aid), note)
        show_success(f"#{aid} dismissed as false positive")
        return True

    def _handle_cost(self, args: str) -> bool:
        from rich.table import Table
        from rich import box
        stats = memory.get_stats()
        model_usage = stats.get("model_usage", [])
        if not model_usage:
            return show_status("No analyses yet.")
        table = Table(box=box.SIMPLE, padding=(0, 2), show_header=True)
        table.add_column("model", style="cyan")
        table.add_column("count", justify="right")
        table.add_column("total_s", justify="right")
        table.add_column("avg_ms", justify="right")
        for m in model_usage:
            table.add_row(
                m["model"],
                str(m["count"]),
                f"{m['total_ms'] / 1000:.1f}",
                str(m["avg_ms"]),
            )
        console.print(table)
        fb = stats.get("precision")
        if fb is not None:
            console.print(f"[dim]  precision: {fb:.1%} ({stats['feedback_confirmed']}/{stats['feedback_total']})[/]")
        return True

    def _handle_session(self, args: str) -> bool:
        """Manage sessions: show current, list all, share, switch, save."""
        import sqlite3
        from rich.table import Table
        from rich.panel import Panel
        from rich import box

        arg = args.strip().lower()
        elapsed = time.time() - self.start_time

        # ── /session list — list all recent sessions ──
        if arg == "list" or arg == "ls":
            try:
                from v2.cli.memory import _get_db
                conn = _get_db()
                rows = conn.execute("""
                    SELECT s.id, s.started_at, s.model, s.dir,
                           COUNT(a.id) as analyses
                    FROM sessions s
                    LEFT JOIN analyses a ON a.session_id = s.id
                    GROUP BY s.id ORDER BY s.id DESC LIMIT 20
                """).fetchall()

                if not rows:
                    return show_status("No previous sessions.", "yellow")

                table = Table(box=box.ROUNDED, title="[bold]Session History[/]",
                              border_style="cyan", header_style="bold cyan")
                table.add_column("ID", style="cyan", width=6)
                table.add_column("Date", style="dim", width=16)
                table.add_column("Model", width=20)
                table.add_column("Dir", style="dim", width=30)
                table.add_column("Scans", justify="right", width=6)

                for r in rows:
                    table.add_row(
                        str(r["id"]),
                        (r["started_at"] or "")[5:19] or "?",
                        (r["model"] or "?")[:20],
                        (r["dir"] or "?")[-30:],
                        str(r["analyses"] or 0),
                    )
                console.print(table)
                console.print(f"  [dim]Use /session <id> to switch to a session[/]")
            except Exception as e:
                show_error(f"Error: {e}")
            return True

        # ── /session share — share current session ──
        if arg == "share" or arg.startswith("share "):
            from v2.cli.session_share import upload_session, save_session_local
            show_status("Uploading session...", "cyan")
            url = upload_session(self._session_id)
            if url:
                show_success(f"Session shared: {url}")
                console.print(f"  [dim]Share this URL for anyone to view the results[/]")
            else:
                show_status("Upload failed. Saving locally...", "yellow")
                fname = f"session_{self._session_id}.json"
                if save_session_local(self._session_id, fname):
                    show_success(f"Saved: {fname}")
                    console.print(f"  [dim]Share this file with your team[/]")
                else:
                    show_error("Save failed")
            return True

        # ── /session save <filename> — save to file ──
        if arg.startswith("save"):
            parts = arg.split(maxsplit=1)
            fname = parts[1] if len(parts) > 1 else f"session_{self._session_id}.json"
            with open(fname, "w") as f:
                json.dump({
                    "session_id": self._session_id,
                    "model": registry.active,
                    "dir": self.current_dir,
                    "started_at": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(self.start_time)),
                    "messages": self.messages,
                }, f, indent=2)
            show_success(f"Saved: {fname}")
            return True

        # ── /session export — export as markdown report ──
        if arg == "export":
            from v2.cli.session_share import export_for_github
            md = export_for_github(self._session_id)
            fname = f"session_{self._session_id}.md"
            with open(fname, "w") as f:
                f.write(md)
            show_success(f"Exported: {fname}")
            return True

        # ── /session <id> — switch to a session ──
        if arg.isdigit():
            session_id = int(arg)
            try:
                from v2.cli.memory import _get_db
                conn = _get_db()
                row = conn.execute("SELECT * FROM sessions WHERE id = ?", (session_id,)).fetchone()
                if row:
                    show_status(f"Switched to session {session_id} ({row['started_at']})", "green")
                    console.print(f"  [dim]Model: {row['model']} | Dir: {row['dir']}[/]")
                    console.print(f"  [dim]Start a new query to continue in this session context.[/]")
                    self._session_id = session_id
                else:
                    show_error(f"Session {session_id} not found")
            except Exception as e:
                show_error(f"Error: {e}")
            return True

        # ── default: show current session info ──
        console.print(Panel(
            f"  [cyan]Session:[/]   {self._session_id}\n"
            f"  [cyan]Model:[/]     {MODEL_LABELS.get(registry.active, registry.active)}\n"
            f"  [cyan]Dir:[/]       {self.current_dir}\n"
            f"  [cyan]Messages:[/]  {len(self.messages)}\n"
            f"  [cyan]Duration:[/]  {elapsed:.0f}s\n"
            f"  [cyan]Scanned:[/]   {self.files_scanned} files\n"
            f"  [cyan]Vulns:[/]     {self.vulnerabilities_found}",
            title="[bold]Current Session[/]",
            border_style="cyan",
        ))
        console.print(f"  [dim]Commands: /session list | /session <id> | /session share | /session save | /session export[/]")
        return True
    
    def _handle_context(self, args: str) -> bool:
        """Show context usage visualization — inspired by Claude Code's /context."""
        from rich.table import Table
        from rich.panel import Panel
        from rich import box
        import math

        context = self._build_project_context()
        msg_count = len(self.messages)
        context_tokens = len(context) // 4
        msg_tokens = sum(len(m.get("content", "")) // 4 for m in self.messages)
        total = context_tokens + msg_tokens
        budget = 8000

        table = Table(box=box.SIMPLE, padding=(0, 2))
        table.add_column("Component", style="cyan")
        table.add_column("Tokens", justify="right")
        table.add_column("Usage", ratio=1)

        for label, tokens in [
            ("Project Context (RAKSHAKAI.md)", context_tokens),
            (f"Conversation ({msg_count} messages)", msg_tokens),
            ("Available", max(0, budget - total)),
        ]:
            pct = tokens / budget if budget > 0 else 0
            bar_len = 20
            filled = max(0, min(bar_len, int(pct * bar_len)))
            bar = "█" * filled + "░" * (bar_len - filled)
            color = "green" if pct < 0.5 else "yellow" if pct < 0.8 else "red"
            table.add_row(label, str(tokens), f"[{color}]{bar}[/] [{pct*100:.0f}%]")

        console.print(Panel(table, title="[bold]Context Usage[/]", border_style="cyan"))
        console.print(f"[dim]Model: {MODEL_LABELS.get(registry.active, registry.active)}[/]")

        # Show RAKSHAKAI.md info
        root = find_project_root(self.current_dir)
        ctx_path = root / "RAKSHAKAI.md"
        if ctx_path.exists():
            console.print(f"[dim]RAKSHAKAI.md: {ctx_path}[/]")
        else:
            console.print(f"[dim]RAKSHAKAI.md: not found — create one for project preferences[/]")

        return True

    def _handle_permissions(self, args: str) -> bool:
        """Set permission mode: always_ask, accept_edits, plan, auto."""
        mode = args.strip().lower()
        if not mode:
            from rich.table import Table
            from rich import box
            table = Table(box=box.SIMPLE, padding=(0, 2))
            table.add_column("Mode", style="cyan")
            table.add_column("Description", style="dim")
            table.add_column("Active", justify="center")
            for m in approval.MODES:
                active = "✓" if m == approval.mode else ""
                desc = {
                    "always_ask": "Prompt for every file change",
                    "accept_edits": "Auto-approve edits, ask for writes",
                    "plan": "Show changes only, never write",
                    "auto": "Auto-approve all operations",
                }[m]
                table.add_row(m, desc, active)
            console.print(table)
            console.print(f"\n[dim]Usage: /permissions [{'|'.join(approval.MODES)}][/]")
            return True
        if mode in approval.MODES:
            approval.set_mode(mode)
            show_success(f"Permission mode: {mode}")
        else:
            show_error(f"Invalid mode: {mode}. Options: {', '.join(approval.MODES)}")
        return True

    def _handle_plan(self, args: str) -> bool:
        """Enter plan mode — see what changes would be made without applying them."""
        was = approval.mode
        approval.set_mode("plan")
        if args.strip():
            # Run the request in plan mode
            self.messages.append({"role": "user", "content": args.strip()})
            context = self._build_project_context()
            response = self._chat_with_react(args.strip(), context)
        else:
            show_success("Plan mode active — all changes are previewed, not applied")
            console.print(f"[dim]Use /permissions always_ask to return to normal mode[/]")
        return True

    def _handle_usage(self, args: str) -> bool:
        """Show current usage stats and plan limits."""
        from rich.table import Table
        from rich.panel import Panel
        from rich import box

        usage = get_usage()
        plan_name = auth_state.plan.capitalize() if auth_state.logged_in else "Free (not logged in)"
        plan_label = auth_state.plan if auth_state.logged_in else "free"

        # Determine if pro or free limits
        ai_limit = 5
        regex_limit = 10
        if plan_label == "pro":
            ai_limit = -1
            regex_limit = -1

        table = Table(box=box.SIMPLE, padding=(0, 2))
        table.add_column("Resource", style="cyan")
        table.add_column("Usage", ratio=1)

        for label, used, limit in [
            ("AI Scans", usage["ai_scans"]["used"], ai_limit),
            ("Regex Scans", usage["regex_scans"]["used"], regex_limit),
        ]:
            if limit == -1:
                bar = "─" * 20 + " unlimited"
            else:
                bar = format_usage_bar(used, limit)
            table.add_row(label, f"[bold]{bar}[/]")

        table.add_row("Plan", f"[bold]{plan_name}[/]")
        table.add_row("Date", f"[dim]{usage['date']}[/]")

        console.print(Panel(table, title="[bold]Usage & Limits[/]", border_style="cyan"))
        if plan_label == "free":
            console.print(f"[dim]Upgrade to Pro for unlimited scans: /pricing[/]")
        return True

    def _handle_pricing(self, args: str) -> bool:
        """Show pricing information for RakshakAI."""
        from rich.table import Table
        from rich.panel import Panel
        from rich import box
        from rich.columns import Columns

        free_features = [
            "[green]✓[/] 5 AI scans/day",
            "[green]✓[/] 10 regex scans/day",
            "[green]✓[/] Llama 3.1 8B model",
            "[green]✓[/] CLI + Web UI",
            "[dim]✗ Session sharing[/]",
            "[dim]✗ Priority support[/]",
        ]
        pro_features = [
            "[green]✓[/] Unlimited AI scans",
            "[green]✓[/] Unlimited regex scans",
            "[green]✓[/] All models (Llama 70B, RakshakAI 14B)",
            "[green]✓[/] CLI + Web UI",
            "[green]✓[/] Session sharing",
            "[green]✓[/] Priority support",
            "[green]✓[/] Agentic tools",
        ]

        free_panel = Panel(
            "\n".join(free_features),
            title="[bold]Free — $0[/]",
            border_style="dim",
            padding=(1, 2),
        )
        pro_panel = Panel(
            "\n".join(pro_features),
            title="[bold]Pro — $10/month[/]",
            border_style="cyan",
            padding=(1, 2),
        )

        console.print()
        console.print(Panel.fit(
            "[bold]▲ RakshakAI Pricing[/]\n"
            "[dim]Simple, transparent pricing. Start free, upgrade when you need more.[/]",
            border_style="cyan",
        ))
        console.print()
        console.print(Columns([free_panel, pro_panel]))
        console.print()
        if auth_state.plan == "pro":
            console.print("[green]✓ You're on the Pro plan — enjoy unlimited access![/]")
        else:
            console.print("[bold yellow]💡 Tip:[/] [cyan]Email us at rakshak@example.com to upgrade to Pro[/]")
        console.print()
        return True

    def _handle_init(self, args: str) -> bool:
        """Scaffold a new project (/init <type> <name>)."""
        from rich.panel import Panel

        parts = args.strip().split(maxsplit=1)
        if len(parts) < 2:
            console.print(Panel.fit(
                "[bold]Project Scaffolding[/]\n\n"
                "Usage: /init <type> <name>\n\n"
                "Types:\n"
                "  python       — Python package with pytest\n"
                "  node         — Node.js project with npm\n"
                "  react        — React + Vite project\n"
                "  flask        — Flask web app\n"
                "  fastapi      — FastAPI web app\n"
                "  cli          — Python CLI with click\n"
                "  security     — Security scanning tool\n"
                "  empty        — Empty directory with git",
                border_style="cyan",
            ))
            return True

        project_type, name = parts[0].lower(), parts[1]
        target = Path(self.current_dir) / name

        if target.exists():
            return show_error(f"Directory '{name}' already exists")

        show_status(f"Scaffolding {project_type} project: {name} ...", "cyan")

        try:
            target.mkdir(parents=True)

            # Common files for all projects
            (target / ".gitignore").write_text("""__pycache__/
*.py[cod]
.env
*.egg-info/
dist/
build/
node_modules/
.venv/
venv/
""")

            if project_type == "python":
                (target / "README.md").write_text(f"# {name}\n\nDescription.\n")
                (target / "pyproject.toml").write_text(f"""[build-system]
requires = ["setuptools", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name = "{name}"
version = "0.1.0"
requires-python = ">=3.10"
""")
                (target / "src" / name).mkdir(parents=True)
                (target / "src" / name / "__init__.py").write_text(f"\"\"\"{name} package.\"\"\"\n")
                (target / "tests").mkdir()
                (target / "tests" / "__init__.py").write_text("")
                (target / "tests" / f"test_{name}.py").write_text(f"\"\"\"Tests for {name}.\"\"\"\n\n\ndef test_placeholder():\n    assert True\n")
                (target / "AGENTS.md").write_text(f"# AGENTS.md — {name}\n\nAI agent instructions for this project.\n")
                (target / "RAKSHAKAI.md").write_text(f"# RAKSHAKAI.md — {name}\n\nProject context for RakshakAI.\n\n## Commands\n- Test: `pytest`\n- Lint: `ruff check .`\n")

            elif project_type == "node":
                pkg = {"name": name, "version": "0.1.0", "private": True, "scripts": {"test": "echo 'no tests'", "start": "node index.js"}}
                (target / "package.json").write_text(json.dumps(pkg, indent=2))
                (target / "index.js").write_text(f"// {name}\nconsole.log('Hello from {name}');\n")
                (target / "AGENTS.md").write_text(f"# AGENTS.md — {name}\n\nAI agent instructions for this project.\n")

            elif project_type == "react":
                pkg = {"name": name, "version": "0.1.0", "private": True, "type": "module",
                       "scripts": {"dev": "vite", "build": "vite build", "preview": "vite preview"}}
                (target / "package.json").write_text(json.dumps(pkg, indent=2))
                (target / "index.html").write_text(f'<!DOCTYPE html>\n<html><head><title>{name}</title></head><body><div id="root"></div><script type="module" src="/src/main.jsx"></script></body></html>')
                (target / "vite.config.js").write_text("import { defineConfig } from 'vite'\nimport react from '@vitejs/plugin-react'\nexport default defineConfig({ plugins: [react()] })")
                src = target / "src"
                src.mkdir()
                (src / "main.jsx").write_text("import React from 'react'\nimport ReactDOM from 'react-dom/client'\nReactDOM.createRoot(document.getElementById('root')).render(<h1>Hello</h1>)")
                (src / "App.jsx").write_text("export default function App() { return <h1>Hello</h1> }")

            elif project_type in ("flask", "fastapi"):
                (target / "README.md").write_text(f"# {name}\n\n{project_type} app.\n")
                (target / "app.py").write_text(f"\"\"\"{project_type} app.\"\"\"\nfrom flask import Flask\n\napp = Flask(__name__)\n\n@app.route('/')\ndef hello():\n    return 'Hello from {name}'\n" if project_type == "flask" else f"\"\"\"{project_type} app.\"\"\"\nfrom fastapi import FastAPI\n\napp = FastAPI(title=\"{name}\")\n\n@app.get('/')\nasync def root():\n    return {{\"message\": \"Hello from {name}\"}}\n")
                (target / "requirements.txt").write_text("flask\n" if project_type == "flask" else "fastapi\nuvicorn\n")

            elif project_type == "security":
                (target / "README.md").write_text(f"# {name}\n\nSecurity scanning tool.\n")
                (target / "scanner.py").write_text(f"\"\"\"Security scanner.\"\"\"\nimport re\n\nVULN_PATTERNS = [\n    (r'exec\\(', 'Code injection'),\n    (r'eval\\(', 'Code injection'),\n    (r'subprocess\\.call', 'Command injection'),\n]\n\ndef scan(code: str) -> list[dict]:\n    findings = []\n    for pattern, vuln_type in VULN_PATTERNS:\n        for match in re.finditer(pattern, code):\n            findings.append({{\n                \"type\": vuln_type,\n                \"line\": code[:match.start()].count('\\n') + 1,\n                \"match\": match.group(),\n            }})\n    return findings\n")
                (target / "AGENTS.md").write_text(f"# AGENTS.md — {name}\n\nSecurity-first development instructions for this project.\n")

            elif project_type == "cli":
                (target / "README.md").write_text(f"# {name}\n\nCLI tool.\n")
                (target / "pyproject.toml").write_text(f"""[project]
name = "{name}"
version = "0.1.0"
requires-python = ">=3.10"
dependencies = ["click"]

[project.scripts]
{name} = "{name}.cli:main"
""")
                pkg_dir = target / name
                pkg_dir.mkdir()
                (pkg_dir / "__init__.py").write_text(f"\"\"\"{name} CLI.\"\"\"\n")
                (pkg_dir / "cli.py").write_text(f"\"\"\"CLI entry point.\"\"\"\nimport click\n\n@click.group()\ndef cli():\n    \"\"\"{name} - CLI tool.\"\"\"\n\n@cli.command()\ndef hello():\n    \"\"\"Say hello.\"\"\"\n    click.echo('Hello from {name}')\n\nif __name__ == '__main__':\n    cli()\n")

            else:  # empty
                (target / "README.md").write_text(f"# {name}\n")

            # Init git
            subprocess.run(["git", "init"], cwd=target, capture_output=True, timeout=5)

            show_success(f"Scaffolded {project_type} project: {name}")
            console.print(f"[dim]  {target}[/]")
            console.print(f"[dim]  Use /scan-project to scan the new project[/]")

            return True

        except Exception as e:
            # Clean up on failure
            import shutil
            shutil.rmtree(target, ignore_errors=True)
            return show_error(f"Failed: {e}")

    def _handle_doctor(self, args: str) -> bool:
        """Run diagnostics on the environment."""
        from rich.table import Table
        from rich.panel import Panel
        from rich import box
        import platform, shutil

        checks = []

        # Python
        py_version = platform.python_version()
        checks.append(("Python", py_version, "OK" if py_version >= "3.10" else "OLD"))

        # Git
        git_path = shutil.which("git")
        checks.append(("Git", "✓" if git_path else "✗ Not found", "OK" if git_path else "MISSING"))

        # Node
        node_path = shutil.which("node")
        checks.append(("Node.js", "✓" if node_path else "✗ Not found", "OK" if node_path else "MISSING"))

        # GPU
        try:
            import torch
            gpu = torch.cuda.is_available() or (hasattr(torch, 'mps') and torch.mps.is_available())
            gpu_name = "MPS" if hasattr(torch, 'mps') and torch.mps.is_available() else (torch.cuda.get_device_name(0) if torch.cuda.is_available() else "None")
            checks.append(("GPU", gpu_name, "OK" if gpu else "NONE"))
        except Exception:
            checks.append(("GPU", "Not available", "NONE"))

        # API keys
        api_keys = {
            "GROQ": bool(os.environ.get("GROQ_API_KEY")),
            "OPENAI": bool(os.environ.get("OPENAI_API_KEY")),
            "ANTHROPIC": bool(os.environ.get("ANTHROPIC_API_KEY")),
            "HF": bool(os.environ.get("HF_TOKEN")),
        }
        for name, present in api_keys.items():
            checks.append((f"{name} Key", "✓" if present else "✗", "OK" if present else "MISSING"))

        # Model availability
        from v2.cli.llm import registry
        models = registry.list()
        checks.append(("Models", str(len(models)), "OK"))

        # Git repo
        git_ok = get_status() is not None
        checks.append(("Git Repo", "✓" if git_ok else "✗ (not in a repo)", "OK" if git_ok else "NONE"))

        table = Table(box=box.ROUNDED, title="[bold]Environment Diagnostics[/]")
        table.add_column("Check", style="cyan")
        table.add_column("Value")
        table.add_column("Status")
        for name, value, status in checks:
            color = {"OK": "green", "MISSING": "red", "NONE": "yellow", "OLD": "red"}.get(status, "white")
            table.add_row(name, value, f"[{color}]{status}[/]")

        console.print(table)

        # Session info
        git = get_status()
        if git:
            console.print(f"\n[dim]Branch: {git.branch} | {'DIRTY' if git.dirty else 'clean'} | {len(git.staged)} staged, {len(git.unstaged)} unstaged, {len(git.untracked)} untracked[/]")

        return True

    def _handle_compact(self, args: str) -> bool:
        """Compact conversation context to stay within token limits."""
        if len(self.messages) < 4:
            return show_status("Conversation too short to compact (< 4 messages).", "yellow")

        report = get_context_report(self.messages)
        show_status(
            f"Context: {report['total_tokens']} tokens / {report['budget']} budget "
            f"({report['usage_pct']}%) — {report['message_count']} messages",
            "yellow",
        )

        if not report["needs_compaction"] and "force" not in args:
            return show_status("Under budget, no compaction needed. Use /compact force to compact anyway.", "green")

        before = len(self.messages)
        self.messages = compact_conversation(self.messages, model=registry.active)
        after = len(self.messages)
        dropped = before - after

        hooks.trigger(HookEvent.ON_COMPACT, {
            "before": before, "after": after, "model": registry.active,
        })

        new_report = get_context_report(self.messages)
        show_success(f"Compacted: {before} → {after} messages ({dropped} dropped, {new_report['total_tokens']} tokens)")
        return True

    def _handle_commit(self, args: str) -> bool:
        """Git commit with AI-suggested message or custom message."""
        from rich.prompt import Prompt, Confirm as RichConfirm
        from rich.panel import Panel

        git = get_status()
        if not git:
            return show_error("Not a git repository")

        if not git.staged and not git.unstaged and not git.untracked:
            return show_status("Nothing to commit.", "yellow")

        # Auto-stage if nothing staged
        if not git.staged:
            if git.unstaged or git.untracked:
                auto_stage = RichConfirm.ask("Stage all changes?")
                if auto_stage:
                    ok, msg = stage_all()
                    if ok:
                        show_success(msg)
                    else:
                        return show_error(msg)
                else:
                    return show_status("Commit cancelled.", "yellow")
            else:
                return show_status("Nothing to commit.", "yellow")

        # Show diff
        diff_text, diff_type = get_current_diff_for_commit()
        if diff_text:
            console.print(Panel(
                diff_text[:2000],
                title=f"[bold]Diff ({diff_type})[/]",
                border_style="cyan",
            ))

        # Suggest message
        show_status("Generating commit message...", "cyan")
        suggested = suggest_commit_message(diff_text, registry.active)

        if args.strip():
            msg = args.strip()
        else:
            console.print(f"\n[dim]Suggested:[/] {suggested.split(chr(10))[0] if suggested else ''}")
            msg = Prompt.ask("Commit message", default=suggested.split("\n")[0] if suggested else "")

        if not msg:
            return show_status("Commit cancelled.", "yellow")

        ok, commit_msg = commit(msg)
        if ok:
            hooks.trigger(HookEvent.POST_COMMIT, {"message": msg})
            show_success(commit_msg)
        else:
            show_error(commit_msg)

        return True

    def _handle_review(self, args: str) -> bool:
        """AI code review of changes or specific files."""
        from rich.panel import Panel
        from v2.cli.prompts import get_explain_messages

        if args.strip():
            # Review specific file
            code = self._read_file(args.strip())
            if code is None:
                return show_error(f"File not found: {args.strip()}")
            review_prompt = f"Review this file for security issues, bugs, and code quality:\n\n```{Path(args.strip()).suffix[1:]}\n{code[:4000]}\n```"
        else:
            # Review git diff
            diff_text, diff_type = get_current_diff_for_commit()
            if not diff_text:
                return show_status("No changes to review.", "yellow")
            review_prompt = f"Review these code changes for security issues, bugs, and quality:\n\n```diff\n{diff_text[:4000]}\n```"

        if not self._check_ai_limit():
            return False
        increment_ai_scan()

        self.messages.append({"role": "user", "content": review_prompt})
        context = self._build_project_context()
        response = self._chat_with_react(review_prompt, context)
        return True

    def _handle_pr(self, args: str) -> bool:
        """Create a GitHub PR."""
        from rich.prompt import Prompt, Confirm as RichConfirm
        from rich.panel import Panel

        if not shutil.which("gh"):
            return show_error("GitHub CLI not found. Install: brew install gh && gh auth login")

        git = get_status()
        if not git:
            return show_error("Not a git repository")

        title = ""
        body = ""
        base = "main"

        parts = args.strip().split()
        if parts:
            # Parse args like: --base develop --title "My PR"
            i = 0
            while i < len(parts):
                if parts[i] == "--base" and i + 1 < len(parts):
                    base = parts[i + 1]
                    i += 2
                elif parts[i] == "--title" and i + 1 < len(parts):
                    title = parts[i + 1]
                    i += 2
                else:
                    i += 1

        if not title:
            # Suggest title from recent commits
            log = get_log(3)
            recent = log[0]["message"] if log else ""
            title = Prompt.ask("PR title", default=recent)

        if not body:
            body = Prompt.ask("PR description (optional)", default="")

        console.print(f"\n[dim]Creating PR: {title}[/]")
        console.print(f"[dim]Base: {base} → Head: {git.branch}[/]")
        if body:
            console.print(f"[dim]Body: {body[:100]}[/]")

        if RichConfirm.ask("Create this PR?"):
            ok, result = create_pr(title, body, base)
            if ok:
                show_success(f"PR created: {result}")
            else:
                show_error(result)
        else:
            show_status("PR cancelled.", "yellow")

        return True

    def _handle_rakshakai_md(self, args: str) -> bool:
        """Create or show RAKSHAKAI.md project context file."""
        root = find_project_root(self.current_dir)
        ctx_path = root / "RAKSHAKAI.md"

        if args.strip() == "create" or not ctx_path.exists():
            if ctx_path.exists():
                return show_error("RAKSHAKAI.md already exists")
            content = load_rakshakai_md(str(root))
            ctx_path.write_text(content, encoding="utf-8")
            show_success(f"Created {ctx_path}")
            console.print("[dim]Edit this file to set project rules and preferences.[/]")
        else:
            from rich.syntax import Syntax
            content = ctx_path.read_text(encoding="utf-8", errors="replace")
            syntax = Syntax(content, "markdown", theme="monokai", line_numbers=True)
            console.print(Panel(syntax, title=f"[bold]RAKSHAKAI.md[/]", border_style="cyan"))

        return True

    def _handle_resume(self, args: str) -> bool:
        """Show recent sessions for resuming."""
        import sqlite3
        from v2.cli.memory import _get_db, DB_PATH
        try:
            conn = _get_db()
            rows = conn.execute("SELECT id, started_at, model, dir FROM sessions ORDER BY id DESC LIMIT 10").fetchall()
            if not rows:
                return show_status("No previous sessions found.", "yellow")
            from rich.table import Table
            from rich import box
            table = Table(box=box.SIMPLE, padding=(0, 2))
            table.add_column("ID", style="cyan")
            table.add_column("Date", style="dim")
            table.add_column("Model")
            table.add_column("Dir", style="dim")
            for r in rows:
                table.add_row(str(r["id"]), (r["started_at"] or "")[5:19], r["model"] or "?", (r["dir"] or "")[-30:])
            console.print(table)
            console.print(f"\n[dim]Start a new session to continue working.[/]")
        except Exception as e:
            show_error(f"Error: {e}")
        return True

    def _handle_fork(self, args: str) -> bool:
        """Fork conversation to try a different direction."""
        outfile = f"session_fork_{int(time.time())}.json"
        with open(outfile, "w") as f:
            json.dump({
                "session_id": self._session_id,
                "messages": self.messages,
                "forked_from": self._session_id,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            }, f)
        show_success(f"Session forked: {outfile}")
        return True

    def _handle_share(self, args: str) -> bool:
        """Share current session via URL or export to file."""
        from v2.cli.session_share import upload_session, save_session_local, export_for_github
        
        arg = args.strip().lower()
        
        if not arg or arg == "upload":
            # Upload to share endpoint
            show_status("Uploading session...", "cyan")
            url = upload_session(self._session_id)
            
            if url:
                show_success(f"Session shared: {url}")
                console.print(f"\n[dim]Share this URL with your team to view scan results[/]\n")
            else:
                show_error("Upload failed. Trying local save...")
                # Fallback to local save
                output_file = f"session_{self._session_id}.json"
                if save_session_local(self._session_id, output_file):
                    show_success(f"Session saved locally: {output_file}")
                else:
                    show_error("Local save also failed")
        
        elif arg == "export" or arg.startswith("export "):
            # Export as markdown
            parts = args.split(maxsplit=1)
            output_file = parts[1] if len(parts) > 1 else f"session_{self._session_id}.md"
            
            md = export_for_github(self._session_id)
            with open(output_file, 'w') as f:
                f.write(md)
            
            show_success(f"Report exported: {output_file}")
        
        elif arg == "save" or arg.startswith("save "):
            # Save as JSON
            parts = args.split(maxsplit=1)
            output_file = parts[1] if len(parts) > 1 else f"session_{self._session_id}.json"
            
            if save_session_local(self._session_id, output_file):
                show_success(f"Session saved: {output_file}")
            else:
                show_error("Save failed")
        
        else:
            show_error("Usage: /share [upload|export <file>|save <file>]")
        
        return True
    
    def _handle_index(self, args: str) -> bool:
        """Index codebase for semantic search."""
        from v2.cli.code_index import CodebaseIndex
        
        arg = args.strip()
        target_dir = arg if arg else self.current_dir
        
        if not os.path.isdir(target_dir):
            return show_error(f"Directory not found: {target_dir}")
        
        show_status("Indexing codebase (this may take a minute)...", "cyan")
        
        try:
            index = CodebaseIndex()
            index.embed_codebase(target_dir, chunk_size=50)
            
            stats = index.stats()
            show_success(
                f"Indexed {stats['chunks']} chunks from {stats['files']} files"
            )
            
            # Update cached index
            self._code_index = index
        
        except ImportError as e:
            show_error(f"Missing dependencies: {e}")
            console.print("[dim]Install with: pip install sentence-transformers faiss-cpu[/]")
        except Exception as e:
            show_error(f"Indexing failed: {e}")
        
        return True
    
    def _handle_search(self, args: str) -> bool:
        """Semantic search in indexed codebase."""
        if not args.strip():
            return show_error("Usage: /search <query>")
        
        index = self._ensure_code_index()
        
        if not index.chunks:
            return show_error("No index found. Run /index first.")
        
        query = args.strip()
        show_status(f"Searching for: {query}", "cyan")
        
        results = index.search(query, top_k=10)
        
        if not results:
            show_status("No results found", "yellow")
            return True
        
        # Display results
        from rich.table import Table
        from rich import box
        from rich.panel import Panel
        from rich.syntax import Syntax
        
        table = Table(
            title=f"[bold]Search Results: '{query}'[/]",
            box=box.ROUNDED,
            border_style="cyan",
        )
        table.add_column("Score", width=6, justify="right")
        table.add_column("File", style="cyan")
        table.add_column("Lines", width=10)
        table.add_column("Preview", ratio=1)
        
        for chunk, score in results[:10]:
            table.add_row(
                f"{score:.2f}",
                os.path.basename(chunk.file_path),
                f"{chunk.start_line}-{chunk.end_line}",
                chunk.content[:80].replace("\n", " ") + "...",
            )
        
        console.print(table)
        
        # Show top result with syntax highlighting
        if results:
            top_chunk, top_score = results[0]
            syntax = Syntax(
                top_chunk.content[:500],
                top_chunk.language,
                theme="monokai",
                line_numbers=True,
            )
            console.print(Panel(
                syntax,
                title=f"[bold]Top Result ({top_score:.2f}): {top_chunk}[/]",
                border_style="green",
            ))
        
        return True

    def _handle_login(self, args: str) -> bool:
        """Login via web browser — opens auth server login page."""
        if auth_state.logged_in:
            show_status(f"Already logged in as {auth_state.email}. Use /logout first to switch accounts.", "yellow")
            return True

        show_status(f"Opening browser to {AUTH_SERVER_HOST}/login ...", "cyan")
        show_status("If browser doesn't open, visit the URL above manually.", "dim")

        token = login_flow()
        if not token:
            show_error("Login timed out or was cancelled. Make sure the auth server is running.")
            show_status(f"Start it with: python3 -m v2.web.server", "yellow")
            return False

        user_info = fetch_user_info(token)
        if not user_info:
            show_error("Could not verify login. Token received but server unreachable.")
            return False

        auth_state.email = user_info.get("email", "")
        auth_state.token = token
        auth_state.logged_in = True
        auth_state.login_time = time.time()
        auth_state.plan = user_info.get("plan", "free")
        auth_state.save()

        from v2.cli.auth import AUTH_SERVER_HOST
        welcome = user_info.get("name", "") or user_info["email"]
        show_success(f"Logged in as {welcome} [{auth_state.plan.title()} Plan]")
        return True

    def _handle_logout(self, args: str) -> bool:
        """Logout and clear stored credentials."""
        if not auth_state.logged_in:
            show_status("Not logged in.", "yellow")
            return True

        # Invalidate token on server
        try:
            import requests as req
            req.post(f"{AUTH_SERVER_HOST}/api/logout",
                     headers={"Authorization": f"Bearer {auth_state.token}"},
                     timeout=5)
        except Exception:
            pass  # offline logout is fine

        email = auth_state.email
        auth_state.clear()
        show_success(f"Logged out {email}")
        return True

    def _handle_whoami(self, args: str) -> bool:
        """Show current login status."""
        if not auth_state.logged_in:
            show_status("Not logged in. Use /login to authenticate.", "yellow")
            return True

        from v2.cli.display import show_auth_status
        show_auth_status(auth_state)
        return True

    def _handle_agent(self, args: str) -> bool:
        if not args.strip():
            return show_error("Usage: /agent <task description>")
        if not self._check_ai_limit():
            return False
        increment_ai_scan()
        show_status(f"Agent: {args.strip()[:80]}", "cyan")
        agent = self._ensure_agent()
        self.models_used.add(agent.model)

        from v2.cli.display import StreamingPanel
        collected = []

        def on_token(tok):
            collected.append(tok)

        with StreamingPanel() as panel:
            result = agent.run(args.strip(), on_token=panel.update)

        self._show_agent_result(result)
        return True

    def _handle_swarm(self, args: str) -> bool:
        if not args.strip():
            return show_error("Usage: /swarm <task description>")
        if not self._check_ai_limit():
            return False
        increment_ai_scan()
        show_status(f"Swarm: {args.strip()[:80]}", "cyan")
        from v2.cli.orchestrator import OrchestratorAgent
        orch = OrchestratorAgent(model=registry.active, max_subagents=5)
        result = orch.run(args.strip())
        show_swarm_results(result)
        return True

    def _handle_skills(self, args: str) -> bool:
        """List or refresh agent skills."""
        a = args.strip().lower()
        if a == "refresh":
            with console.status("[cyan]Refreshing skill cache...", spinner="dots"):
                self._ensure_agent()
                self._skills.refresh_cache()
            show_success("Skills refreshed")
        elif a:
            # Show specific skill details
            self._ensure_agent()
            skill = self._skills.get_skill(a)
            if skill:
                from rich.panel import Panel
                console.print(Panel(
                    f"[bold]{skill.name}[/] v{skill.version}\n"
                    f"Source: {skill.source}\n"
                    f"Tools: {', '.join(skill.tools_required)}\n\n"
                    f"{skill.description[:500]}",
                    title="Skill Details",
                    border_style="cyan",
                ))
            else:
                show_error(f"Skill '{a}' not found")
        else:
            self._ensure_agent()
            skills = self._skills.list_skills()
            from rich.table import Table
            from rich import box
            table = Table(title=f"[bold]Skills ({len(skills)})[/]", box=box.ROUNDED, border_style="cyan")
            table.add_column("Name", style="bold cyan")
            table.add_column("Source")
            table.add_column("Tools Required")
            for name in skills:
                s = self._skills.get_skill(name)
                table.add_row(name, s.source, ", ".join(s.tools_required) if s.tools_required else "—")
            console.print(table if skills else "[dim]No skills loaded. Use /skills refresh to fetch from GitHub.[/]")
        return True

    def _handle_def(self, args: str) -> bool:
        """Jump to symbol definition via LSP."""
        if not args.strip():
            return show_error("Usage: /def <file:line:col> or just <symbol>")
        
        from v2.cli.lsp_client import LSPClient, detect_language
        from rich.syntax import Syntax
        from rich.panel import Panel
        
        # Parse input: either "file:line:col" or "symbol" (use current context)
        parts = args.strip().split(":")
        if len(parts) == 3:
            file_path, line, col = parts[0], int(parts[1]), int(parts[2])
        else:
            # TODO: Track current file context
            return show_error("Specify file:line:col (e.g., /def src/main.py:45:10)")
        
        try:
            language = detect_language(file_path)
            with LSPClient(language=language) as lsp:
                location = lsp.goto_definition(file_path, line, col)
                if location:
                    show_success(f"Definition: {location}")
                    
                    # Show code snippet around definition
                    try:
                        with open(location.file, 'r') as f:
                            lines = f.readlines()
                            start = max(0, location.line - 5)
                            end = min(len(lines), location.line + 5)
                            snippet = ''.join(lines[start:end])
                            
                            syntax = Syntax(
                                snippet,
                                detect_language(location.file),
                                theme="monokai",
                                line_numbers=True,
                                start_line=start + 1,
                                highlight_lines={location.line},
                            )
                            
                            console.print(Panel(
                                syntax,
                                title=f"[bold cyan]{os.path.basename(location.file)}:{location.line}[/]",
                                border_style="cyan",
                            ))
                    except Exception:
                        pass  # Snippet display is optional
                else:
                    show_status("No definition found", "yellow")
        except Exception as e:
            show_error(f"LSP error: {e}")
            console.print("[dim]Tip: Install language server: pip install python-lsp-server[/]")
        
        return True
    
    def _handle_refs(self, args: str) -> bool:
        """Find all references to a symbol via LSP."""
        if not args.strip():
            return show_error("Usage: /refs <file:line:col>")
        
        from v2.cli.lsp_client import LSPClient, detect_language
        
        parts = args.strip().split(":")
        if len(parts) != 3:
            return show_error("Specify file:line:col (e.g., /refs src/main.py:45:10)")
        
        file_path, line, col = parts[0], int(parts[1]), int(parts[2])
        
        try:
            language = detect_language(file_path)
            with LSPClient(language=language) as lsp:
                references = lsp.find_references(file_path, line, col)
                if references:
                    from rich.table import Table
                    from rich import box
                    table = Table(title=f"[bold]References ({len(references)})[/]", box=box.SIMPLE)
                    table.add_column("File", style="cyan")
                    table.add_column("Line", justify="right")
                    table.add_column("Column", justify="right")
                    
                    for ref in references[:50]:  # Limit display
                        table.add_row(
                            os.path.basename(ref.file),
                            str(ref.line),
                            str(ref.column),
                        )
                    
                    console.print(table)
                    if len(references) > 50:
                        console.print(f"[dim]... and {len(references) - 50} more[/]")
                else:
                    show_status("No references found", "yellow")
        except Exception as e:
            show_error(f"LSP error: {e}")
        
        return True
    
    def _handle_hover(self, args: str) -> bool:
        """Get hover information (type hints, docs) via LSP."""
        if not args.strip():
            return show_error("Usage: /hover <file:line:col>")
        
        from v2.cli.lsp_client import LSPClient, detect_language
        
        parts = args.strip().split(":")
        if len(parts) != 3:
            return show_error("Specify file:line:col (e.g., /hover src/main.py:45:10)")
        
        file_path, line, col = parts[0], int(parts[1]), int(parts[2])
        
        try:
            language = detect_language(file_path)
            with LSPClient(language=language) as lsp:
                info = lsp.hover(file_path, line, col)
                if info:
                    from rich.panel import Panel
                    from rich.markdown import Markdown
                    console.print(Panel(
                        Markdown(info) if "```" in info else info,
                        title="[bold]Hover Info[/]",
                        border_style="cyan",
                        padding=(1, 2),
                    ))
                else:
                    show_status("No hover info available", "yellow")
        except Exception as e:
            show_error(f"LSP error: {e}")
        
        return True
    
    def _handle_rename(self, args: str) -> bool:
        """Rename symbol across all files via LSP."""
        parts = args.strip().split(maxsplit=1)
        if len(parts) != 2:
            return show_error("Usage: /rename <file:line:col> <new_name>")
        
        location, new_name = parts[0], parts[1]
        loc_parts = location.split(":")
        if len(loc_parts) != 3:
            return show_error("Specify file:line:col new_name")
        
        file_path, line, col = loc_parts[0], int(loc_parts[1]), int(loc_parts[2])
        
        from v2.cli.lsp_client import LSPClient, detect_language
        
        try:
            language = detect_language(file_path)
            with LSPClient(language=language) as lsp:
                edits = lsp.rename(file_path, line, col, new_name)
                if edits:
                    # Show preview
                    from rich.table import Table
                    from rich import box
                    table = Table(title=f"[bold]Rename Preview ({len(edits)} edits)[/]", box=box.SIMPLE)
                    table.add_column("File", style="cyan")
                    table.add_column("Line", justify="right")
                    table.add_column("New Text", style="green")
                    
                    for edit in edits[:20]:
                        table.add_row(
                            os.path.basename(edit.file),
                            str(edit.start_line),
                            edit.new_text[:50],
                        )
                    
                    console.print(table)
                    if len(edits) > 20:
                        console.print(f"[dim]... and {len(edits) - 20} more[/]")
                    
                    # TODO: Prompt user to confirm and apply edits
                    console.print("\n[yellow]Apply edits? (Not yet implemented - coming soon!)[/]")
                else:
                    show_status("No rename edits found", "yellow")
        except Exception as e:
            show_error(f"LSP error: {e}")
        
        return True

    def _show_agent_result(self, result: dict):
        """Display agent execution result."""
        from rich.panel import Panel
        from v2.cli.display import console
        success = result.get("success", False)
        border = "green" if success else "red"
        title = "✓ Agent Complete" if success else "✗ Agent Failed"
        text = f"Steps: {result['steps']}\n"
        if result.get("error"):
            text += f"Error: {result['error']}\n"
        for t in result["thoughts"]:
            action_str = ""
            if t.get("action"):
                a = t["action"]
                action_str = f" → {a['tool']}.{a['action']}({a['params']})"
            status = "✓" if t.get("success") else "✗" if t.get("success") is False else "?"
            text += f"\n  Step {t['step']}: [{status}] {t['thought'][:120]}{action_str}"
        console.print(Panel(text.strip(), title=title, border_style=border))

    # ── main loop ──────────────────────────────────────────

    def run(self):
        auth_state.load()
        show_banner(registry.active)
        usage = get_usage()
        plan_name = auth_state.plan.capitalize() if auth_state.logged_in else "Free"
        ai_rem = usage["ai_scans"]["remaining"]
        rx_rem = usage["regex_scans"]["remaining"]
        status_parts = [
            f"⚡ RakshakAI ready · /help for commands",
            f"📋 {plan_name} — {ai_rem} AI / {rx_rem} regex scans left today",
        ]
        if auth_state.logged_in:
            status_parts.append(f"🔐 {auth_state.email}")
        show_status(" · ".join(status_parts), "green")
        if ai_rem <= 1 and auth_state.plan != "pro":
            console.print(f"[yellow]⚠ Low on scans. Upgrade: /pricing for unlimited use[/]")

        from prompt_toolkit import PromptSession
        from prompt_toolkit.history import FileHistory
        from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
        from prompt_toolkit.key_binding import KeyBindings
        from prompt_toolkit.styles import Style

        kb = KeyBindings()
        @kb.add("c-c")
        def _cancel(event):
            raise KeyboardInterrupt()
        @kb.add("c-d")
        def _eof(event):
            sys.exit(0)
        @kb.add("up")
        def _up(event):
            buf = event.app.current_buffer
            if buf.complete_state:
                buf.complete_previous()
            else:
                buf.history_backward()
        @kb.add("down")
        def _down(event):
            buf = event.app.current_buffer
            if buf.complete_state:
                buf.complete_next()
            else:
                buf.history_forward()

        prompt_style = Style.from_dict({"prompt": "bold cyan"})
        session = PromptSession(
            history=FileHistory(HISTORY_FILE),
            auto_suggest=AutoSuggestFromHistory(),
            completer=ModelCompleter(),
            key_bindings=kb,
            style=prompt_style,
            complete_while_typing=True,
            enable_history_search=False,
        )

        while True:
            try:
                text = session.prompt("> ", default="")
            except KeyboardInterrupt:
                console.print("\n[yellow]Use /exit or Ctrl+D to quit[/]")
                continue
            except EOFError:
                break

            text = text.strip()
            if not text:
                continue

            self.session_count += 1

            if text.startswith("/"):
                parts = text.split(maxsplit=1)
                cmd = parts[0].lower()
                args = parts[1] if len(parts) > 1 else ""

                handlers = {
                    "/help": lambda a: show_help(),
                    "/model": self._handle_model,
                    "/models": self._handle_models,
                    "/parallel": self._handle_parallel,
                    "/scan": self._handle_scan,
                    "/scan-project": self._handle_scan_project,
                    "/explain": self._handle_explain,
                    "/fix": self._handle_fix,
                    "/batch": self._handle_batch,
                    "/watch": self._handle_watch,
                    "/watch-stop": self._handle_watch_stop,
                    "/diff": self._handle_diff,
                    "/precommit": self._handle_precommit,
                    "/test": self._handle_test,
                    "/share": self._handle_share,
                    "/index": self._handle_index,
                    "/search": self._handle_search,
                    "/history": self._handle_history,
                    "/log": self._handle_log,
                    "/stats": self._handle_stats,
                    "/dashboard": lambda a: self._handle_stats("dashboard"),
                    "/confirm": self._handle_confirm,
                    "/dismiss": self._handle_dismiss,
                    "/cost": self._handle_cost,
                    "/context": self._handle_context,
                    "/permissions": self._handle_permissions,
                    "/plan": self._handle_plan,
                    "/rakshakai.md": self._handle_rakshakai_md,
                    "/usage": self._handle_usage,
                    "/pricing": self._handle_pricing,
                    "/init": self._handle_init,
                    "/doctor": self._handle_doctor,
                    "/compact": self._handle_compact,
                    "/commit": self._handle_commit,
                    "/review": self._handle_review,
                    "/pr": self._handle_pr,
                    "/resume": self._handle_resume,
                    "/fork": self._handle_fork,
                    "/clear": lambda a: (self.messages.clear(), show_status("Conversation context cleared", "green")),
                    "/session": self._handle_session,
                    "/login": self._handle_login,
                    "/logout": self._handle_logout,
                    "/whoami": self._handle_whoami,
                    "/agent": self._handle_agent,
                    "/swarm": self._handle_swarm,
                    "/skills": self._handle_skills,
                    "/def": self._handle_def,
                    "/refs": self._handle_refs,
                    "/hover": self._handle_hover,
                    "/rename": self._handle_rename,
                    "/exit": lambda a: self._exit_gracefully(),
                }

                handler = handlers.get(cmd)
                if handler:
                    try:
                        handler(args)
                    except Exception as e:
                        show_error(f"Command failed: {e}")
                else:
                    show_error(f"Unknown command: {cmd} (type /help for available commands)")
                continue

            # Regular chat with autonomous tool use (opencode-style)
            self.messages.append({"role": "user", "content": text})
            context = self._build_project_context()
            response = self._chat_with_react(text, context)

    def _chat_with_react(self, text: str, context: str) -> str:
        """Chat using native function calling — token-aware context."""
        from rich.markdown import Markdown
        from v2.cli.llm import trim_messages

        system = get_system(registry.active) + "\n\n" + context
        full = [{"role": "system", "content": system}] + self.messages[-30:]

        # Add RAKSHAKAI.md project context with instructions
        rakshakai_ctx = load_rakshakai_md(self.current_dir)
        if rakshakai_ctx and "RakshakAI" not in system:
            full.insert(0, {"role": "system", "content": rakshakai_ctx})
        # Trim to fit token budget (leaves room for response)
        messages = trim_messages(full, max_tokens=5000)
        user_msg = {"role": "user", "content": text}

        cfg = registry.get(registry.active)
        supports_fc = registry.supports_function_calling(registry.active)

        if supports_fc:
            return self._chat_with_functions(messages, user_msg, cfg)
        else:
            return self._chat_with_action_text(messages, user_msg, cfg)

    def _chat_with_functions(self, messages: list[dict], user_msg: dict, cfg) -> str:
        """Chat using OpenAI-compatible function calling — loops until the model responds with text."""
        from rich.markdown import Markdown
        import json
        from v2.cli.tools import build_openai_tools, dispatch_tool_call

            # Use enhanced agentic tools (Claude Code-style)
        tools = build_openai_tools_v2()
        full_messages = messages + [user_msg]
        t_start = time.time()
        max_rounds = 10
        td = ThinkingDisplay(enabled=True)

        def _summarize(name: str, result: object) -> str:
            if result is None:
                return "No result"
            if isinstance(result, str):
                lines = result.split("\n")
                return lines[0][:80] + ("..." if len(lines) > 1 else "")
            if isinstance(result, list):
                return f"[{len(result)} items]"
            if isinstance(result, dict):
                if "error" in result:
                    return f"Error: {result['error'][:80]}"
                if "success" in result and not result.get("success"):
                    return f"Error: {result.get('stderr', result.get('error', 'Failed'))[:80]}"
                if "stdout" in result:
                    return result["stdout"][:80]
            return str(result)[:80]

        for _ in range(max_rounds):
            response = chat_with_tools(full_messages, cfg, tools=tools)
            tool_calls = response.get("tool_calls")

            if not tool_calls:
                final_content = response.get("content", "").strip()
                if final_content:
                    console.print(Markdown(final_content))
                show_thought_timing(t_start, time.time())
                self.messages.append({"role": "assistant", "content": final_content})
                return final_content

            asst_content = response.get("content", "")
            full_messages.append({
                "role": "assistant",
                "content": asst_content or None,
                "tool_calls": tool_calls,
            })

            for tc in tool_calls:
                name = tc["function"]["name"]
                try:
                    args = json.loads(tc["function"]["arguments"])
                except json.JSONDecodeError:
                    args = {}

                td.update(f"Using {name}: {str(args)[:60]}")
                show_tool_call(name, args)

                result = agentic_dispatch(name, args)

                result_str = _summarize(name, result)
                show_tool_result(result_str)

                raw_str = json.dumps(result) if not isinstance(result, str) else result
                full_messages.append({
                    "role": "tool",
                    "tool_call_id": tc["id"],
                    "content": raw_str[:3000] if raw_str else "(empty)",
                })

        show_error("Tool use exceeded maximum rounds (10)")
        show_thought_timing(t_start, time.time())
        return ""

    def _chat_with_action_text(self, messages: list[dict], user_msg: dict, cfg) -> str:
        """Fallback: parse ACTION[...] from text for models without function calling."""
        from v2.cli.agent import AgentAction

        full_messages = messages + [user_msg]
        t0 = time.time()
        response = chat_sync(full_messages, cfg)
        action = self._parse_action_text(response)

        if not action:
            content = response.strip()
            if content:
                console.print(Markdown(content))
            show_thought_timing(t0, time.time())
            self.messages.append({"role": "assistant", "content": response})
            return response

        # Show action
        show_tool_call(f"{action.tool}.{action.action}", action.params)

        tool_obj = TOOLS.get(action.tool)
        if not tool_obj:
            show_tool_error(f"{action.tool}.{action.action}", f"Tool '{action.tool}' not available")
            self.messages.append({"role": "assistant", "content": response})
            return response

        method = getattr(tool_obj, action.action, None)
        if not method:
            show_tool_error(f"{action.tool}.{action.action}", f"Action not found")
            self.messages.append({"role": "assistant", "content": response})
            return response

        try:
            result = method(**action.params)
        except Exception as e:
            show_tool_error(f"{action.tool}.{action.action}", str(e))
            self.messages.append({"role": "assistant", "content": response})
            return response

        # Feed back to LLM
        result_str = str(result)[:800] if result else "(empty)"
        final = chat_sync(full_messages + [
            {"role": "assistant", "content": response},
            {"role": "user", "content": f"The tool returned: {result_str[:500]}"},
        ], cfg)

        content = final.strip()
        if content:
            console.print(Markdown(content))
        show_thought_timing(t0, time.time())
        self.messages.append({"role": "assistant", "content": final})
        return final

    def _parse_action_text(self, response: str) -> Optional[AgentAction]:
        """Extract ACTION[tool:action](params) from LLM output (fallback)."""
        from v2.cli.agent import AgentAction
        pattern = r'ACTION\[(\w+):(\w+)\]\((.*?)\)'
        match = re.search(pattern, response, re.DOTALL)
        if not match:
            return None
        tool, action_name, params_str = match.groups()
        params = {}
        if params_str.strip():
            for pair in params_str.split(','):
                if '=' in pair:
                    k, v = pair.split('=', 1)
                    k, v = k.strip(), v.strip().strip('"\'')
                    if v.isdigit():
                        v = int(v)
                    elif v.lower() == 'true':
                        v = True
                    elif v.lower() == 'false':
                        v = False
                    params[k] = v
        return AgentAction(tool=tool, action=action_name, params=params, reasoning=response)

    def _exit_gracefully(self):
        """Exit with session summary."""
        duration = time.time() - self.start_time
        show_session_summary(
            duration_seconds=duration,
            files_scanned=self.files_scanned,
            vulnerabilities_found=self.vulnerabilities_found,
            models_used=sorted(list(self.models_used)),
        )
        sys.exit(0)


def main():
    # Headless JSON mode for CI/CD
    import argparse
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('command', nargs='?', help='Command to run')
    parser.add_argument('target', nargs='?', help='File or directory to scan')
    parser.add_argument('--json', action='store_true', help='Output JSON (headless mode)')
    parser.add_argument('--model', default=None, help='Model to use')
    parser.add_argument('--no-interactive', action='store_true', help='Suppress all prompts')
    parser.add_argument('--fail-on', default='critical,high', help='Fail on severity levels (comma-separated)')
    parser.add_argument('--auto-commit', action='store_true', help='Auto-commit fixes to git')
    parser.add_argument('--models', action='store_true', help='List available models and exit')
    
    # Parse known args (ignore unknown for REPL mode)
    args, unknown = parser.parse_known_args()
    
    # List models and exit
    if args.models:
        from v2.cli.display import show_model_list
        show_model_list(registry.models, registry.active)
        return
    
    # Headless JSON mode
    if args.json or args.no_interactive:
        if not args.command or not args.target:
            output = {"error": "Usage: rakshakai scan <target> --json"}
            print(json.dumps(output, indent=2))
            sys.exit(2)
        
        if args.command == 'scan':
            from v2.cli.scanner import scan_code, collect_source_files, BatchScanner
            
            try:
                if os.path.isfile(args.target):
                    code = Path(args.target).read_text(encoding='utf-8', errors='replace')
                    result = scan_code(code, language=Path(args.target).suffix[1:], model=registry.active)
                    
                    if args.json:
                        print(json.dumps(result, indent=2))
                    
                    # Exit code: 0=clean, 1=vulns found, 2=error
                    fail_on = [s.strip().lower() for s in args.fail_on.split(',')]
                    vulns = result.get("vulnerabilities", [])
                    has_critical = any(v.get("severity", "").lower() in fail_on for v in vulns)
                    sys.exit(1 if has_critical else 0)
                
                elif os.path.isdir(args.target):
                    files = collect_source_files(args.target)
                    if not files:
                        output = {"error": "No source files found", "scanned": 0}
                        print(json.dumps(output, indent=2))
                        sys.exit(0)
                    
                    scanner = BatchScanner(max_workers=4)
                    results = scanner.scan_files(files, model=registry.active)
                    
                    output = {
                        "scanned": len(files),
                        "vulnerable": sum(1 for r in results if r.cwe),
                        "results": [r.to_dict() for r in results],
                        "summary": scanner.summary(),
                        "model": registry.active,
                    }
                    
                    if args.json:
                        print(json.dumps(output, indent=2))
                    
                    # Exit code
                    fail_on = [s.strip().lower() for s in args.fail_on.split(',')]
                    has_critical = any(r.severity and r.severity.lower() in fail_on for r in results)
                    sys.exit(1 if has_critical else 0)
                
                else:
                    output = {"error": f"Path not found: {args.target}"}
                    print(json.dumps(output, indent=2))
                    sys.exit(2)
            
            except Exception as e:
                output = {
                    "error": str(e),
                    "type": type(e).__name__,
                    "help": "Check API keys if using external models, or use --model rakshak"
                }
                print(json.dumps(output, indent=2))
                sys.exit(2)
        
        else:
            output = {"error": f"Unknown command: {args.command}"}
            print(json.dumps(output, indent=2))
            sys.exit(2)
        
        return
    
    # Non-interactive mode: run a scan and exit (legacy)
    if len(sys.argv) > 1 and not sys.stdin.isatty():
        from rakshak_cli import local_scan_file, print_table
        target = sys.argv[1]
        if os.path.isfile(target):
            issues = local_scan_file(target)
            if issues:
                print(f"\n  \033[1m📄 {target}\033[0m")
                print_table(issues)
            else:
                print(f"\n  ✅ \033[92mNo vulnerabilities found in {target}\033[0m")
        elif os.path.isdir(target):
            from rakshak_cli import scan_directory, load_config
            cfg = load_config()
            results = scan_directory(target, cfg)
            for fpath, issues in results.items():
                if issues:
                    print(f"\n  \033[1m📄 {fpath}\033[0m")
                    print_table(issues)
        else:
            print(f"\033[91m✖ Path not found: {target}\033[0m")
            sys.exit(1)
        return

    # Set model if specified (both interactive and headless)
    if args.model and args.model in registry.models:
        registry.set_active(args.model)

    # Interactive REPL mode (requires TTY)
    if not sys.stdin.isatty():
        # Show help in non-TTY mode
        print("RakshakAI v3 — Multi-Model Security CLI")
        print("Usage: python3 v2/cli/main.py <file-or-dir>")
        print("       python3 v2/cli/main.py            # interactive REPL (requires terminal)")
        print("\nCommands when scanning a file:")
        print("  python3 v2/cli/main.py app.py          Scan a single file")
        print("  python3 v2/cli/main.py src/            Scan a directory")
        return

    # Check API key early
    has_key = bool(os.environ.get("OPENROUTER_API_KEY") or os.environ.get("OPENAI_API_KEY") or os.environ.get("ANTHROPIC_API_KEY"))

    try:
        repl = RakshakREPL()
        try:
            if not has_key:
                from v2.cli.display import console as c
                c.print("  [yellow]⚠ No API key set. Set one to use AI chat:[/yellow]")
                c.print("  [dim]  export OPENROUTER_API_KEY=\"sk-or-v1-...\"[/dim]")
                c.print("  [dim]  or create ~/.rakshak/.env with: OPENROUTER_API_KEY=...[/dim]")
                c.print("  [green]  Scan still works: /scan <file> or type naturally[/green]\n")
            repl.run()
        except KeyboardInterrupt:
            duration = time.time() - repl.start_time
            show_session_summary(
                duration_seconds=duration,
                files_scanned=repl.files_scanned,
                vulnerabilities_found=repl.vulnerabilities_found,
                models_used=sorted(list(repl.models_used)),
            )
        finally:
            if repl._ensure_watcher().is_running:
                repl._ensure_watcher().stop()
            memory.end_session(repl._session_id)
    except Exception as e:
        msg = str(e)
        if "api_key" in msg.lower() or "API key" in msg or "credentials" in msg.lower():
            show_error("No valid API key found. Set OPENROUTER_API_KEY or OPENAI_API_KEY")
        else:
            show_error(f"{msg}")
            import traceback
            traceback.print_exc()


if __name__ == "__main__":
    main()
