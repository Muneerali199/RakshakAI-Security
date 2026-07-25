"""Permission/approval system — ask user before dangerous operations (Claude Code-style).
Every file write/edit requires approval. Shows diff previews."""
from __future__ import annotations
import os, sys, difflib
from pathlib import Path
from typing import Optional


class PermissionDenied(Exception):
    pass


class ApprovalManager:
    """Manages user approval for file operations with modes:
    - 'always_ask': prompt for every operation (default)
    - 'accept_edits': auto-approve edits, ask for write/create
    - 'plan': auto-deny all writes, show what would happen
    - 'auto': auto-approve known-safe operations
    """

    MODES = ["always_ask", "accept_edits", "plan", "auto"]

    def __init__(self, mode: str = "always_ask"):
        self.mode = mode if mode in self.MODES else "always_ask"
        self._approved_hashes: set[str] = set()
        self._denied_patterns: list[str] = []

    def set_mode(self, mode: str):
        if mode in self.MODES:
            self.mode = mode

    def require_approval(
        self,
        operation: str,
        file_path: str,
        old_string: str = "",
        new_string: str = "",
        diff: str = "",
    ) -> bool:
        """Check if operation needs approval. Returns True if approved."""
        if self.mode == "auto":
            return True
        if self.mode == "plan":
            self._show_plan_preview(operation, file_path, diff or new_string)
            return False

        # Show diff preview
        self._show_diff_preview(operation, file_path, diff, old_string, new_string)

        if self.mode == "accept_edits" and operation in ("edit", "write"):
            return True

        return self._prompt_user(operation, file_path)

    def _show_diff_preview(self, operation: str, file_path: str, diff: str, old: str, new: str):
        from v2.cli.display import console
        from rich.panel import Panel
        from rich.syntax import Syntax
        from rich.table import Table

        rel = os.path.relpath(file_path)
        ext = Path(file_path).suffix.lstrip(".")

        if diff:
            # Show unified diff
            syntax = Syntax(diff[:2000], "diff", theme="monokai")
            console.print(Panel(
                syntax,
                title=f"[bold]{'✏️' if operation == 'edit' else '📝'} {operation.title()}: {rel}[/]",
                border_style="yellow",
            ))
        elif old and new:
            # Side-by-side for short strings
            old_syntax = Syntax(old[:500], ext or "python", theme="monokai")
            new_syntax = Syntax(new[:500], ext or "python", theme="monokai")
            table = Table(box=None, padding=(0, 2), show_header=True)
            table.add_column(f"[red]Before[/]", style="red")
            table.add_column(f"[green]After[/]", style="green")
            table.add_row(old_syntax, new_syntax)
            console.print(Panel(
                table,
                title=f"[bold]{'✏️' if operation == 'edit' else '📝'} {operation.title()}: {rel}[/]",
                border_style="yellow",
            ))
        elif new:
            # Show new content for writes
            syntax = Syntax(new[:1000], ext or "python", theme="monokai")
            console.print(Panel(
                syntax,
                title=f"[bold]📝 Create: {rel}[/]",
                border_style="yellow",
            ))

    def _show_plan_preview(self, operation: str, file_path: str, content: str):
        """In plan mode, just show what would happen without asking."""
        from v2.cli.display import console
        from rich.panel import Panel
        rel = os.path.relpath(file_path)
        preview = content[:500]
        console.print(Panel(
            f"[yellow]{'✏️' if operation == 'edit' else '📝'} {operation}[/] [cyan]{rel}[/]\n"
            f"[dim]{preview}[/]",
            title="[bold]Plan Preview[/]",
            border_style="blue",
        ))

    def _prompt_user(self, operation: str, file_path: str) -> bool:
        """Ask user for approval via rich prompt."""
        from rich.prompt import Confirm
        from v2.cli.display import console

        rel = os.path.relpath(file_path)
        icon = "✏️" if operation == "edit" else "📝" if operation == "write" else "❓"

        console.print()
        result = Confirm.ask(
            f"  [bold]{icon} {operation}[/] [cyan]{rel}[/] — [dim]Approve?[/]",
            default=True,
        )
        console.print()
        return result

    def approve_dangerous(self, operation: str, details: str) -> bool:
        """For dangerous operations (bash, rm, etc.), require explicit approval."""
        from rich.prompt import Confirm
        from v2.cli.display import console

        console.print(f"\n[bold red]⚠️  Dangerous Operation[/]")
        console.print(f"  [yellow]{operation}[/]: [dim]{details[:200]}[/]\n")
        result = Confirm.ask("  [bold]Are you sure?[/]", default=False)
        console.print()
        return result


# Global approval manager
approval = ApprovalManager()

# Patch the EditTool to use approvals
_original_edit_apply = None


def patch_tools_with_approval():
    """Patch agentic tools to ask for approval before writing."""
    from v2.cli.agentic_tools import EditTool, BashTool

    original_edit = EditTool.edit
    original_write = EditTool.write
    original_bash = BashTool.bash

    def approved_edit(self, file_path, old_string, new_string):
        content = Path(file_path).read_text(encoding="utf-8", errors="replace") if Path(file_path).exists() else ""
        diff = _make_diff(content, content.replace(old_string, new_string, 1), file_path)
        if approval.require_approval("edit", file_path, old_string, new_string, diff):
            return original_edit(self, file_path, old_string, new_string)
        return {"skipped": True, "reason": "User denied permission"}

    def approved_write(self, file_path, content):
        if approval.require_approval("write", file_path, new_string=content):
            return original_write(self, file_path, content)
        return {"skipped": True, "reason": "User denied permission"}

    DANGEROUS_CMDS = ["rm", "dd", "mkfs", ">", "chmod", "sudo", "wget", "curl"]

    def approved_bash(self, command, timeout=120, workdir=None):
        is_dangerous = any(cmd in command for cmd in DANGEROUS_CMDS)
        if is_dangerous:
            if not approval.approve_dangerous("bash", command):
                return {"skipped": True, "reason": "User denied dangerous command"}
        return original_bash(self, command, timeout, workdir)

    EditTool.edit = approved_edit
    EditTool.write = approved_write
    BashTool.bash = approved_bash


def _make_diff(old: str, new: str, filepath: str) -> str:
    diff = difflib.unified_diff(
        old.splitlines(keepends=True),
        new.splitlines(keepends=True),
        fromfile=filepath, tofile=filepath,
    )
    return "".join(diff)
