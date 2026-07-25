"""Thinking/reasoning display — shows model reasoning in real-time.
Inspired by Claude Code's thinking display with expandable/collapsible sections."""
from __future__ import annotations
import os, sys, time, threading, re
from datetime import datetime
from typing import Optional, Callable


class ThinkingDisplay:
    """Displays model reasoning in real-time with expandable/collapsible sections.

    Usage:
        with ThinkingDisplay() as td:
            td.update("Analyzing code structure...")
            td.update("Looking for CWE-89 patterns...")
            result = td.result("SQL injection detected in line 42")
    """

    SPINNER_CHARS = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]

    def __init__(self, verbose: bool = False, enabled: bool = True):
        self.enabled = enabled and sys.stdout.isatty()
        self.verbose = verbose or os.environ.get("RAKSHAK_VERBOSE", "").lower() in ("1", "true")
        self._current_line = ""
        self._thoughts: list[str] = []
        self._start_time = time.time()
        self._spinner_idx = 0
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        self._final_result = ""

    def _spin(self):
        while self._running:
            with self._lock:
                if self._current_line and self.enabled:
                    spinner = self.SPINNER_CHARS[self._spinner_idx % len(self.SPINNER_CHARS)]
                    elapsed = time.time() - self._start_time
                    sys.stderr.write(f"\r\033[2K\033[36m{spinner}\033[0m {self._current_line} \033[2m({elapsed:.0f}s)\033[0m")
                    sys.stderr.flush()
                    self._spinner_idx += 1
            time.sleep(0.1)
        sys.stderr.write("\r\033[2K")
        sys.stderr.flush()

    def __enter__(self):
        if self.enabled:
            self._running = True
            self._thread = threading.Thread(target=self._spin, daemon=True)
            self._thread.start()
        return self

    def __exit__(self, *args):
        self._running = False
        if self._thread:
            self._thread.join(timeout=0.5)

    def update(self, thought: str):
        with self._lock:
            self._thoughts.append(thought)
            self._current_line = thought[:80]

    def thought(self, text: str):
        """Record a reasoning step (always, even if display disabled)."""
        self._thoughts.append(text)
        if self.verbose:
            ts = datetime.now().strftime("%H:%M:%S")
            sys.stderr.write(f"\r\033[2K\033[2m[{ts}] \033[33m┊\033[0m {text}\n")
            sys.stderr.flush()

    def result(self, text: str) -> str:
        self._final_result = text
        elapsed = time.time() - self._start_time
        with self._lock:
            self._current_line = ""

        if self.verbose and self._thoughts:
            # Show thought chain
            sys.stderr.write(f"\n\033[2m─ Thinking chain ({elapsed:.1f}s) ─────────────────\033[0m\n")
            for t in self._thoughts[-8:]:
                sys.stderr.write(f"  \033[33m┊\033[0m {t[:120]}\n")

        return text

    def get_thoughts(self) -> list[str]:
        return self._thoughts


class ThinkingPanel:
    """Renders thinking content as a collapsible panel in the terminal."""

    COLLAPSED_HEIGHT = 5

    @staticmethod
    def render(thoughts: list[str], collapsed: bool = True, elapsed: float = 0) -> str:
        if not thoughts:
            return ""
        if collapsed and len(thoughts) > ThinkingPanel.COLLAPSED_HEIGHT:
            visible = thoughts[:ThinkingPanel.COLLAPSED_HEIGHT]
            hidden = len(thoughts) - ThinkingPanel.COLLAPSED_HEIGHT
            lines = [f"  \033[33m┊\033[0m {t[:100]}" for t in visible]
            lines.append(f"  \033[2m┊ ... ({hidden} more reasoning steps) ...\033[0m")
        else:
            lines = [f"  \033[33m┊\033[0m {t[:100]}" for t in thoughts]

        header = f"\033[2m─ Reasoning{' ' + f'({elapsed:.1f}s)' if elapsed else ''} ─\033[0m"
        return f"{header}\n" + "\n".join(lines) + "\n" + "\033[2m─" + "─" * 30 + "\033[0m"


# Streaming thinking display for real-time model output
class StreamingThinking:
    """Live-updating thinking overlay during streaming responses."""

    def __init__(self):
        self._buffer = ""
        self._thinking_start = time.time()

    def on_token(self, token: str):
        self._buffer += token
        if sys.stdout.isatty():
            elapsed = time.time() - self._thinking_start
            preview = self._buffer[-60:].replace("\n", " ").strip()
            sys.stderr.write(f"\r\033[2K\033[2m[{elapsed:.0f}s]\033[0m \033[33m⟫\033[0m {preview}")
            sys.stderr.flush()

    def done(self):
        if sys.stdout.isatty():
            sys.stderr.write("\r\033[2K")
            sys.stderr.flush()
