"""File system watcher — auto-scan files on change."""
from __future__ import annotations
import os, time, threading
from pathlib import Path
from typing import Callable, Optional

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileModifiedEvent, FileCreatedEvent

from v2.cli.scanner import BatchScanner, SCAN_EXTS

class ScanEventHandler(FileSystemEventHandler):
    """Fires scan callbacks on file create/modify for source files."""

    def __init__(self, on_scan: Callable[[str], None], debounce_ms: int = 2000):
        self.on_scan = on_scan
        self.debounce_ms = debounce_ms
        self._last_trigger: dict[str, float] = {}

    def _should_scan(self, path: str) -> bool:
        ext = Path(path).suffix.lower()
        if ext not in SCAN_EXTS:
            return False
        now = time.time()
        last = self._last_trigger.get(path, 0)
        if now - last < self.debounce_ms / 1000:
            return False
        self._last_trigger[path] = now
        return True

    def on_modified(self, event):
        if not event.is_directory and self._should_scan(event.src_path):
            self.on_scan(event.src_path)

    def on_created(self, event):
        if not event.is_directory and self._should_scan(event.src_path):
            self.on_scan(event.src_path)


class FileWatcher:
    """Watch a directory and scan files on change."""

    def __init__(self, model: str = "deepseek"):
        self.model = model
        self._observer: Optional[Observer] = None
        self._handler: Optional[ScanEventHandler] = None
        self._scanner = BatchScanner(max_workers=2)
        self._results: list[dict] = []
        self._on_notify: Optional[Callable] = None

    def on_notify(self, callback: Callable):
        self._on_notify = callback

    def start(self, directory: str):
        if self._observer and self._observer.is_alive():
            return False

        abs_path = os.path.abspath(directory)
        if not os.path.isdir(abs_path):
            return False

        self._handler = ScanEventHandler(self._on_file_event)
        self._observer = Observer()
        self._observer.schedule(self._handler, abs_path, recursive=True)
        self._observer.daemon = True
        self._observer.start()
        return True

    def stop(self):
        if self._observer:
            self._observer.stop()
            self._observer = None
        self._handler = None

    @property
    def is_running(self) -> bool:
        return self._observer is not None and self._observer.is_alive()

    @property
    def results(self) -> list[dict]:
        return self._results

    @property
    def vulnerable_count(self) -> int:
        return sum(1 for r in self._results if r.get("cwe"))

    def clear_results(self):
        self._results = []

    def _on_file_event(self, file_path: str):
        """Called when a file changes — scan it in background."""
        from v2.cli.display import show_status
        from v2.cli.llm import registry as _reg
        show_status(f"[watch] change detected: {os.path.basename(file_path)}", "yellow")

        def scan_and_notify():
            try:
                results = self._scanner.scan_files([file_path], model=_reg.active)
                self._results.extend([r.to_dict() for r in results])
                for r in results:
                    if r.cwe:
                        if self._on_notify:
                            self._on_notify({
                                "file": r.file,
                                "cwe": r.cwe,
                                "severity": r.severity,
                                "summary": r.summary,
                            })
            except Exception as e:
                from v2.cli.display import show_error
                show_error(f"[watch] scan failed: {e}")

        t = threading.Thread(target=scan_and_notify, daemon=True)
        t.start()
