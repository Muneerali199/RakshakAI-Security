"""Sync mechanism for Notion integration."""
from __future__ import annotations
import json
import logging
import time
import threading
from pathlib import Path
from typing import Optional, Callable
from datetime import datetime

from v2.integrations.notion.client import NotionClient
from v2.integrations.notion.database import NotionDatabase
from v2.integrations.notion.pages import NotionPageBuilder
from v2.integrations.notion.types import VulnerabilityReport, FindingStatus

log = logging.getLogger("rakshakai.notion.sync")

SYNC_STATE_FILE = Path.home() / ".rakshak" / "notion_sync.json"


class NotionSync:
    """Bidirectional sync between RakshakAI and Notion."""

    def __init__(self, client: NotionClient, database: NotionDatabase,
                 builder: NotionPageBuilder):
        self.client = client
        self.database = database
        self.builder = builder
        self._sync_queue: list[dict] = []
        self._lock = threading.Lock()
        self._running = False
        self._callbacks: dict[str, list[Callable]] = {
            "on_create": [],
            "on_update": [],
            "on_status_change": [],
            "on_sync_complete": [],
        }
        self._load_state()

    def _load_state(self):
        if SYNC_STATE_FILE.exists():
            try:
                state = json.loads(SYNC_STATE_FILE.read_text())
                self._sync_queue = state.get("queue", [])
            except Exception:
                self._sync_queue = []

    def _save_state(self):
        SYNC_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        SYNC_STATE_FILE.write_text(json.dumps({
            "queue": self._sync_queue,
            "last_sync": datetime.utcnow().isoformat(),
        }, indent=2))

    def on(self, event: str, callback: Callable):
        if event in self._callbacks:
            self._callbacks[event].append(callback)

    def _emit(self, event: str, data: dict):
        for cb in self._callbacks.get(event, []):
            try:
                cb(data)
            except Exception as e:
                log.error(f"Sync callback error: {e}")

    def report_vulnerability(self, report: VulnerabilityReport) -> str:
        if not self.client.is_configured:
            log.warning("Notion not configured — queuing report")
            self._sync_queue.append({
                "report": report.__dict__,
                "action": "create",
                "queued_at": datetime.utcnow().isoformat(),
            })
            self._save_state()
            return ""

        if not self.database.database_id:
            log.warning("No Notion database_id set — queuing report")
            self._sync_queue.append({
                "report": report.__dict__,
                "action": "create",
                "queued_at": datetime.utcnow().isoformat(),
            })
            self._save_state()
            return ""

        children = self.builder.build_report_page(report)
        page_id = self.database.add_vulnerability(report, children)
        self._emit("on_create", {"page_id": page_id, "report": report})
        return page_id

    def update_report(self, page_id: str, report: VulnerabilityReport):
        self.database.update_vulnerability(page_id, report)
        self._emit("on_update", {"page_id": page_id, "report": report})

    def mark_fixed(self, page_id: str, notes: str = ""):
        report = VulnerabilityReport(
            title="",
            severity=SeverityLevel.INFO,
            confidence=0,
            status=FindingStatus.RESOLVED,
            resolution_notes=notes,
            updated_at=datetime.utcnow().isoformat(),
        )
        self.database.update_status(page_id, FindingStatus.RESOLVED)
        self._emit("on_status_change", {
            "page_id": page_id,
            "status": "resolved",
            "notes": notes,
        })

    def mark_in_progress(self, page_id: str):
        self.database.update_status(page_id, FindingStatus.IN_PROGRESS)
        self._emit("on_status_change", {"page_id": page_id, "status": "in_progress"})

    def mark_false_positive(self, page_id: str):
        self.database.update_status(page_id, FindingStatus.FALSE_POSITIVE)

    def update_score(self, page_id: str, score: float):
        self.database.update_security_score(page_id, score)

    def assign(self, page_id: str, developer: str):
        self.database.assign_developer(page_id, developer)

    def set_due(self, page_id: str, date: str):
        self.database.set_due_date(page_id, date)

    def flush_queue(self):
        with self._lock:
            if not self._sync_queue:
                return
            log.info(f"Flushing {len(self._sync_queue)} queued reports")
            remaining = []
            for item in self._sync_queue:
                try:
                    report = VulnerabilityReport(**item["report"])
                    self.report_vulnerability(report)
                except Exception as e:
                    log.error(f"Failed to sync queued item: {e}")
                    remaining.append(item)
            self._sync_queue = remaining
            self._save_state()
            self._emit("on_sync_complete", {"synced": len(self._sync_queue) - len(remaining)})

    def get_queue_size(self) -> int:
        return len(self._sync_queue)

    def start_auto_sync(self, interval: int = 30):
        self._running = True
        def _sync_loop():
            while self._running:
                time.sleep(interval)
                if self._sync_queue:
                    self.flush_queue()
        t = threading.Thread(target=_sync_loop, daemon=True)
        t.start()

    def stop_auto_sync(self):
        self._running = False
