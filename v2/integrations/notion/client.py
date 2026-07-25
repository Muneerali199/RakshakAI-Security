"""Notion API client — uses Personal Access Token only."""
from __future__ import annotations
import os
import time
import logging
from typing import Optional

import requests
from dotenv import load_dotenv
from pathlib import Path as _Path

load_dotenv(_Path(__file__).resolve().parent.parent.parent.parent / ".env")

log = logging.getLogger("rakshakai.notion")


class NotionClient:
    """Notion API client — PAT only, no OAuth needed."""

    def __init__(self, token: Optional[str] = None, database_id: Optional[str] = None):
        self._token = token or os.environ.get("NOTION_API_KEY", "") or os.environ.get("NOTION_TOKEN", "")
        self._database_id = database_id or os.environ.get("NOTION_DATABASE_ID", "")
        self._session = requests.Session()
        self._session.headers.update({
            "Authorization": f"Bearer {self._token}",
            "Notion-Version": "2022-06-28",
            "Content-Type": "application/json",
        })
        self._rate_limit_remaining = 3
        self._rate_limit_reset = 0.0

    @property
    def is_configured(self) -> bool:
        return bool(self._token)

    @property
    def database_id(self) -> str:
        return self._database_id

    @database_id.setter
    def database_id(self, value: str):
        self._database_id = value

    def _request(self, method: str, endpoint: str, **kwargs) -> dict:
        url = f"https://api.notion.com/v1{endpoint}"
        if self._rate_limit_remaining <= 1:
            wait = max(0, self._rate_limit_reset - time.time())
            if wait > 0:
                time.sleep(wait)

        resp = self._session.request(method, url, **kwargs)
        self._rate_limit_remaining = int(resp.headers.get("X-Rate-Limit-Remaining", 3))
        reset = resp.headers.get("X-Rate-Limit-Reset")
        if reset:
            self._rate_limit_reset = float(reset)

        if resp.status_code == 429:
            retry_after = float(resp.headers.get("Retry-After", "1"))
            time.sleep(retry_after)
            return self._request(method, endpoint, **kwargs)

        resp.raise_for_status()
        return resp.json()

    def get(self, endpoint: str, **kwargs) -> dict:
        return self._request("GET", endpoint, **kwargs)

    def post(self, endpoint: str, **kwargs) -> dict:
        return self._request("POST", endpoint, **kwargs)

    def patch(self, endpoint: str, **kwargs) -> dict:
        return self._request("PATCH", endpoint, **kwargs)

    def delete(self, endpoint: str, **kwargs) -> dict:
        return self._request("DELETE", endpoint, **kwargs)

    def search(self, query: str = "", filter_type: str = "page", page_size: int = 100) -> dict:
        body: dict = {"page_size": page_size}
        if query:
            body["query"] = query
        if filter_type:
            body["filter"] = {"value": filter_type, "property": "object"}
        return self.post("/search", json=body)

    def get_database(self, database_id: str) -> dict:
        return self.get(f"/databases/{database_id}")

    def create_database(self, parent_page_id: str, title: str, properties: dict) -> dict:
        body = {
            "parent": {"type": "page_id", "page_id": parent_page_id},
            "title": [{"type": "text", "text": {"content": title}}],
            "properties": properties,
        }
        return self.post("/databases", json=body)

    def query_database(self, database_id: str, filter_obj: Optional[dict] = None,
                       sorts: Optional[list] = None, page_size: int = 100) -> list:
        body: dict = {"page_size": page_size}
        if filter_obj:
            body["filter"] = filter_obj
        if sorts:
            body["sorts"] = sorts
        results = []
        while True:
            resp = self.post(f"/databases/{database_id}/query", json=body)
            results.extend(resp.get("results", []))
            if not resp.get("has_more"):
                break
            body["start_cursor"] = resp["next_cursor"]
        return results

    def create_page(self, parent: dict, properties: dict,
                    children: Optional[list] = None) -> dict:
        body: dict = {"parent": parent, "properties": properties}
        if children:
            body["children"] = children[:100]
        return self.post("/pages", json=body)

    def update_page(self, page_id: str, properties: dict) -> dict:
        return self.patch(f"/pages/{page_id}", json={"properties": properties})

    def get_page(self, page_id: str) -> dict:
        return self.get(f"/pages/{page_id}")

    def get_page_content(self, page_id: str) -> dict:
        return self.get(f"/blocks/{page_id}/children")

    def append_block_children(self, block_id: str, children: list) -> dict:
        return self.patch(f"/blocks/{block_id}/children", json={"children": children[:100]})

    def delete_block(self, block_id: str) -> dict:
        return self.delete(f"/blocks/{block_id}")

    def get_current_user(self) -> dict:
        return self.get("/users/me")
