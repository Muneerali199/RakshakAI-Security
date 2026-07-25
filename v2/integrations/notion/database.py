"""Notion database operations for Security Center."""
from __future__ import annotations
import logging
from typing import Optional

from v2.integrations.notion.client import NotionClient
from v2.integrations.notion.types import (
    DatabaseSchema, VulnerabilityReport, FindingStatus, SeverityLevel,
)

log = logging.getLogger("rakshakai.notion.db")


class NotionDatabase:
    """Manage the RakshakAI Security Center database in Notion."""

    def __init__(self, client: NotionClient):
        self.client = client
        self._database_id = client.database_id

    @property
    def database_id(self) -> str:
        return self._database_id

    @database_id.setter
    def database_id(self, value: str):
        self._database_id = value
        self.client.database_id = value

    def create_security_center(self, parent_page_id: str) -> str:
        schema = DatabaseSchema()
        result = self.client.create_database(
            parent_page_id=parent_page_id,
            title=schema.title,
            properties=schema.properties,
        )
        db_id = result["id"]
        self.database_id = db_id
        log.info(f"Created Security Center database: {db_id}")
        return db_id

    def add_vulnerability(self, report: VulnerabilityReport, children: Optional[list] = None) -> str:
        parent = {"database_id": self.database_id}
        properties = report.to_notion_properties()
        result = self.client.create_page(
            parent=parent,
            properties=properties,
            children=children,
        )
        page_id = result["id"]
        report.notion_page_id = page_id
        report.notion_database_id = self.database_id
        log.info(f"Created vulnerability page: {page_id} — {report.title}")
        return page_id

    def update_vulnerability(self, page_id: str, report: VulnerabilityReport) -> dict:
        properties = report.to_notion_properties()
        result = self.client.update_page(page_id, properties)
        log.info(f"Updated vulnerability page: {page_id}")
        return result

    def update_status(self, page_id: str, status: FindingStatus) -> dict:
        return self.client.update_page(page_id, {
            "Status": {"select": {"name": status.value}},
            "Updated Date": {"date": {"start": __import__("datetime").datetime.utcnow().isoformat()}},
        })

    def update_security_score(self, page_id: str, score: float) -> dict:
        return self.client.update_page(page_id, {
            "Security Score": {"number": round(score, 1)},
            "Updated Date": {"date": {"start": __import__("datetime").datetime.utcnow().isoformat()}},
        })

    def assign_developer(self, page_id: str, assignee: str) -> dict:
        return self.client.update_page(page_id, {
            "Assignee": {"rich_text": [{"text": {"content": assignee}}]},
        })

    def set_due_date(self, page_id: str, due_date: str) -> dict:
        return self.client.update_page(page_id, {
            "Due Date": {"date": {"start": due_date}},
        })

    def get_vulnerability(self, page_id: str) -> dict:
        return self.client.get_page(page_id)

    def list_vulnerabilities(self, status: Optional[FindingStatus] = None,
                             severity: Optional[SeverityLevel] = None,
                             language: Optional[str] = None,
                             limit: int = 100) -> list:
        filters = []
        if status:
            filters.append({"property": "Status", "select": {"equals": status.value}})
        if severity:
            filters.append({"property": "Severity", "select": {"equals": severity.value}})
        if language:
            filters.append({"property": "Language", "select": {"equals": language}})

        filter_obj = None
        if len(filters) == 1:
            filter_obj = filters[0]
        elif len(filters) > 1:
            filter_obj = {"and": filters}

        return self.client.query_database(
            self.database_id,
            filter_obj=filter_obj,
            sorts=[{"property": "Detected Date", "direction": "descending"}],
            page_size=limit,
        )

    def get_stats(self) -> dict:
        all_items = self.client.query_database(self.database_id, page_size=100)
        total = len(all_items)
        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        status_counts = {"Open": 0, "In Progress": 0, "Resolved": 0}
        language_counts = {}
        owasp_counts = {}
        repo_counts = {}
        total_score = 0
        score_count = 0

        for item in all_items:
            props = item.get("properties", {})
            sev = props.get("Severity", {}).get("select", {}).get("name", "")
            if sev in severity_counts:
                severity_counts[sev] += 1

            status = props.get("Status", {}).get("select", {}).get("name", "")
            if status in status_counts:
                status_counts[status] += 1

            lang = props.get("Language", {}).get("select", {}).get("name", "")
            if lang:
                language_counts[lang] = language_counts.get(lang, 0) + 1

            owasp = props.get("OWASP", {}).get("select", {}).get("name", "")
            if owasp:
                owasp_counts[owasp] = owasp_counts.get(owasp, 0) + 1

            repo = props.get("Repository", {}).get("rich_text", [{}])
            if repo and repo[0].get("text", {}).get("content"):
                repo_name = repo[0]["text"]["content"]
                repo_counts[repo_name] = repo_counts.get(repo_name, 0) + 1

            score = props.get("Security Score", {}).get("number")
            if score:
                total_score += score
                score_count += 1

        return {
            "total": total,
            "critical": severity_counts["Critical"],
            "high": severity_counts["High"],
            "medium": severity_counts["Medium"],
            "low": severity_counts["Low"],
            "info": severity_counts["Info"],
            "open": status_counts["Open"],
            "in_progress": status_counts["In Progress"],
            "resolved": status_counts["Resolved"],
            "security_score": total_score / max(score_count, 1),
            "top_repos": [
                {"name": k, "count": v}
                for k, v in sorted(repo_counts.items(), key=lambda x: -x[1])[:5]
            ],
            "owasp_distribution": [
                {"category": k, "count": v}
                for k, v in sorted(owasp_counts.items(), key=lambda x: -x[1])[:10]
            ],
            "language_distribution": [
                {"language": k, "count": v}
                for k, v in sorted(language_counts.items(), key=lambda x: -x[1])[:10]
            ],
        }

    def search_vulnerabilities(self, query: str) -> list:
        return self.client.search(query=query, filter_type="page", page_size=20)
