"""Type definitions for Notion integration."""
from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional


class SeverityLevel(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


class FindingStatus(str, Enum):
    OPEN = "Open"
    IN_PROGRESS = "In Progress"
    RESOLVED = "Resolved"
    FALSE_POSITIVE = "False Positive"
    ACCEPTED = "Accepted"


class OWASPCategory(str, Enum):
    A01_BROKEN_ACCESS_CONTROL = "A01:2021 - Broken Access Control"
    A02_CRYPTOGRAPHIC_FAILURES = "A02:2021 - Cryptographic Failures"
    A03_INJECTION = "A03:2021 - Injection"
    A04_INSECURE_DESIGN = "A04:2021 - Insecure Design"
    A05_SECURITY_MISCONFIGURATION = "A05:2021 - Security Misconfiguration"
    A06_VULNERABLE_COMPONENTS = "A06:2021 - Vulnerable and Outdated Components"
    A07_AUTH_FAILURES = "A07:2021 - Identification and Authentication Failures"
    A08_DATA_INTEGRITY = "A08:2021 - Software and Data Integrity Failures"
    A09_LOGGING_FAILURES = "A09:2021 - Security Logging and Monitoring Failures"
    A10_SSRF = "A10:2021 - Server-Side Request Forgery"
    UNKNOWN = "Unknown"


@dataclass
class NotionConfig:
    api_key: str = ""
    integration_token: str = ""
    database_id: str = ""
    dashboard_page_id: str = ""
    oauth_client_id: str = ""
    oauth_client_secret: str = ""
    oauth_redirect_uri: str = "http://localhost:8080/v2/notion/callback"
    api_version: str = "2022-06-28"
    base_url: str = "https://api.notion.com/v1"


@dataclass
class CodeBlock:
    language: str
    code: str
    label: str = ""


@dataclass
class VulnerabilityReport:
    title: str
    severity: SeverityLevel
    confidence: float
    cwe_id: str = ""
    owasp_category: str = ""
    vulnerability_type: str = ""
    repository: str = ""
    file_path: str = ""
    line_number: int = 0
    language: str = ""
    description: str = ""
    root_cause: str = ""
    attack_scenario: str = ""
    secure_fix: str = ""
    patched_code: str = ""
    original_code: str = ""
    references: list[str] = field(default_factory=list)
    related_cves: list[str] = field(default_factory=list)
    status: FindingStatus = FindingStatus.OPEN
    assignee: str = ""
    due_date: str = ""
    resolution_notes: str = ""
    security_score: float = 0.0
    detected_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    updated_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    notion_page_id: str = ""
    notion_database_id: str = ""
    tags: list[str] = field(default_factory=list)
    checklist: list[dict] = field(default_factory=list)

    def to_notion_properties(self) -> dict:
        props = {
            "Name": {"title": [{"text": {"content": self.title}}]},
            "Severity": {"select": {"name": self.severity.value}},
            "Status": {"select": {"name": self.status.value}},
            "CWE": {"rich_text": [{"text": {"content": self.cwe_id}}]},
            "Language": {"select": {"name": self.language or "Unknown"}},
        }
        return props


@dataclass
class DatabaseSchema:
    title: str = "RakshakAI Security Center"
    description: str = "AI-powered vulnerability tracking and security operations"
    properties: dict = field(default_factory=lambda: {
        "Title": {"title": {}},
        "Severity": {
            "select": {
                "options": [
                    {"name": "Critical", "color": "red"},
                    {"name": "High", "color": "orange"},
                    {"name": "Medium", "color": "yellow"},
                    {"name": "Low", "color": "blue"},
                    {"name": "Info", "color": "gray"},
                ]
            }
        },
        "Status": {
            "select": {
                "options": [
                    {"name": "Open", "color": "red"},
                    {"name": "In Progress", "color": "yellow"},
                    {"name": "Resolved", "color": "green"},
                    {"name": "False Positive", "color": "gray"},
                    {"name": "Accepted", "color": "blue"},
                ]
            }
        },
        "Confidence": {"number": {"format": "percent"}},
        "Security Score": {"number": {"format": "number"}},
        "Language": {
            "select": {
                "options": [
                    {"name": "Python", "color": "blue"},
                    {"name": "JavaScript", "color": "yellow"},
                    {"name": "TypeScript", "color": "blue"},
                    {"name": "Java", "color": "red"},
                    {"name": "Go", "color": "cyan"},
                    {"name": "Rust", "color": "orange"},
                    {"name": "C", "color": "gray"},
                    {"name": "C++", "color": "gray"},
                    {"name": "PHP", "color": "purple"},
                    {"name": "Ruby", "color": "red"},
                    {"name": "C#", "color": "green"},
                ]
            }
        },
        "Repository": {"rich_text": {}},
        "File Path": {"rich_text": {}},
        "Line Number": {"number": {}},
        "CWE ID": {"rich_text": {}},
        "OWASP": {
            "select": {
                "options": [
                    {"name": "A01:2021 - Broken Access Control", "color": "red"},
                    {"name": "A02:2021 - Cryptographic Failures", "color": "orange"},
                    {"name": "A03:2021 - Injection", "color": "red"},
                    {"name": "A04:2021 - Insecure Design", "color": "yellow"},
                    {"name": "A05:2021 - Security Misconfiguration", "color": "yellow"},
                    {"name": "A06:2021 - Vulnerable Components", "color": "orange"},
                    {"name": "A07:2021 - Auth Failures", "color": "orange"},
                    {"name": "A08:2021 - Data Integrity", "color": "yellow"},
                    {"name": "A09:2021 - Logging Failures", "color": "blue"},
                    {"name": "A10:2021 - SSRF", "color": "red"},
                ]
            }
        },
        "Vulnerability Type": {"select": {}},
        "Assignee": {"people": {}},
        "Detected Date": {"date": {}},
        "Updated Date": {"date": {}},
        "Due Date": {"date": {}},
        "Tags": {"multi_select": {"options": []}},
    })
