"""Notion page builder with rich formatting."""
from __future__ import annotations
from typing import Optional

from v2.integrations.notion.types import VulnerabilityReport, SeverityLevel, FindingStatus


class NotionPageBuilder:
    """Build richly formatted Notion pages for vulnerability reports."""

    SEVERITY_EMOJI = {
        SeverityLevel.CRITICAL: "🔴",
        SeverityLevel.HIGH: "🟠",
        SeverityLevel.MEDIUM: "🟡",
        SeverityLevel.LOW: "🔵",
        SeverityLevel.INFO: "⚪",
    }

    STATUS_EMOJI = {
        FindingStatus.OPEN: "🚨",
        FindingStatus.IN_PROGRESS: "🔧",
        FindingStatus.RESOLVED: "✅",
        FindingStatus.FALSE_POSITIVE: "❌",
        FindingStatus.ACCEPTED: "📝",
    }

    def build_report_page(self, report: VulnerabilityReport) -> list:
        blocks = []
        blocks.append(self._callout_block(
            f"{self.SEVERITY_EMOJI.get(report.severity, '⚠️')} "
            f"{report.severity.value} Vulnerability Detected",
            f"Confidence: {report.confidence:.0%} | "
            f"CWE: {report.cwe_id or 'N/A'} | "
            f"OWASP: {report.owasp_category or 'N/A'}",
            color=self._severity_color(report.severity),
        ))
        blocks.append(self._divider_block())

        blocks.append(self._heading_block("📋 Vulnerability Overview", level=2))
        blocks.append(self._table_block([
            ["Property", "Value"],
            ["Severity", f"{self.SEVERITY_EMOJI.get(report.severity, '')} {report.severity.value}"],
            ["Status", f"{self.STATUS_EMOJI.get(report.status, '')} {report.status.value}"],
            ["Confidence", f"{report.confidence:.0%}"],
            ["Security Score", f"{report.security_score:.1f}/10"],
            ["CWE ID", report.cwe_id or "N/A"],
            ["OWASP Category", report.owasp_category or "Unknown"],
            ["Vulnerability Type", report.vulnerability_type or "Unknown"],
            ["Language", report.language or "Unknown"],
            ["Repository", report.repository or "N/A"],
            ["File Path", report.file_path or "N/A"],
            ["Line Number", str(report.line_number) if report.line_number else "N/A"],
            ["Detected", report.detected_at],
            ["Updated", report.updated_at],
        ]))

        if report.description:
            blocks.append(self._heading_block("📝 Description", level=2))
            blocks.append(self._paragraph_block(report.description))

        if report.root_cause:
            blocks.append(self._heading_block("🔍 Root Cause Analysis", level=2))
            blocks.append(self._callout_block(
                "Root Cause",
                report.root_cause,
                color="orange",
            ))

        if report.attack_scenario:
            blocks.append(self._heading_block("⚔️ Attack Scenario", level=2))
            blocks.append(self._callout_block(
                "How this vulnerability can be exploited",
                report.attack_scenario,
                color="red",
            ))

        if report.original_code or report.patched_code:
            blocks.append(self._heading_block("🔄 Code Comparison", level=2))
            if report.original_code:
                blocks.append(self._heading_block("❌ Vulnerable Code", level=3))
                blocks.append(self._code_block(report.original_code, report.language or "python"))
            if report.patched_code:
                blocks.append(self._heading_block("✅ Secure Fix", level=3))
                blocks.append(self._code_block(report.patched_code, report.language or "python"))

        if report.secure_fix:
            blocks.append(self._heading_block("💡 Secure Coding Recommendation", level=2))
            blocks.append(self._callout_block(
                "How to fix this vulnerability",
                report.secure_fix,
                color="green",
            ))

        if report.related_cves:
            blocks.append(self._heading_block("🔗 Related CVEs", level=2))
            for cve in report.related_cves:
                blocks.append(self._bulleted_list_block(f"[{cve}](https://nvd.nist.gov/vuln/detail/{cve})"))

        if report.references:
            blocks.append(self._heading_block("📚 References", level=2))
            for ref in report.references:
                blocks.append(self._bulleted_list_block(ref))

        blocks.append(self._divider_block())
        blocks.append(self._heading_block("📋 Security Checklist", level=2))
        checklist_items = [
            "Vulnerability confirmed as valid",
            "Root cause identified",
            "Attack vector documented",
            "Secure fix implemented",
            "Code review completed",
            "Tests added for regression",
            "Security score updated",
        ]
        for item in checklist_items:
            blocks.append(self._to_do_block(item, checked=False))

        if report.resolution_notes:
            blocks.append(self._heading_block("📝 Resolution Notes", level=2))
            blocks.append(self._toggle_block(
                "Resolution Details",
                report.resolution_notes,
            ))

        if report.assignee:
            blocks.append(self._heading_block("👤 Assignment", level=2))
            blocks.append(self._paragraph_block(
                f"Assigned to: **{report.assignee}** | "
                f"Due: {report.due_date or 'Not set'}"
            ))

        return blocks

    def build_dashboard_blocks(self, stats: dict) -> list:
        blocks = []
        total = stats.get("total", 0)
        critical = stats.get("critical", 0)
        high = stats.get("high", 0)
        medium = stats.get("medium", 0)
        low = stats.get("low", 0)
        resolved = stats.get("resolved", 0)
        score = stats.get("security_score", 0)

        blocks.append(self._callout_block(
            f"🛡️ Security Score: {score:.1f}/10",
            f"Total: {total} | Critical: {critical} | High: {high} | "
            f"Medium: {medium} | Low: {low} | Resolved: {resolved}",
            color="green" if score >= 7 else ("yellow" if score >= 5 else "red"),
        ))
        blocks.append(self._divider_block())

        blocks.append(self._heading_block("📊 Vulnerability Distribution", level=2))
        blocks.append(self._table_block([
            ["Severity", "Count", "Percentage"],
            ["🔴 Critical", str(critical), f"{critical/max(total,1)*100:.1f}%"],
            ["🟠 High", str(high), f"{high/max(total,1)*100:.1f}%"],
            ["🟡 Medium", str(medium), f"{medium/max(total,1)*100:.1f}%"],
            ["🔵 Low", str(low), f"{low/max(total,1)*100:.1f}%"],
            ["✅ Resolved", str(resolved), f"{resolved/max(total,1)*100:.1f}%"],
        ]))

        if stats.get("top_repos"):
            blocks.append(self._heading_block("📁 Top Vulnerable Repositories", level=2))
            for repo in stats["top_repos"][:5]:
                blocks.append(self._bulleted_list_block(
                    f"**{repo['name']}** — {repo['count']} vulnerabilities"
                ))

        if stats.get("owasp_distribution"):
            blocks.append(self._heading_block("OWASP Distribution", level=2))
            for owasp in stats["owasp_distribution"][:10]:
                blocks.append(self._bulleted_list_block(
                    f"**{owasp['category']}** — {owasp['count']} findings"
                ))

        if stats.get("weekly_trend"):
            blocks.append(self._heading_block("📈 Weekly Trend", level=2))
            blocks.append(self._paragraph_block(stats["weekly_trend"]))

        return blocks

    def _heading_block(self, text: str, level: int = 1) -> dict:
        key = f"heading_{level}"
        return {
            "object": "block",
            "type": key,
            key: {
                "rich_text": [{"type": "text", "text": {"content": text}}],
                "is_toggleable": False,
            },
        }

    def _paragraph_block(self, text: str) -> dict:
        return {
            "object": "block",
            "type": "paragraph",
            "paragraph": {
                "rich_text": [{"type": "text", "text": {"content": text}}],
            },
        }

    def _callout_block(self, title: str, content: str, color: str = "blue") -> dict:
        return {
            "object": "block",
            "type": "callout",
            "callout": {
                "rich_text": [
                    {"type": "text", "text": {"content": f"{title}\n{content}"}},
                ],
                "icon": {"type": "emoji", "emoji": "🛡️"},
                "color": f"{color}_background",
            },
        }

    def _code_block(self, code: str, language: str = "python") -> dict:
        lang_map = {
            "python": "python", "javascript": "javascript", "typescript": "typescript",
            "java": "java", "go": "go", "rust": "rust", "c": "c", "cpp": "c++",
            "php": "php", "ruby": "ruby", "csharp": "c#", "sql": "sql",
            "bash": "bash", "shell": "bash", "json": "json", "yaml": "yaml",
        }
        return {
            "object": "block",
            "type": "code",
            "code": {
                "rich_text": [{"type": "text", "text": {"content": code[:2000]}}],
                "language": lang_map.get(language.lower(), "plain text"),
                "caption": [],
            },
        }

    def _table_block(self, rows: list[list[str]]) -> dict:
        table_rows = []
        for row in rows:
            table_rows.append({
                "type": "table_row",
                "table_row": {
                    "cells": [[{"type": "text", "text": {"content": cell}}] for cell in row],
                },
            })
        return {
            "object": "block",
            "type": "table",
            "table": {
                "table_width": len(rows[0]) if rows else 1,
                "has_column_header": True,
                "has_row_header": False,
                "children": table_rows[:25],
            },
        }

    def _bulleted_list_block(self, text: str) -> dict:
        return {
            "object": "block",
            "type": "bulleted_list_item",
            "bulleted_list_item": {
                "rich_text": [{"type": "text", "text": {"content": text}}],
            },
        }

    def _to_do_block(self, text: str, checked: bool = False) -> dict:
        return {
            "object": "block",
            "type": "to_do",
            "to_do": {
                "rich_text": [{"type": "text", "text": {"content": text}}],
                "checked": checked,
            },
        }

    def _toggle_block(self, title: str, content: str) -> dict:
        return {
            "object": "block",
            "type": "toggle",
            "toggle": {
                "rich_text": [{"type": "text", "text": {"content": title}}],
                "children": [
                    {
                        "type": "paragraph",
                        "paragraph": {
                            "rich_text": [{"type": "text", "text": {"content": content}}],
                        },
                    }
                ],
            },
        }

    def _divider_block(self) -> dict:
        return {"object": "block", "type": "divider", "divider": {}}

    def _severity_color(self, severity: SeverityLevel) -> str:
        return {
            SeverityLevel.CRITICAL: "red",
            SeverityLevel.HIGH: "orange",
            SeverityLevel.MEDIUM: "yellow",
            SeverityLevel.LOW: "blue",
            SeverityLevel.INFO: "gray",
        }.get(severity, "gray")
