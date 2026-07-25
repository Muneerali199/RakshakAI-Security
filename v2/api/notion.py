"""FastAPI routes for Notion Security Hub integration."""
from __future__ import annotations
import os
import logging
from typing import Optional

from fastapi import APIRouter, HTTPException, Request, Query
from pydantic import BaseModel, Field

from v2.integrations.notion.client import NotionClient
from v2.integrations.notion.database import NotionDatabase
from v2.integrations.notion.pages import NotionPageBuilder
from v2.integrations.notion.sync import NotionSync
from v2.integrations.notion.types import (
    VulnerabilityReport, SeverityLevel, FindingStatus, NotionConfig,
)

log = logging.getLogger("rakshakai.notion.api")

router = APIRouter(prefix="/v2/notion", tags=["notion"])

_client: Optional[NotionClient] = None
_db: Optional[NotionDatabase] = None
_builder: Optional[NotionPageBuilder] = None
_sync: Optional[NotionSync] = None


def get_client() -> NotionClient:
    global _client
    if _client is None:
        _client = NotionClient()
    return _client


def get_db() -> NotionDatabase:
    global _db
    if _db is None:
        _db = NotionDatabase(get_client())
    return _db


def get_builder() -> NotionPageBuilder:
    global _builder
    if _builder is None:
        _builder = NotionPageBuilder()
    return _builder


def get_sync() -> NotionSync:
    global _sync
    if _sync is None:
        _sync = NotionSync(get_client(), get_db(), get_builder())
    return _sync


# ─── Request / Response Models ───

class CreateReportRequest(BaseModel):
    title: str = Field(..., min_length=1)
    severity: str = Field("Medium")
    confidence: float = Field(0.8, ge=0, le=1)
    cwe_id: str = Field("")
    owasp_category: str = Field("")
    vulnerability_type: str = Field("")
    repository: str = Field("")
    file_path: str = Field("")
    line_number: int = Field(0)
    language: str = Field("")
    description: str = Field("")
    root_cause: str = Field("")
    attack_scenario: str = Field("")
    secure_fix: str = Field("")
    patched_code: str = Field("")
    original_code: str = Field("")
    references: list[str] = Field(default_factory=list)
    related_cves: list[str] = Field(default_factory=list)
    assignee: str = Field("")
    due_date: str = Field("")
    tags: list[str] = Field(default_factory=list)


class UpdateStatusRequest(BaseModel):
    status: str
    notes: str = Field("")


class UpdateScoreRequest(BaseModel):
    score: float = Field(..., ge=0, le=10)


class AssignRequest(BaseModel):
    assignee: str


class SetupRequest(BaseModel):
    parent_page_id: str


# ─── Routes ───

@router.get("/health")
async def notion_health():
    client = get_client()
    configured = client.is_configured
    user = None
    if configured:
        try:
            user = client.get_current_user()
        except Exception:
            pass
    return {
        "configured": configured,
        "database_id": get_db().database_id or None,
        "user": user.get("name") if user else None,
        "queue_size": get_sync().get_queue_size(),
    }


@router.post("/setup")
async def setup_security_center(req: SetupRequest):
    if not get_client().is_configured:
        raise HTTPException(400, "Notion not configured. Set NOTION_TOKEN in .env")
    db_id = get_db().create_security_center(req.parent_page_id)
    return {"database_id": db_id, "message": "Security Center created"}


@router.post("/report")
async def create_report(req: CreateReportRequest):
    if not get_client().is_configured:
        raise HTTPException(400, "Notion not configured")

    report = VulnerabilityReport(
        title=req.title,
        severity=SeverityLevel(req.severity),
        confidence=req.confidence,
        cwe_id=req.cwe_id,
        owasp_category=req.owasp_category,
        vulnerability_type=req.vulnerability_type,
        repository=req.repository,
        file_path=req.file_path,
        line_number=req.line_number,
        language=req.language,
        description=req.description,
        root_cause=req.root_cause,
        attack_scenario=req.attack_scenario,
        secure_fix=req.secure_fix,
        patched_code=req.patched_code,
        original_code=req.original_code,
        references=req.references,
        related_cves=req.related_cves,
        assignee=req.assignee,
        due_date=req.due_date,
        tags=req.tags,
    )

    sync = get_sync()
    page_id = sync.report_vulnerability(report)

    if not page_id:
        return {"queued": True, "queue_size": sync.get_queue_size()}

    return {
        "page_id": page_id,
        "url": f"https://notion.so/{page_id.replace('-', '')}",
        "message": "Report created in Notion Security Center",
    }


@router.post("/report/{page_id}/status")
async def update_status(page_id: str, req: UpdateStatusRequest):
    try:
        status = FindingStatus(req.status)
    except ValueError:
        raise HTTPException(400, f"Invalid status: {req.status}")

    sync = get_sync()
    if status == FindingStatus.RESOLVED:
        sync.mark_fixed(page_id, req.notes)
    else:
        sync.mark_in_progress(page_id) if status == FindingStatus.IN_PROGRESS else \
        sync.mark_false_positive(page_id) if status == FindingStatus.FALSE_POSITIVE else \
        get_db().update_status(page_id, status)

    return {"page_id": page_id, "status": req.status}


@router.post("/report/{page_id}/score")
async def update_score(page_id: str, req: UpdateScoreRequest):
    get_sync().update_score(page_id, req.score)
    return {"page_id": page_id, "score": req.score}


@router.post("/report/{page_id}/assign")
async def assign_developer(page_id: str, req: AssignRequest):
    get_sync().assign(page_id, req.assignee)
    return {"page_id": page_id, "assignee": req.assignee}


@router.get("/reports")
async def list_reports(
    status: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    language: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=100),
):
    s = FindingStatus(status) if status else None
    sev = SeverityLevel(severity) if severity else None
    items = get_db().list_vulnerabilities(status=s, severity=sev, language=language, limit=limit)
    return {"reports": items, "count": len(items)}


@router.get("/stats")
async def get_stats():
    return get_db().get_stats()


@router.get("/dashboard")
async def get_dashboard():
    stats = get_db().get_stats()
    builder = get_builder()
    blocks = builder.build_dashboard_blocks(stats)
    return {"stats": stats, "blocks": blocks}


@router.post("/webhook")
async def notion_webhook(request: Request):
    body = await request.body()
    event = await request.json()
    event_type = event.get("type", "")
    log.info(f"Notion webhook: {event_type}")
    return {"received": True}
