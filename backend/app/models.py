from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from pydantic import BaseModel, Field


class Role(StrEnum):
    AGENT = "agent"
    MANAGER = "manager"
    ADMIN = "admin"


class TicketStatus(StrEnum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"


class TicketCreate(BaseModel):
    customer: str = Field(min_length=2, max_length=80)
    subject: str = Field(min_length=5, max_length=140)
    priority: int = Field(default=2, ge=1, le=4)


class Ticket(TicketCreate):
    id: int
    owner: str
    status: TicketStatus
    created_at: datetime


class TicketPatch(BaseModel):
    status: TicketStatus


class AuditEvent(BaseModel):
    id: int
    actor: str
    role: Role
    action: str
    target: str
    occurred_at: datetime


class Finding(BaseModel):
    id: str
    title: str
    severity: str
    category: str
    evidence: str
    remediation: str
    status: str

