from __future__ import annotations

from uuid import uuid4
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .auth import Identity, identity, require_admin
from .case_study import case_study
from .models import AuditEvent, Ticket, TicketCreate, TicketPatch
from .service import RescueService

app = FastAPI(title="AI App Rescue Lab", version="1.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:5173"], allow_methods=["*"], allow_headers=["*"])
service = RescueService()


@app.middleware("http")
async def correlation_id(request: Request, call_next):
    request_id = request.headers.get("X-Request-ID", str(uuid4()))[:80]
    try:
        response = await call_next(request)
    except Exception:
        return JSONResponse(status_code=500, content={"error": {"code": "internal_error", "message": "Unexpected server error", "request_id": request_id}})
    response.headers["X-Request-ID"] = request_id
    return response


@app.get("/")
def root() -> dict[str, str]:
    return {
        "name": "AI App Rescue Lab API",
        "health": "/health",
        "case_study": "/api/case-study",
        "docs": "/docs",
    }


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/api/case-study")
def get_case_study() -> dict:
    return case_study()


@app.get("/api/tickets", response_model=list[Ticket])
def list_tickets(user: Identity = Depends(identity)) -> list[Ticket]:
    return service.visible_tickets(user)


@app.post("/api/tickets", response_model=Ticket, status_code=201)
def create_ticket(data: TicketCreate, user: Identity = Depends(identity)) -> Ticket:
    return service.create(data, user)


@app.patch("/api/tickets/{ticket_id}", response_model=Ticket)
def update_ticket(ticket_id: int, patch: TicketPatch, user: Identity = Depends(identity)) -> Ticket:
    ticket = service.update(ticket_id, patch, user)
    if ticket is None:
        raise HTTPException(status_code=404, detail={"code": "not_found", "message": "Ticket not found or unavailable"})
    return ticket


@app.get("/api/audit-events", response_model=list[AuditEvent])
def audit_events(user: Identity = Depends(identity)) -> list[AuditEvent]:
    require_admin(user)
    return list(reversed(service.events))

