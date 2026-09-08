from __future__ import annotations

from datetime import datetime, timezone
from threading import Lock
from .models import AuditEvent, Role, Ticket, TicketCreate, TicketPatch, TicketStatus
from .auth import Identity


class RescueService:
    def __init__(self) -> None:
        self._lock = Lock()
        now = datetime.now(timezone.utc)
        self.tickets = [
            Ticket(id=1, customer="Northwind", subject="Invoice export returns duplicate rows", priority=4, owner="demo-agent", status=TicketStatus.IN_PROGRESS, created_at=now),
            Ticket(id=2, customer="Contoso", subject="New user cannot access shared workspace", priority=3, owner="sana", status=TicketStatus.OPEN, created_at=now),
            Ticket(id=3, customer="Fabrikam", subject="Webhook delivery is delayed", priority=2, owner="demo-agent", status=TicketStatus.OPEN, created_at=now),
        ]
        self.events: list[AuditEvent] = []

    def visible_tickets(self, user: Identity) -> list[Ticket]:
        if user.role in {Role.MANAGER, Role.ADMIN}:
            return list(self.tickets)
        return [ticket for ticket in self.tickets if ticket.owner == user.username]

    def create(self, data: TicketCreate, user: Identity) -> Ticket:
        with self._lock:
            ticket = Ticket(id=max((item.id for item in self.tickets), default=0) + 1, owner=user.username, status=TicketStatus.OPEN, created_at=datetime.now(timezone.utc), **data.model_dump())
            self.tickets.append(ticket)
            self._audit(user, "ticket.created", f"ticket:{ticket.id}")
            return ticket

    def update(self, ticket_id: int, patch: TicketPatch, user: Identity) -> Ticket | None:
        with self._lock:
            for index, ticket in enumerate(self.tickets):
                if ticket.id != ticket_id:
                    continue
                if user.role is Role.AGENT and ticket.owner != user.username:
                    return None
                updated = ticket.model_copy(update={"status": patch.status})
                self.tickets[index] = updated
                self._audit(user, f"ticket.status.{patch.status}", f"ticket:{ticket.id}")
                return updated
        return None

    def _audit(self, user: Identity, action: str, target: str) -> None:
        self.events.append(AuditEvent(id=len(self.events) + 1, actor=user.username, role=user.role, action=action, target=target, occurred_at=datetime.now(timezone.utc)))

