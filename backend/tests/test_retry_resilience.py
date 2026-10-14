from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest
from fastapi.testclient import TestClient
from app.auth import Identity
from app.models import Role, TicketCreate
from app.service import RescueService
from app import main


DATA = {"customer": "Northwind", "subject": "Export failed after timeout", "priority": 2}
USER = Identity("retry-agent", Role.AGENT)


def test_baseline_without_key_creates_duplicates():
    service = RescueService()
    first = service.create(TicketCreate(**DATA), USER)
    second = service.create(TicketCreate(**DATA), USER)
    assert first.id != second.id
    assert len(service.events) == 2


def test_lost_response_retry_returns_original_ticket():
    service = RescueService()
    # Server commits, but the caller loses the response. Retry the same intent.
    committed = service.create(TicketCreate(**DATA), USER, "request-1")
    retried = service.create(TicketCreate(**DATA), USER, "request-1")
    assert retried.model_dump() == committed.model_dump()
    assert len(service.visible_tickets(USER)) == 1
    assert len(service.events) == 1


def test_twenty_simultaneous_retries_create_once():
    service = RescueService()
    barrier = Barrier(20)
    def submit(_):
        barrier.wait(timeout=10)
        return service.create(TicketCreate(**DATA), USER, "concurrent").id
    with ThreadPoolExecutor(max_workers=20) as pool:
        ids = list(pool.map(submit, range(20)))
    assert len(set(ids)) == 1
    assert len(service.visible_tickets(USER)) == 1
    assert len(service.events) == 1


def test_key_reuse_with_changed_payload_is_rejected():
    service = RescueService()
    service.create(TicketCreate(**DATA), USER, "same")
    with pytest.raises(ValueError):
        service.create(TicketCreate(**{**DATA, "priority": 4}), USER, "same")
    assert len(service.events) == 1


def test_keys_are_scoped_to_user():
    service = RescueService()
    first = service.create(TicketCreate(**DATA), USER, "same")
    second = service.create(TicketCreate(**DATA), Identity("other", Role.AGENT), "same")
    assert first.id != second.id
    assert second.owner == "other"


def test_new_keys_allow_identical_legitimate_tickets():
    service = RescueService()
    first = service.create(TicketCreate(**DATA), USER, "intent-1")
    second = service.create(TicketCreate(**DATA), USER, "intent-2")
    assert first.id != second.id


def test_replay_preserves_original_response_after_status_change():
    from app.models import TicketPatch, TicketStatus
    service = RescueService()
    first = service.create(TicketCreate(**DATA), USER, "same")
    service.update(first.id, TicketPatch(status=TicketStatus.RESOLVED), USER)
    replay = service.create(TicketCreate(**DATA), USER, "same")
    assert replay.status == first.status == TicketStatus.OPEN
    assert service.visible_tickets(USER)[0].status == TicketStatus.RESOLVED


def test_api_retry_and_conflict(monkeypatch):
    service = RescueService()
    monkeypatch.setattr(main, "service", service)
    with TestClient(main.app) as client:
        headers = {"X-User": USER.username, "Idempotency-Key": "api-retry"}
        first = client.post("/api/tickets", json=DATA, headers=headers)
        retry = client.post("/api/tickets", json=DATA, headers=headers)
        conflict = client.post("/api/tickets", json={**DATA, "priority": 4}, headers=headers)
    assert first.status_code == retry.status_code == 201
    assert first.json() == retry.json()
    assert conflict.status_code == 409
    assert len(service.events) == 1


@pytest.mark.parametrize("key", ["", "   ", "x" * 129])
def test_invalid_api_keys_do_not_create_tickets(monkeypatch, key):
    service = RescueService()
    monkeypatch.setattr(main, "service", service)
    with TestClient(main.app) as client:
        response = client.post("/api/tickets", json=DATA, headers={"Idempotency-Key": key})
    assert response.status_code == 422
    assert service.events == []
