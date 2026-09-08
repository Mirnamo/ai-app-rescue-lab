from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_agent_only_sees_owned_tickets():
    response = client.get("/api/tickets", headers={"X-User": "demo-agent", "X-Role": "agent"})
    assert response.status_code == 200
    assert all(ticket["owner"] == "demo-agent" for ticket in response.json())


def test_manager_sees_all_tickets():
    response = client.get("/api/tickets", headers={"X-User": "manager", "X-Role": "manager"})
    assert len(response.json()) >= 3


def test_validation_rejects_invalid_priority():
    response = client.post("/api/tickets", json={"customer": "ACME", "subject": "Broken export", "priority": 99})
    assert response.status_code == 422


def test_non_admin_cannot_read_audit_events():
    response = client.get("/api/audit-events", headers={"X-Role": "agent"})
    assert response.status_code == 403


def test_admin_can_read_audit_events():
    client.post("/api/tickets", headers={"X-User": "admin", "X-Role": "admin"}, json={"customer": "ACME", "subject": "Webhook timeout", "priority": 3})
    response = client.get("/api/audit-events", headers={"X-User": "admin", "X-Role": "admin"})
    assert response.status_code == 200
    assert response.json()

