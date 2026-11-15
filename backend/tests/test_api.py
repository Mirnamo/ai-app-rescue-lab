from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_root_describes_api_entry_points():
    response = client.get("/")
    assert response.status_code == 200
    assert response.json()["analyze"] == "/api/analyze"


def test_removed_demo_routes_return_not_found():
    assert client.get("/api/tickets").status_code == 404
    assert client.get("/api/audit-events").status_code == 404
    assert client.get("/api/case-study").status_code == 404
