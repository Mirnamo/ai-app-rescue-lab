from io import BytesIO
from zipfile import ZipFile

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


def test_zip_upload_checks_dependencies_only_when_requested(monkeypatch):
    archive = BytesIO()
    with ZipFile(archive, "w") as zipped:
        zipped.writestr("requirements.txt", "jinja2==2.4.1")
    files = {"file": ("demo.zip", archive.getvalue(), "application/zip")}
    queries = []

    def query(batch):
        queries.extend(batch)
        return [{"vulns": [{"id": "PYSEC-2014-8"}]}]

    monkeypatch.setattr("app.dependency_scan.query_osv", query)
    response = client.post("/api/analyze", files=files)
    assert response.status_code == 200
    assert not queries

    response = client.post("/api/analyze", data={"check_dependencies": "true"}, files=files)
    assert response.status_code == 200
    assert queries == [{"package": {"ecosystem": "PyPI", "name": "jinja2"}, "version": "2.4.1"}]
    assert response.json()["dependencyScan"] == {"status": "complete", "checked": 1}
