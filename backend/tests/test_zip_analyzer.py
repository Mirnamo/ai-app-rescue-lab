from __future__ import annotations

import io
import json
import zipfile

import pytest

from app.zip_analyzer import analyze_zip


def test_reports_new_source_patterns_with_locations() -> None:
    report = analyze_zip(make_archive({
        "network.py": 'response = requests.get(\n    target, verify=False\n)\nhttpx.get(request.query_params["url"])',
        "logs.js": 'console.info("password changed");\nconsole.info("headers", req.headers.authorization);',
        "payload.py": "yaml.safe_load(body)\npickle.loads(body)",
        "webhooks.js": 'app.post("/webhooks/safe", (req) => stripe.webhooks.constructEvent(req.rawBody, sig, secret));\napp.post("/webhooks/unsafe", (req) => processEvent(req.body));',
        "safe.py": 'requests.get(url, verify=True)\nhttpx.get("https://example.com")',
    }), "demo")

    assert sorted(
        (item["id"].rsplit("-", 1)[0], item["path"], item["line"])
        for item in report["findings"] if item["id"] != "TEST-REVIEW"
    ) == [
        ("DESERIALIZE", "payload.py", 2),
        ("SECRET-LOG", "logs.js", 2),
        ("SSRF", "network.py", 4),
        ("TLS-VERIFY", "network.py", 1),
        ("WEBHOOK-SIGNATURE", "webhooks.js", 2),
    ]


def test_reports_dependency_advisories_and_keeps_source_findings_when_unavailable(monkeypatch) -> None:
    archive = make_archive({
        "package-lock.json": json.dumps({"packages": {
            "": {"name": "private-project", "version": "1.0.0"},
            "node_modules/lodash": {"version": "4.17.20", "resolved": "https://private.example/archive"},
        }}),
        "backend/requirements.txt": "Jinja2==2.4.1\nrequests>=2.0\nprivate @ https://private.example/archive",
        "app.js": "eval(input);",
    })

    def query(queries):
        assert queries == [
            {"package": {"ecosystem": "npm", "name": "lodash"}, "version": "4.17.20"},
            {"package": {"ecosystem": "PyPI", "name": "jinja2"}, "version": "2.4.1"},
        ]
        return [{"vulns": [{"id": "CVE-2021-23337"}]}, {}]

    monkeypatch.setattr("app.dependency_scan.query_osv", query)
    assert "dependencyScan" not in analyze_zip(archive, "demo")
    report = analyze_zip(archive, "demo", check_dependencies=True)
    assert report["dependencyScan"] == {"status": "complete", "checked": 2}
    dependency = next(item for item in report["findings"] if item["id"].startswith("DEPENDENCY-"))
    assert dependency["advisories"] == ["CVE-2021-23337"]

    def fail(_queries):
        raise OSError("offline")

    monkeypatch.setattr("app.dependency_scan.query_osv", fail)
    report = analyze_zip(archive, "demo", check_dependencies=True)
    assert report["dependencyScan"] == {"status": "unavailable", "checked": 0}
    assert any(item["id"].startswith("EVAL-") for item in report["findings"])


def make_archive(files: dict[str, str]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for path, content in files.items():
            archive.writestr(path, content)
    return buffer.getvalue()


def test_reports_credential_signal_with_line_number() -> None:
    report = analyze_zip(make_archive({"src/app.py": "# sample\npassword = 'not-a-real-secret-value'\n"}), "sample")
    finding = next(item for item in report["findings"] if item["id"].startswith("SECRET"))
    assert finding["path"] == "src/app.py"
    assert finding["line"] == 2
    assert report["summary"]["high"] == 1


def test_lists_explicit_cors_origins_and_their_locations_for_review() -> None:
    report = analyze_zip(make_archive({
        "app.py": 'allow_origins = [\n  "https://shop.example",\n  "http://[::1]:5173",\n]',
        "app.js": 'res.setHeader("Access-Control-Allow-Origin", "https://partner.example");',
        "other.js": 'const url = "https://unrelated.example";',
        "wildcard.py": 'allow_origins = ["*"]',
        "userinfo.py": 'allow_origins = ["https://user:secret@shop.example"]',
    }), "sample")
    assert report["corsOrigins"] == [
        {"origin": "https://shop.example", "path": "app.py", "line": 2},
        {"origin": "http://[::1]:5173", "path": "app.py", "line": 3},
        {"origin": "https://partner.example", "path": "app.js", "line": 1},
    ]


def test_rejects_traversal_path() -> None:
    with pytest.raises(ValueError, match="Unsafe archive path"):
        analyze_zip(make_archive({"../escape.py": "print('x')"}), "sample")


@pytest.mark.parametrize("path", ["src/.env", "config/.ENV.local", "deployment/prod.env", "vendor/.env"])
def test_rejects_archives_with_environment_files(path: str) -> None:
    with pytest.raises(ValueError, match="ZIP contains an environment file"):
        analyze_zip(make_archive({"app.py": "print('x')", path: "KEY=placeholder"}), "sample")


def test_flags_request_origins_copied_into_cors_response_headers() -> None:
    report = analyze_zip(make_archive({
        "app.js": '// CORS configuration\nres.setHeader("access-control-allow-origin", req.headers.origin);',
        "app.py": '# CORS configuration\nresponse.headers["Access-Control-Allow-Origin"] = request.headers.get("Origin")',
        "fixed.js": 'res.setHeader("Access-Control-Allow-Origin", "https://app.example");',
    }), "sample")
    reflected = [item for item in report["findings"] if item["id"].startswith("CORS-REFLECT")]
    assert [(item["path"], item["line"]) for item in reflected] == [("app.js", 2), ("app.py", 2)]


def test_ignores_dependency_directories() -> None:
    report = analyze_zip(make_archive({
        "node_modules/lib/index.js": "eval(input())",
        "src/main.js": "export const ok = true",
    }), "sample")
    assert [item["path"] for item in report["files"]] == ["src/main.js"]


def test_rejects_non_zip() -> None:
    with pytest.raises(ValueError, match="Invalid ZIP"):
        analyze_zip(b"not a zip", "sample")


def test_flags_client_controlled_roles_and_interpolated_sql() -> None:
    source = (
        "def is_admin(headers):\n"
        "    return headers.get('X-User-Role') == 'admin'\n"
        "query = f'SELECT * FROM users WHERE email = {email}'\n"
    )
    report = analyze_zip(make_archive({
        "src/routes.py": source,
        "src/routes.test.py": "assert True\n",
    }), "sample")
    auth = next(item for item in report["findings"] if item["id"].startswith("AUTH"))
    sql = next(item for item in report["findings"] if item["id"].startswith("SQL"))
    assert auth["path"] == "src/routes.py"
    assert auth["line"] == 2
    assert sql["path"] == "src/routes.py"
    assert sql["line"] == 3


def test_does_not_flag_trusted_roles_or_parameterized_sql() -> None:
    report = analyze_zip(make_archive({
        "src/safe.py": (
            "def is_admin(current_user):\n"
            "    return current_user.role == 'admin'\n"
            "cursor.execute('SELECT * FROM users WHERE email = ?', (email,))\n"
        ),
        "src/safe.test.py": "assert True\n",
    }), "sample")
    assert not any(item["id"].startswith(("AUTH", "SQL")) for item in report["findings"])
