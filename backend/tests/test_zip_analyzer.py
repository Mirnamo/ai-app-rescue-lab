from __future__ import annotations

import io
import zipfile

import pytest

from app.zip_analyzer import analyze_zip


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
