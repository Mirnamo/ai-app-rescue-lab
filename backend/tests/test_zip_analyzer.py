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


def test_ignores_dependency_directories() -> None:
    report = analyze_zip(make_archive({
        "node_modules/lib/index.js": "eval(input())",
        "src/main.js": "export const ok = true",
    }), "sample")
    assert [item["path"] for item in report["files"]] == ["src/main.js"]


def test_rejects_non_zip() -> None:
    with pytest.raises(ValueError, match="Invalid ZIP"):
        analyze_zip(b"not a zip", "sample")
