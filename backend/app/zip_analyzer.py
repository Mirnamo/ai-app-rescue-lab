from __future__ import annotations

import io
import re
import stat
import zipfile
from pathlib import PurePosixPath

SKIP_PARTS = {"node_modules", ".git", "dist", "build", "vendor", ".venv"}
SUPPORTED = re.compile(r"\.(js|jsx|ts|tsx|py|php|java|rb|go|json|ya?ml|toml|env|sql|html|css|md|txt)$|(^|/)Dockerfile$|(^|/)\.env$", re.I)
RULES = [
    ("SECRET", "Possible hardcoded credential", "high", re.compile(r"""(?:api[_-]?key|secret|password|access[_-]?token)\s*[:=]\s*['"][^'"\n]{8,}['"]""", re.I), "Move credentials to server-side environment variables; rotate any exposed real credentials."),
    ("EVAL", "Dynamic code execution", "high", re.compile(r"\b(?:eval|exec)\s*\("), "Avoid executing dynamic input; use explicit parsing and allowlisted operations."),
    ("HTML", "Unsafe HTML rendering signal", "medium", re.compile(r"dangerouslySetInnerHTML|\.innerHTML\s*="), "Check the source of HTML and sanitize untrusted content before rendering."),
    ("DEBUG", "Debug mode enabled", "medium", re.compile(r"debug\s*[:=]\s*(?:true|True)\b"), "Disable debug mode in production configuration."),
    ("CORS", "Wildcard CORS policy", "medium", re.compile(r"""allow_origins\s*=\s*\[\s*['"]\*['"]|Access-Control-Allow-Origin['"]?\s*[:=]\s*['"]\*['"]""", re.I), "Review allowed origins and credential handling for sensitive endpoints."),
    ("SILENT", "Silent error handling signal", "medium", re.compile(r"catch\s*\([^)]*\)\s*\{\s*\}|except[^:\n]*:\s*pass\b|\.catch\s*\(\s*\(\)\s*=>\s*\[\]"), "Return actionable errors and log failures without exposing secrets."),
    ("SHELL", "Shell execution enabled", "high", re.compile(r"shell\s*=\s*True"), "Avoid shell execution for untrusted input; pass explicit argument lists."),
]


def analyze_zip(data: bytes, project: str) -> dict:
    if len(data) > 15 * 1024 * 1024:
        raise ValueError("ZIP exceeds the 15 MB limit.")
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except (zipfile.BadZipFile, OSError) as exc:
        raise ValueError("Invalid ZIP archive.") from exc

    infos = archive.infolist()
    if len(infos) > 2000:
        raise ValueError("Archive exceeds 2,000 entries.")
    if sum(info.file_size for info in infos) > 40 * 1024 * 1024 or any(info.file_size > 2 * 1024 * 1024 for info in infos):
        raise ValueError("Archive exceeds expanded size limits (40 MB total, 2 MB per file).")

    findings: list[dict] = []
    inventory: list[dict] = []
    expanded = 0
    try:
        for info in infos:
            normalized = info.filename.replace("\\", "/")
            path = PurePosixPath(normalized)
            mode = (info.external_attr >> 16) & 0xFFFF
            if path.is_absolute() or re.match(r"^[A-Za-z]:", normalized) or ".." in path.parts:
                raise ValueError("Unsafe archive path.")
            if stat.S_ISLNK(mode):
                raise ValueError("Archive contains a symbolic link.")
            if info.is_dir() or not SUPPORTED.search(normalized):
                continue
            if any(part in SKIP_PARTS for part in path.parts):
                continue
            try:
                chunks: list[bytes] = []
                actual_size = 0
                with archive.open(info) as member:
                    while chunk := member.read(64 * 1024):
                        actual_size += len(chunk)
                        expanded += len(chunk)
                        if actual_size > 2 * 1024 * 1024 or expanded > 40 * 1024 * 1024:
                            raise ValueError("Archive exceeds expanded size limits (40 MB total, 2 MB per file).")
                        chunks.append(chunk)
                raw = b"".join(chunks)
            except (RuntimeError, zipfile.BadZipFile, OSError) as exc:
                raise ValueError("Could not read a file in this ZIP archive.") from exc
            if b"\0" in raw:
                continue
            source = raw.decode("utf-8", errors="replace")
            lines = source.split("\n")
            inventory.append({"path": normalized, "lines": len(lines)})
            for rule, title, severity, pattern, remediation in RULES:
                match = pattern.search(source)
                if match:
                    findings.append({"id": f"{rule}-{len(findings) + 1}", "title": title, "severity": severity, "path": normalized, "line": source.count("\n", 0, match.start()) + 1, "remediation": remediation, "status": "Needs review"})
            if len(lines) > 500:
                findings.append({"id": f"SIZE-{len(findings) + 1}", "title": "Large file maintenance signal", "severity": "low", "path": normalized, "line": 1, "remediation": "Review responsibilities and split cohesive modules where appropriate.", "status": "Needs review"})
    finally:
        archive.close()

    if not inventory:
        raise ValueError("No supported text source files found in this ZIP.")
    if not any(re.search(r"(test|spec)", item["path"], re.I) for item in inventory):
        findings.append({"id": "TEST-REVIEW", "title": "No test files identified", "severity": "medium", "path": "Project", "line": None, "remediation": "Confirm tests exist outside the archive or add tests for authentication, validation, and error paths.", "status": "Needs review"})
    rank = {"high": 0, "medium": 1, "low": 2}
    findings.sort(key=lambda item: rank[item["severity"]])
    return {
        "project": project,
        "files": inventory,
        "findings": findings,
        "summary": {"files": len(inventory), "lines": sum(item["lines"] for item in inventory), "high": sum(item["severity"] == "high" for item in findings)},
        "limitations": "Static heuristic review only. Signals may be false positives and absence of findings does not establish security. Code is not executed or automatically repaired. Review authentication, business logic, dependencies, and runtime behavior separately.",
    }
