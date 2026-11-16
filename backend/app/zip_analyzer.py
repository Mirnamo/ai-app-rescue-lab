from __future__ import annotations

import io
import re
import stat
import zipfile
from pathlib import PurePosixPath

from .dependency_scan import collect_dependencies, scan_dependencies

SKIP_PARTS = {"node_modules", ".git", "dist", "build", "vendor", ".venv"}
CORS_SETTINGS = re.compile(
    r"""\b(?:Access-Control-Allow-Origin['"]?\s*(?:\]\s*=|[:,])|(?:allow_origins|allowed_origins|allowedOrigins)['"]?\s*[:=])\s*(\[\s*(?:['"][^'"\r\n]*['"]\s*,\s*)*['"][^'"\r\n]*['"]\s*,?\s*\]|['"][^'"\r\n]*['"])""", re.I | re.ASCII
)
CORS_ORIGIN = re.compile(r"""['"](https?://(?:[a-z0-9.-]+|\[[0-9a-f:]+\])(?::[0-9]{1,5})?)['"]""", re.I | re.ASCII)
SUPPORTED = re.compile(r"\.(js|jsx|ts|tsx|py|php|java|rb|go|json|ya?ml|toml|env|sql|html|css|md|txt)$|(^|/)Dockerfile$|(^|/)\.env$", re.I)
WEBHOOK_VERIFICATION = re.compile(r"\b(?:constructEvent(?:Async)?|construct_event|verify_signature|verifySignature|verify_webhook(?:_signature)?|verifyWebhook(?:Signature)?|timingSafeEqual|compare_digest)\s*\(")
ROUTE_DECLARATION = re.compile(r"""\b(?:app|router|bp|blueprint)\.(?:get|post|put|patch|delete|route)\s*\(\s*['"]""", re.I)
RULES = [
    ("SECRET", "Possible hardcoded credential", "high", re.compile(r"""(?:api[_-]?key|secret|password|access[_-]?token)\s*[:=]\s*['"][^'"\n]{8,}['"]""", re.I), "Move credentials to server-side environment variables; rotate any exposed real credentials."),
    ("EVAL", "Dynamic code execution", "high", re.compile(r"\b(?:eval|exec)\s*\("), "Avoid executing dynamic input; use explicit parsing and allowlisted operations."),
    ("HTML", "Unsafe HTML rendering signal", "medium", re.compile(r"dangerouslySetInnerHTML|\.innerHTML\s*="), "Check the source of HTML and sanitize untrusted content before rendering."),
    ("DEBUG", "Debug mode enabled", "medium", re.compile(r"debug\s*[:=]\s*(?:true|True)\b"), "Disable debug mode in production configuration."),
    ("CORS", "Wildcard CORS policy", "medium", re.compile(r"""allow_origins\s*=\s*\[\s*['"]\*['"]|Access-Control-Allow-Origin['"]?\s*[:=]\s*['"]\*['"]""", re.I), "Review allowed origins and credential handling for sensitive endpoints."),
    (
        "CORS-REFLECT", "Possible CORS origin reflection", "medium",
        re.compile(r"""\bAccess-Control-Allow-Origin['"]\s*(?:\]\s*=|[:,])\s*(?:req|request)\s*\.\s*(?:headers\s*(?:\.\s*origin\b|\[\s*['"]origin['"]\s*\]|\.\s*get\s*\(\s*['"]origin['"]\s*\))|(?:get|header)\s*\(\s*['"]origin['"]\s*\))""", re.I),
        "Check the request Origin against an explicit allowlist before returning it in Access-Control-Allow-Origin. Review credentialed access on sensitive endpoints.",
    ),
    ("SILENT", "Silent error handling signal", "medium", re.compile(r"catch\s*\([^)]*\)\s*\{\s*\}|except[^:\n]*:\s*pass\b|\.catch\s*\(\s*\(\)\s*=>\s*\[\]"), "Return actionable errors and log failures without exposing secrets."),
    ("AUTH", "Client-controlled authorization signal", "high", re.compile(r"""(?:\b(?:request|req)\.headers|\bheaders)\s*(?:\.\s*get\s*\(\s*|\[\s*)['"]x-(?:user-)?(?:role|admin)['"]|\b(?:request|req)\.(?:json|body|form|query_params)(?:\(\))?(?:\.\s*get\s*\(\s*|\[\s*)['"](?:role|is_admin|isAdmin|admin)['"]""", re.I), "Do not trust caller-supplied roles. Authenticate the user and enforce permissions server-side."),
    ("SQL", "Potentially unsafe SQL construction", "high", re.compile(r"""\b(?:select|insert|update|delete|replace)\b[^;\n]{0,500}(?:\{[A-Za-z_]\w*\}|\$\x7b[^}]+\}|\$[A-Za-z_]\w*|\+\s*(?:email|user_?input|input|request|req|params?|user_?id)\b|\.format\s*\()""", re.I), "Use parameterized queries or prepared statements; never interpolate untrusted input into SQL."),
    ("SHELL", "Shell execution enabled", "high", re.compile(r"shell\s*=\s*True"), "Avoid shell execution for untrusted input; pass explicit argument lists."),
    ("TLS-VERIFY", "TLS certificate verification disabled", "high", re.compile(r"""\b(?:(?:requests|httpx)\.(?:get|post|put|patch|delete|head|request|Client|AsyncClient)\s*\([^()]{0,500}\bverify\s*=\s*False\b|rejectUnauthorized\s*:\s*false\b|NODE_TLS_REJECT_UNAUTHORIZED\s*[:=]\s*['"]?0\b|ssl\._create_unverified_context\s*\()"""), "Enable certificate verification and configure a trusted CA for private services."),
    ("SECRET-LOG", "Possible sensitive data written to logs", "high", re.compile(r"""\b(?:console\.(?:log|info|debug|warn|error)|(?:logger|logging|log)\.(?:debug|info|warning|warn|error|exception|critical))\s*\((?:"[^"\n]*"|'[^'\n]*'|[^'");\n]){0,300}?(?:\b(?:password|access[_-]?token|api[_-]?key|session[_-]?cookie)\b|\bheaders\s*(?:\.\s*authorization\b|\[\s*['"](?:authorization|cookie)['"]|\.\s*get\s*\(\s*['"](?:authorization|cookie)['"]))"""), "Remove credentials and session data from log arguments or redact them before logging."),
    ("DESERIALIZE", "Potentially unsafe deserialization", "high", re.compile(r"""\b(?:(?:pickle|cPickle|dill|cloudpickle)\.loads?\s*\(|yaml\.unsafe_load\s*\(|yaml\.load\s*\([^)\n]{0,400}\bLoader\s*=\s*yaml\.(?:UnsafeLoader|Loader)\b|unserialize\s*\(\s*\$_(?:POST|GET|REQUEST)\b)"""), "Use a data-only format and validate its schema when reading request or upload content."),
    ("SSRF", "Possible user-controlled outbound request", "high", re.compile(r"""\b(?:fetch|(?:requests|httpx|axios)\.(?:get|post|put|patch|delete|head)|(?:urllib\.request\.)?urlopen)\s*\(\s*(?:req|request)\s*\.\s*(?:query|query_params|body|form|params|json)(?:\s*\(\s*\))?\s*(?:\.\s*(?:url|target|destination|callbackUrl)\b|\[\s*['"](?:url|target|destination|callbackUrl)['"]\s*\]|\.\s*get\s*\(\s*['"](?:url|target|destination|callbackUrl)['"]\s*\))"""), "Validate destinations against an explicit allowlist and enforce the policy after DNS resolution and redirects."),
    ("WEBHOOK-SIGNATURE", "Webhook signature verification needs review", "medium", re.compile(r"""\b(?:app|router|bp|blueprint)\.(?:post|route)\s*\(\s*['"][^'"\r\n]*webhooks?[^'"\r\n]*['"]""", re.I), "Verify the provider signature over the raw request body before processing the event. Check route middleware and replay protection."),
]


def analyze_zip(data: bytes, project: str, check_dependencies: bool = False) -> dict:
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
    cors_origins: list[dict] = []
    packages: dict = {}
    expanded = 0
    try:
        for info in infos:
            name = PurePosixPath(info.filename.replace("\\", "/")).name.lower()
            if not info.is_dir() and (name == ".env" or name.startswith(".env.") or name.endswith(".env")):
                raise ValueError("ZIP contains an environment file. Remove .env files before using the Python scanner.")

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
            source = raw.decode("utf-8", errors="replace").replace("\r\n", "\n").replace("\r", "\n")
            lines = source.split("\n")
            inventory.append({"path": normalized, "lines": len(lines)})
            if check_dependencies:
                collect_dependencies(source, normalized, packages)
            for setting in CORS_SETTINGS.finditer(source):
                for match in CORS_ORIGIN.finditer(setting[1]):
                    offset = setting.start(1) + match.start()
                    cors_origins.append({
                        "origin": match[1],
                        "path": normalized,
                        "line": source.count("\n", 0, offset) + 1,
                    })
            for rule, title, severity, pattern, remediation in RULES:
                match = pattern.search(source)
                if rule == "WEBHOOK-SIGNATURE":
                    while match:
                        next_route = ROUTE_DECLARATION.search(source, match.end())
                        end = min(next_route.start() if next_route else len(source), match.end() + 5000)
                        if not WEBHOOK_VERIFICATION.search(source, match.end(), end):
                            break
                        match = pattern.search(source, end)
                if match:
                    line = source.count("\n", 0, match.start()) + 1
                    findings.append({
                        "id": f"{rule}-{len(findings) + 1}",
                        "title": title,
                        "severity": severity,
                        "path": normalized,
                        "line": line,
                        "endLine": line + match[0].count("\n"),
                        "remediation": remediation,
                        "status": "Needs review",
                    })
            if len(lines) > 500:
                findings.append({"id": f"SIZE-{len(findings) + 1}", "title": "Large file maintenance signal", "severity": "low", "path": normalized, "line": 1, "remediation": "Review responsibilities and split cohesive modules where appropriate.", "status": "Needs review"})
    finally:
        archive.close()

    if not inventory:
        raise ValueError("No supported text source files found in this ZIP.")
    if not any(re.search(r"(test|spec)", item["path"], re.I) for item in inventory):
        findings.append({"id": "TEST-REVIEW", "title": "No test files identified", "severity": "medium", "path": "Project", "line": None, "remediation": "Confirm tests exist outside the archive or add tests for authentication, validation, and error paths.", "status": "Needs review"})
    report = {
        "project": project,
        "files": inventory,
        "findings": findings,
        "corsOrigins": cors_origins,
        "summary": {"files": len(inventory), "lines": sum(item["lines"] for item in inventory), "high": sum(item["severity"] == "high" for item in findings)},
        "limitations": "Static review only. Code patterns may produce false positives. Dependency results cover known advisories for checked versions. Review authentication, business logic, and runtime behavior separately.",
    }
    if check_dependencies:
        scan_dependencies(report, packages)
    rank = {"high": 0, "medium": 1, "low": 2}
    findings.sort(key=lambda item: rank[item["severity"]])
    return report
