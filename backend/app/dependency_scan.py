import json
import re
from http.client import HTTPException, HTTPSConnection
from pathlib import PurePosixPath

MAX_PACKAGES = 500
MAX_RESPONSE_BYTES = 1024 * 1024
NAME = re.compile(r"(?:@[A-Za-z0-9_.-]+/)?[A-Za-z0-9][A-Za-z0-9_.-]*")
VERSION = re.compile(r"[0-9][A-Za-z0-9_.+!-]{0,79}")
PIN = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9_.-]*)(?:\[[^\]\n]*\])?\s*==\s*([^\s;#]+)\s*(?:[;#].*)?$")
ADVISORY = re.compile(r"[A-Za-z0-9][A-Za-z0-9.-]{0,79}")


def collect_dependencies(source: str, path: str, packages: dict) -> None:
    filename = PurePosixPath(path).name
    if filename == "package-lock.json":
        try:
            lock = json.loads(source)
        except (ValueError, RecursionError):
            return
        entries = lock.get("packages") if isinstance(lock, dict) else None
        if not isinstance(entries, dict):
            return
        ecosystem = "npm"
        candidates = (
            (entry.get("name", key.rsplit("node_modules/", 1)[1]), entry.get("version"))
            for key, entry in entries.items()
            if "node_modules/" in key and isinstance(entry, dict) and not entry.get("link")
        )
    elif filename == "requirements.txt":
        ecosystem = "PyPI"
        candidates = (match.groups() for line in source.splitlines() if (match := PIN.fullmatch(line)))
    else:
        return

    for name, version in candidates:
        if len(packages) > MAX_PACKAGES:
            return
        if (
            isinstance(name, str) and len(name) <= 214 and NAME.fullmatch(name)
            and isinstance(version, str) and VERSION.fullmatch(version)
        ):
            if ecosystem == "PyPI":
                name = re.sub(r"[-_.]+", "-", name).lower()
            packages.setdefault((ecosystem, name, version), path)


def query_osv(queries: list[dict]) -> list[dict]:
    connection = HTTPSConnection("api.osv.dev", timeout=8)
    try:
        connection.request("POST", "/v1/querybatch", json.dumps({"queries": queries}), {"Content-Type": "application/json"})
        response = connection.getresponse()
        body = response.read(MAX_RESPONSE_BYTES + 1)
        if response.status != 200 or len(body) > MAX_RESPONSE_BYTES:
            raise ValueError("OSV request failed")
        return json.loads(body)["results"]
    finally:
        connection.close()


def scan_dependencies(report: dict, packages: dict) -> None:
    if not packages:
        report["dependencyScan"] = {"status": "no-packages", "checked": 0}
        return

    selected = list(packages)[:MAX_PACKAGES]
    queries = [
        {"package": {"ecosystem": ecosystem, "name": name}, "version": version}
        for ecosystem, name, version in selected
    ]
    try:
        results = query_osv(queries)
        if not isinstance(results, list) or len(results) != len(selected) or not all(isinstance(item, dict) for item in results):
            raise ValueError("Unexpected OSV response")
    except (OSError, HTTPException, ValueError, KeyError, TypeError, RecursionError):
        report["dependencyScan"] = {"status": "unavailable", "checked": 0}
        return

    for package, result in zip(selected, results):
        vulnerabilities = result.get("vulns", [])
        if not isinstance(vulnerabilities, list):
            continue
        advisories = sorted({
            item["id"] for item in vulnerabilities
            if isinstance(item, dict) and isinstance(item.get("id"), str) and ADVISORY.fullmatch(item["id"])
        })
        if advisories:
            _, name, version = package
            report["findings"].append({
                "id": f"DEPENDENCY-{len(report['findings']) + 1}",
                "title": f"Known vulnerability in {name} {version}",
                "severity": "medium",
                "path": packages[package],
                "line": None,
                "advisories": advisories,
                "remediation": "Review the linked advisories for severity and affected versions, then update the dependency.",
                "status": "Needs review",
            })
    partial = len(packages) > len(selected) or any(result.get("next_page_token") for result in results)
    report["dependencyScan"] = {"status": "partial" if partial else "complete", "checked": len(selected)}
