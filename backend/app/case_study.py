from .models import Finding

FINDINGS = [
    Finding(id="AUTH-01", title="Client-side authorization only", severity="critical", category="Security", evidence="Admin controls were hidden in React but the API accepted direct requests from any user.", remediation="Enforce roles at every protected API boundary using verified identity claims.", status="fixed"),
    Finding(id="DATA-02", title="Missing input validation", severity="high", category="Data integrity", evidence="Ticket priority accepted negative numbers and subjects exceeding database limits.", remediation="Use typed request schemas with length and range constraints.", status="fixed"),
    Finding(id="SEC-03", title="Secret committed to source", severity="critical", category="Security", evidence="A provider token was stored in a frontend configuration file.", remediation="Rotate the credential, remove it from history, and keep secrets server-side.", status="fixed"),
    Finding(id="REL-04", title="Silent API failures", severity="high", category="Reliability", evidence="Rejected requests were converted to empty arrays, making failures look like valid empty states.", remediation="Return structured errors with correlation IDs and render explicit failure states.", status="fixed"),
    Finding(id="OBS-05", title="No mutation audit trail", severity="high", category="Operations", evidence="Status changes did not record actor, role, action, target, or time.", remediation="Record append-only audit events for state-changing operations.", status="fixed"),
    Finding(id="TEST-06", title="Critical flows untested", severity="high", category="Quality", evidence="The project had no tests for authorization, validation, or error contracts.", remediation="Add contract and behavior tests before structural refactoring.", status="fixed"),
]


def case_study() -> dict:
    return {
        "application": "RelayDesk",
        "summary": "AI-generated support workspace rescued through contract-first remediation.",
        "before_score": 31,
        "after_score": 91,
        "findings": [item.model_dump() for item in FINDINGS],
        "metrics": {"findings_fixed": len(FINDINGS), "tests_added": 12, "protected_routes": 4, "audit_coverage": 100},
        "phases": [
            {"name": "Baseline", "result": "Reproduced 8 failures and mapped trust boundaries"},
            {"name": "Contain", "result": "Closed authorization, credential, and validation risks"},
            {"name": "Stabilize", "result": "Added error contracts, audit events, and tests"},
            {"name": "Modernize", "result": "Separated service, repository, and API boundaries"},
        ],
    }

