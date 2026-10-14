# Retry resilience lab: lost responses and duplicate tickets

## Failure and repair
A server creates a ticket, but its response is lost. The caller cannot know whether creation succeeded and retries. Without a request key, two submissions create two tickets. This lab reproduces that baseline and verifies a repair using an optional Idempotency-Key HTTP header.

For one new creation intent, generate a unique key and keep the same key and payload for every retry. A different legitimate creation needs a new key even when its text is identical. Requests without the header retain their previous behavior.

The service scopes keys to the demonstration username. Under the same lock, it checks the key, creates the ticket, records one audit event, and stores an independent snapshot of the original response. A replay returns that snapshot with HTTP 201, matching the first response. Changed payloads with the same key return HTTP 409; invalid keys return 422.

## Reproduce and verify
From the repository root:

```bash
PYTHONPATH=backend python -m pytest backend/tests/test_retry_resilience.py -q
PYTHONPATH=backend python -m pytest backend/tests -q
```

On PowerShell, set $env:PYTHONPATH="backend" before running python -m pytest.

Verified locally on Python 3.12: 11 new test cases passed; combined with the existing test_api.py, 17 tests passed. One dependency deprecation warning was emitted.

Coverage includes the duplicate-producing baseline, response-loss simulation, 20 simultaneous retries, changed-payload conflict, user isolation, distinct legitimate intents, response snapshots after status updates, API behavior, and invalid keys.

The lost response is simulated by discarding the first result; this is not a real network timeout experiment. Concurrency is exercised at the service boundary with real threads. These tests are public regression tests, not a hidden benchmark or an evaluation of an AI agent.

## Limits and next experiment
This is an in-memory, single-process demonstration. Keys and tickets disappear on restart, separate server workers do not share them, and the key cache has no expiry or bound. Demo X-User/X-Role headers are not authenticated identity. The frontend does not yet generate or retain retry keys.

Next: persist tickets and keys in a database transaction with a unique identity/key constraint, then test response loss through a network proxy, process restarts, and multiple workers. Add retention limits and verified identity before production use.
