# ADR-001: Establish explicit application boundaries

## Status

Accepted

## Context

The generated application mixed HTTP concerns, authorization decisions, persistence, and business rules. This made defects difficult to isolate and encouraged client-side trust.

## Decision

Separate the application into API, identity/policy, service, repository, and audit responsibilities. API models are typed contracts. Authorization is evaluated before service mutation. Persistence can be replaced without changing HTTP behavior.

## Consequences

The codebase gains testable seams and clearer ownership. The small increase in structure is justified by safer changes and easier production migration.

