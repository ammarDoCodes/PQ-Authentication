# Decision 0001: Specification precedence

- Status: accepted for this implementation
- Date: 2026-09-26
- Scope: all work in this repository

## Context

The implementation brief gives this order when specification documents conflict: security requirements, threat model, architecture, product specification, API contract, testing requirements, roadmap, README. Specs/AGENTS.md lists a different source-of-truth order and requires conflicts to be surfaced rather than silently resolved.

## Decision

Follow the explicit order in the user implementation brief. It is the task-level resolution for this repository. Surface substantive contradictions that remain within the same priority level in a separate decision record before implementing the affected behavior.

## Consequences

Security and threat-model constraints can narrow or block a product requirement. API and roadmap details are implemented only when compatible with higher-priority constraints. This decision does not waive the review, testing, documentation, or security gates in the specification pack.
