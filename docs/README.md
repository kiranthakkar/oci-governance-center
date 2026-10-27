# Documentation index

Reviewed against the current OGC source on 2026-10-27. Use the current pages below for operation;
OSC design documents are retained as historical input, not instructions for this application.

| Current document | Purpose |
|---|---|
| [Project README](../README.md) | Installation, two-process startup and quick reference |
| [Operator guide](operations.md) | Settings, parent/child setup, storage, recovery and troubleshooting |
| [Scan controls](scanning.md) | Schedules, per-tenancy collection, diagnostics and finding triage |
| [Architecture](architecture.md) | Runtime boundaries, data flow and implementation limitations |
| [Implementation status](implementation/status.md) | Implemented capabilities, validation and live acceptance gates |
| [IAM catalog](iam/README.md) and [local scanner permissions](iam/ogc-local-read.md) | Current parent/child read grants and authentication prerequisites |
| [Detection catalog](detections/README.md) | Implemented rule contracts and planned detections |
| [Specifications](../AGENTS.md) | Product requirements and implementation plan, especially sections 6–7 |

[Collection](collection.md) has a current Tier 1 dataset catalog and cost contract, followed by
historical/planned higher-tier design. Its older OSC implementation references are not current.

The following pages describe the removed OSC runtime or future designs:
[storage](storage.md), [control plane](control-plane.md), [Audit delta recovery](delta-fetching.md),
[delegated scans](delegated-scans.md), [historical review fixes](review-fixes.md), and the historical
IAM templates labeled in the IAM catalog. Their old commands, refresh grants, schemas, backup
utilities and Endorse/Admit prerequisites must not be used as current OGC setup instructions.
