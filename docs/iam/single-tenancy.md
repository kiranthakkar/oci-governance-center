# Single-tenancy configuration

> **Historical (2026-10-22).** This page describes the removed OSC implementation. The current
> OGC grants and setup are in [OGC local scanner permissions](ogc-local-read.md) and AGENTS.md §6.

Register the tenancy as the parent and select no children. Apply only the relevant blocks from
[parent access](parent-access.md) and, for OIDC, [domain setup](parent-domain-setup.md).
No Define/Endorse/Admit statements are needed. The same read-only, capability, storage, retention and
production release requirements apply; parent-only operation is not an authentication bypass.
An absent Organization is shown as absent; denied discovery is unknown coverage, not proof of absence.
