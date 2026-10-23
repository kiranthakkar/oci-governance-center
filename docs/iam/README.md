# IAM requirements and templates

Status: 2026-10-22. This catalog owns permission intent. The current scanner grants are in
[OGC local scanner permissions](ogc-local-read.md); the parent/child Terraform bundles and manual
guides render them from `src/oci_governance_center/provisioning/bundle.py`. Keep the catalog,
renderer and `tests/unit/test_provisioning.py` in one change. OGC never applies these policies.

| Template | Status | Purpose | Apply in |
|---|---|---|---|
| [OGC local read](ogc-local-read.md) | **Current** | Local `ogc_scanner` read grants and default-domain WIF prerequisites | Parent and each child root |
| [Parent access](parent-access.md) | Historical (OSC) | Admin reads and scanner access | — |
| [Cross-tenancy](cross-tenancy.md) | Historical (OSC) | Endorse and Define/Admit blocks; not an OGC access mechanism | — |
| [Single tenancy](single-tenancy.md) | Historical (OSC) | Parent-only deployment | — |
| [Identity-domain setup](parent-domain-setup.md) | Historical (OSC) | OSC groups, OIDC app and token-exchange trust | — |
| [Delegated scan](delegated-scan.md) | Historical (OSC) | Child-local delegated UPST prerequisites | — |

Historical pages describe the removed OSC implementation. Where they conflict with AGENTS.md
sections 6–7 or `ogc-local-read.md`, the current pages win.

## Validation status and constraints

`organizations-family` is an official resource family. Oracle maps ListOrganizations to
ORGANIZATIONS_ENTITY_INSPECT and ListOrganizationTenancies to ORGANIZATIONS_TENANCY_INSPECT; the
parent's `read organizations-family` grant includes those inspect permissions. Documentation checks
do not replace a live connection test.
[Oracle Organization Management reference](https://docs.oracle.com/en-us/iaas/Content/Identity/policyreference/organizationsreference.htm)

The scanner uses per-family local read grants, not `read all-resources`. Each grant maps to reviewed
SDK operations in `oci_clients.OPERATIONS`; a new operation needs an allow-list entry, a grant here
and in `provisioning/bundle.py`, and tests in the same change. Grants are local to each tenancy.
Parent group membership grants no child access, and Endorse/Admit is not an OGC access mechanism.

All-domain user/group/membership reads, SCIM member limits, regional behaviour and the API key →
parent JWT → child UPST caller authorization remain live release gates
([implementation status](../implementation/status.md)). Never broaden grants automatically when a
capability fails; report the denied scope as coverage. Viewers need no OCI permissions, and OGC
requires no write verb. Collector field projections do not limit what stolen scanner credentials
could read, so restrict scanner host access.
