# IAM requirements and templates

Status: Design baseline, 2026-10-08. This catalog owns permission intent; executable rendering lives
in `src/oci_security_center/control_plane/policy_templates.py`. Keep renderer, catalog and tests in
one change. Templates contain placeholders and are displayed for humans; OSC never applies them.

| Template | Purpose | Apply in |
|---|---|---|
| [Parent access](parent-access.md) | Admin reads and scanner access | Parent root |
| [Cross-tenancy](cross-tenancy.md) | Complete Endorse and Define/Admit blocks | Parent and child roots respectively |
| [Single tenancy](single-tenancy.md) | Parent-only deployment; no cross-tenancy grant | Registered tenancy root |
| [Identity-domain setup](parent-domain-setup.md) | OIDC groups, app and validated token-exchange trust | Parent identity domain, manually |

## Validation status and constraints

`organizations-family` is an official resource family. Oracle maps ListOrganizations to
ORGANIZATIONS_ENTITY_INSPECT and ListOrganizationTenancies to ORGANIZATIONS_TENANCY_INSPECT; the
existing `read organizations-family` template includes those inspect permissions. This documentation
verification does not replace a scanner-method-specific sandbox connection test.
[Oracle Organization Management reference](https://docs.oracle.com/en-us/iaas/Content/Identity/policyreference/organizationsreference.htm)

Cross-tenancy examples require complete policy-local definitions and matching region subscriptions.
[Oracle cross-tenancy reference](https://docs.oracle.com/en-us/iaas/Content/Identity/policieshow/iam-cross-domain.htm)
Domain API authorization/member paging, Logging Search limits and Container Instance matching rules
remain capability gates in collection §10 and control-plane §2.6. Never broaden grants automatically
when a capability fails. Viewers need no OCI permissions. No write verb is required by OSC.

The MVP's `read all-resources` is deliberately broad; it is not proof of least privilege or that every
service supports cross-tenancy reads. It increases the compromised-scanner blast radius beyond the
fields OSC retains. Collector field allow-lists do not restrict an attacker's stolen credentials.
Show this scope to IAM admins and constrain scanner host access; per-family grants remain D7.

Vault secret retrieval follows control-plane §3.1; API-key-only scan identities cannot retrieve their
own key. Do not add a standalone Vault permission or independent retrieval identity without a reviewed
design and same-change template update. Encryption-key injection is an operator deployment concern.

Optional administrator child browsing stays disabled until D2 has evidence. When splitting a combined
Endorse policy to meet the verified statement limit, repeat required definitions in every resulting
policy document; aliases are not global. Validate actual principal/domain identity before rendering.
