# Delegated scan prerequisites

> **Historical (2026-10-22).** This page describes the removed OSC implementation. The current
> OGC grants and setup are in [OGC local scanner permissions](ogc-local-read.md) and AGENTS.md §6.

A human child administrator provisions a local user/group and the OIDC application/trust described
in [delegated scans](../delegated-scans.md). OSC displays requirements and makes read-only API calls;
it never creates users, policies, applications or trust configuration.

For the MVP, the local scanner group needs the same read scope as the existing scanner:

```text
Allow group '<sign-in-domain>'/'OSC-Scanners' to read all-resources in tenancy
```

Use the actual domain/group names. The principal must belong to the intended tenancy. This is a
local Allow grant; foreign Endorse/Admit grants do not establish local IAM inventory coverage.
The OAuth application is the credential client, not the source of the user's OCI permissions.
Do not assign broad application administrator roles just for token exchange. Domain-level user,
group, membership and dynamic-group access must be verified for each domain, including named domains.

Reviewed reads include get tenancy, get user, region subscriptions, compartments, policies,
domains and domain list-users/groups/dynamic-resource-groups. `GetUser` needs `inspect users`,
included by the existing local `read all-resources` grant. At initial exchange and every renewal,
`GetUser(sub)` must return a user whose `compartment_id` is the configured tenancy; `GetTenancy`
must return that tenancy. These checks establish a local identity without assuming a UPST
`res_tenant` claim. A successful target-tenancy read alone cannot prove the caller belongs to it. No permission to modify those resources
is needed. Broader grants remain subject to policy review. Least-privilege refinements and actual
cross-domain authorization are live POC gates; successful OAuth sign-in is not proof of coverage.
