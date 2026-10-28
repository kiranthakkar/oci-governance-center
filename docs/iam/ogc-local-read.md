# OGC local scanner permissions

This catalog supersedes the old Endorse/Admit templates for the new implementation. Runtime code
never applies these policies. The administrator-applied parent/child bundles and manual guide share
the same statement generator in `provisioning/bundle.py`; download them through OGC or `ogc setup-package`.

The scanner group belongs to the selected default or non-default identity domain.
The following name-qualified example assumes Default; replace it with the chosen domain. Generated
Terraform uses `Allow group id <scanner-group-OCID>` instead, avoiding a hard-coded domain name:

```text
Allow group 'Default'/'ogc_scanner' to read tenancies in tenancy
Allow group 'Default'/'ogc_scanner' to read compartments in tenancy
Allow group 'Default'/'ogc_scanner' to read users in tenancy
Allow group 'Default'/'ogc_scanner' to read groups in tenancy
Allow group 'Default'/'ogc_scanner' to read dynamic-groups in tenancy
Allow group 'Default'/'ogc_scanner' to read policies in tenancy
Allow group 'Default'/'ogc_scanner' to read domains in tenancy
Allow group 'Default'/'ogc_scanner' to read cloud-guard-family in tenancy
Allow group 'Default'/'ogc_scanner' to read audit-events in tenancy
Allow group 'Default'/'ogc_scanner' to read optimizer-api-family in tenancy
```

The parent additionally requires:

```text
Allow group 'Default'/'ogc_scanner' to read organizations-family in tenancy
Allow group 'Default'/'ogc_scanner' to read usage-report in tenancy
```

`read usage-report` (2026-10-27) lets the parent read organization cost through the Usage API.
Children do not need it: the parent's cost data covers the tenancies its billing includes.
Existing installations add it to the parent's OGC policy by hand.

| Read surface | SDK client operations |
|---|---|
| Identity/regions | IdentityClient get_tenancy/get_domain/list_compartments/list_region_subscriptions/list_policies/list_domains |
| Every domain | IdentityDomainsClient list_users/list_groups/list_dynamic_resource_groups/list_api_keys |
| Organization | OrganizationClient list_organizations/list_organization_tenancies |
| Cloud Guard/Zones | CloudGuardClient get_configuration/list_problems/list_security_zones |
| Advisor | OptimizerClient list_categories/list_enrollment_statuses/list_recommendations |
| Audit | AuditClient list_events per compartment and subscribed region |
| Cost (parent only) | UsageapiClient request_summarized_usages (read-only query sent as POST; reviewed exception to the read-prefix rule) |

`list_categories` (2026-10-22) is covered by the existing `read optimizer-api-family` grant.
`list_api_keys` (2026-10-22) reads API-key metadata only (owner and creation date; OGC never stores
the key or fingerprint). Whether `read users` authorizes it in every identity domain is a **live
gate**; a denial is reported as an `identity_domains.api_keys` coverage gap and only blocks the
`analysis.api_keys` rules. Do not broaden the grant to `manage` to obtain it.

Resource names checked against [IAM with domains](https://docs.oracle.com/en-us/iaas/Content/Identity/policyreference/iampolicyreference.htm),
[Cloud Guard policies](https://docs.oracle.com/en-us/iaas/Content/cloud-guard/using/policies.htm),
[Security Zones](https://docs.oracle.com/en-us/iaas/Content/Security/Reference/securityzone_security.htm),
[Audit](https://docs.oracle.com/en-us/iaas/Content/Audit/Tasks/viewinglogevents.htm),
[Cloud Advisor](https://docs.oracle.com/en-us/iaas/Content/CloudAdvisor/Reference/cloudadvisorpolicyreference.htm)
[Usage API](https://docs.oracle.com/en-us/iaas/Content/Billing/Concepts/costanalysisoverview.htm)
and [organization access](https://docs.oracle.com/en-us/iaas/Content/General/organization/organization_required_iam_policy.htm).
These are local grants, not proof of all-domain or WIF support; run the release gates before certification.
The application groups grant no OCI administration permissions. Human membership verification uses
the dedicated login app's user access token with `/admin/v1/Asserter` and
`includeMemberships=true`; it does not use Me or depend on the scanner key.

Each child additionally needs an active confidential exchange app, its OAuth client ID bound in the
propagation trust, and an exact parent-subject impersonation rule (for example `sub eq ogc`, without
quotes). OGC uses that child app's ID/secret for HTTP Basic caller authentication. Parent JWT issuance
remains API-key-signed. Child Configure discovers the service user by `userName eq "ogc"`; the user
OCID, domain identifiers and home region are verified automatically. See the
[operator setup guide](../operations.md#child-setup-and-credential-separation).

[API key → domain access token](https://docs.oracle.com/en/cloud/paas/identity-cloud/idcsa/token_exchange_grant_type.html)
and [JWT → UPST](https://docs.oracle.com/en-us/iaas/Content/Identity/api-getstarted/json_web_token_exchange.htm)
are authentication infrastructure operations outside the read-only resource-operation allow-list.
No scanner OAuth client ID or secret is sent. Verify the combined caller-authorization flow live.

Parent organization verification uses the `compartment_id` (owning tenancy OCID) from
`ListOrganizations`, then lists children only from that organization. It does not require the
parent to appear as a `PARENT` row in `ListOrganizationTenancies`. Organizations owned by other
tenancies are excluded; contradictory current roles or ambiguous ownership stop verification.
See Oracle's [OrganizationSummary model](https://docs.oracle.com/en-us/iaas/tools/python/latest/api/tenant_manager_control_plane/models/oci.tenant_manager_control_plane.models.OrganizationSummary.html).
