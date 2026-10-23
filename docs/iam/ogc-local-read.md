# OGC local scanner permissions

This catalog supersedes the old Endorse/Admit templates for the new implementation. Runtime code
never applies these policies. The administrator-applied parent/child bundles and manual guide share
the same statement generator in `provisioning/bundle.py`; download them through OGC or `ogc setup-package`.

The scanner group is in the target tenancy's default identity domain:

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
```

| Read surface | SDK client operations |
|---|---|
| Identity/regions | IdentityClient get_tenancy/get_user/get_domain/list_compartments/list_region_subscriptions/list_policies/list_domains |
| Every domain | IdentityDomainsClient list_users/list_groups/list_dynamic_resource_groups |
| Organization | OrganizationClient list_organizations/list_organization_tenancies |
| Cloud Guard/Zones | CloudGuardClient get_configuration/list_problems/list_security_zones |
| Advisor | OptimizerClient list_enrollment_statuses/list_recommendations |
| Audit | AuditClient list_events per compartment and subscribed region |

Resource names checked against [IAM with domains](https://docs.oracle.com/en-us/iaas/Content/Identity/policyreference/iampolicyreference.htm),
[Cloud Guard policies](https://docs.oracle.com/en-us/iaas/Content/cloud-guard/using/policies.htm),
[Security Zones](https://docs.oracle.com/en-us/iaas/Content/Security/Reference/securityzone_security.htm),
[Audit](https://docs.oracle.com/en-us/iaas/Content/Audit/Tasks/viewinglogevents.htm),
[Cloud Advisor](https://docs.oracle.com/en-us/iaas/Content/CloudAdvisor/Reference/cloudadvisorpolicyreference.htm)
and [organization access](https://docs.oracle.com/en-us/iaas/Content/General/organization/organization_required_iam_policy.htm).
These are local grants, not proof of all-domain or WIF support; run the release gates before certification.
The application groups grant no OCI administration permissions. Human self-service Me/group access
uses the dedicated OIDC app's human token and does not depend on the scanner key.

[API key → domain access token](https://docs.oracle.com/en/cloud/paas/identity-cloud/idcsa/token_exchange_grant_type.html)
and [JWT → UPST](https://docs.oracle.com/en-us/iaas/Content/Identity/api-getstarted/json_web_token_exchange.htm)
are authentication infrastructure operations outside the read-only resource-operation allow-list.
No scanner OAuth client ID or secret is sent. Verify the combined caller-authorization flow live.

Parent organization verification uses the `compartment_id` (owning tenancy OCID) from
`ListOrganizations`, then lists children only from that organization. It does not require the
parent to appear as a `PARENT` row in `ListOrganizationTenancies`. Organizations owned by other
tenancies are excluded; contradictory current roles or ambiguous ownership stop verification.
See Oracle's [OrganizationSummary model](https://docs.oracle.com/en-us/iaas/tools/python/latest/api/tenant_manager_control_plane/models/oci.tenant_manager_control_plane.models.OrganizationSummary.html).
