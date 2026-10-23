# Parent access template

> **Historical (2026-10-22).** This page describes the removed OSC implementation. The current
> OGC grants and setup are in [OGC local scanner permissions](ogc-local-read.md) and AGENTS.md §6.

Status: Existing MVP statement set; capability/production gates are in [the catalog](README.md).
Root policy name: `osc-parent-access`. Resolve names/OCIDs using read-only parent lookups. For a
named identity domain use `group '<DomainName>'/'<GroupName>'` (and the validated dynamic-group
form); never paste unresolved placeholders or infer that same names identify the same group.

```text
Allow group <OSC-Admins> to inspect tenancies in tenancy
Allow group <OSC-Admins> to read organizations-family in tenancy
Allow group <OSC-Admins> to inspect compartments in tenancy
Allow group <OSC-Admins> to read policies in tenancy
Allow group <OSC-Admins> to inspect groups in tenancy
Allow group <OSC-Admins> to inspect dynamic-groups in tenancy
```

Choose the scanner block for the supported identity, not both:

```text
# OCI instance principal
Allow dynamic-group <OSC-Scanner-DG> to read all-resources in tenancy
Allow dynamic-group <OSC-Scanner-DG> to read organizations-family in tenancy
```

```text
# Workstation service-user API key / supported CLI profile
Allow group <OSC-Scanners> to read all-resources in tenancy
Allow group <OSC-Scanners> to read organizations-family in tenancy
```

The admin reads support connection testing, organization discovery, root policy checks and group-ID
resolution. The scanner reads support parent inventory and background discovery. Group/API-key
identity belongs to the configured scanner group. There are no viewer grants. See control-plane §3.1
for secret references and §2.3 for unsupported signer/deployment combinations.

The renderer supplies copy/download and safely quoted human CLI commands. OSC executes none of them.
Read-only status checks must distinguish unknown, missing and broader grants, and must not treat this
template as evidence that an untested collector is accessible.
