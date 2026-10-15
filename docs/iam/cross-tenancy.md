# Cross-tenancy templates

Status: Existing MVP statement shape; [capability gates](../collection.md#10-capability-release-gates)
remain required. Replace every placeholder with verified tenancy/group identities. Use the scanner
principal from [parent access](parent-access.md). Default names below are editable aliases.

## Parent root: osc-endorse-children

```text
Define tenancy <ChildAlias> as <child_tenancy_ocid>
Endorse dynamic-group <OSC-Scanner-DG> to read all-resources in tenancy <ChildAlias>
```

For a workstation scanner replace the Endorse line with:

```text
Endorse group <OSC-Scanners> to read all-resources in tenancy <ChildAlias>
```

## Child root: osc-admit-parent

```text
Define tenancy <ParentAlias> as <parent_tenancy_ocid>
Define dynamic-group <ScannerAlias> as <scanner_dynamic_group_ocid>
Admit dynamic-group <ScannerAlias> of tenancy <ParentAlias> to read all-resources in tenancy
```

For a workstation scanner use:

```text
Define tenancy <ParentAlias> as <parent_tenancy_ocid>
Define group <ScannerAlias> as <scanner_group_ocid>
Admit group <ScannerAlias> of tenancy <ParentAlias> to read all-resources in tenancy
```

Keep each grant and all aliases it references in the same policy document, including when splitting
the parent roll-up. A child scanner alias identifies the parent's principal OCID; it does not name a
new local group. Resolve named-domain references using the verified domain and principal identity.
Both IAM administrators apply their sides manually. Check READY region subscriptions in both
tenancies, then probe the actual collector APIs. No per-child credentials are permitted.

[Oracle cross-tenancy policy and region prerequisites](https://docs.oracle.com/en-us/iaas/Content/Identity/policieshow/iam-cross-domain.htm)
