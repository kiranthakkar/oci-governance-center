# OSC-ACCESS-002 — Source not collected

Version: 1 (2026-10-09). Status: implemented (collection runner and audit coordinator). Source: coverage. Severity: HIGH. No CIS mapping.

Inputs: configured tier, required capability dependencies, collection scope, scan-run item, completeness
manifest and last successful collection. Trigger on unsupported/failed/partial required source scopes,
including missing shared regions, pagination truncation and exhausted capacity/retry budgets.
An intentionally disabled higher-tier dataset is not failed; show its disabled state separately.

Identity: generation, tenancy, rule ID, dataset/API, region, domain/compartment and failure stage.
Independent scope failures must coexist. Resolve only after successful capability verification and a
complete collection of the affected scope; do not resolve by a successful neighboring region.
Evidence: error category, failed scope, last success, missed interval and sanitized request reference.
Display retained data as stale/partial; never replace it with an empty successful-looking inventory.

Required tests: failed source versus complete empty source; unsupported domain; truncated membership;
multiple simultaneous region/dataset failures; successful neighboring scope does not resolve; full
scope recovery resolves; tier-disabled dataset is excluded. Implementation requires these tests and
scope-specific storage identities before enabling the rule.
