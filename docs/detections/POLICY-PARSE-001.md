# POLICY-PARSE-001 — Policy analysis incomplete

Version: proposed 1 (2026-10-08). Status: finding planned; tolerant parser exists.
Source: policy. Severity: LOW. No CIS mapping.

Inputs: policy OCID, attachment compartment, statement text, canonical statement identity and parser
version. Trigger when a statement cannot be parsed reliably. Never crash the tenancy analysis or
infer safe access from a parse failure. Identity: tenancy, policy OCID, canonical statement identity
and rule ID. Retain a source reference and sanitized explanation; do not log full SDK responses.

Resolve only after a complete same-scope policy scan proves the statement removed or successfully
parsed. Other successfully parsed statements continue through analysis. Condition semantics that are
not proven remain unknown even when syntax parses. Tests need unrecognized versus supported syntax,
multiple failures in one policy, parser upgrade/re-evaluation, and failed scan retaining findings.
