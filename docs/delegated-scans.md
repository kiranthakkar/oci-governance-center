# Delegated tenancy scans

> **2026-10-22:** This page contains historical design/implementation details.
> New enrollment/scanner contracts are in [AGENTS.md sections 6–7](../AGENTS.md#6-oci-integration--enrollment-application-access-and-scanner-trust);
> current code and release gates are in [implementation status](implementation/status.md).

Decision: 2026-10-15. Optional delegated UPST connections are supported for the parent and each
registered child. This replaces the cross-tenancy-only restriction for child IAM inventory and the
blanket prohibition on scheduled UPST use. The existing parent scanner remains the default for
connections without an override. Configured delegated connections never fall back on failure.

## Authentication and permissions

An OSC administrator configures one selected identity domain in a tenancy, registers a confidential
OIDC application with Authorization Code + PKCE, Refresh Token and token-exchange support, and sets
up Identity Propagation Trust. Request `openid profile offline_access`. Domain issuer, JWKS, subject
mapping and allowed OAuth client must match the actual tokens. Setup is performed by humans, never
OSC. The runtime application must not have Identity Domain Administrator merely to exchange tokens.
See [Oracle token exchange](https://docs.oracle.com/en-us/iaas/Content/Identity/api-getstarted/json_web_token_exchange.htm)
and [refresh grants](https://docs.oracle.com/en-us/iaas/Content/Identity/api-getstarted/RefreshGT.htm).

Authorize using an account local to the intended tenancy with the read-only access described in
[delegated IAM prerequisites](iam/delegated-scan.md). One application in the selected sign-in domain
is intended to cover the tenancy; other domains still need authorization and endpoint verification.
A UPST does not add permissions. Cross-tenancy Audit access is not proof of child IAM access.

## Connection and grant lifecycle

- `delegated_scan` is a separate Connection purpose; only `oidc_token_exchange` is allowed.
- Admin-only web forms configure, authorize, reauthorize and disconnect each tenancy's connection.
  Authorization is a separate OIDC round trip, not a change of OSC login or role. A valid OSC admin
  session, CSRF, OIDC state/nonce/PKCE, connection ID and organization generation bind the operation.
- Confidential client credentials are encrypted local secrets or references; access/refresh tokens
  and subject metadata are independently encrypted in `delegated_grants` in local `osc.db` (0700
  directory, 0600 file). Tokens never enter templates, URLs, logs, fixtures or command arguments.
  Keep the encryption key separate and recoverable; production injects it through the existing key
  mechanism. Browser logout does not disconnect a delegated background grant.
- Status is `pending`, `active` or `reauthentication_required`. A valid callback must include a
  refresh token, verified subject and ID token; it exchanges the access JWT for UPST before saving.
  A UPST user subject (`sub`) must identify an OCI user. Before saving or using each new UPST,
  a temporary fixed SDK signer uses that token and its matching ephemeral key for `GetTenancy`
  and `GetUser`. The returned tenancy ID, user ID and user's owning tenancy (`compartment_id`)
  must match the connection. Reauthorization pins the user for later exchanges. No `res_tenant`
  claim is required or treated as identity proof. Scans establish per-dataset coverage.
- Each worker owns its signer and ephemeral signing key. UPST and that key stay in memory and are
  re-created after restart. Persist no UPST without its key. The signer checks tenancy and subject on
  every exchange, including automatic renewal. SDK request logging remains disabled.
- Refresh under one main-DB `BEGIN IMMEDIATE` transaction per grant operation. This deliberately
  serializes renewal across scheduler/web processes and connection changes (15-second HTTP timeout).
  Save a replacement refresh token durably before releasing the transaction. Connection identity,
  authorization ID and generation are also bound inside the encrypted payload and fence stale workers. No token response body appears in an error.
  Long scans re-check authorization at client creation; revoked leases fence in-flight publication.
- OAuth `invalid_grant` / `invalid_client` requires reauthorization for only that connection. Network
  and server failures remain visible and retryable; a rotated token lost across a crash/network
  boundary may require reauthorization. Refresh expiry and absolute/sliding session behavior follow
  the domain's policies; never promise perpetual unattended access. Oracle documents a configurable
  seven-day refresh-token default:
  https://docs.oracle.com/en-us/iaas/Content/Identity/api-getstarted/refreshtokenexiry.htm.
- Remote refresh-token revocation is discovered at renewal; an already-issued UPST may remain
  usable until its own expiry. Local disconnect fences future client creation and publication.
- Configure/disconnect invalidates outstanding authorization and collection leases. Organization
  replacement removes grants of deleted connections. Offline restore discards all restored grant
  tokens and marks their connections for reauthorization: backups may contain superseded rotations.
  Local disconnect removes ciphertext; administrators may also revoke the grant at the issuer.

## Scan routing and coverage

CLI, scheduler and child Verify resolve the registered tenancy's delegated connection when present.
The parent scanner still supports organization discovery and existing Endorse/Admit paths. A child
with its own connection need not share subscribed regions with the parent for Audit collection.
Unconfigured children retain the existing cross-tenancy path; errors are reported rather than hiding
unsupported IAM scope. One failing/revoked grant does not stop other tenancies. Delegate-read failures
must not silently replace stored inventory or resolve open coverage findings.

## Onboarding screens

The child configuration screen offers delegated scanning first and shows the selected connection's
pending/active/reauthentication status. The delegated connection screen includes local Allow policy,
OAuth application/trust, callback URI and offline scopes, then save, authorize, verify and scan steps.
Endorse/Define/Admit templates are shown in a separate parent-scanner section only when no delegated
connection exists. Pending or revoked delegated grants do not restore cross-tenancy requirements.

The organization screen distinguishes OSC admin sign-in, default parent scanning and delegated
parent scanning. Its Endorse roll-up omits scanner grants for delegated children (optional admin
browsing remains independent). Default scanner grants are omitted when the parent and all selected
children use delegated connections. OSC administration grants remain required for discovery and
policy checks. Child Verify uses the selected identity, checks child root-policy readability and
never resolves parent groups or requires Admit statements for a delegated identity. Stored smoke
results from a different connection are hidden until verification is repeated.

Short issue/fix summary: legacy onboarding templates and Verify still assumed parent-only scanning.
The screens and required-policy checks now follow the configured scan connection, with regression
coverage for delegated, mixed and default paths. This changes local requirements only; OSC does not
remove or apply policies in OCI.

Authorization-start diagnostics distinguish discovery HTTP failures, connectivity/TLS, timeouts,
invalid metadata and local redirect failures. Only OSC-authored messages, HTTP status and exception
type are displayed/logged, never provider response bodies, URLs or credential-bearing exception text.
Failed starts clear the pending authorization marker. A regression uses the real installed Authlib
redirect builder with synthetic metadata, rather than replacing the entire OAuth client.

Short issue/fix summary: the authorization-start catch-all incorrectly suggested every failure was
an app-configuration problem. Stage-specific safe diagnostics now identify where setup stopped.
An actual environment failure still needs its reported diagnostic; mocked success does not establish
connectivity to a real identity domain.

Short issue/fix summary: a successful local authorization POST could still have its external
redirect blocked by the page's `form-action 'self'` policy. Delegated setup and authorization
responses now allow only the saved, validated identity-domain origin in `form-action`; other pages
remain local-only. Regression checks exercise the real Authlib redirect builder and both pages' CSP.
Browser differences are documented in [MDN form-action](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy/form-action).
Endpoint validation also now compares host and effective HTTPS port: an explicit `:443` is equivalent
to an omitted port. Different hosts, nonmatching ports, credentials and query/fragment URLs remain
rejected. These fixes are verified synthetically; the deployment's actual metadata is not inspected.

Short issue/fix summary: the callback previously combined missing refresh grants, ID-token
validation, UPST identity checks, OCI read denial and encrypted-grant persistence into one generic
failure. It now records and displays a safe stage-specific diagnostic. Missing access and refresh
tokens have separate instructions; known identity-binding errors and standard OAuth rejection codes
are mapped to fixed messages. OCI read failures report HTTP status without the provider body. Unknown
errors expose only the stage and exception type. The previous grant is never replaced on failure,
and tenancy/user/ID-token checks remain mandatory. Mocked callback regressions cover no refresh token,
wrong-tenancy UPST, denied tenancy read and rejected authorization code, including secret-leak checks.
Actual deployment failure remains unconfirmed until its new stage diagnostic or live evidence exists.

For an inactive delegated grant, the child page offers **Authorize scanning** instead of **Verify
access**; direct Verify/scan calls still fail closed with the appropriate grant-state error.

Grant-use errors distinguish never-authorized (`pending`), expired/revoked/restore-invalidated
(`reauthentication_required`), changed authorization (restart the scan/Verify request), and replaced
or removed connections (authorize the current connection). Saving connection settings deliberately
replaces the connection and clears its previous grant; do not save again after authorizing unless
changing settings. Only a successful validated callback moves a pending grant to active. Scan errors
about grant state are not evidence that an OAuth callback completed successfully.

Short issue/fix summary (2026-10-15): a real UPST exchange succeeded but OSC rejected the token
because it assumed a `res_tenant` claim. Tenancy binding now uses authoritative read-only OCI
metadata rather than that claim. `GetTenancy` alone is insufficient because a foreign principal may
have cross-tenancy access: `GetUser(sub)` must also return the same user and its owning tenancy must
match. A separate fixed `SecurityTokenSigner` avoids recursive renewal during these probes. Both
reads repeat on every UPST exchange/renewal; denied or mismatched responses fail closed. All clients
still pass through the read-only factory. Only matching metadata fields are inspected; raw tokens,
user records and provider bodies are never logged. This does not establish full dataset coverage.
See [Oracle User model](https://docs.oracle.com/en-us/iaas/tools/python/latest/api/identity/models/oci.identity.models.User.html).

## Acceptance and live evidence

Mocked checks must cover token isolation, encrypted storage, refresh rotation, restart, concurrent
renewals, revoked grants, generation/config fencing, callback authorization, endpoint validation,
read-only client routing, backup/restore and removal. `IdentityClient.get_user` is newly allow-listed
for delegated identity proof, covered by the existing `read all-resources` local grant; no dependency,
write operation or broader IAM grant is added. Only reviewed OAuth endpoints add raw HTTP access.

Live POC remains required: authorize a named non-production child, confirm API-backed UPST user/tenancy binding,
read root and compartment policies, discover domains and read users/groups in both the sign-in and a
second domain. Exercise access expiry, UPST renewal, restart, revocation and reauthorization. Record
only sanitized results, never tokens. This document does not authorize live calls or provisioning.
