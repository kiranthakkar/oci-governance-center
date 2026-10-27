# OGC operator guide

Reviewed against the source on 2026-10-27. Installation commands are in the
[README](../README.md); scan behavior is specified in [scanning](scanning.md).

## Processes and environment

Run the web server and scanner separately, from the repository root, with the same data root,
encryption key and public URL. Use an absolute data root so different working directories cannot
silently create separate databases.

```bash
ogc web --host 127.0.0.1 --port 8000
# In another terminal with the same OGC environment:
ogc scheduler
```

The web server queues scans; the scanner claims them. `ogc scheduler --once` requests and attempts
one organization job, then exits; it is not a persistent scheduler and may exit without running
if another job or tenancy lease prevents claiming work. `ogc scan --family all` collects directly
and includes Audit; `identity`, `governance` and `audit` restrict the family. Direct CLI scans do
not create a queued scan-history job. Run only one collection mechanism at a time.

Settings are environment variables read on process startup by `config.Settings`. Restart both
processes after changes. No `.env` file is automatically loaded by the current settings class.

| Variable | Default / requirement | Purpose |
|---|---|---|
| `OGC_ENCRYPTION_KEY` | Required | Fernet key from `ogc encryption-key`; generate once and retain separately |
| `OGC_SETUP_PASSWORD` | Required; at least 16 characters | Protects initial setup before the first parent is enrolled |
| `OGC_PUBLIC_BASE_URL` | `https://localhost:8443` | Public origin, without a path; loopback HTTP is supported for development |
| `OGC_DATA_ROOT` | `.ogc` | Private local runtime directory; prefer an absolute path |
| `OGC_PARENT_PACKAGE_URL` | Empty | Published immutable parent ZIP for the deploy button |
| `OGC_CHILD_PACKAGE_URL` | Empty | Published immutable child ZIP for the deploy button |
| `OGC_MAX_WORKERS` | `4` | Maximum concurrent tenancy collection threads |
| `OGC_RETENTION_DAYS` | `90` | Local retention and initial Audit history window |
| `OGC_SESSION_SECONDS` | `3600` | Absolute browser session / setup-draft lifetime |
| `OGC_AUDIT_BACKFILL_HOURS` | `168` | Historical Audit hours processed per region per scan |
| `OGC_INACTIVE_DAYS` | `90` | No-sign-in/no-Audit inactivity analysis threshold |
| `OGC_API_KEY_MAX_AGE_DAYS` | `90` | API-key rotation-age finding threshold |

Numeric settings must be positive. The former fixed family scan intervals are not settings in
this runtime; configure daily or weekly recurrence in the Scan tab. `OGC_DEBUG_TOKEN_EXCHANGE`
is also no longer supported: bearer-token logging was removed. Tokens remain redacted.

Never replace the encryption key to fix a startup failure on an existing installation. Recover
the original key; changing it makes stored scanner credentials, child secrets and sessions unreadable.
The setup password stops authorizing enrollment once a parent is installed. Administrator login,
not the setup password, authorizes configuration and replacement after that point.

## Parent setup and human login

Generate/download a parent setup ZIP through the wizard or
`ogc setup-package parent /tmp/ogc-parent.zip`. An administrator applies it in the parent's Default
domain using Terraform or Resource Manager. It creates the scanner user/group, human login groups,
initial admin membership, read policies and dedicated confidential login app. It does not deploy OGC.
Generate the scanner RSA key pair outside Terraform; supply only its public key to the stack.

Complete enrollment with the parent identifiers, scanner user OCID, key fingerprint/private key,
and login application client ID/secret requested by the wizard. Successful scanner verification
and a human `ogc_admin` sign-in are both required before the candidate becomes active.

Human login uses Authorization Code + PKCE, requesting only `urn:opc:idm:__myscopes__`.
It requires a signed user access token, not an ID token. OGC validates issuer, keys, expiration,
API audience and OAuth client binding, then calls `/admin/v1/Asserter` with that access token
and `includeMemberships=true`. Only configured parent Default-domain group IDs authorize access:
`ogc_viewer` reads organization data; `ogc_admin` also changes configuration and triages findings.
Membership is checked every five minutes and before configuration writes. Login credentials are
independent of the scanner credentials; a scanner-key failure must not prevent repair through the UI.

Register exactly `${OGC_PUBLIC_BASE_URL}/auth/callback` with the login app. Use the same origin
in the browser. Local loopback HTTP uses a development cookie; HTTPS uses a Secure `__Host-`
cookie. Reverse proxies must preserve the configured Host; forwarded headers do not redefine it.

## Child setup and credential separation

For each discovered child, apply its setup package as a child administrator. The package creates:

1. The child Default-domain non-interactive `ogc` service user.
2. `ogc_scanner`, its user membership and tenancy-local read policies.
3. An active confidential application, **OGC Parent Token Exchange**.
4. An active JWT propagation trust with the parent's issuer/JWKS, the app's OAuth client ID,
   and an exact impersonation rule targeting the child service user's SCIM ID.

For a parent JWT whose subject is `ogc`, enter `parent_subject=ogc`; the generated rule is
`sub eq ogc`, without quotes around the subject. The subject must match the actual issued JWT;
the Terraform scanner-subject output is a SCIM ID and does not by itself establish the JWT's `sub`.
Keep the app's OAuth client ID (`name`) distinct from its SCIM resource ID (`id`).

Child Configure asks for the **Default-domain URL and child app client ID/secret**. No child user
OCID, domain OCID, GUID or region needs manual entry. OGC obtains a child UPST, discovers the
child's home region/Default-domain metadata, searches `userName eq "ogc"`, requires one active
service user, and validates the discovered identities against the selected child tenancy.

| Operation | Credential |
|---|---|
| Parent scans / organization discovery | Parent `ogc` API key |
| Parent JWT issuance | Parent API-key-signed request, scope `urn:opc:idm:__myscopes__` |
| Child JWT-to-UPST exchange | Parent JWT as `subject_token`; child confidential app ID/secret as HTTP Basic caller authentication |
| Child OCI reads | Child UPST plus its ephemeral bound signing key |
| Human login | Separate parent login app and human access token |

No child API key is created. Child app secrets are stored encrypted separately from inventory,
committed only after successful verification. Blank secret retains the saved value only for the
same client ID and domain URL; changing either requires a new secret. A failed check preserves
previous configuration and credentials. Resume reuses saved credentials and repeats discovery.
The app secret is not an ordinary Terraform output; retrieve it securely from its configuration.
Terraform state may contain it. Protect that state and never upload it to OGC.

Configured children start monitoring automatically; the Scan tab controls what to collect in each
tenancy. Identities default to the Default domain only; enable All identity domains when required.
These settings do not change the scanner's tenancy-wide read grants.

## Reading scan results

A finished worker does not establish complete data coverage. Partial means one or more enabled
collection scopes are incomplete. A scope is a dataset plus tenancy, region and optional domain
or compartment. The count is organization-wide and includes unresolved results from earlier attempts.
Use **Scan → View scan details**, **Coverage → Show incomplete scopes**, or the **Scanner coverage
gap** findings (`OGC-ACCESS-002`). Scan details distinguish this run's attempts from earlier ones.
Newly completed jobs retain diagnostic snapshots; older runs without one link to current coverage.

For Audit, `audit.events` tracks current activity, `audit.reconcile` re-reads recent intervals
for late events, and `audit.backfill` loads historical events toward the fixed point where forward
collection began. The endpoint is five minutes behind the current clock. Backfill is bounded by
`OGC_AUDIT_BACKFILL_HOURS`; current catch-up is not limited to that budget.

**“Audit history is still being collected through <timestamp>”** reports a saved progress cursor
after successful interval reads. It is not a permission-denial message. Subsequent scans resume
there. The current UI records unfinished backfill as incomplete coverage and raises the same
coverage finding as a failed read; there is not yet a separate Backfill-in-progress status.
This does not certify that intervals outside the completed range were collected. Read the
`audit.events` row separately to assess current-event collection.

Cost is queried only by the parent for the tenancies covered by its billing. Parent `ogc_scanner`
requires `read usage-report`; children do not. The Cost tab covers the current month and eleven
previous months, retaining currencies separately. Compartment queries use depth 6, with deeper
costs aggregated into their depth-6 ancestor. Equal tenancy names remain separate by OCID.

Policy counts in Resource organization describe attached statements, not evaluated effective
permissions. Counts require complete compartment discovery and policy coverage for the root and
all active compartments. Missing reads remain unknown. An orphan's own count may be shown, but
its hierarchy and descendants' hierarchy totals remain unavailable until all ancestors are known.

## Troubleshooting and recovery

| Symptom | Check / next action |
|---|---|
| Scan stays Queued | Start `ogc scheduler` with the same data root/key. Check the worker-offline warning and lease-wait explanation in Scan. Refresh the page. |
| Worker finished, result Partial | Read incomplete Coverage rows or scan details; successful datasets remain available. A backfill progress message is distinct from an API error. |
| Child token endpoint returns 400 | Read the safe OAuth error/category and request ID. Check child client ID/secret, trust `oauthClients`, parent issuer/JWKS, exact unquoted subject rule and mapped service user. HTTP status alone does not prove which prerequisite failed. |
| Parent assertion mismatch | Verify the parent key belongs to Default-domain `ogc` and check its subject mapping. OGC supports matching username, SCIM ID or OCID with consistent identity claims. Do not log bearer tokens. |
| Cost read denied | Add the parent-only `read usage-report` statement using a tenancy administrator, then rescan. OGC does not apply policies. |
| Cross-origin form rejected | Compare the browser origin with `OGC_PUBLIC_BASE_URL`; omit `/setup` from that setting and restart the web app. |
| Fernet / unreadable credentials | Validate key format; restore the original key for existing data. Do not silently re-enroll or delete data. |
| Parent API key confirmed invalid | All organization collection stops, including child token renewal. An `ogc_admin` repairs the parent scanner credentials through Configuration; historical data remains readable. |

Scanner logs identify tenancy phases, safe errors and Audit progress every 24 historical hours.
The current logging configuration redacts bearer tokens; it never needs raw token payloads to
operate. Logs are server-side. The UI serves recorded diagnostics, not raw log files or tracebacks.
Remove any bearer-token logs captured by earlier troubleshooting versions from log destinations.

The first Ctrl-C/SIGTERM to `ogc scheduler` (including `--once`) requests a safe stop; the second
marks this worker's job interrupted, releases its tenancy locks and exits immediately. A crash
without cleanup recovers after job-lease expiry, normally about two minutes. Standalone CLI scan
leases can remain until their own expiry. Committed Audit hours remain durable; interrupted hours
are retried. See [scan shutdown and recovery](scanning.md#scanner-trace-2026-10-27).

## Local storage and maintenance

`OGC_DATA_ROOT/ogc.db` contains organization state, children, encrypted child credentials, encrypted
sessions/candidates, scoped records/coverage/findings, finding triage, changes, scan settings,
schedule/jobs/scope snapshots, leases, checkpoints, receipts and local control events. Only credential
and session payloads are Fernet-encrypted; the whole SQLite file is not encrypted by this code.
Audit events live under `audit/g<N>/<hashed-tenancy>/<YYYY-MM>.db` and are durable before progress
is committed to the main database.

The scanner runs retention daily; `ogc purge` runs it on demand. Retention deletes events, old
records/findings/changes, finished scan jobs and their snapshots according to `OGC_RETENTION_DAYS`.
Triage is removed with purged findings; local control events use 365 days. Credentials/settings
remain until changed or the organization is replaced. This is not a per-dataset retention setting.

Successful parent replacement atomically switches configuration and clears prior local organization
state, then performs journaled filesystem cleanup. Incomplete new onboarding leaves the old parent
intact. A failed cleanup blocks collection and retries on startup. Same-parent credential repair
preserves organization history and child secrets while fencing old sessions/workers. Downloaded
artifacts outside the runtime directory cannot be recalled.

There is no automated backup/restore command, key rotation migration, or versioned database migration
runner. Do not use historical `osc db` examples. Before operator-managed copies or software changes,
stop both processes and preserve the entire data root, SQLite sidecar files if present, and the
original encryption key separately. A database-only copy omits Audit history. Recovery/restore of
such a copy has not been certified; rehearse recovery on an isolated copy before relying on it.
