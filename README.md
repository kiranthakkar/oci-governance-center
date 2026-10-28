# OCI Governance Center

Read-only governance and observability for one OCI parent organization and its child tenancies.

This is a new implementation of the enrollment and scanner design in
[AGENTS.md sections 6–7](AGENTS.md#6-oci-integration--enrollment-application-access-and-scanner-trust).
The previous implementation has been removed. See the [documentation index](docs/README.md)
and [operator guide](docs/operations.md) for current setup, settings and troubleshooting.

## Implemented

- Setup-password-protected parent enrollment, with Terraform ZIPs and manual setup instructions.
- Parent API-key scanner and separate OAuth Code + PKCE human login.
- Parent selected-domain `ogc_viewer` / `ogc_admin` authorization, five-minute membership checks,
  checks before configuration changes, and session downgrade/revocation.
- Organization discovery, child scanner-domain configuration, API-key → parent JWT → child UPST
  exchange, and worker-local token renewal. Children use confidential-app client credentials for
  exchange and have no API keys.
- Separate bounded collection scheduler: IAM/domain inventory, Cloud Guard, Security Zones,
  Cloud Advisor, regional Audit ingestion, historical backfill and rolling reconciliation.
- Tabs: Overview, Coverage, Cloud Guard, Cloud Advisor, Cost, Resource organization (compartment
  tree and policy statement counts),
  Identity (users, groups, dynamic groups, policies, policy analysis), Activity, Scan, Configuration.
- Per-tenancy collection settings, daily/weekly schedules, scan diagnostics and finding triage.
- Monthly cost by tenancy/service/compartment from the parent Usage API.
- Normalized JSON exports, snapshot change history,
  encrypted credentials and server sessions, and local retention.
- Partial collection recovery, pause/resume, key repair, confirmed child-departure handling,
  and fresh parent replacement with generation fencing and recoverable old-data cleanup.

**OCI compatibility is not yet certified.** Python tests use synthetic data and mock remote calls;
parent/child Terraform packages have passed validation against the pinned official provider.
Live WIF caller authorization, scopes, all-domain reads, group completeness, human Asserter access,
provisioning behavior and volume limits still need an authorized non-production organization.
See [implementation status and release gates](docs/implementation/status.md).
Tier 4 policy and identity analysis is enabled; Tier 2 guardrail collectors and Tier 5 anomaly
detection are not. See [detection specifications](docs/detections/README.md).

## Run locally

Python 3.11+ is required; this checkout was checked on Python 3.13. `uv.lock` also records
transitive dependency versions/hashes (`uv sync --locked --extra dev` is an alternative install).
Run from the repository root:

```bash
python3.13 -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'

# Generate once; retain this key separately from the database. Do not regenerate on restart.
export OGC_ENCRYPTION_KEY="$(ogc encryption-key)"
export OGC_SETUP_PASSWORD='<operator-chosen long random setup password, at least 16 characters>'
export OGC_PUBLIC_BASE_URL='http://127.0.0.1:8000'
export OGC_DATA_ROOT='/path/to/private/ogc-data'

ogc web --host 127.0.0.1 --port 8000
```

Optional: `OGC_AUDIT_BACKFILL_HOURS` (default 168) limits how many historical Audit hours each scan
backfills; current events are always caught up to the present. `OGC_INACTIVE_DAYS` (default 90)
sets the no-sign-in/no-Audit window for inactive users, and `OGC_API_KEY_MAX_AGE_DAYS` (default 90)
the API-key rotation age (OCI API keys do not expire).

Local development supports HTTP on `localhost`, `127.0.0.1`, or `[::1]`. Set `OGC_PUBLIC_BASE_URL`
to the origin only (for example `http://127.0.0.1:8000`), without `/setup` or any other path.
Restart OGC after changing this setting, then open `http://127.0.0.1:8000/setup` in your browser.
Use the configured origin and register its `/auth/callback` URL with the parent OIDC application.
Development sessions use a separate HttpOnly, SameSite=Lax cookie without the Secure flag.

For production, set `OGC_PUBLIC_BASE_URL` to your HTTPS origin, such as `https://ogc.example.com`,
and put the web process behind an HTTPS reverse proxy that preserves the configured Host header.
HTTPS sessions use Secure, HttpOnly, SameSite=Lax cookies with the `__Host-` prefix and HSTS.
The backend binds to loopback by default. Raw Uvicorn access logging is disabled so OIDC
authorization codes do not enter access logs. Safe application summaries include route patterns,
status, duration and `X-OGC-Request-ID`, omitting queries, bodies and credentials. OGC's public URL is configuration, not inferred from untrusted
forwarded headers. Hosting/deployment automation remains in the backlog.

In a second process with the same settings and encryption key:

```bash
ogc scheduler
# Or collect once:
ogc scheduler --once
```

Use the **Scan** tab to start an on-demand full scan or save a **daily** (time) or **weekly**
(day and time) schedule with a timezone. Only `ogc_admin` can change these controls; viewers can
see the schedule and history. Keep `ogc scheduler` running separately: web requests queue work,
and the tab shows when the worker is offline. Recurrence is disabled until a schedule is saved.
These calendar schedules replace the previous fixed collection intervals. New enrollment and
child configuration still trigger collection automatically. Paused children remain paused.
See [scan controls and scheduling](docs/scanning.md) for recovery and daylight-saving behavior.

Open the public URL, enter the setup password, and follow the enrollment wizard. Apply the parent
setup as a tenancy administrator, provide the scanner and OIDC credentials, and finish with an
`ogc_admin` sign-in. Configure each discovered child with its scanner-domain URL and confidential-app
client ID/secret; OGC discovers the domain identifiers, home region and service user named `ogc`.
Failed scanner authentication does
not prevent OIDC login or viewing historical data.

## Setup packages and Resource Manager

```bash
ogc setup-package parent /tmp/ogc-parent.zip
ogc setup-package child /tmp/ogc-child.zip
```

Both ZIPs contain Terraform JSON, a Resource Manager schema, and setup instructions. They configure
IAM prerequisites only; they do not deploy the OGC application. Run Terraform/Resource Manager as
an authorized administrator in the target tenancy. OGC never applies the configuration itself.
Generate the parent scanner key pair locally and pass only its PUBLIC key to Terraform. Supply the
private key to OGC over HTTPS after provisioning. Treat both parent-login and child-exchange application Terraform state as sensitive.
For a parent subject of `ogc`, the child trust rule must be `sub eq ogc` without quotes.
See [child setup and credentials](docs/operations.md#child-setup-and-credential-separation).

For a direct **Deploy to Oracle Cloud** button, publish immutable parent and child ZIPs to a
Resource Manager-supported location and set `OGC_PARENT_PACKAGE_URL` / `OGC_CHILD_PACKAGE_URL`.
Until published, the application offers download plus the Resource Manager upload workflow.
It never emits a deploy link pointing to a nonexistent public package.

## Storage and operator commands

`OGC_DATA_ROOT/ogc.db` stores application state, coverage, normalized inventory and findings.
Credentials, enrollment candidates and server-side sessions are encrypted using Fernet.
Audit events live under `audit/g<N>/<hashed-tenancy>/<YYYY-MM>.db` and are committed before
interval receipts/checkpoints. Only credential/session payloads are encrypted, not all inventory
in SQLite. Runtime directories are private. Retention defaults to 90 days;
local control events use 365 days. Parent replacement removes the previous organization's control
history as well as inventory, findings, audit, credentials, sessions, managed backups and exports.
Key repair preserves organization history and fences existing workers/sessions.

```bash
ogc scan --family identity
ogc scan --family governance
ogc scan --family audit
ogc purge
```

Do not lose the encryption key or store it inside the data directory. A failed organization cleanup
is journaled and fences collection; starting the application again retries cleanup. Do not declare
replacement complete until cleanup succeeds. Previously downloaded files are outside OGC's control.

## Quality gates

```bash
ruff format --check .
ruff check .
mypy src
pytest -m 'not live'
```

[Tests](tests/) prohibit live network connections. The SDK operation allow-list and static boundary
tests reject unreviewed operations and SDK/HTTP construction outside reviewed modules. Generated
Terraform is validated separately with `terraform init -backend=false` and `terraform validate`;
neither validation nor the unit suite applies resources or certifies live OCI permissions.

## Browser regression check

With Node 22+ and Google Chrome installed, run `node tests/browser/setup.mjs` from the repository
root. Set `CHROME_PATH` for a different Chromium executable. This starts a temporary local server
and isolated browser profile with synthetic credentials, submits the setup form, and checks the
browser-generated Origin header and successful onboarding unlock. No OCI credentials are used.

Parent enrollment reports the verification step that failed, such as API-key validation,
GetTenancy/GetDomain, selected-domain ListUsers/ListGroups, or organization discovery.
The same safe diagnostic is written to the server log. Error responses omit raw OCI bodies,
private keys, and login secrets. When requesting help, share the step and safe diagnostic only.

Enrollment values are saved as an encrypted server-side draft when you select **Save draft** or
**Verify credentials and sign in**. A failed check returns to the same form. Saved private keys
and client secrets can be reused with their inputs left blank; uploading or entering replacements
updates them. Reloading the page or restarting OGC retains the draft within the same browser setup
session (one hour by default, controlled by `OGC_SESSION_SECONDS`). Browser cookies and the original
encryption key must be retained. Drafts are cleared by discard, cancellation, completed enrollment,
or a fresh replacement flow; changing parent domain/tenancy metadata clears saved credentials.

Human login uses Authorization Code + PKCE and requests only `urn:opc:idm:__myscopes__`.
It does not request `openid`, `profile`, or `groups` or require an ID token. OGC verifies the
returned user access token's signature, issuer, expiry, identity-domain API audience, and OAuth
client binding. It POSTs that access token to `/admin/v1/Asserter` with `includeMemberships=true`,
binds the returned user to verified `user_id` or `sub`, and checks the configured `ogc_admin` or
`ogc_viewer` group IDs. Client-only tokens and group display names do not authorize login.

The access token and identity binding remain encrypted in the server-side session for membership
rechecks every five minutes and before configuration changes. Expiry or older sessions without
the required access-token binding require a fresh login. The existing confidential application
must allow `urn:opc:idm:__myscopes__` and permit the assertion; live-domain acceptance remains a gate.
Group diagnostics show verified access-token and Asserter group fields and safe failure stages,
excluding tokens, authorization codes, client secrets, and unrelated profile values.

The scanner also uses `urn:opc:idm:__myscopes__` for API-key-to-parent-JWT issuance before child
UPST exchanges. It does not use human login credentials. Parent collection uses its API key directly.

Run `node tests/browser/setup.mjs --enrollment` to check the full credential POST → local login
redirect → identity-domain navigation in Chrome. OCI verification/discovery are synthetic, and the
identity-domain page is intercepted locally. Enrollment CSP permits only the configured domain's
HTTPS origin in addition to local form targets, so Chrome can follow this redirect chain.

Signing-key retrieval uses the newly received access token as bearer authorization against the
trusted identity-domain JWKS endpoint. This supports domains that disallow anonymous signing-key
reads. Logs distinguish code exchange, signing-key retrieval, local access-token validation, and
Asserter authorization. An omitted token-response `scope` field is reported as omitted; it is not
interpreted as an empty permission grant. ID-token presence is not checked or required.


## Understanding partial scans

A finished scan can have **Partial** coverage. Open **Scan → View scan details** or filter
**Coverage** to incomplete scopes. `OGC-ACCESS-002` flags collection gaps; it is not itself proof
of a security violation. Unfinished Audit backfill currently uses this flag too: “history is still
being collected through” describes successful progress, not a read denial. The default backfill
budget is now 168 hours per region per scan; current Audit events are collected separately.

Finding triage (Ignore, Mark closed, Reopen) is local to OGC and restricted to `ogc_admin`.
See [scanning and triage](docs/scanning.md) and [troubleshooting](docs/operations.md#troubleshooting-and-recovery).

The former `OGC_DEBUG_TOKEN_EXCHANGE` setting has been removed. Current logs redact tokens;
raw bearer tokens and request payloads are not exposed in the UI.


For load-balancer failures, use the [web diagnostics guide](docs/operations.md#web-request-and-connection-diagnostics).
`ogc web` reports safe parser rejection reasons, including HTTPS/TLS sent to its plain HTTP port.
Use HTTP/1.1 for backend forwarding when HTTPS terminates at the load balancer.


Scanner users can belong to a **default or non-default identity domain**. Parent enrollment keeps
**tenancy home region** separate from **identity-domain region**; enter the latter when different.
User verification queries the selected domain's Users API rather than legacy IAM `GetUser`.
Terraform policies bind the created scanner group by OCID. Child Configure discovers the selected
domain and its region from the supplied URL. See [selected-domain setup](docs/operations.md#selected-scanner-domains-and-regions).
