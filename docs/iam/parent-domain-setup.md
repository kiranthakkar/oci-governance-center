# Parent identity domain setup (for OCI IAM sign-in)

OSC does **not** create any of this (it is read-only). A parent-tenancy identity-domain admin performs
these steps once. Verify every step against current OCI documentation; names of menus and CLI
flags change over time.

## 1. Groups

In the parent's Default identity domain create:

| Group | Purpose |
|---|---|
| `OSC-Admins` | Organization / child configuration screens, Verify |
| `OSC-Viewers` | Findings, policy review, audit views and exports; no OCI permissions |
| `OSC-Scanners` | *workstation mode only*: holds the OSC service user (API key) |

For `oci` mode create a **dynamic group** `OSC-Scanner-DG` with a matching rule that names only the
OSC instance:

```
ALL {instance.id = '<OCID of the OSC compute instance>'}
```

(For Container Instances use the matching rule the OCI docs give for container instance resource
principals.)

## 2. Confidential integrated application

Identity & Security → Domains → Default → Integrated applications → Add → **Confidential Application**:

- Client configuration: **Authorization Code** and **Client Credentials** grant types; do not assign
  identity-domain administrative roles to the OAuth application. The app must not acquire domain
  administration powers merely by possession of its client secret.
- Redirect URL: `https://<osc-host>/auth/callback` (workstation: `http://localhost:8000/auth/callback`)
- Include **group membership** in the ID token / userinfo so OSC can map `OSC-Admins` / `OSC-Viewers`
  (OSC reads the claim named by `OSC_GROUPS_CLAIM`, default `groups`)
- Activate the app; record the **client ID** and **client secret**. Store the secret in OCI Vault
  and give OSC the secret OCID (`--client-secret-ocid`) only with an independently usable keyless
  scan identity. Otherwise use the encrypted local secret prompt during host bootstrap. See
  [secret dependency restrictions](../control-plane.md#31-secret-retrieval-and-bootstrap-dependency).

## 3. Identity Propagation Trust (token exchange → UPST)

Lets OSC exchange the signed-in admin's access token for an OCI session token
(`oci.auth.signers.TokenExchangeSigner`). This is a **parameterized setup template**, not a proven
same-domain interactive-token recipe. A domain admin must validate the intended access-token issuer,
JWKS source and subject mapping in an authorized sandbox. A token's `sub` is not necessarily its
userName; map a verified claim to the corresponding supported user attribute. Keep impersonation off,
restrict exchange to this OAuth client, and test a denied client and a wrong subject as well as success.
Do not record JWTs or personal claims in documentation or fixtures.

Example with the OCI CLI (check flags against the installed CLI help):

```bash
oci identity-domains identity-propagation-trust create \
  --endpoint "https://idcs-<guid>.identity.oraclecloud.com" \
  --schemas '["urn:ietf:params:scim:schemas:oracle:idcs:IdentityPropagationTrust"]' \
  --name "OSC token exchange" \
  --type JWT \
  --issuer "<verified access-token issuer>" \
  --active true \
  --allow-impersonation false \
  --subject-claim-name "<verified subject claim>" \
  --subject-mapping-attribute "<matching supported user attribute>" \
  --subject-type User \
  --client-claim-name "<verified client-binding claim>" \
  --client-claim-values '["<verified allowed claim value>"]' \
  --oauth-clients '["<client ID>"]' \
  --public-key-endpoint "<verified issuer JWKS URL>"
```

The verified JWKS endpoint must be reachable by the token-exchange service without authentication (domain
settings → "Configure client access" / access signing certificate).

Validate group claims in both initial login and userinfo at refresh; missing/unconfirmed membership
ends the session. Test admin-to-viewer downgrade and complete group removal. Scope/grant configuration
must actually support refresh tokens; a refresh token is not guaranteed simply by requesting login.
The application release test must verify expiry, issuer/audience/nonce, PKCE, wrong-client rejection,
and user mapping for the chosen identity domain. Child UPST browsing remains disabled until D2 passes.

## 4. Policies

Open **Organization configuration** in OSC (or run `osc policies parent`). It lists every statement
OSC needs, with an `oci iam policy create` command, and shows which are already applied.

## References
- Oracle token exchange grant and identity propagation trust:
  https://docs.oracle.com/en-us/iaas/Content/Identity/api-getstarted/json_web_token_exchange.htm
- A-Team, OIDC token exchange to OCI UPST:
  https://www.ateam-oracle.com/github-actions-oci-a-guide-to-secure-oidc-token-exchange
