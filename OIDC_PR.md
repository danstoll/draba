# Add OIDC / SSO login (opt-in, security-first)

Adds optional OpenID Connect single sign-on alongside the existing local
password auth. SSO is **disabled by default** and fully inert — no new network
calls, no behaviour change — unless `DRABA_OIDC_ISSUER` is set. Built to slot
into the existing patterns rather than reshape them.

## Why

Draba is a great fit for self-hosted stacks where every tool federates to one
identity provider (Authentik, Keycloak, Zitadel, Auth0, Google…). Today draba
is the only piece that needs its own accounts. This lets an operator point draba
at their IdP and have "Sign in with SSO" just work, while keeping local accounts
as the default and as a break-glass.

## What it does

- New routes (public, registered only-as-handlers; both 404 when SSO is off):
  - `GET /auth/oidc/login` → redirects to the IdP (PKCE + state + nonce).
  - `GET /auth/oidc/callback` → verifies the ID token, finds-or-provisions the
    local user, issues the **same** draba access/refresh JWTs as password login,
    and hands them to the SPA via the URL fragment.
- First SSO login auto-provisions a local account (respecting the tier user
  limit); the first user on a fresh install becomes the superadmin, exactly like
  password registration. Set `DRABA_OIDC_AUTO_CREATE=0` to require accounts be
  pre-created.
- Returning users are matched on the stable `(issuer, subject)` pair; email and
  display name are refreshed from claims each login.
- Login page shows a "Sign in with SSO" button only when the instance reports
  `ssoEnabled` (added to the public `/settings/branding` response).

## Security posture

- **ID token signature is verified** against the IdP JWKS via `go-oidc`
  (`coreos/go-oidc/v3`). No unsigned/self-asserted tokens are trusted.
- **PKCE (S256)** on every flow, **state** bound to an httpOnly cookie (CSRF),
  **nonce** bound into the ID token and compared in constant time (replay).
- Transient flow cookies are httpOnly, `SameSite=Lax`, `Secure` when the request
  is HTTPS (honouring `X-Forwarded-Proto`), scoped to `/auth/oidc`, 10-min TTL,
  cleared on callback.
- The client secret is read once from the env and never leaves the process or
  any API response.
- An OIDC account (no password) can **never** authenticate via `POST /auth/login`
  or change a password — both reject `nil`-password users with the same generic
  error, so the endpoints don't become an account-type oracle.
- Tokens are returned to the SPA in the URL **fragment** (`#…`), never the query
  string, so they are not sent to a server or written to access logs.

## Opt-in dependency note

OIDC pulls in `github.com/coreos/go-oidc/v3` and `golang.org/x/oauth2`. They are
compiled in but **dormant** unless SSO is configured (`NewOIDCService` returns
`nil` for an empty issuer, and every handler treats a nil service as disabled),
so a default install does no OIDC work. Versions are pinned to the newest that
keep the module on **`go 1.24.0`** (`go-oidc v3.16.0`, `oauth2 v0.34.0`) — the
toolchain directive is unchanged.

## Database

Migration `024_oidc_identity.sql`:
- Makes `users.password_hash` nullable (OIDC users have no password).
- Adds `auth_provider ('local'|'oidc')`, `oidc_issuer`, `oidc_subject`, with a
  row-level `CHECK` (local ⇒ password; oidc ⇒ issuer+subject) and a unique index
  on `(oidc_issuer, oidc_subject)`.
- **Safety:** `users` is referenced by ~17 foreign keys, several
  `ON DELETE CASCADE`. The rebuild follows the official SQLite procedure
  (`foreign_keys=OFF` → rebuild → `foreign_key_check` → `foreign_keys=ON`) so the
  `DROP TABLE` cannot cascade-delete dependent rows. A migration test seeds a
  user with team/membership rows and asserts they survive the rebuild.

## Config (all optional)

| Env var | Purpose |
|---|---|
| `DRABA_OIDC_ISSUER` | IdP issuer URL. **Unset = SSO disabled.** |
| `DRABA_OIDC_CLIENT_ID` / `_CLIENT_SECRET` | OAuth2 client credentials |
| `DRABA_OIDC_REDIRECT_URL` | Callback URL (defaults to `DRABA_BASE_URL` + `/auth/oidc/callback`) |
| `DRABA_OIDC_AUTO_CREATE` | `0` to disable first-login provisioning |

## Tests / checks

- `go build ./...`, `go vet ./...`, full `go test ./...` — all green.
- New: `oidc_handler_test.go` (disabled→404, `ssoEnabled` flag, OIDC user can't
  password-login, create/lookup/unique round-trip) and the migration safety test.
- `gofmt` clean. Web `tsc --noEmit` (the `lint` script) clean.
- Not run locally: `golangci-lint` (not installed in my env) — worth a final pass
  before merge.

## Open questions for you

1. **Dependency appetite** — happy with `go-oidc` + `oauth2`, or would you prefer
   a leaner hand-rolled discovery/JWKS path? I went with the audited libraries
   given the security surface, but it's your call on the dep philosophy.
2. **`go 1.24` pin** — kept it. If you're open to `go 1.25`, I can bump to the
   latest `go-oidc`/`oauth2`.
3. **Auto-provisioning default** — defaults ON to mirror password registration.
   Reasonable, or default OFF?
