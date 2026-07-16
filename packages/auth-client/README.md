# @neko/auth-client

Framework-independent browser OAuth 2.0 Authorization Code + PKCE client used by N.E.K.O. web applications.

The package owns PKCE, authorization transactions, callback exchange, refresh de-duplication, token revocation, and session clearing. Application-specific routes, return-path validation, account URLs, and logout UI remain in each consumer.

`0.1.0-rc.6` keeps the `browser-auth-v1` defaults while adding opt-in consumer
safeguards:

- `transactionMaxAgeMs` rejects callbacks with missing, future, or expired
  state-bound transaction timestamps.
- `preserveSessionOnServerError` makes refresh reject without clearing the
  current session for Hydra `5xx` and `429` responses. Network failures already
  reject without clearing under the v1 contract.
- `preserveSessionOnRefreshError` preserves the session for every ambiguous
  refresh failure, including `408`, temporary `4xx`, `429`, `5xx`, malformed
  successful responses, and network errors. Only explicit OAuth credential
  errors such as `invalid_grant` clear the matching session.
- `oauthRequestTimeoutMs` bounds token and revocation HTTP requests. It aborts
  the underlying request and rejects on schedule even when a fetch adapter
  ignores `AbortSignal`, so a refresh coordinator cannot remain locked forever.
- `refreshCoordinator` lets consumers provide a cross-tab mutex. The SDK
  rechecks the refresh-token snapshot inside the critical section, so two tabs
  cannot submit the same rotating refresh token concurrently.
- `localFirstRevoke` clears local state before bounded best-effort revocation;
  `revokeTimeoutMs` controls the bound and defaults to three seconds.
- `revokeTokens({ accessToken, refreshToken })` performs the same bounded
  best-effort revocation for a detached token snapshot without reading,
  clearing, or otherwise mutating the client's current session. Consumers can
  therefore complete local logout before deferred client/config initialization.

Session stores receive an optional `{ grantType }` context. Consumers can use it
to replace an authorization-code token family without accidentally inheriting a
refresh token from another account, while still retaining an unrotated refresh
token after a refresh grant.

Error callbacks are state-validated before authorization state is cancelled;
an unrelated or forged `?error=...&state=...` cannot erase a real transaction.

Refresh responses are also guarded by a refresh-token snapshot: if another
account replaces or clears the session while a refresh is in flight, the stale
response cannot overwrite or clear that newer session.

Do not publish the package without confirming ownership of the `@neko` npm scope.
