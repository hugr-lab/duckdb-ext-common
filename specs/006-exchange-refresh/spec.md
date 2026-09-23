# Spec 006: token exchange that keeps a refresh token, when asked

- **Status**: implemented
- **Date**: 2026-09-23
- **Author**: hugr lab (the tresor session)
- **Consumer**: tresor spec 009 (forwarding a session's user token to downstream servers)

## Summary

`TokenExchange` (spec 004) always asks for an access token and drops any refresh token. That suits a
token used once (tresor trades it for a delegation grant). It does not suit a token forwarded on
the user's behalf to a downstream server for as long as the user's session lasts:
- tresor must not keep the user's original token (acl's contract);
- an exchanged access token lives minutes.

A new flag `with_refresh`, on `TokenExchange` and `OnBehalfOf`, asks the IdP for a refresh token too
and keeps it, so the caller can renew the forwarded token with `RefreshGrant` for the session's life.

## Design

```cpp
TokenSet TokenExchange(ep, client_id, client_secret, subject_token, audience, scope = "", resource = "",
                       bool with_refresh = false);
TokenSet OnBehalfOf(ep, client_id, client_secret, assertion, scope, bool with_refresh = false);
```

- **`TokenExchange` with the flag** sends
  `requested_token_type=urn:ietf:params:oauth:token-type:refresh_token`, because Keycloak's standard
  exchange issues a refresh token only when asked so. Keycloak also needs
  `standard.token.exchange.enableRefreshRequestedTokenType: SAME_SESSION` on the client.
  - The answer may be typed as a refresh token. It must still carry an access token, or it is
    refused as before.
  - Its `refresh_token` is kept.
- **`OnBehalfOf` with the flag** keeps the refresh token Entra returns when `scope` includes
  `offline_access`.
- **An IdP that will not issue a refresh token by exchange** answers with its own error. Keycloak's
  is `invalid_request: requested_token_type unsupported`. The caller decides whether to ask again
  without the flag.
- **Only in Keycloak's shape.** A refresh-typed answer must have an access token *and* a distinct
  refresh token beside it. RFC 8693's strict shape puts the refresh token itself in `access_token`
  (`token_type: N_A`), and a refresh token must never be taken for an access token, so that shape is
  refused, as is any `token_type: N_A` on every exchange.
- **The flag may succeed without a refresh token,** from an IdP that ignores it, or OBO without
  `offline_access`. An empty `refresh_token` means no renewal. The caller also learns that a refresh
  token has died only when `RefreshGrant` fails (`invalid_grant`): `refresh_expires_in` is not carried.
- **Without the flag** nothing changes. Only an access token is accepted, any refresh token is
  dropped, and a refresh-typed answer is refused.
- A refresh token is a credential like any other: it never appears in an error, and the caller keeps
  it in memory for the session it was issued for.

### Checked against Keycloak 26.4

Asked with `requested_token_type=refresh_token` and the client attribute set, Keycloak answers:
- `issued_token_type: …refresh_token`;
- an access token (`aud` = the requested audience, `azp` = the exchanging client);
- a refresh token with `refresh_expires_in: 1800`, bound to the user's SSO session.

`RefreshGrant` by the exchanging client renews it with the same audience. Without the attribute,
Keycloak refuses with `requested_token_type unsupported`.

## Compatibility

A module change; the defaults keep every existing call as it was. No contract changes: `ACLA` 2 and
`ACLC` 1 stay. Ships as **v0.5.0**.

## The review's findings (applied)

- **The strict RFC shape was accepted with the flag.** A refresh token alone in `access_token` would
  have been handed on as a bearer token. It is refused now, as is `token_type: N_A`.
- **`RefreshGrant` did not redact the presented refresh token** from an IdP's error. It does now,
  with the same helper as the exchange.
- **Smaller fixes:** OBO's refresh behaviour (kept or dropped) is tested; weak assertions were
  replaced; the empty-refresh case is documented.

## Testing

- **The fake IdP:** a refresh-typed answer with a refresh token when `requested_token_type` asks for
  one, and "requested_token_type unsupported" for one audience.
- **Scenarios:**
  - with the flag: access token, refresh token and expiry kept, and the request asks for the
    refresh type;
  - the unsupported refusal;
  - without the flag: a refresh-typed answer is still refused.
