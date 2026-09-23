# Spec 004: the OIDC core exchanges tokens — RFC 8693 token exchange and Entra's On-Behalf-Of

- **Status**: implemented
- **Date**: 2026-09-23
- **Author**: hugr lab (the tresor session)
- **Consumer side**: tresor (the actor spec, after duckdb-acl's `contracts/acl_connection.hpp`)

## Summary

A server that serves a user's session often has to call a *third* service as that user. The token the
user opened the session with is for the server (its `aud`), and the rule in every consumer is that a
token goes only to its audience. The standard way out is to ask the **identity provider** to exchange
it: the server presents the token it legitimately received, and receives one for the other service.
This spec adds that to the OIDC core, in two shapes:
- **RFC 8693 token exchange**: Keycloak's standard token exchange, Okta, Auth0 and others.
- **Entra's On-Behalf-Of** flow, which is RFC 7523 `jwt-bearer` with `requested_token_use`.

The first consumer is tresor on a duckdb-acl node. When a user's session opens, it exchanges the
session's token for one with the secrets service's audience, and then for a delegation grant (tresor
spec 007, the actor spec to come).

## Problem

The core can obtain a token for the caller itself (client credentials, password, device, browser)
and renew one (refresh). It cannot turn a token *someone else* presented into a token for another
audience.

## Design

New in `oidc_core.hpp`, duckdb-free (R10), on the same `PostGrant` path as the other grants:

```cpp
//! RFC 8693: the client (client_id / client_secret, client_secret_post) presents `subject_token` (an
//! access token it received) and asks for an access token for `audience` (and/or `resource`, `scope`).
TokenSet TokenExchange(const Endpoints &ep, const std::string &client_id, const std::string &client_secret,
                       const std::string &subject_token, const std::string &audience,
                       const std::string &scope = "", const std::string &resource = "");

//! Entra's On-Behalf-Of (RFC 7523 jwt-bearer + requested_token_use=on_behalf_of): `assertion` is the
//! access token the client received; `scope` names the downstream API (api://…/.default).
TokenSet OnBehalfOf(const Endpoints &ep, const std::string &client_id, const std::string &client_secret,
                    const std::string &assertion, const std::string &scope);
```

- **The request** follows RFC 8693 §2.1:
  - `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`;
  - `subject_token_type` and `requested_token_type` both `urn:ietf:params:oauth:token-type:access_token`;
  - `audience`, `resource` and `scope` only when given, and **at least one of them**. Without a
    target, Keycloak answers with a token for every audience the client may reach, which is the
    multi-audience token rejected below. So it is refused locally (`invalid_request`), as is an
    empty subject token. OBO needs both its assertion and its scope.
  - client authentication in the body (`client_secret_post`), as every flow of the core does. A
    public exchanger passes an empty secret.
- **The answer** goes through `ParseTokenResponse`, which now also reads `issued_token_type` (a new
  `TokenSet` field, empty when absent).
  - An answer whose `issued_token_type` is anything but an access token is **refused**: the caller
    asked for an access token, and a refresh or ID token in its place must not be used as one. The
    refusal is fixed text; the IdP's value is not quoted. An absent `issued_token_type` is accepted,
    because Entra's OBO never sends one.
  - A **refresh token** in the answer is **dropped**. An exchanged token belongs to one session, and a
    server holding a refresh token could act as the user after the session ends.
  - The IdP's refusals come back as its error codes, like every flow's: `invalid_client`,
    `invalid_grant`, `invalid_target` (RFC 8693 §2.2.2), `unauthorized_client`.
- **No caching.** An exchanged token belongs to one user's session, so the `TokenCache` stays the
  consumer's choice.
- **Tokens stay out of everything.** Neither the subject token nor the exchanged token ever appears
  in an error or a log line.
  - Errors carry the IdP's code and description, made printable (no control characters) and
    bounded, for every flow of the core.
  - An IdP that quotes the presented token back in its description gets it replaced by
    `<redacted>`.

### Checked against Keycloak 26.4

Keycloak's standard token exchange (V2) worked against a live Keycloak 26.4. It needs:
- `standard.token.exchange.enabled: true` on the exchanging client (the server);
- the subject token's `aud` to include that client (an audience mapper on the users' client);
- the target audience to be "available" to the exchanging client (an audience mapper on it that
  names the target).

The result carries `sub` = the user, `aud` = only the requested audience, `azp` = the exchanging
client, the user's roles, and `issued_token_type` = access token. Client authentication in the body
works. The consumer's end-to-end test (tresor) pins this with the realm it imports. Entra's OBO is
tested against the fake only here.

## Compatibility

A module change, no contract changes: `ACLA` stays 2. `TokenSet` grows a field. It is not a contract
type, since every consumer compiles its own copy (R10, R13). Ships as **v0.3.0**, or in the tag that
also carries duckdb-acl's `contracts/acl_connection.hpp`, whichever comes first.

## Testing

- **The fake IdP** answers:
  - `token-exchange`: it checks the client, the subject token, the token types and the audience, and
    grants a token with `issued_token_type`;
  - `jwt-bearer` with `requested_token_use=on_behalf_of`.
- **Scenarios:**
  - a successful exchange and its `issued_token_type`;
  - `resource` and `scope` passed through when given and absent when not;
  - a public exchanger that sends no `client_secret`;
  - a wrong client secret → `invalid_client`;
  - a client not allowed to exchange → `unauthorized_client`;
  - an unknown subject token → `invalid_grant`;
  - an audience the client may not reach → `invalid_target`;
  - a refresh or ID token as `issued_token_type` → refused, with nothing handed out;
  - a refresh token next to the access token → dropped;
  - an IdP quoting the subject token → redacted;
  - no target, no subject token, and OBO without a scope or an assertion → refused before any
    request;
  - OBO: success, its request parameters, and refusal;
  - no presented or issued token in any error string.
- The fuzz corpus gains an exchange answer for `ParseTokenResponse`. The refusal logic around it is
  covered by the tests, not by the fuzzer.

## The review's findings (applied)

An independent review found:
- The refusal quoted the IdP's `issued_token_type` unbounded. It is now fixed text.
- `error_description` was copied through raw, so a token the IdP quoted back would land in the error.
  It is now printable and bounded, and the presented token is redacted.
- A refresh token from an exchange was handed on. It is now dropped.
- An exchange without a target, and OBO without a scope, were sent anyway. They are now refused
  locally.
- Smaller fixes: several tests could not fail (the no-leak check looked for the wrong token); OBO's
  parameters were unchecked; `unauthorized_client`, a public exchanger and ID tokens were untested.
  `ACCESS_TOKEN_TYPE` is now `constexpr`.

## Alternatives considered

- **Multi-audience tokens at the IdP** (the users' client puts both the server and the secrets service
  into `aud`). It needs no exchange, but every server a user connects to could then call the secrets
  service with the user's token. An exchange is per server and per session, and the IdP can audit it.
- **Exchanging at the secrets service** (it accepts tokens for other audiences). It breaks "a token
  goes only to its audience" on the service side, and every service would need its own trust list of
  audiences.

## Follow-ups

- Other subject token types (`id_token`, `jwt`, custom), fixed to `access_token` now. An IdP that
  labels its answer `…:token-type:jwt` is refused. That is safe, and can be relaxed when an IdP needs it.
- `private_key_jwt` client authentication for the exchange, together with the rest of the charter's
  additions (federated assertions, Azure identities).
