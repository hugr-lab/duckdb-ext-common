# Spec 017: PKCE on the device flow, where the issuer advertises it

- **Status**: implemented
- **Date**: 2026-10-22
- **Author**: hugr lab (the tresor session)
- **Consumer side**: tresor (its device login: `ATTACH … (LOGIN 'device')`, `tresor_login(…, login := 'device')`);
  duckdb-acl's device flow (its OIDC secret) takes it when it moves to this tag

## Summary

A person's device login (RFC 8628) failed against Keycloak when its public client enforces PKCE (a common setting,
and the one tresor's test realm uses): Keycloak then requires PKCE on the device authorization request too, and
the core sent none - `invalid_request: Missing parameter: code_challenge_method`. Found while shooting tresor's
announcement; the device flow had been tested against fakes only.

## Design

- **Discovery** reads `code_challenge_methods_supported`: `Endpoints::pkce_s256` is true when it lists `S256`.
- **`DeviceBegin`** sends `code_challenge` (S256 of a fresh 32-byte verifier) and `code_challenge_method=S256`
  when `pkce_s256`, and returns the verifier in `DeviceAuthorization::code_verifier`. An extra never replaces
  them (as for the other flows' own parameters).
- **`DevicePoll`** takes the verifier - a new parameter after the device code, **with no default** - and sends
  `code_verifier` when it is not empty, never echoing it (or the device code) into an error.
- **An issuer that advertises nothing is sent nothing**: Entra's v2 discovery lists no
  `code_challenge_methods_supported`, so its device flow is unchanged. An issuer that advertises S256 for its
  authorization endpoint and does not take PKCE on the device endpoint would ignore the parameters (RFC 6749 §3.1:
  unrecognized request parameters are ignored); not seen yet.
- **Every caller must pass the verifier**, hence no default: Keycloak lists S256 in its discovery for every client,
  so the challenge is sent to any Keycloak, and Keycloak checks the verifier at the poll whenever the request
  carried a challenge - for a client that does not enforce PKCE too. A caller left on the old call would fail at
  every Keycloak's poll, including where its device flow works today; with no default it does not compile, and
  the consumers (tresor, duckdb-acl's OIDC secret) change one line as they take this tag.
- Not checked live: Okta and Auth0 advertise S256 too, and RFC 6749 (§3.1) has them ignore parameters they do not
  know on the device endpoint; no rejection is known.

## Testing

`oidc/test/test_oidc_core.cpp`, the fake IdP as Keycloak with PKCE enforced (`advertise_pkce`: discovery lists
S256, `/device` refuses a request without an S256 challenge, the device grant checks the verifier): an issuer
that advertises nothing is sent none; with S256 the request carries the challenge of the verifier returned (not
an extra's, 43 characters); a poll without the verifier is refused, a wrong one refused and not echoed, the
right one granted. Plain and TLS builds. Live: tresor's
`test_keycloak.sh` logs a person in by the device flow at a real Keycloak enforcing PKCE.
