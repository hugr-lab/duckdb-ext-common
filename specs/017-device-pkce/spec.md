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
- **`DevicePoll`** takes the verifier (a new trailing parameter, default empty) and sends `code_verifier` when it
  is not empty.
- **An issuer that advertises nothing is sent nothing**: Entra's v2 discovery lists no
  `code_challenge_methods_supported`, so its device flow is unchanged. An issuer that advertises S256 for its
  authorization endpoint and does not take PKCE on the device endpoint would ignore the parameters (RFC 6749 §3.1:
  unrecognized request parameters are ignored); not seen yet.
- A caller that does not pass the verifier to `DevicePoll` fails at the poll against an issuer that requires
  PKCE, as it failed at the request before: consumers move with the tag.

## Testing

`oidc/test/test_oidc_core.cpp`, the fake IdP as Keycloak with PKCE enforced (`advertise_pkce`: discovery lists
S256, `/device` refuses a request without an S256 challenge, the device grant checks the verifier): an issuer
that advertises nothing is sent none; with S256 the request carries the challenge of the verifier returned (not
an extra's); a poll without the verifier is refused, one with it granted. Plain and TLS builds. Live: tresor's
`test_keycloak.sh` logs a person in by the device flow at a real Keycloak enforcing PKCE.
