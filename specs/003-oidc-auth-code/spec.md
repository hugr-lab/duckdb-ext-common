# Spec 003: the OIDC core for people — authorization code + PKCE with a loopback redirect; the TLS gate fixed

- **Status**: draft
- **Date**: 2026-09-23
- **Author**: hugr lab (the tresor session)
- **Consumer side**: tresor/specs/002-attach-login

## Summary

The first of the charter's "oidc/ additions" (R6, "Initial contents"): the **authorization code
flow with PKCE and a loopback redirect** (RFC 6749 §4.1, RFC 7636, RFC 8252 §7.3), the way a
person logs in from a native client. tresor's `ATTACH 'tresor:<host>'` needs it (tresor spec 002).
Two findings ride along: the module's **TLS gate tests a macro nobody defines**, so every https
request of v0.1.0 fails in every consumer; and the charter's **R9 still says "both lines"** while CI
and the owner's decision (spec 002) say 2.0 only.

## Problem

- A person on a laptop logs in through a browser. The core offers the device flow (RFC 8628), which
  works everywhere but asks the person to type a code; the browser flow every CLI of a cloud or IdP
  uses is missing.
- `Run()` in `oidc/src/oidc_core.cpp` compiles its https branch under `#ifdef ACL_OIDC_TLS` — the
  macro's name before the move. Consumers now define `DUCKDB_EXT_COMMON_OIDC_TLS` (the README, the
  cmake snippet, the top of the same file), so the https branch is compiled out: an https issuer
  answers *"https needs a TLS-enabled build"* even in a build that links OpenSSL. **duckdb-acl is
  affected since its switch to v0.1.0** (duckdb-acl spec 076): its client_credentials / password /
  device secrets against a real (https) IdP, Entra included, fail. Nothing caught it because the
  module's own test runs over http and never compiles the TLS variant.
- R9 (charter, and the rule line in `CLAUDE.md`) says headers compile against v1.5.5 and 2.0 and "CI
  checks both"; CI checks 2.0 only, by the owner's decision of 2026-09-18.

## Design

### The TLS gate

`#ifdef ACL_OIDC_TLS` → `#ifdef DUCKDB_EXT_COMMON_OIDC_TLS`, the one macro the module documents.
The message of the non-TLS branch loses its "(the flight build carries OpenSSL)" — an acl detail.

### Authorization code + PKCE, loopback redirect

New in `oidc_core.hpp`, all duckdb-free (R10):

- `Endpoints::authorization_endpoint` — from discovery; may be empty (a machine-only issuer). The
  cleartext-downgrade check of an https issuer covers it like the other endpoints.
- `PkceChallenge(verifier)` — `BASE64URL(SHA256(verifier))`, no padding (RFC 7636 §4.2, `S256`
  only; `plain` is never offered). `RandomUrlSafe(bytes)` — the verifier (32 bytes → 43 chars) and the
  `state`. SHA-256 is a small implementation inside the module's TU (no crypto library: the module
  must build without OpenSSL, and the test does); the randomness is `std::random_device`, which is
  the OS CSPRNG on every platform the consumers ship (libc++/libstdc++ read `getrandom`/`/dev/urandom`,
  MSVC `rand_s`).
- `LoopbackRedirect` — the redirect receiver (pimpl: no httplib in the header). `Start()` binds the
  bundled httplib server to **`127.0.0.1` on a port the OS picks** (RFC 8252 §7.3; never `0.0.0.0`,
  never `localhost`, which may resolve off-box), `RedirectUri()` is `http://127.0.0.1:<port>/callback`.
  `Wait(state, deadline, cancelled)` returns the first `GET /callback` whose `state` matches: the
  `code`, or the IdP's `error`/`error_description`. A callback with a wrong or missing `state` is
  answered 400 and **ignored** — the wait continues (a stray or forged request neither completes nor
  aborts the login). The browser gets a short fixed page ("login complete / failed — you can close
  this window"); nothing from the request is reflected into it. The wait checks the cancellation
  and the deadline in slices of 200 ms; the server is stopped and joined on return and in the
  destructor.
- `BuildAuthorizationRequest(ep, client_id, redirect_uri, scope)` → `{url, state, verifier}`:
  `response_type=code`, `client_id`, `redirect_uri`, `scope`, `state`, `code_challenge`,
  `code_challenge_method=S256`. An endpoint that already has a query string is appended to with `&`.
- `ExchangeAuthorizationCode(ep, client_id, code, verifier, redirect_uri)` —
  `grant_type=authorization_code` with the `code_verifier` and the same `redirect_uri`; a public
  client, so no secret.
- `AuthorizationCodeLogin(ep, client_id, scope, present, deadline, cancelled)` — the whole flow:
  start the receiver, build the request, hand the URL to `present` (the consumer prints it and opens
  a browser — spawning processes is the consumer's business, not a duckdb-free module's), wait,
  exchange. Errors come back in `TokenSet::error` / `error_code` like every other flow
  (`access_denied`, `expired_token` for the deadline, `cancelled`).

What the module does **not** do: open a browser, pick between the browser and the device flow, keep
tokens anywhere but the existing in-memory `TokenCache`. Those are consumer policy.

### R9

R9 becomes "the duckdb line the consumers build on — today the 2.0 line (`v2.0-cyanoptera`), the
owner's decision of 2026-09-18 (spec 002); a line added later is added to CI with it". The rule line
in `CLAUDE.md` follows.

## Compatibility

A module change, no contract changes — `ACLA` stays 2. Ships as **v0.2.0**; `docs/compatibility.md`
gets the row. duckdb-acl should take v0.2.0 for the TLS fix (its session's bump); the new API is
additive, acl's call sites compile unchanged. Checked against `v2.0-cyanoptera`.

## Testing

- `oidc/test/test_oidc_core.cpp`: the fake IdP grows `/authorize` (records the challenge, redirects
  to the `redirect_uri` with a code and the `state`, or with `error=access_denied` for a denying
  client id) and the `authorization_code` grant (checks the code, the `redirect_uri`, and
  `S256(code_verifier)` against the recorded challenge). A test "browser" follows the redirect with a
  plain http client. Scenarios: the RFC 7636 appendix B vector; the full login; a denied login; a
  forged callback (wrong `state`) that is ignored while the real one completes; a PKCE verifier that
  does not match; cancellation; the deadline; the downgrade check on `authorization_endpoint`.
- **The TLS variant compiles and reaches the TLS branch**: `test_oidc.sh` with `OIDC_TLS=1` builds
  the module with `DUCKDB_EXT_COMMON_OIDC_TLS` against the system OpenSSL, and the test asserts that
  an https request fails as a *connection* failure, not as "needs a TLS-enabled build" (the
  regression above). CI runs both variants.
- The fuzz target is unchanged in shape; the discovery corpus gains `authorization_endpoint`.
- Consumer side: tresor spec 002's attach tests.

## Alternatives considered

- **OpenSSL for SHA-256 and randomness** — the module would need OpenSSL in its non-TLS variant and
  in its test; 100 lines of SHA-256 are cheaper than that dependency.
- **Opening the browser in the module** — spawning processes (`open`, `xdg-open`, `ShellExecute`) is
  platform policy and a consumer's business; the `present` callback keeps the module pure.
- **A fixed redirect port** — collides with whatever else listens; RFC 8252 §7.3 requires that any
  port be accepted by the IdP, which Keycloak, Entra and Okta do for loopback redirect URIs.

## Follow-ups

- `private_key_jwt` (RFC 7523), federated assertions (Kubernetes projected tokens, GitHub OIDC) and
  the Azure sources from mssql-extension (IMDS, workload identity) — the rest of the charter's
  additions, a later spec here, driven by tresor.
