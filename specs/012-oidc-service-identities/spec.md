# Spec 012: the OIDC core for services without a shared secret — signed and federated client assertions, Azure managed identity, an audience parameter

- **Status**: implemented
- **Date**: 2026-09-24
- **Author**: hugr lab (the tresor session)
- **Consumer side**: tresor specs/013-service-identities; mssql-extension (its `managed_identity` provider is
  a stub today)

## Summary

The OIDC core's client credentials grant knows one way for a client to prove itself: a shared
`client_secret`. A DuckDB node on a server should not have to carry one. This spec adds three
credential-free ways and one parameter:

1. **`private_key_jwt`** (RFC 7523 §2.2, OIDC Core §9). The client signs a short-lived JWT with its
   own private key and sends it as `client_assertion`. The IdP holds only the public key or
   certificate.
2. **Federated assertion.** The same `client_assertion`, but the JWT comes from somewhere else: a
   Kubernetes projected service-account token (Azure workload identity, Keycloak's federated client
   authentication), or a GitHub Actions OIDC token. The platform issues it and the client only
   passes it on.
3. **Azure managed identity.** On an Azure VM, App Service, Functions or Container Apps, the
   platform's own endpoint (IMDS, or `IDENTITY_ENDPOINT`) hands out a token for a resource. There is
   no client credential at all.
4. **An `audience` request parameter**, for IdPs that pick the token's audience from it rather than
   from the scope (Auth0), on the authorization, device and client credentials requests.

## Design

### Client assertions (`oidc/`)

```cpp
//! How a confidential client proves itself at the token endpoint - the first given of: a private key (signed
//! here, per request), a federated assertion (as is), a client secret.
struct ClientAuth {
	std::string client_id;
	std::string client_secret;      // client_secret_post, as today
	std::string private_key_pem;    // private_key_jwt
	std::string key_id;             // the header's kid
	std::string certificate_pem;    // x5t / x5t#S256
	std::string assertion_audience; // the assertion's aud; empty: the token endpoint (Auth0 wants its issuer)
	std::string assertion;          // a federated client assertion
};

//! RFC 7523: a client assertion signed with the client's key - iss = sub = client_id, aud = the token endpoint,
//! jti random, iat now, exp now + 300 s, no nbf. RS256 for an RSA key (2048 bits or more), ES256 for a P-256 key
//! (checked by curve name); `kid` when given; with a certificate, `x5t#S256` and `x5t` (SHA-1, which Entra
//! reads) of its DER.
struct SignedAssertion { std::string jwt; std::string error; };
SignedAssertion SignClientAssertion(const std::string &client_id, const std::string &audience,
                                    const std::string &private_key_pem, const std::string &key_id = "",
                                    const std::string &certificate_pem = "");

//! grant_type=client_credentials with any ClientAuth.
TokenSet ClientCredentials(const Endpoints &ep, const ClientAuth &auth, const std::string &scope = "",
                           const std::map<std::string, std::string> &extra = {});
```

- **Signing needs OpenSSL.** It is under `DUCKDB_EXT_COMMON_OIDC_TLS`, like https itself. Without it,
  `SignClientAssertion` says so.
- **The key comes in as PEM text.** The module reads no files: the consumer decides where a key may
  come from, and wipes its copy. The module wipes its own copies, frees OpenSSL objects, and never
  puts a key, a certificate or an assertion into an error.
- **Token exchange and On-Behalf-Of accept a `ClientAuth` too.** A node acting for sessions with a
  certificate instead of a secret (Entra OBO supports certificates) needs the same thing.

### A GitHub Actions token

```cpp
//! The job's OIDC token for `audience`: GET $ACTIONS_ID_TOKEN_REQUEST_URL&audience=... with
//! "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN". Error when the job has no id-token permission.
TokenSet GithubActionsToken(const std::string &audience);
```

A file-based federated token (Kubernetes, `AZURE_FEDERATED_TOKEN_FILE`) is the consumer's to read,
since the module reads no files.

### Azure managed identity

```cpp
struct ManagedIdentity {
	std::string resource;   // what the token is for: an app ID URI or its client id
	std::string client_id;  // a user-assigned identity; empty: the system-assigned one
	std::string imds = "http://169.254.169.254"; // loopback or link-local only (tests point it at a fake)
};
//! App Service / Functions / Container Apps: IDENTITY_ENDPOINT + X-IDENTITY-HEADER (api-version 2019-08-01);
//! otherwise IMDS: GET http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01 with
//! "Metadata: true". A token with its expiry; the error names the source, never a token.
TokenSet ManagedIdentityToken(const ManagedIdentity &identity, int timeout_seconds = 5);
```

- **The endpoints are the platform's own:**
  - IMDS is a link-local address and is plain http by design; nothing else is ever sent plain.
  - `IDENTITY_ENDPOINT` is honoured only on loopback or link-local; anything else is refused (an
    environment variable must not redirect a request that carries the identity header).
- **No IMDS answer** (not on Azure) comes back within the timeout and says so, so a consumer can
  fall back or fail.

### The audience parameter

- `BuildAuthorizationRequest`, `DeviceBegin` and `ClientCredentials` take an optional
  `extra` map (`audience=<aud>`, `resource=<uri>`), sent as form or query parameters.
- It is the consumer's decision when to send one (tresor: when the discovery asks, specs/013).

## Enforcement & security

- **Where assertions go.** A signed assertion carries `aud` = the token endpoint it is sent to, and
  lives 60 seconds, with a fresh `jti` each time. It is never logged, never cached beyond one
  request, and never sent anywhere else.
- **Where a federated token goes.** Only to the token endpoint it is presented at. Where it came
  from (a file, GitHub) is the consumer's business.
- **What a managed-identity token is.** A bearer token for its resource. The module hands it over
  and keeps nothing.
- **No key material in errors,** and the module's copies of keys are wiped.

## Tests

`test_oidc_core` gains:
- **A fake IdP that verifies assertions:** RS256 and ES256 signatures against the public key;
  `iss = sub = client_id`; `aud` = the token endpoint; `exp` in the future; a `jti` it has not
  seen; `kid` and `x5t#S256` when given. A replayed assertion is refused.
- **A fake IMDS** on loopback, reached through `ManagedIdentity::imds` (loopback or link-local
  only). Its checks: the `Metadata` header, the resource and the user-assigned `client_id`. An IMDS
  elsewhere is refused.
- **A fake App Service endpoint** through `IDENTITY_ENDPOINT` and `IDENTITY_HEADER`, loopback
  only; a non-loopback one is refused.
- **A fake GitHub token endpoint** through the two environment variables.
- **The `audience` parameter** carried by all three requests.
- **Errors** never carrying the key, the certificate, the assertion or a token.

The key pairs come from the test itself (OpenSSL), with none in the repository. Beyond the
above, the test checks:
- another key's signature is refused;
- a garbage key and an encrypted key are refused without being quoted;
- an RSA key under 2048 bits is refused;
- a plain build (no TLS) says it cannot sign.

## The review's findings (applied)

- **MEDIUM: "local" accepted a DNS name.** It took a prefix, so `169.254.attacker.example` passed, as
  did a URL with userinfo (both confirmed). Now only literal addresses count: 127.0.0.0/8,
  169.254.0.0/16, `::1`, and `localhost`. Userinfo is refused.
- **MEDIUM: ES256 took any 256-bit curve.** secp256k1 and brainpoolP256r1 signed a JWT labelled ES256
  (confirmed). Now it is P-256 by curve name, or refused.
- **MEDIUM: `aud` was fixed at the token endpoint, and the time claims were tight.**
  - `ClientAuth::assertion_audience` overrides it; Auth0 wants its issuer.
  - `nbf` is gone (RFC 7523 makes it optional), and `exp` is now + 300 s.
- **MEDIUM: an answer with no expiry was cached forever,** and a huge `expires_on` saturated. Now
  `expires_on` is clamped to a year, and GitHub's token takes its expiry from its own `exp`.
- **MEDIUM: the identity header and error codes were not redacted.** Now what the caller presented
  (a secret, an assertion, a subject or refresh token, the identity header, GitHub's bearer) is cut
  out of the raw answer before it is parsed. A quoted credential is gone before the description's
  length limit could cut it in two.
- **Smaller fixes:**
  - the endpoints are checked before a key signs;
  - `extra` can never add `request`, `request_uri` or `response_mode`;
  - a value under 8 characters is not redacted (it cut "exchange" apart);
  - `JsonQuote` is under TLS, which clears the plain build's warning;
  - `<cstdio>` is included;
  - the header documents the precedence, the unsupported Azure hosts (Service Fabric, Arc) and GitHub's
    expiry.
- **Tests added:**
  - a quoted assertion and a quoted identity header are cut out;
  - the four non-local addresses;
  - GitHub over plain http;
  - secp256k1;
  - `extra` trying to replace `client_id`/`client_secret`, and `request_uri`/`response_mode`;
  - `expires_on` clamped;
  - `x5t` equal to the certificate's SHA-1;
  - GitHub's expiry read from its JWT;
  - token exchange with a key.
- **Not taken:**
  - IMDS retries (the caller retries);
  - `_putenv_s` for the environment scenarios on Windows (the OIDC test runs on Linux and macOS in
    CI);
  - wiping httplib's own buffers, which is out of the module's reach (best effort, as documented).

## Compatibility

A module change, not a contract. The existing `ClientCredentials(ep, id, secret, scope)` stays as a
wrapper. Tag `v0.9.0`.
