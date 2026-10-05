# Spec 013: a consumer's HTTP transport for the OIDC core

- **Status**: implemented
- **Date**: 2026-10-05
- **Author**: hugr lab (the tresor session)
- **Consumer side**: tresor specs/020-wasm (tresor in DuckDB-wasm)

## Summary

The OIDC core sends every request with its own client: httplib, with TLS where the consumer links OpenSSL.
A consumer can now hand it **a transport of its own**, and every request of the module goes through it:
- discovery, the grants and a refresh;
- the consumer's own REST calls through `HttpSend`.

The first user is tresor in DuckDB-wasm. A browser has no sockets, so the requests must go through
DuckDB's `HTTPUtil`, which httpfs implements with the browser's `fetch`.

## Design

```cpp
using Transport = std::function<HttpResult(method, url, headers, body, content_type, timeout_seconds)>;
void SetDefaultTransport(Transport transport);      // the process's, where no scope sets one
class TransportScope { explicit TransportScope(Transport); ~TransportScope(); };  // the calling thread's
```

- **One entry point.** `HttpGet` and `HttpPostForm` are now `HttpSend` with a method, a body and a
  content type. `HttpSend` picks the transport in force in this order:
  1. the calling thread's scope;
  2. the process's default;
  3. the built-in client, as before.
- **A scope is per thread and nests.** A consumer sets it around one of its calls, so the module's own
  requests made inside that call use it too: a token refresh, a discovery. Another thread never sees it.
  An empty transport in a scope means the built-in client, whatever the default.
- **Per thread, not per process.** A consumer's transport may belong to one database instance (DuckDB's
  `HTTPUtil` needs one), and one process may hold several.
- **The module stays DuckDB-free** (charter R10). The transport is a `std::function` the consumer
  writes. The module knows nothing of DuckDB's HTTP layer.
- **No change for a consumer that sets nothing.** The built-in client is the same code as before.

## Enforcement & security

- **The transport gets what the built-in client would send**: the URL, the headers (an `Authorization`
  included) and the body (a client secret or an assertion included). It belongs to the consumer, in the
  consumer's process.
- **What the module checks on any transport's answer**: the discovery document's issuer, and no
  cleartext endpoint named by an https issuer (the downgrade check). The URL is checked before it is
  handed over (`http`/`https` only).
- **What moves to the transport**: TLS certificate verification, and the built-in client's refusal of
  https in a build without TLS. Whether a cleartext issuer is acceptable at all stays the consumer's rule
  (tresor allows `http` for loopback only), as before.
- **The transport's contract** (`oidc_core.hpp`): it follows no redirect (a followed 307 would re-send a
  secret), logs no header or body, and reports a failure as `error` with status 0.
- **Errors never carry what was sent**: after a consumer's transport, the module redacts from its error
  the `Authorization` header's value, each form value (encoded and decoded) and a body, so a grant's
  error (refresh, client credentials, device, code exchange) cannot quote a credential.
- **Re-entry**: a transport that calls the module (a grant inside a request) reaches the built-in
  client, not itself.
- **Lifetime**: the default is process-wide for the consumer's namespace, the last one set wins; clearing
  it does not wait for a request in flight, so a transport keeps what it captures alive. A scope is a
  local variable, LIFO; an empty scope is the built-in client whatever the default.

## Testing

`oidc/test/test_oidc_core.cpp`, the scenario "a consumer's transport carries every request", run with and
without TLS:
- a GET, and a form POST encoded with its content type;
- a discovery through the scope;
- an empty inner scope as the built-in client, and the outer scope restored after it;
- another thread unaffected;
- the default transport, and an empty default as the built-in client.
- a scope over a default, and an empty scope with a default set (the built-in client);
- the headers and the timeout passed through as given;
- a transport error that echoes the request: no refresh token, client secret, bearer token or body in it;
- a non-http(s) URL refused before the transport; a transport's discovery answer still issuer-checked;
- a transport calling back into the module reaches the built-in client once.
