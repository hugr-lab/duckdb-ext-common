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
- **The module's guarantees still hold**: the issuer check, the redaction of presented credentials in
  errors and the refusal of `http` for non-loopback hosts. They are made on the answer, whoever carried
  it.

## Testing

`oidc/test/test_oidc_core.cpp`, the scenario "a consumer's transport carries every request", run with and
without TLS:
- a GET, and a form POST encoded with its content type;
- a discovery through the scope;
- an empty inner scope as the built-in client, and the outer scope restored after it;
- another thread unaffected;
- the default transport, and an empty default as the built-in client.
