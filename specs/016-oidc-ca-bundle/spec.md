# Spec 016: a CA bundle for the OIDC core's built-in client

- **Status**: implemented
- **Date**: 2026-10-15
- **Author**: hugr lab (the tresor session)
- **Consumer side**: tresor specs/030-ca-bundle (DuckDB's `ca_cert_file` for tresor's built-in client)

## Summary

The OIDC core's built-in client (httplib with OpenSSL) verifies an https server against the system's
roots only. A consumer can now name **a CA bundle** - a PEM file of one or more certificates - that the
client trusts **in addition to** the system's roots, for the process or for the calling thread, the way
spec 013 sets a transport. Verification stays on; nothing replaces the system's roots.

## Problem

A duckdb-acl / hugr node reaching a tresor service, or an IdP, whose certificate a private CA issued cannot
verify it: tresor's default client is this module's, and it has no CA option. DuckDB's own `ca_cert_file` is
set on such a node, and DuckDB's HTTP client honours it - this module's does not. A node also needs the
public roots at the same time (a public IdP such as Entra beside a private service), so a bundle that
replaced them would not do.

## Design

```cpp
void SetDefaultCaBundle(std::string path);                       // the process's, where no scope sets one
class CaBundleScope { explicit CaBundleScope(std::string path); ~CaBundleScope(); };  // the calling thread's
```

- **In force**: the calling thread's scope, else the process's default. Empty = the system's roots alone;
  an empty scope means that whatever the default (as an empty `TransportScope` means the built-in client).
  Scopes nest and restore the previous one; a local variable only, LIFO. The default is behind a mutex,
  the scope `thread_local` - another thread never sees a scope.
- **Added, not replacing.** On each https request the client reads the file (a regular file, checked before it
  is opened - a FIFO would block; a UTF-8 path on Windows too), parses it as OpenSSL's file loader does
  (`PEM_X509_INFO_read_bio`: CERTIFICATE and TRUSTED CERTIFICATE blocks count, any other block - a CRL, a key -
  is ignored, text around the blocks too; a block that does not parse is an error), requires at least one
  certificate, and adds them, re-encoded, to **that client's own** store
  (`SSLClient::load_ca_cert_store`, into its `SSL_CTX`'s `X509_STORE`, freed with the client) and turns the
  system's roots on beside them (`enable_system_ca(true)` - httplib's default leaves them out once a custom
  CA is given). Nothing is shared across requests or threads; no store outlives its client.
- **The system's roots are httplib's**: OpenSSL's default paths on Linux; on macOS the keychain
  (`CPPHTTPLIB_USE_CERTS_FROM_MACOSX_KEYCHAIN`, on by default for clang on macOS - the bundle goes into the
  same store the keychain's roots are added to, so it applies there as well); on Windows the system's ROOT
  and CA stores loaded into OpenSSL.
- **Windows, a known difference**: httplib runs its extra Schannel check (end-certificate revocation, the
  Disallowed store) only when no custom CA is set. With a bundle, OpenSSL's verification against both sets
  decides alone, for every host - a public IdP's included: nothing a chain or name check refuses is accepted,
  but revocation and the Disallowed store are not consulted. Restoring Schannel for chains ending in a system
  root (`set_server_certificate_verifier`) is a follow-up.
- **Verification always on**: certificate and hostname verification as before; a bundle only adds anchors.
- **A bundle that cannot be used fails the request** before anything is sent: unreadable (missing, a
  directory, a FIFO, over 16 MiB), empty, holding no certificate, or holding a block that does not parse. The error
  names the file (`the CA bundle <path> cannot be read` / `... holds no PEM certificate, or one that does not
  parse`) and never its content. No fallback to the system's roots alone.
- **Read on each request**, so a rotated bundle counts at once; a bundle is a few KB.
- **Plain http** does not read it. **A build without TLS** refuses https as before, whatever is set. **A
  consumer's transport** (spec 013) carries its own TLS and ignores the bundle.
- **No contract changes**, no stamp. The module stays duckdb-free (R10).

## Compatibility

The 2.0 line's bundled httplib (0.53.1: `load_ca_cert_store`, `enable_system_ca`). Consumers that want the
bundle (tresor) call the new API; one that sets nothing behaves as before. Ships in the tag after v0.12.0.

**A drift fix rides along**: the 2.0 line's head now defines `hugeint_t(int64_t)` constexpr in `hugeint.hpp`,
which the test's RegexMatch shim also defined (CI clones the head: every OIDC job and the fuzz job failed).
`test_oidc.sh` and `fuzz_oidc.sh` detect the header's definition and pass `DUCKDB_SHIM_HUGEINT_INLINE`, so the
shim builds against older trees (tresor's f702a1f) and the head alike.

## Testing

`oidc/test/test_oidc_core.cpp`, "a CA bundle beside the system's roots", TLS build: a private CA and an
httplib `SSLServer` with a certificate it signed, generated in the test (OpenSSL APIs).
- without a bundle: verification fails;
- with it in a scope, in `HttpSend`, and as the default: verifies;
- an empty inner scope, an empty scope over a default, a cleared default: the system's roots alone (fails);
  the outer scope restored; another thread unaffected; a scope's bundle wins over the default;
- a bundle of two certificates; a trusted CA's certificate for another name still fails (hostname checked);
- a TRUSTED CERTIFICATE block with a comment and another block before it, CRLF line ends: verifies;
- missing, a directory, a FIFO, garbage, a key only, a truncated second block, empty: each fails with its error,
  naming the file, and none reaches the server;
- the system's roots still count beside a bundle: on Linux, network-free, through `SSL_CERT_FILE` standing in
  for the system's store (a second private CA). On macOS the keychain is the system's store and cannot be
  seeded by a test: there `OIDC_TEST_NETWORK=1` runs a real public host with a bundle set (checked locally,
  not in CI);
- the plain build: a bundle does not affect http, and https is refused as before.

## Alternatives considered

- Building an `X509_STORE` ourselves (default paths + bundle) and `set_ca_cert_store`: it would bypass
  httplib's macOS keychain and Windows store loading, i.e. a different "system roots" than the client
  without a bundle has. httplib's own loading with the system roots forced on keeps them identical.
- `set_ca_cert_path`: OpenSSL's loader, but its failure is httplib's generic `SSLLoadingCerts`; reading the
  file ourselves gives a clear error and refuses a bundle without a certificate.
- PEM text instead of a path: no consumer needs it (DuckDB's `ca_cert_file` is a path).

## Follow-ups

- A tag, and `docs/compatibility.md`'s row, after merge (the owner).
- Windows: Schannel's revocation and Disallowed-store check for chains that end in a system root, with a bundle
  set (above).
