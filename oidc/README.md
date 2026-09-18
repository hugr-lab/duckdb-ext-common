# oidc/ — the OIDC client core

duckdb-free token acquisition shared by duckdb-acl, tresor and (later) mssql-extension (charter R10):
endpoint discovery (RFC 8414, with the issuer-match check), the client-credentials, refresh-token and
device (RFC 8628) flows, and a token cache with a refresh margin. Uses only the httplib and yyjson
duckdb bundles, taken from the consumer's own duckdb tree; TLS comes from the consumer's build.

**Empty until the duckdb-acl migration** — it moves duckdb-acl spec 060's module here with its tests.
The tresor bootstrap then adds, through a spec here: authorization code + PKCE with a loopback
redirect (RFC 8252), `private_key_jwt` (RFC 7523), federated assertions, and the Azure credential
sources from mssql-extension.

Namespace: `duckdb::ext_common::oidc`. Consumed through its CMake target (defined when it lands).
