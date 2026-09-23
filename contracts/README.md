# contracts/ — what separately built extensions exchange at runtime

One header per contract, named for its producer: `acl_*.hpp` (duckdb-acl), `tresor_*.hpp` (tresor),
`mirror_*.hpp` (mirror). Each carries its own magic and `CONTRACT_VERSION` (charter R3–R5) and is
owned by its producer (R6): a consumer asks the producer for a change.

Contents (charter, "Initial contents"):

| Header | Producer | Consumers | Arrives with |
| --- | --- | --- | --- |
| `acl_audit.hpp` + `acl_principal.hpp` | duckdb-acl | acl-otel | **spec 002** — moved as is, magic `ACLA`, version 2, no bump; `Principal` is part of the layout |
| `tresor_audit.hpp` | tresor | acl-otel | the tresor bootstrap, on top of `hooks/` |
| `acl_connection.hpp` | duckdb-acl | tresor | **spec 005** - magic `ACLC`, version 2 (spec 007: the publisher mark): `AclConnection` (the session of the running statement, per connection) and `AclSessionHooks` (session open/close observers) |

Namespace: `duckdb::<producer>` (`duckdb::acl`, `duckdb::tresor`).
