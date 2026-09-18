# contracts/ — what separately built extensions exchange at runtime

One header per contract, named for its producer: `acl_*.hpp` (duckdb-acl), `tresor_*.hpp` (tresor),
`mirror_*.hpp` (mirror). Each carries its own magic and `CONTRACT_VERSION` (charter R3–R5) and is
owned by its producer (R6): a consumer asks the producer for a change.

Planned first contents (charter, "Initial contents"):

| Header | Producer | Consumers | Arrives with |
| --- | --- | --- | --- |
| `acl_audit.hpp` | duckdb-acl | acl-otel | the duckdb-acl migration — moved as is, no version bump |
| `tresor_audit.hpp` | tresor | acl-otel | the tresor bootstrap, on top of `hooks/` |
| `acl_connection.hpp` | duckdb-acl | tresor | when tresor's delegation needs it |

Namespace: `duckdb::<producer>` (`duckdb::acl`, `duckdb::tresor`).
