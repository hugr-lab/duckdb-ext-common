# Compatibility

Per tag, the version of every contract it carries, and the duckdb lines its headers were checked
against. Runtime compatibility between two extensions is decided by the contract stamps (charter R3),
not by the tag — two extensions built from different tags interoperate as long as every contract they
share has the same `CONTRACT_VERSION` in both.

| Tag | Contract | Magic | Version | Producer | Checked against |
| --- | --- | --- | --- | --- | --- |
| — | *(no tag yet: the first contents arrive with the duckdb-acl migration and the tresor bootstrap)* | | | | |
