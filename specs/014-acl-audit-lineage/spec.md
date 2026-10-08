# Spec 014: `acl_audit` v3 - the lineage kind

- **Status**: implemented
- **Date**: 2026-10-08
- **Author**: owner + Claude
- **Consumer side**: duckdb-acl/specs/107-lineage (producer); acl-otel (the OpenLineage transport, its
  own spec to follow)

## Summary

`contracts/acl_audit.hpp` gains a lineage payload and a new event kind, `lineage`. duckdb-acl fills
it with what a node defines (virtual and physical DDL, grants, attached sources) and with what it
writes (DML, ingest). acl-otel renders it as OpenLineage RunEvents and DatasetEvents. The payload
follows OpenLineage's facets one to one, so the transport only maps. `CONTRACT_VERSION` goes from 2
to 3. Charter R7 gets one stated exception, for a normalized statement text.

## Problem

duckdb-acl spec 107 needs to hand column- and field-level edges to an OpenLineage transport in
another image (R1/R2: header-only, reached through the registry). `AuditEvent` has no place for
them. Two rules also stand in the way:

- the base's rule (duckdb-acl 069) that an event never names a physical dataset;
- the charter's R7: no statement text.

The OpenLineage SQL facet the owner allowed, opt-in and with no values, is statement text.

## Design

### `contracts/acl_audit.hpp`

- **New types** (header-only, plain data):
  - `AuditLineageField` - a schema field; STRUCT and LIST children nest.
  - `AuditLineageSymlink`.
  - `AuditLineageTag` - `key`, `value`, an optional `field` path.
  - `AuditLineageDataset` - namespace, name, dataset type, `physical`, lifecycle, schema, symlinks
    and tags.
  - `AuditLineageEdge` - target / source as dataset indices plus field paths; OpenLineage's
    `type`, `subtype` and `masking`.
  - `AuditLineageRunRef` - the parent and the root parent.
  - `AuditLineage` - event type, run, job, parent / root, datasets, inputs and outputs, edges,
    the normalized `sql` and `dialect`, the identity fields, `approximate`, `truncated`, and
    `dropped`.
- **`AuditEvent::lineage`** - `shared_ptr<const AuditLineage>`, null for every other kind. A shared
  immutable payload costs nothing for the events that do not carry it, and is never copied on fan-out.
- **`AuditSink::WantsLineage() const`** - default `false`. A producer delivers a `lineage` event only
  to the sinks that return `true`, and never to its own file or ring of decisions. An auditor's
  stream keeps the old guarantees.
- **The version.** `AuditHooks::CONTRACT_VERSION` goes from 2 to 3. `AuditEvent` gains a member and
  `AuditSink` gains a virtual: both are layout changes (R4).

### Charter R7, amended

A `lineage` payload may carry a **normalized** statement text: the statement as the client wrote it,
before any rewrite, with every constant replaced by `?`.

- It is carried only when the producer's operator turns it on. In duckdb-acl that is
  `acl_lineage_sql = 'normalized'`, off by default.
- It never carries a parameter value, a literal, a secret, a token or a handle - the rest of R7
  stands.
- A lineage payload may also name physical datasets. That is not an R7 matter, but the producer's
  rule changes, and `AuditLineageDataset::physical` lets a transport drop them.

## Compatibility

- **Checked against:** `scripts/check_headers.sh` over duckdb `v2.0-cyanoptera` 4fbae43 - every
  header compiles alone (R9).
- **Who must rebuild.** duckdb-acl (producer) and acl-otel (consumer) move together: under a
  mismatch, R4 does its job.
  - acl audits on a private registry and says so in `acl.audit.contract`.
  - acl-otel refuses to attach.
- **tresor.** It uses `tresor_audit` (TRSA), not this contract, and is unaffected.
- **Ships in:** v0.11.0.

## Testing

- **This repository:**
  - `check_headers.sh` - the header compiles alone, its nested types included;
  - clang-format 11.0.1.
- **duckdb-acl spec 107:**
  - a sink that asks for lineage receives it;
  - one that does not, and the base's file and ring, never see it;
  - the payload carries no literal and no claim value.
- **acl-otel:** its spec renders the payload against Marquez.
