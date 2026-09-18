# Spec NNN: <change>

- **Status**: draft | accepted | implemented | superseded by NNN
- **Date**: YYYY-MM-DD
- **Author**: <who>
- **Consumer side**: <repository>/specs/<NNN-slug> (if the change spans repositories)

## Summary

One paragraph: what changes and why.

## Problem

What is missing or wrong today, and for which consumer.

## Design

What lands where (`hooks/`, `contracts/`, a module). For a contract: the magic, the
`CONTRACT_VERSION` before and after, the layout, how both sides reach it (key, `GetOrCreate`,
`Reach()`), what a mismatch does on each side. For a module: its API, its dependencies (R10), its
tests.

## Compatibility

Which duckdb lines it was checked against (R9); which consumers must rebuild; the tag it ships in.

## Testing

How it is proven — `check_headers.sh`, module unit tests, the consumer-side tests.

## Alternatives considered

## Follow-ups
