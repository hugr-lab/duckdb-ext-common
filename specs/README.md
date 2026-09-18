# Specs

One **lightweight spec per change** — deliberately not full spec-kit: no plan/tasks machinery, just a
short, honest document so decisions are written down and reviewable.

## Process

1. Before (or alongside) a change, create `specs/NNN-slug/spec.md` from `TEMPLATE.md` (`NNN` = next
   zero-padded number, `slug` = short kebab-case).
2. A change that spans repositories is specced on both sides: the part landing here in a spec here,
   the consumer's part in the consumer's repository, each referencing the other.
3. Keep the spec current; set `Status: implemented` when it lands; reference it in the commit/PR.
4. Supersede, don't rewrite: a reversed decision gets a new spec, the old one `superseded by NNN`.

Research and thinking-out-loud live in the local, gitignored `design/` folder.

## Index

| Spec | Title | Status |
| --- | --- | --- |
| [001](001-charter/spec.md) | the charter — what this repository is, and the rules everything in it follows | accepted |
