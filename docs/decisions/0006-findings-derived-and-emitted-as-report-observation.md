# 6. Derive findings from `UdfAnomalyKind`; emit them as `forensicnomicon::report`

Date: 2026-07-24

Status: Accepted

## Context

Every analyzer in the fleet must emit its findings in one normalized vocabulary
(`forensicnomicon::report`) so an orchestrator (Issen, disk4n6) renders them
uniformly with partition- and other filesystem-layer findings, instead of N
bespoke `XxxAnalysis` types. The producer pattern (`ronin-issen/CLAUDE.md`, "The
Reporting Model"): keep the analyzer's own typed anomaly enum (domain knowledge)
and *derive* the canonical `Severity`, machine-readable `code`, `Category`, and
`note` from it, so they cannot drift.

UDF descriptors carry self-validating integrity data — an ECMA-167 tag with a
5-byte mod-256 checksum and a CRC-CCITT (polynomial `0x1021`, initial `0x0000`)
over the body — that can be recomputed and checked with no external oracle.

## Decision

`src/findings.rs` defines `UdfAnomalyKind` (the domain enum) and `UdfAnomaly`
(the graded finding). Severity, category, code, and note are all functions of the
kind — e.g. `code()` maps each variant to a stable scheme-prefixed
SCREAMING-KEBAB code: `UDF-TAG-CRC-MISMATCH`, `UDF-TAG-CHECKSUM-BAD`,
`UDF-TIME-AFTER-VOLUME`, `UDF-SLACK-DATA`. `UdfAnomaly` implements
`forensicnomicon::report::Observation` so an orchestrator aggregates it into one
`Report` alongside every other analyzer. `analyze()` is the end-to-end entry
point over a `Read + Seek` source. `Severity` is re-exported at the crate root
for convenience.

The analyzer emits **only what the reader can observe** over the already-parsed
model (integrity: recomputed tag CRC/checksum on visited descriptors; history:
a File Entry modified later than the File Set Descriptor's recording time;
residue: non-zero bytes in a file's final-block slack). Findings are worded as
observations ("consistent with…"), never legal conclusions.

## Consequences

- The `UDF-*` codes are a published contract: a shipped code never changes; new
  anomalies get new codes.
- CRC/checksum checks are self-validating against ECMA-167 — the recomputation
  matches the values `mkudffs` itself wrote, so no external oracle is needed for
  those (`docs/validation.md`).
- Adding an anomaly is a localized change (a new `UdfAnomalyKind` variant plus
  its derived code/severity/note), and consumers matching the shared report enums
  keep a `_` arm so the model stays additively evolvable.
- The module doc still lists an `OrphanFileEntry` anomaly that the enum does not
  yet implement (only four codes ship); the doc is ahead of the code and should
  be reconciled — the shipped surface is the four codes above.
