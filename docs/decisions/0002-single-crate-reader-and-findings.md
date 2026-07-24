# 2. Keep reader and findings analyzer in one crate

Date: 2026-07-24

Status: Accepted

## Context

The fleet's Crate-structure standard (`ronin-issen/CLAUDE.md`, "Pattern A —
single-format repo") prescribes **two** crates for a single-format filesystem
repo: `<x>-core` (the raw reader) and `<x>-forensic` (the anomaly analyzer that
depends on the reader). `vmdk`, `vhdx`, `ntfs`, and `qcow2` all follow it.

`udf-forensic` does not. It is a **single** crate whose `src/lib.rs` is the
reader (`detect_udf`, `parse_udf_state*`, `read_dir_at_lba`, `read_fe_data`,
`UdfState`, `UdfPartitionKind`) and whose `src/findings.rs` is the analyzer
(`UdfAnomalyKind`, `UdfAnomaly`, `analyze()`, the `UDF-*` codes). The analyzer
module imports the reader's already-parsed model directly
(`use crate::{descriptor_label, ecma167_crc, UdfState, …}` at the top of
`findings.rs`) rather than across a crate boundary.

The standard's own binding principle is that the split is a *default, not a
requirement*: `-forensic` may parse lower-level structure directly when the
reader's API already exposes what the audit needs. Here the analyzer emits "only
what the reader can actually observe over the already-parsed model" (the
`findings.rs` module doc): descriptor tag CRC/checksum on the sectors the
bootstrap and directory walk already visit, plus derived observations
(file-after-volume, final-block slack). No audit here needs a view the reader
hides, so the two live together.

## Decision

Publish a single crate, `udf-forensic`, exposing both the reader API and the
`findings` analyzer module. Do **not** introduce a separate `udf-core` package
at this size.

Original intent for choosing single-crate over the two-crate split is only
partially recorded in history; the technical justification above (the analyzer
observes solely the reader's parsed model, so no lower-level seam is needed) is
reconstructed from the current structure. **Rationale reconstructed from
structure; original intent not recovered in available history.**

## Consequences

- One version, one dependency, one `cargo add` for a consumer that wants both
  reading and grading — simpler than the two-crate dance for a format this size.
- No independent low-MSRV `-core` reader that a third party could link without
  pulling `forensicnomicon::report`; the whole crate shares one MSRV (ADR 0009).
- If a future audit needs raw byte/slack structure the reader normalizes away,
  the split becomes worthwhile and this ADR should be revisited (a `udf-core`
  reader + `udf-forensic` analyzer, per the standard).
- The crate keeps the analyzer name (`udf-forensic`), consistent with the fleet
  convention that the analyzer is the headline even in a combined repo.
