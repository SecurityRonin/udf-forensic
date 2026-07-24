# udf-forensic — Design, Purpose & Scope

*A reverse-written design note grounded in a same-session read of `src/`,
`Cargo.toml`, and the git history (2026-07-24). The load-bearing decisions live
as ADRs under [`docs/decisions/`](decisions/); this note frames the purpose,
scope, and non-goals they sit inside. This is a **library** — it is linked, not
run; there is no binary an examiner executes. It is therefore a DESIGN note, not
a PRD.*

## Purpose

`udf-forensic` is a pure-Rust, forensic-grade reader and tamper analyzer for the
UDF (Universal Disk Format, ECMA-167 / OSTA) filesystem, over any `Read + Seek`
source. It reads UDF as written to DVD, Blu-ray, packet-written optical media,
and UDF-formatted USB/hard-disk volumes, and grades structural anomalies as
normalized findings.

It occupies the FILESYSTEM layer of the fleet architecture: a self-contained
expert in one artifact family, depending down only on the KNOWLEDGE leaf
(`forensicnomicon`) and the shared `safe-read` primitive. It was extracted from
`iso9660-forensic` (ADR 0001); the ISO reader has since dropped all UDF handling
(iso9660-forensic `ff0b179`), keeping only a native `has_udf()` recognition
boolean, and no longer depends on this crate. The sole fleet consumer today is
`forensic-vfs-engine`, which composes the UDF `FileSystem` adapter via the
optional `vfs` feature (ADR 0008) for optical evidence images.

## Who uses it

- **Fleet filesystem/container consumers** — `forensic-vfs-engine` is the sole
  fleet consumer today, composing the UDF `FileSystem` adapter (the `vfs` feature)
  for uniform, format-agnostic image access. The `findings::analyze` output has no
  fleet aggregator wired in yet; folding `UDF-*` findings into an Issen / disk4n6
  `Report` is intended future work, not a present dependency.
- **Rust developers** parsing UDF directly over a `File`, a container-decoded
  sector stream, or a carved region — no image-format knowledge required.
- **Forensic examiners**, transitively, through the tools above: they see graded
  `UDF-*` findings and honest capability boundaries, not silent wrong output.

## What it does (grounded in the code)

- **Volume recognition** — NSR02 / NSR03 detection in the recognition sequence at
  sector 16 (`detect_udf`).
- **Bootstrap chain** — AVDP (LBA 256) → Volume Descriptor Sequence → Partition
  Descriptor + Logical Volume Descriptor → File Set Descriptor → root File Entry
  (`parse_udf_state` / `parse_udf_state_checked`), distinguishing a read/truncation
  failure (`Err`) from a structural "not UDF" negative (`Ok(None)`) — ADR 0005.
- **Block-size auto-detection** — 512 / 1024 / 2048 / 4096 derived from a valid
  AVDP, so seeks are correct across optical, USB/HDD, and Advanced-Format media
  (ADR 0007).
- **Partition-map classification** — Physical (Type 1) resolved as
  `partition_start + logical_block`; Virtual (VAT), Sparable, and Metadata
  (Type 2) detected and reported, never silently mis-resolved (ADR 0004).
- **Directory traversal + file data** — File Entry + File Identifier Descriptors,
  OSTA CS0 name decoding, short/long extent reading (`read_dir_at_lba`,
  `read_fe_data`).
- **Graded findings** — `findings::analyze()` emits `UDF-TAG-CRC-MISMATCH`,
  `UDF-TAG-CHECKSUM-BAD`, `UDF-TIME-AFTER-VOLUME`, `UDF-SLACK-DATA` as
  `forensicnomicon::report::Observation`s (ADR 0006).
- **Optional VFS adapter** — `impl FileSystem for UdfVfs` behind the `vfs`
  feature (ADR 0008).

## Scope / non-goals (honest boundaries)

- **Type-2 block resolution is out of scope today.** VAT / Sparable / Metadata
  partitions are classified and reported, but their block mapping (VAT, sparing
  table, metadata file) is not followed — a Type-2 volume's file traversal is a
  named gap, not a wrong answer (ADR 0004).
- **The analyzer emits only what the reader observes.** No anomaly is invented
  beyond the parsed model. The module doc currently names an `OrphanFileEntry`
  anomaly that is not yet implemented (four `UDF-*` codes ship); the doc is ahead
  of the code and should be reconciled.
- **VFS metadata is partial.** Per-File-Entry times, true on-disk extents, and
  deleted/unallocated/symlink recovery are not yet surfaced through the reader's
  public API, so the adapter reports them as honestly absent (all-`None` times, a
  single logical run, empty streams) rather than fabricated (ADR 0008).
- **Not a writer.** Read-only over `Read + Seek`; it never modifies the source.
- **Single crate, not a `-core`/`-forensic` split** (ADR 0002).

## Validation approach

Correctness is established against **independent oracles on real corpora**, tiered
by who confirms the check (`docs/validation.md`):

- **Tier 1** — partition-map classification and the resolved partition-space start
  are reconciled against the independent **`udfinfo`** (udftools 2.3) decoder on
  real **`mkudffs`**-authored images committed to `tests/data/` (VAT / cdr / 1.50
  and Sparable / dvdrw / 2.01). The findings analyzer has a Tier-1 true-negative
  on the same corpus.
- **Self-validating** — ECMA-167 tag CRC-CCITT (poly `0x1021`, init `0x0000`) and
  the mod-256 tag checksum are recomputed and compared; their implementations
  match the values `mkudffs` itself wrote, so no external oracle is needed.
- **Fuzzed** — `cargo-fuzz` targets over `detect` / `parse_state` / `read_dir` /
  `read_fe` back the panic-free posture (ADR 0003).
- **Named gaps** — volume-recognition and directory/file-data oracles
  (`isoinfo` / `mount -t udf`) are documented as gaps rather than dressed up as
  stronger claims.
