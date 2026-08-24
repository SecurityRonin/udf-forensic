# 10. Split the reader into `udf-core`, keeping `udf-forensic` source-compatible

Date: 2026-08-24

Status: Accepted

Supersedes [ADR-0002](0002-single-crate-reader-and-findings.md).

## Context

[ADR-0002](0002-single-crate-reader-and-findings.md) kept the reader and the
`findings` analyzer in one published crate, `udf-forensic`. Its reasoning was
sound for the conditions at the time: the analyzer observes solely the reader's
already-parsed model, so no lower-level seam was needed, and — decisively — it
recorded that **no reader-only consumer existed** that would want the reader
without pulling `forensicnomicon`. It named the exact trigger for revisiting
itself:

> *"No independent low-MSRV `-core` reader that a third party could link without
> pulling `forensicnomicon::report` … the split becomes worthwhile and this ADR
> should be revisited."*

That condition now holds. Two consumers read UDF volumes and have no use for the
analyzer:

- **`forensic-vfs-engine`** composes UDF alongside the other container/filesystem
  readers behind `Vfs::open(path)`; it wants the `vfs` adapter, not findings.
- **An external archiver** (`zmanager`, via a fork of `forensic-vfs-engine`)
  opens UDF containers to extract files. Pulling a forensic report model into an
  archiver is dead weight.

A reader-only `udf-core` therefore has real consumers, which is precisely what
ADR-0002 said would justify the split.

## Decision

Split the workspace into two published members:

- **`udf-core`** — the reader: detection, the AVDP→VDS→FSD bootstrap, partition
  maps, File Entry / FID traversal, file data, and the optional `vfs` adapter.
  It carries **no `forensicnomicon` dependency**; a bare `udf-core` (no features)
  depends only on `safe-read`. This is the lean, low-MSRV crate a reader-only
  consumer links.
- **`udf-forensic`** — the analyzer (`findings`), depending on `udf-core` and
  `forensicnomicon::report`.

`udf-forensic` **re-exports the entire `udf-core` surface** (`pub use
udf_core::*`) and forwards the `vfs` feature (`vfs = ["udf-core/vfs"]`). Existing
consumers that reached the reader through `udf_forensic::UdfState` /
`udf_forensic::detect_udf` / `udf_forensic::vfs::UdfVfs`, with or without the
`vfs` feature, **compile unchanged** — the split is source-compatible, verified
by an external consumer crate that mirrors `forensic-vfs-engine`'s usage.

The low-level format primitives the analyzer grades over (descriptor tag
CRC/checksum helpers, the tag-identity constants, the FSD recording-time reader)
become `pub` on `udf-core`. They are the ECMA-167 format's own defined values and
checks, a legitimate part of a forensic reader's surface.

## Consequences

- A reader-only consumer links `udf-core` with a single dependency (`safe-read`),
  no `forensicnomicon`, and can hold a lower MSRV than the analyzer requires.
- No consumer is forced to migrate. `udf-forensic` stays a drop-in; migrating to
  `udf-core` for a leaner graph is opt-in, at each consumer's pace.
- Two crates publish independently. `udf-core` is versioned from `0.1.0`;
  `udf-forensic` continues its series and gains a `udf-core` dependency.
- The analyzer now depends on the reader across a crate boundary, so the reader
  internals it needs are part of `udf-core`'s public API rather than
  `pub(crate)`. This widens `udf-core`'s surface with format primitives — an
  acceptable cost for a forensic format reader, and the seam is explicit.
- ADR-0002's simplicity argument (one `cargo add` for a consumer that wants both)
  is preserved: `udf-forensic` still delivers reader + analyzer in one dependency.
