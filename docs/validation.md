# Validation

`udf-forensic` parses untrusted UDF (ECMA-167 / OSTA) structures from potentially
compromised optical-media images. Correctness for forensic tooling is established
against **independent oracles** (a different tool, or a different code path, that
already decodes the same bytes correctly) on **real third-party corpora** with
known ground truth — never against fixtures we hand-encoded and then graded
ourselves.

This page records exactly which oracle and which corpus back each capability, so
the claim is independently re-checkable. Partition-map classification and the
partition-space start are backed by the independent **`udfinfo`** (udftools)
oracle on real `mkudffs`-authored images committed to `tests/data/` (Tier 1); the
**findings analyzer** is validated by a Tier-1 true-negative on the same real
corpus plus self-validating ECMA-167 CRC/checksum checks (whose implementations
match the values `mkudffs` itself wrote). It remains deliberate about what is
**not yet** backed by an independent oracle:
where the current evidence is self-authored, it is labelled Tier 3 and the
missing oracle is named as a gap rather than dressed up as a stronger claim.

## How to read the evidence tiers

Each validation below is tagged with the trustworthiness of its check, not
whether the data is "synthetic":

- **Tier 1** — an independent third party authored the artifact *and* the answer
  key, or it is real-world data decoded by an independent tool. The strongest claim.
- **Tier 2** — real engine output whose ground truth is derivable from the
  documented construction, or confirmed by an *independent code path* on real
  data. Genuinely checked, but we chose the scenario.
- **Tier 3** — fixture and expected answer both authored here, nothing
  independent vouching. Used only for per-branch coverage, never as a
  correctness claim: a self-consistent round trip proves internal consistency,
  not correctness against real-world bytes.

## Independent oracles

`udfinfo` (udftools 2.3) is now wired into the suite as the independent decoding
oracle. It is a separate codebase from this crate; its reported `PSPACE` start
block and partition-map shape are reconciled against this crate's parse output in
`real_media_tests`, and its verbatim output is captured in `tests/data/README.md`.
The remaining oracles below are named gaps for the capabilities they would cover.

| Oracle | Wired in? | Validates | Tier established |
|---|---|---|---|
| **`udfinfo`** (udftools) | **Yes** | Partition-map kind + partition-space start, on real `mkudffs` images | 1 |
| **`isoinfo`** (cdrtools) / **`xorriso`** | Evaluated — N/A for this corpus | Volume descriptors on **UDF-bridge** discs (the committed corpus is pure UDF; `isoinfo -d` reports "NOT in ISO 9660 format") | 1 |
| **Linux `mount -t udf` + `find`** | No — **recommended gap** | Directory traversal + file-data extents, byte-for-byte file contents | 1 |
| **`mkudffs` construction profile** | Yes (the fixtures' build flags) | Partition-map kind matches the media type the image was built for | 2 |

Adding either remaining oracle to a differential test would lift volume
recognition or directory/file-data extraction to Tier 1.

## Independent test corpora

Three real `mkudffs`-authored images are committed to `tests/data/` with full
provenance (verbatim `mkudffs` commands, udftools version, MD5, and the captured
`udfinfo` oracle output) in [`tests/data/README.md`](https://github.com/SecurityRonin/udf-forensic/blob/main/tests/data/README.md).
They are mostly-zero (≈10 KB each when packed by git), so they are committed
rather than gitignored. The partition-map tests run against them in CI.

| Corpus | Source (verbatim) | Used for | MD5 | License |
|---|---|---|---|---|
| `udf_vat.img` | `mkudffs --media-type=cdr --udfrev=0x0150` (UDF 1.50) | Virtual (VAT) classification + PSPACE start 257 | `1258d2b1…9eac84` | mkudffs output, freely redistributable |
| `udf_spar.img` | `mkudffs --media-type=dvdrw --udfrev=0x0201` (UDF 2.01) | Sparable classification + PSPACE start 1296 | `70285bf8…ae6ee6` | mkudffs output, freely redistributable |
| `udf_plain.img` | `mkudffs --media-type=hd --udfrev=0x0201` (UDF 2.01, 512-byte blocks) | Physical classification + 512-byte block-size detection + PSPACE start 257 | `31d06a99…c4e30` | mkudffs output, freely redistributable |

Per-file provenance lives in `tests/data/README.md`; the fleet-wide machine index
is `issen/docs/corpus-catalog.md`.

## Per-capability validation

### Volume recognition (NSR02 / NSR03) — Tier 3

Recognition of the UDF Volume Structure Descriptor sequence is exercised only by
the in-crate bootstrap tests over hand-built buffers. No independent oracle
(`isoinfo`/`xorriso`) confirms the recognition decision on a real disc yet —
**recommended gap.**

### Partition-map classification + block-size detection — Tier 1

`src/lib.rs` `mod real_media_tests` asserts, against committed real `mkudffs`
images, that each image classifies correctly and resolves its partition start —
across **two media sector sizes** (2048-byte optical and 512-byte hard-disk):

- `vat_image_classified_virtual` and `sparable_image_classified_sparable` — the
  kind assertion (`cdr`/1.50 → `Virtual`, `dvdrw`/2.01 → `Sparable`).
- `vat_image_matches_udfinfo_oracle` and `sparable_image_matches_udfinfo_oracle`
  — the **independent oracle differential**: each asserts this crate's resolved
  `partition_start` equals the `PSPACE` start block `udfinfo` reports (257 for the
  VAT image, 1296 for the Sparable image), and `partition_map_count` matches the
  media-type's layout (2 for cdr, 1 for dvdrw).
- `plain_512_block_image_parses_via_detected_block_size` — the **512-byte-block**
  case: the `hd`/2.01 image's Anchor Volume Descriptor Pointer lives at byte
  `256 × 512`, so it parses only because the crate detects the block size from the
  AVDP location rather than assuming 2048. Asserts `block_size = 512`, a `Physical`
  partition, `partition_start = 257`, one map — reconciled against `udfinfo`.

All expected values are the oracle's reported ground truth — captured verbatim in
`tests/data/README.md` — not recomputed by this crate.

This is Tier 1: a real third-party tool authored both the artifact (`mkudffs`)
and the answer key (`udfinfo`), and a separate codebase re-decodes the same bytes.
The classifier (the entity-string scan in `classify_type2`) and the partition
resolution are confirmed correct on genuine media structure, not just on the
construction profile.

### Bootstrap-failure vs not-UDF distinction — Tier 3

`src/lib.rs` `mod checked_bootstrap_tests` validates that
`parse_udf_state_checked` separates a genuine read/seek failure (truncated or
unreadable image) from a structural negative (readable image whose anchor is not
an AVDP):

- `io_error_at_anchor_surfaces_as_err` (`src/lib.rs:751`) — a faulting reader at
  the LBA-256 anchor surfaces `Err`, never `Ok(None)`.
- `truncated_before_anchor_surfaces_as_err` (`src/lib.rs:761`) — a buffer too
  short to reach the anchor yields `Err(UnexpectedEof)`.
- `full_size_but_wrong_anchor_is_ok_none` (`src/lib.rs:777`) — a readable image
  with a non-AVDP anchor is the legitimate `Ok(None)` "not UDF" case.

These are self-authored fixtures with self-authored expectations (Tier 3). They
are genuinely useful — they pin the fail-loud-vs-degrade-to-empty contract — but
they prove internal consistency, not correctness against real-world media.

### Directory traversal and file-data extents — not yet validated

FID traversal and short/long extent file-data reading have **no committed test
backing of any tier**. The recommended oracle is `mount -t udf` + a byte-for-byte
`find`/checksum comparison on a real disc image — **recommended gap.**

### Forensic findings analyzer (`findings::analyze`) — Tier 1 (true-negative) + Tier 2 (positive)

`src/findings.rs` grades anomalies over the already-parsed structures, emitting
`forensicnomicon::report::Observation`s (mirroring `iso9660-forensic`). It surfaces
only what the reader can observe:

| Code | Severity | Category | What it observes | How it is checked |
|---|---|---|---|---|
| `UDF-TAG-CRC-MISMATCH` | High | Integrity | A descriptor's recorded `DescriptorCRC` ≠ the CRC-CCITT (poly `0x1021`, init `0x0000`) recomputed over its body | **Self-validating against ECMA-167** — no external oracle needed |
| `UDF-TAG-CHECKSUM-BAD` | High | Integrity | A descriptor tag's recorded mod-256 `TagChecksum` ≠ recomputed | **Self-validating against ECMA-167** |
| `UDF-TIME-AFTER-VOLUME` | Medium | History | A File Entry modification time later than the FSD recording time | Derivable from the documented construction |
| `UDF-SLACK-DATA` | Low | Residue | Non-zero bytes in a file's final-block slack (past `InformationLength`) | Derivable from the documented construction |

**Oracle for the structural checks.** The CRC and checksum are *self-validating*:
ECMA-167 §3/7.2 fully specifies both algorithms, so the recomputed value is the
ground truth — there is no separate tool to disagree with. The implementations
were confirmed against real third-party output: the CRC-CCITT and tag-checksum
recomputed over the AVDP of all three committed `mkudffs` images **equal the
values `mkudffs` itself wrote** (`udf_plain` CRC `0x13b5` / checksum 192;
`udf_vat` `0x43a1` / 219; `udf_spar` `0x9317` / 162). `mkudffs` is an independent
authoring tool, so this is a real cross-check, not a self-encoded round trip. The
CRC also matches the published CRC-16/XMODEM vector (`"123456789"` → `0x31C3`).

**`udfinfo` is the volume-level decode oracle** already wired into
`real_media_tests`; `isoinfo -d` was evaluated as an additional volume-descriptor
oracle but **cannot read these pure-UDF `mkudffs` images** — they carry only the
NSR02/NSR03 UDF mark and no ISO 9660 bridge structures, so `isoinfo -d` reports
"CD-ROM is NOT in ISO 9660 format". It remains the right oracle for UDF-bridge
discs (which carry both filesystems); for the committed pure-UDF corpus the
self-validating CRC/checksum + `udfinfo` cover the structural and volume layers.

**Tier 1 true-negative on the real corpus.** `tests/findings.rs`
`real_plain_image_is_clean` / `real_vat_image_is_clean` / `real_spar_image_is_clean`
run `analyze()` over each committed `mkudffs` image and assert **zero anomalies**.
A clean authoring tool writes correct tag checksums + CRCs and stamps file times at
the volume recording time, so a finding here would be a false positive — the
true-negative on genuine third-party media is the strongest evidence the analyzer
does not over-report.

**Tier 2 positives on derived fixtures.** Each positive path is driven by
surgically mutating one field of a real image (a documented mutation of a genuine
artifact, not a hand-built blob): flipping an AVDP body byte →
`UDF-TAG-CRC-MISMATCH`; flipping a tag byte → `UDF-TAG-CHECKSUM-BAD`; bumping the
root File Entry's modification-time year past the volume time →
`UDF-TIME-AFTER-VOLUME`. The `UDF-SLACK-DATA` emission and the directory recursion
are exercised by minimal but spec-valid synthetic descriptors (built with the same
CRC/checksum helpers, so the walk sees no spurious tag anomaly).

**Deliberate scope decision — no orphan-File-Entry check.** An "orphan File Entry"
(a valid FE referenced by no directory FID) was prototyped as a partition-wide FE
sweep and **removed**: a clean `mkudffs` image legitimately contains stream-directory
(FileType 13), VAT (FileType 0), and empty-file (FileType 5) File Entries that are
reachable through UDF stream directories / Type-2 metadata partitions — structures
this reader explicitly does not model (see the `UdfPartitionKind` note in
`src/lib.rs`). A partition-wide sweep flags all of them on *every clean image*, so
shipping it would fail the Tier-1 true-negative above. Sound orphan detection
needs the stream-directory / metadata-partition model first; until then it is out
of scope rather than shipped as a false-positive generator.

## Reproducing the validation

All tests run with `cargo test` — the real-media tests run against the committed
fixtures (the skip-if-missing arm is a defensive fallback for a stripped checkout):

```bash
# Everything
cargo test

# Only the bootstrap fail-loud contract
cargo test checked_bootstrap_tests

# The real-media partition-map + udfinfo-oracle differential tests
cargo test real_media_tests
```

To regenerate the corpus from scratch (e.g. to confirm the committed MD5s),
`mkudffs`/`udfinfo` are Linux-only; on macOS use a rootless Linux container — the
exact one-liner, the verbatim per-image `mkudffs` commands, the udftools version,
the MD5s, and the captured `udfinfo` oracle output are all in
[`tests/data/README.md`](https://github.com/SecurityRonin/udf-forensic/blob/main/tests/data/README.md).

## Coverage & fuzzing backstops

There is **no CI coverage gate and no fuzz harness in this repo yet** — CI runs
`ci.yml` (build/test/clippy/fmt) and `docs.yml` (MkDocs) only. Production code is
`#![forbid(unsafe_code)]` (`Cargo.toml`), reads through bounds-checked helpers,
and folds malformed structure into `None` rather than panicking.

The `findings` analyzer and its lib-side support helpers are exercised to the
fleet `// cov:unreachable` standard: measured with `cargo llvm-cov --all-targets`,
`src/findings.rs` reaches ~95% lines with the single remaining uncovered line
being an annotated `// cov:unreachable` File-Entry guard, and every findings
helper added to `src/lib.rs` is covered bar one annotated defensive guard. The
pre-existing reader paths (`detect_udf`, partition-map edge arms) remain below the
fleet bar — a `cargo-fuzz` target over `parse_udf_state` / `read_dir_at_lba` and a
repo-wide `cargo llvm-cov` CI gate are recommended additions to bring the whole
crate to the fleet backstop standard.
