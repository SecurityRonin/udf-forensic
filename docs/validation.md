# Validation

`udf-forensic` parses untrusted UDF (ECMA-167 / OSTA) structures from potentially
compromised optical-media images. Correctness for forensic tooling is established
against **independent oracles** (a different tool, or a different code path, that
already decodes the same bytes correctly) on **real third-party corpora** with
known ground truth — never against fixtures we hand-encoded and then graded
ourselves.

This page records exactly which oracle and which corpus back each capability, so
the claim is independently re-checkable. Partition-map classification and the
partition-space start are now backed by the independent **`udfinfo`** (udftools)
oracle on real `mkudffs`-authored images committed to `tests/data/` (Tier 1). It
remains deliberate about what is **not yet** backed by an independent oracle:
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
| **`isoinfo`** (cdrtools) / **`xorriso`** | No — **recommended gap** | Volume recognition (NSR02/NSR03), directory tree on UDF-bridge discs | 1 |
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
| `udf_plain.img` | `mkudffs --media-type=hd --udfrev=0x0201` (UDF 2.01, 512-byte blocks) | Documents the fixed-2048-block-size limitation (not asserted) | `31d06a99…c4e30` | mkudffs output, freely redistributable |

Per-file provenance lives in `tests/data/README.md`; the fleet-wide machine index
is `issen/docs/corpus-catalog.md`.

## Per-capability validation

### Volume recognition (NSR02 / NSR03) — Tier 3

Recognition of the UDF Volume Structure Descriptor sequence is exercised only by
the in-crate bootstrap tests over hand-built buffers. No independent oracle
(`isoinfo`/`xorriso`) confirms the recognition decision on a real disc yet —
**recommended gap.**

### Partition-map classification (Virtual / Sparable) — Tier 1

`src/lib.rs` `mod real_media_tests` asserts, against committed real `mkudffs`
images, that the `cdr`/UDF 1.50 image classifies as `Virtual` and the
`dvdrw`/UDF 2.01 image as `Sparable`:

- `vat_image_classified_virtual` (`src/lib.rs:649`) and
  `sparable_image_classified_sparable` (`src/lib.rs:662`) — the kind assertion.
- `vat_image_matches_udfinfo_oracle` (`src/lib.rs:685`) and
  `sparable_image_matches_udfinfo_oracle` (`src/lib.rs:709`) — the **independent
  oracle differential**: each asserts that this crate's resolved
  `partition_start` equals the `PSPACE` start block reported by `udfinfo` (257 for
  the VAT image, 1296 for the Sparable image), and that `partition_map_count`
  matches the media-type's map layout (2 for cdr, 1 for dvdrw). The expected
  values are the oracle's reported ground truth — captured verbatim in
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

There is **no coverage gate and no fuzz harness in this repo yet** — CI runs
`ci.yml` (build/test/clippy/fmt) and `docs.yml` (MkDocs) only. Production code is
`#![forbid(unsafe_code)]` (`Cargo.toml`), reads through bounds-checked helpers,
and folds malformed structure into `None` rather than panicking. A `cargo-fuzz`
target over `parse_udf_state` / `read_dir_at_lba` and a `cargo llvm-cov --lib`
gate are recommended additions to bring this crate to the fleet backstop standard.
