# `udf-forensic` test fixtures

Per-file provenance for this crate's test data. The fleet-wide machine index is
[`issen/docs/corpus-catalog.md`](https://github.com/SecurityRonin/issen) — this README is
the co-located human detail; cross-reference, never duplicate. The tier rationale and the
list of independent-oracle validations live in [`docs/validation.md`](../../docs/validation.md);
this file documents only the per-fixture provenance.

## Status: real `mkudffs` corpus committed, reconciled against the `udfinfo` oracle

Three real UDF images, authored by **`mkudffs` (udftools 2.3)** and committed here, back the
`real_media_tests` in `src/lib.rs`. Each image's ground truth is cross-checked against the
independent **`udfinfo`** decoder (a separate codebase from this crate) — the oracle output is
captured verbatim below. The images are mostly-zero (≈10 KB each when packed by git), so they are
committed despite the global `*.img` ignore (a `.gitignore` negation un-ignores these three).

The corpus was minted on macOS via a rootless Linux container (`podman run ubuntu:24.04`) because
`mkudffs`/`udfinfo` are Linux-only; the verbatim commands are below and reproduce byte-identically
on any udftools 2.3 host.

- **Tool:** `udftools 2.3` (`2.3-1build2`, arm64), package `udftools`.
- **Mint command (per image):** `apt-get install -y udftools` then the `dd` + `mkudffs` lines below.
- **Redistribution:** `mkudffs` output is freely redistributable (the images contain only tool-authored
  filesystem structure and zero user data).

#### udf_vat.img — UDF 1.50, cdr media, Virtual (VAT) partition map

- **Source:** a UDF 1.50 image authored by `mkudffs` for CD-R media. The logical volume carries a
  physical partition map plus a Type-2 `*UDF Virtual Partition` (VAT) map.
- **Generator command (verbatim):**
  ```sh
  dd if=/dev/zero of=udf_vat.img bs=1M count=8
  mkudffs --media-type=cdr --udfrev=0x0150 udf_vat.img
  ```
- **Size / MD5:** 8 388 608 bytes - `1258d2b17f095af79bdb1141059eac84`
- **Consumed by:** `src/lib.rs` `mod real_media_tests` -> `vat_image_classified_virtual`
  (asserts `UdfPartitionKind::Virtual`) and `vat_image_matches_udfinfo_oracle`
  (asserts `partition_start == 257`, `partition_map_count == 2`).
- **`udfinfo` oracle output (independent ground truth):**
  ```
  udfinfo: Error: Virtual Allocation Table not found, maybe wrong --vatblock?
  udfinfo: Warning: Logical Volume is in inconsistent state
  filename=udf_vat.img
  label=LinuxUDF
  blocksize=2048
  blocks=4096
  numfiles=0
  numdirs=1
  udfrev=1.50
  udfwriterev=1.50
  integrity=opened
  accesstype=writeonce
  start=16, blocks=3, type=VRS
  start=96, blocks=16, type=MVDS
  start=128, blocks=1, type=LVID
  start=240, blocks=16, type=RVDS
  start=256, blocks=1, type=ANCHOR
  start=257, blocks=3839, type=PSPACE
  ```
  The VAT-not-found / inconsistent-state notes are expected for freshly-built write-once media (the
  LVID is left "opened" until the disc is closed); the partition space (`PSPACE`) starts at block 257,
  which this crate independently resolves as `partition_start = 257`.

#### udf_spar.img — UDF 2.01, dvdrw media, Sparable partition map

- **Source:** a UDF 2.01 image authored by `mkudffs` for DVD-RW media. The logical volume carries a
  single Type-2 `*UDF Sparable Partition` map; the image contains a sparing-space (`SSPACE`) region.
- **Generator command (verbatim):**
  ```sh
  dd if=/dev/zero of=udf_spar.img bs=1M count=8
  mkudffs --media-type=dvdrw --udfrev=0x0201 udf_spar.img
  ```
- **Size / MD5:** 8 388 608 bytes - `70285bf8979a026380517bfc48ae6ee6`
- **Consumed by:** `src/lib.rs` `mod real_media_tests` -> `sparable_image_classified_sparable`
  (asserts `UdfPartitionKind::Sparable`) and `sparable_image_matches_udfinfo_oracle`
  (asserts `partition_start == 1296`, `partition_map_count == 1`).
- **`udfinfo` oracle output (independent ground truth):**
  ```
  filename=udf_spar.img
  label=LinuxUDF
  blocksize=2048
  blocks=4096
  numfiles=0
  numdirs=1
  udfrev=2.01
  udfwriterev=2.01
  integrity=closed
  accesstype=overwritable
  start=16, blocks=3, type=VRS
  start=96, blocks=16, type=MVDS
  start=112, blocks=1, type=STABLE
  start=128, blocks=1, type=LVID
  start=256, blocks=1, type=ANCHOR
  start=272, blocks=1024, type=SSPACE
  start=1296, blocks=2528, type=PSPACE
  start=3839, blocks=1, type=ANCHOR
  start=3936, blocks=16, type=RVDS
  start=4080, blocks=1, type=STABLE
  start=4095, blocks=1, type=ANCHOR
  ```
  The 1024-block `SSPACE` (sparing space) sits before the partition space, so `PSPACE` starts at
  block 1296 — which this crate independently resolves as `partition_start = 1296`.

#### udf_plain.img — UDF 2.01, hd media, 512-byte blocks

- **Source:** a UDF 2.01 image authored by `mkudffs` for hard-disk media. Plain physical partition,
  **512-byte block size**.
- **Generator command (verbatim):**
  ```sh
  dd if=/dev/zero of=udf_plain.img bs=1M count=8
  mkudffs --media-type=hd --udfrev=0x0201 udf_plain.img
  ```
- **Size / MD5:** 8 388 608 bytes - `31d06a9942f8bc4983617631a9ac4e30`
- **Consumed by:** `real_media_tests::plain_512_block_image_parses_via_detected_block_size`. This is the
  512-byte-block oracle case: the crate detects the block size from the AVDP location (the anchor is at
  byte `256 × 512`, not `256 × 2048`) and resolves a **physical** partition at `partition_start = 257`
  with one map. Reconciled against `udfinfo` (`blocksize=512`, `udfrev=2.01`, `start=257, blocks=15864,
  type=PSPACE`). Together with the 2048-byte `vat`/`spar` images it exercises block-size detection across
  two media sector sizes.

## Reproducing the corpus on a non-Linux host

`mkudffs`/`udfinfo` are Linux-only. On macOS, mint via a rootless Linux container (no VM SSH needed):

```sh
mkdir -p ~/udfwork && cd ~/udfwork           # must live under /Users (podman machine mount)
podman machine start                          # one-time
podman run --rm -v "$PWD:/work:Z" ubuntu:24.04 bash -c '
  apt-get update -qq && apt-get install -y -qq udftools && cd /work &&
  dd if=/dev/zero of=udf_vat.img  bs=1M count=8 && mkudffs --media-type=cdr   --udfrev=0x0150 udf_vat.img  &&
  dd if=/dev/zero of=udf_spar.img bs=1M count=8 && mkudffs --media-type=dvdrw --udfrev=0x0201 udf_spar.img &&
  dd if=/dev/zero of=udf_plain.img bs=1M count=8 && mkudffs --media-type=hd   --udfrev=0x0201 udf_plain.img &&
  udfinfo udf_vat.img; udfinfo udf_spar.img; udfinfo udf_plain.img'
```

Then verify the MD5s match the values above before relying on the images. The matching entries in
[`issen/docs/corpus-catalog.md`](https://github.com/SecurityRonin/issen) classify these `SYNTHETIC`
(self-minted from a real third-party tool) and record the same verbatim commands.
