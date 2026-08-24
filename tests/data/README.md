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

#### udf_symlink.img — UDF 2.01, hd media, populated with a symlink

- **Source:** the `udf_plain` recipe (UDF 2.01, hd media, 512-byte blocks) populated via a
  Linux loop mount: a small payload tree (`README.txt`, `nested/file.txt`) plus a symlink
  `nested/readme-link.txt -> ../README.txt` created by the Linux UDF driver (`cp -a`), which
  stores it as an ECMA-167 4/14.16.2 PATH_COMPONENT record chain (4-byte records: type,
  length, `__le16 componentFileVersionNum`). The kernel struct is stable across v6.6–v6.14.
- **Generator command (verbatim), inside a privileged `ubuntu:24.04` container:**
  ```sh
  dd if=/dev/zero of=udf_symlink.img bs=1M count=8
  mkudffs --media-type=hd --udfrev=0x0201 udf_symlink.img
  # losetup + mount -t udf, then: cp -a src/. /mnt/udf/   (src contains the symlink)
  ```
- **Size / MD5:** 8 388 608 bytes - `7dff64a7729478cd609a8291840b0a94`
- **Consumed by:** `vfs.rs` `mod tests::udf_symlink_surfaces_as_symlink_with_target` (the vfs
  adapter's `NodeKind::Symlink` classification and `FileSystem::read_link` PATH_COMPONENT
  decode), and by the fuzz corpus (all `tests/data/*.img` are seeded into every fuzz target).
  Ground truth: the Linux UDF driver resolves the same record to `../README.txt` (the image's
  own author), cross-checked on macOS via `hdiutil attach` (shows `readme-link.txt ->
  ../README.txt`).

#### udf_all_node_types.img — UDF 2.01, hd media, every non-regular node type

- **Source:** the `udf_symlink` recipe extended so the image is a **superset** of it — the same
  `README.txt`, `nested/file.txt` and `nested/readme-link.txt -> ../README.txt` tree, plus a
  `nodes/` directory carrying one of every non-regular type the format can express. All five
  were created by the Linux UDF driver on a loop mount (`ln -s`, `mknod`, `mkfifo`, and a
  `bind()`ed `AF_UNIX` socket), so the ICB File Type bytes are the driver's own.
- **Node types recorded (ECMA-167 4/14.6.6, ICB Tag File Type at File Entry offset 27):**

  | path | ICB `file_type` | meaning |
  |---|---|---|
  | `nodes/symlink` | `0x0C` | symbolic link |
  | `nodes/chardev` | `0x07` | character device (1, 3) |
  | `nodes/blockdev` | `0x06` | block device (7, 0) |
  | `nodes/fifo` | `0x09` | FIFO |
  | `nodes/socket` | `0x0A` | socket |

- **Generator command (verbatim), inside a privileged `ubuntu:24.04` container:**
  ```sh
  dd if=/dev/zero of=udf_all_node_types.img bs=1M count=8
  mkudffs --media-type=hd --udfrev=0x0201 udf_all_node_types.img
  # losetup + mount -t udf /dev/loopN /mnt/udf, then in /mnt/udf:
  #   printf 'readme\n' > README.txt; mkdir nested
  #   printf 'nested file\n' > nested/file.txt
  #   ln -s ../README.txt nested/readme-link.txt
  #   mkdir nodes && cd nodes
  #   ln -s ../README.txt symlink
  #   mknod chardev c 1 3 ; mknod blockdev b 7 0 ; mkfifo fifo
  #   python3 -c "import socket;s=socket.socket(socket.AF_UNIX);s.bind('socket')"
  ```
  **`mknod` needs real `CAP_MKNOD`** — rootless podman cannot create device nodes even with
  `--privileged` (the capability is namespaced; it fails on tmpfs too, which is the tell). On
  macOS run the container rootful inside the VM: `podman machine ssh 'sudo podman run …'`.
  The container's `/dev` also carries only `loop0`, so materialize more before `losetup -f`.
- **Size / MD5:** 8 388 608 bytes - `350ce39ff0208e1583f96460d37654d9`
- **Ground truth:** the Linux UDF driver's own readback after remount lists `b`, `c`, `p`, `s`
  and `l` for the five nodes and resolves the legacy symlink to `../README.txt`; the ICB
  `file_type` histogram was independently confirmed by reading File Entry offset 27 directly
  (`0x04 ×3, 0x05 ×2, 0x06, 0x07, 0x09, 0x0A, 0x0C ×2`).
- **Classification:** Tier 2 — real `mkudffs` + kernel-driver output, ground truth from the
  driver's own resolution, but the scenario (which nodes exist) was chosen here.
- **Consumed by:** `vfs.rs` `mod tests::every_non_regular_node_type_is_classified`, and by the
  fuzz corpus (all `tests/data/*.img` are seeded into every fuzz target).

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
