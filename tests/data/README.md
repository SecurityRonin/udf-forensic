# `udf-forensic` test fixtures

Per-file provenance for this crate's test data. The fleet-wide machine index is
[`issen/docs/corpus-catalog.md`](https://github.com/SecurityRonin/issen) — this README is
the co-located human detail; cross-reference, never duplicate. The tier rationale and the
list of recommended independent-oracle gaps live in [`docs/validation.md`](../../docs/validation.md);
this file documents only the per-fixture provenance and the **current absence** of the corpus.

## Status: `tests/data/` is currently EMPTY

**No fixtures are committed, and no generator ships in the repo yet.** The two real-media
images named below (`udf_vat.img`, `udf_spar.img`) and the generator script
(`corpus/gen_udf_type2.sh`) referenced by the test module comment in `src/lib.rs`
(`mod real_media_tests`) are **absent**. The two tests that consume them
(`vat_image_classified_virtual`, `sparable_image_classified_sparable`) are written to
**skip cleanly when the fixture is missing** — they `eprintln!("skip: …")` and return — so
the committed suite is green without the corpus. This README records what *should* be here
and how to reproduce it, so the gap is documented rather than silent.

The path to compliance is to commit `corpus/gen_udf_type2.sh` (the exact `mkudffs` invocations
below) plus the generated images — or, if the images are too large to commit, gitignore them
and pin the exact `mkudffs` flags **and the MD5 of each generated file** in this README so the
corpus is reproducible. See the *Independent test corpora* section of
[`docs/validation.md`](../../docs/validation.md) for the gap write-up and the recommended
`udfinfo`/`isoinfo`/`mount -t udf` oracles that would lift these from Tier 2 to Tier 1.

#### udf_vat.img — NOT COMMITTED (generator absent)

- **Intended source:** a UDF 1.50 image authored by `mkudffs` (udftools) for CD-R media,
  whose partition map is a **Virtual Allocation Table (VAT)** partition.
  - Intended generator command:
    ```sh
    dd if=/dev/zero of=tests/data/udf_vat.img bs=1M count=32
    mkudffs --media-type=cdr --udfrev=0x0150 tests/data/udf_vat.img
    ```
- **Consumed by:** `src/lib.rs` `mod real_media_tests` → `vat_image_classified_virtual`
  (asserts `UdfPartitionKind::Virtual`).
- **Ground-truth basis:** the `mkudffs` construction profile for `cdr`/UDF 1.50 (Tier 2 — the
  tool author's documented output for that media type; no independent decoder cross-checks the
  same bytes yet).
- **Status:** **NOT COMMITTED.** The fixture is absent and the generator
  `corpus/gen_udf_type2.sh` does not exist in the repo. Must be regenerated with the command
  above before `vat_image_classified_virtual` can run.
- **Redistribution:** `mkudffs` output is freely redistributable.
- **MD5:** *not available — the fixture has never been committed; do not record a hash until a
  real generated image exists.*

#### udf_spar.img — NOT COMMITTED (generator absent)

- **Intended source:** a UDF 2.01 image authored by `mkudffs` (udftools) for DVD-RW media,
  whose partition map is a **Sparable** partition.
  - Intended generator command:
    ```sh
    dd if=/dev/zero of=tests/data/udf_spar.img bs=1M count=32
    mkudffs --media-type=dvdrw --udfrev=0x0201 tests/data/udf_spar.img
    ```
- **Consumed by:** `src/lib.rs` `mod real_media_tests` → `sparable_image_classified_sparable`
  (asserts `UdfPartitionKind::Sparable`).
- **Ground-truth basis:** the `mkudffs` construction profile for `dvdrw`/UDF 2.01 (Tier 2; no
  independent decoder cross-checks the same bytes yet).
- **Status:** **NOT COMMITTED.** The fixture is absent and the generator
  `corpus/gen_udf_type2.sh` does not exist in the repo. Must be regenerated with the command
  above before `sparable_image_classified_sparable` can run.
- **Redistribution:** `mkudffs` output is freely redistributable.
- **MD5:** *not available — the fixture has never been committed; do not record a hash until a
  real generated image exists.*

## When you commit the corpus

1. Place `corpus/gen_udf_type2.sh` in the repo containing the `dd` + `mkudffs` lines above so
   the images are reproducible from one script.
2. Generate `tests/data/udf_vat.img` and `tests/data/udf_spar.img`.
3. Hash each generated file (`md5 tests/data/udf_vat.img`) and replace the *MD5 not available*
   lines above with the real values, plus a byte-size column.
4. Add the matching entries to `issen/docs/corpus-catalog.md` (classify `SYNTHETIC`, record the
   verbatim `mkudffs` command).
5. Add a `udfinfo` (or `isoinfo`/`mount -t udf`) differential as the independent oracle to lift
   the partition-map assertion from Tier 2 to Tier 1, per `docs/validation.md`.
