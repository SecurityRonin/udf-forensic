# Validation

`udf-forensic` parses untrusted UDF (ECMA-167 / OSTA) structures from potentially
compromised optical-media images. Correctness for forensic tooling is established
against **independent oracles** (a different tool, or a different code path, that
already decodes the same bytes correctly) on **real third-party corpora** with
known ground truth — never against fixtures we hand-encoded and then graded
ourselves.

This page records exactly which oracle and which corpus back each capability, so
the claim is independently re-checkable. It is deliberate about what is **not yet**
backed by an independent oracle: where the current evidence is self-authored, it
is labelled Tier 3 and the missing oracle is named as a gap rather than dressed up
as a stronger claim.

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

The honest current state: **no independent decoding oracle is wired into the test
suite yet.** The partition-map tests assert against the *intended construction
profile* of `mkudffs`-built images (the tool author's documented output for a
given media type), not against a second tool that re-decodes the same bytes. That
makes them Tier 2 *inputs* with no Tier 1 cross-check.

| Oracle | Wired in? | Would validate | Tier it would establish |
|---|---|---|---|
| **`udfinfo`** (udftools) | No — **recommended gap** | Partition-map kind, volume identifiers, FSD/root-FE location | 1 |
| **`isoinfo`** (cdrtools) / **`xorriso`** | No — **recommended gap** | Volume recognition (NSR02/NSR03), directory tree on UDF-bridge discs | 1 |
| **Linux `mount -t udf` + `find`** | No — **recommended gap** | Directory traversal + file-data extents, byte-for-byte file contents | 1 |
| **`mkudffs` construction profile** | Yes (implicitly, via the fixture's build flags) | Partition-map kind matches the media type the image was built for | 2 |

Adding any one of the first three to a differential test would lift the
corresponding capability from its current tier to Tier 1.

## Independent test corpora

The two real-media fixtures the tests reference (`udf_vat.img`,
`udf_spar.img`) are **not committed** and, at present, **no generator script or
provenance entry ships in the repo** — `tests/data/` is empty and the
`corpus/gen_udf_type2.sh` named in the test module comment does not exist here yet.
The tests are written to **skip cleanly when the fixtures are absent**, so the
committed suite is green without them. Reproducible provenance for these fixtures
is an open item (see *Honesty caveats* below).

| Corpus | Source | Used for | License / redistribution |
|---|---|---|---|
| `udf_vat.img` | `mkudffs --media-type=cdr` (UDF 1.50) — **generator not yet in repo** | Partition-map = Virtual (VAT) assertion | mkudffs output is freely redistributable; fixture untracked |
| `udf_spar.img` | `mkudffs --media-type=dvdrw` (UDF 2.01) — **generator not yet in repo** | Partition-map = Sparable assertion | mkudffs output is freely redistributable; fixture untracked |

Per-file provenance belongs in `tests/data/README.md` (to be created when the
generator is committed); the fleet-wide machine index is
`issen/docs/corpus-catalog.md`.

## Per-capability validation

### Volume recognition (NSR02 / NSR03) — Tier 3

Recognition of the UDF Volume Structure Descriptor sequence is exercised only by
the in-crate bootstrap tests over hand-built buffers. No independent oracle
(`isoinfo`/`xorriso`) confirms the recognition decision on a real disc yet —
**recommended gap.**

### Partition-map classification (Virtual / Sparable / Metadata) — Tier 2 (fixtures absent)

`src/lib.rs` `mod real_media_tests` (`vat_image_classified_virtual` at
`src/lib.rs:644`, `sparable_image_classified_sparable` at `src/lib.rs:657`)
asserts that an image **`mkudffs` built for `cdr`/UDF 1.50** classifies as
`Virtual` and one built for **`dvdrw`/UDF 2.01** classifies as `Sparable`. The
ground truth is the construction profile of a real third-party tool, which is why
this is Tier 2 rather than Tier 3 — but there is **no independent decoder
cross-checking the same bytes**, and the fixtures themselves are not present in
the repo, so the assertion does not run in CI today. Adding a `udfinfo`
differential and committing a generator would make this Tier 1 and reproducible.

### Bootstrap-failure vs not-UDF distinction — Tier 3

`src/lib.rs` `mod checked_bootstrap_tests` validates that
`parse_udf_state_checked` separates a genuine read/seek failure (truncated or
unreadable image) from a structural negative (readable image whose anchor is not
an AVDP):

- `io_error_at_anchor_surfaces_as_err` (`src/lib.rs:695`) — a faulting reader at
  the LBA-256 anchor surfaces `Err`, never `Ok(None)`.
- `truncated_before_anchor_surfaces_as_err` (`src/lib.rs:705`) — a buffer too
  short to reach the anchor yields `Err(UnexpectedEof)`.
- `full_size_but_wrong_anchor_is_ok_none` (`src/lib.rs:721`) — a readable image
  with a non-AVDP anchor is the legitimate `Ok(None)` "not UDF" case.

These are self-authored fixtures with self-authored expectations (Tier 3). They
are genuinely useful — they pin the fail-loud-vs-degrade-to-empty contract — but
they prove internal consistency, not correctness against real-world media.

### Directory traversal and file-data extents — not yet validated

FID traversal and short/long extent file-data reading have **no committed test
backing of any tier**. The recommended oracle is `mount -t udf` + a byte-for-byte
`find`/checksum comparison on a real disc image — **recommended gap.**

## Reproducing the validation

The committed, always-on tests run with `cargo test` (the bootstrap tests run
unconditionally; the real-media tests skip when their fixtures are absent):

```bash
# All committed tests (bootstrap tests run; real-media tests skip if fixtures absent)
cargo test

# Only the bootstrap fail-loud contract
cargo test checked_bootstrap_tests

# The real-media partition-map tests (require the untracked fixtures in tests/data/)
cargo test real_media_tests
```

To exercise the real-media tests you must place `udf_vat.img` and `udf_spar.img`
in `tests/data/`. Until a generator and provenance entry are committed, build them
with `mkudffs` (udftools) directly, e.g.:

```bash
# illustrative — pin exact flags + hashes in tests/data/README.md when committing
dd if=/dev/zero of=tests/data/udf_vat.img  bs=1M count=32
mkudffs --media-type=cdr   --udfrev=0x0150 tests/data/udf_vat.img
dd if=/dev/zero of=tests/data/udf_spar.img bs=1M count=32
mkudffs --media-type=dvdrw --udfrev=0x0201 tests/data/udf_spar.img
```

## Coverage & fuzzing backstops

There is **no coverage gate and no fuzz harness in this repo yet** — CI runs
`ci.yml` (build/test/clippy/fmt) and `docs.yml` (MkDocs) only. Production code is
`#![forbid(unsafe_code)]` (`Cargo.toml`), reads through bounds-checked helpers,
and folds malformed structure into `None` rather than panicking. A `cargo-fuzz`
target over `parse_udf_state` / `read_dir_at_lba` and a `cargo llvm-cov --lib`
gate are recommended additions to bring this crate to the fleet backstop standard.
