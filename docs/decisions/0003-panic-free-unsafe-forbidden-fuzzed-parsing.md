# 3. Panic-free, unsafe-forbidden, fuzzed parsing

Date: 2026-07-24

Status: Accepted

## Context

`udf-forensic` parses untrusted, attacker-controllable UDF images pulled from
optical media of unknown provenance. Every length, offset, and count in the
descriptor chain is data an adversary can forge. The fleet's Paranoid Gatekeeper
standard (`ronin-issen/CLAUDE.md`) is explicit for `*-forensic` crates: never
panic, never read out of bounds, never trust a length field — a panic on crafted
input is a denial-of-service vector.

The reader has no legitimate need for `unsafe` (no mmap; it reads over `Read +
Seek`), so the strongest posture is available: memory safety proved by the
compiler, not asserted by a human.

## Decision

Three complementary controls, all present in the tree:

1. **`#![forbid(unsafe_code)]`** — `[lints.rust] unsafe_code = "forbid"` in
   `Cargo.toml` and the crate-level attribute in `src/lib.rs`. `forbid` (not the
   `deny` + bounded-allow used by the mmap crates) because there is zero `unsafe`
   to justify; this earns the honest "no `unsafe`" claim in the README.
2. **Panic-free by lint** — `clippy::unwrap_used` and `expect_used` are `deny`
   (`Cargo.toml [lints.clippy]`), with `#![cfg_attr(test, allow(...))]` so tests
   may still unwrap on known-good fixtures. Every fixed-width integer field is
   read through the shared **`safe-read`** crate (`use safe_read::{le_u32,
   le_u64}`), the fleet's single audited, `no_std`, `forbid(unsafe)`, fuzzed
   bounds-checked reader — fixed-width reads return `0` out of range instead of
   panicking, rather than re-deriving a per-crate `bytes.rs` (commit `80d757d`:
   *"panic-free by lint — route fixed-width reads through safe-read"*).
3. **Fuzzed** — a `cargo-fuzz` harness with one target per parsed structure:
   `fuzz/fuzz_targets/{detect,parse_state,read_dir,read_fe}.rs`, wired into CI
   (commit `2156872`: *"add cargo-fuzz harness + coverage CI job"*).

The lints make panics unreachable *by construction*; the fuzzer *tests* that
empirically over the read/parse pipeline. They are complementary — the README's
robustness wording leads with the measured "input-fuzzed" evidence and qualifies
"panic-free" as the static half, per the fleet Evidence-Based Rigor rule.

## Consequences

- A malformed UDF image degrades to a structural negative or a graceful `Err`,
  never a crash — the property forensic tooling depends on.
- `safe-read` covers fixed-width fields only; range-checking every image-supplied
  length/offset/count before use and capping allocations remain the reader's job
  (e.g. `parse_partition_maps` clamps `maps_end` and checks `off + map_len`).
- `forbid` cannot be locally overridden, so any future need for `unsafe` (e.g. an
  mmap fast path) would require a deliberate downgrade to `deny` + an annotated
  per-site allow, forcing the cost-benefit decision into the open.
