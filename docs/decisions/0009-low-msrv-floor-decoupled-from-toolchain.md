# 9. Declare a low MSRV floor, decoupled from the pinned dev toolchain

Date: 2026-07-24

Status: Accepted

## Context

The fleet MSRV policy (`ronin-issen/CLAUDE.md`, "Rust MSRV & Toolchain") splits
two concepts that must not be conflated: the **dev toolchain** (what contributors
and CI build with — pinned to one current stable across the fleet) and the
**declared MSRV** (`rust-version`, a downstream-facing compatibility promise).
Published libraries keep a **low, CI-verified MSRV** because a low floor is a
deliberate compatibility feature and a trust signal; raising it narrows the
crates.io audience and is treated as near-breaking.

`udf-forensic` is a published library (ADR 0001), so it must honor this split.

## Decision

Pin the dev toolchain to the fleet's current stable in `rust-toolchain.toml`
(`channel = "1.96.0"`, with `clippy` + `rustfmt` components declared there as the
single source of truth), while declaring a lower `rust-version = "1.85"` in
`Cargo.toml` as the downstream promise. Develop on 1.96.0; promise only 1.85.
Commit `a2993d9` pinned the toolchain to 1.96.0 per fleet policy.

The specific floor of **1.85** (higher than the fleet's typical `1.75`/`1.80`
library floors) is not explained in the commit history — it is most plausibly the
minimum imposed by a dependency in the graph (`forensicnomicon 1`, `safe-read`,
or `forensic-vfs 0.7`), but that is inference. **Rationale reconstructed from
structure; original intent (why exactly 1.85, not a lower floor) not recovered in
available history.**

## Consequences

- Third-party consumers on Rust 1.85+ can link the crate even though the fleet
  develops on a newer stable; the promise matches what a CI MSRV job verifies,
  not the drifting pin.
- The floor should be raised only when the crate genuinely needs a newer-Rust
  feature — never merely to match the toolchain — and a raise is treated as a
  near-breaking change.
- If a future audit finds the 1.85 floor is looser or tighter than the true
  dependency-imposed minimum, it can be adjusted with a CI-verified MSRV job as
  the check.
