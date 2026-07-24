# 5. Distinguish an I/O failure from a structural "not UDF" negative

Date: 2026-07-24

Status: Accepted

## Context

The bootstrap chain (AVDP at LBA 256 → Volume Descriptor Sequence → File Set
Descriptor) is the prerequisite every later traversal depends on. There are two
very different reasons it can fail to yield state:

- the source could not be **read** — a seek/read error, or an `UnexpectedEof`
  because the image is **truncated** before the anchor; or
- the source was read fine but simply is **not UDF** — the anchor tag is not an
  AVDP, or the descriptor chain is absent/incoherent.

The fleet's Robustness discipline ("Bootstrap failure ≠ artifact-not-found")
requires these be kept apart: a truncated or unreadable evidence image is itself
forensically suspicious and must surface loudly, never masquerade as a clean
"this isn't UDF" negative. Collapsing both into `None` would make a damaged image
indistinguishable from an ISO-only disc.

## Decision

Provide two entry points (commit `47f3feb`: *"add parse_udf_state_checked
surfacing anchor read I/O errors"*, with its RED test `6a4159d`):

- **`parse_udf_state_checked() -> Result<Option<UdfState>, io::Error>`** — the
  honest three-way answer: `Err(io)` = a real read/seek failure (including
  truncation), `Ok(None)` = read succeeded but the structure is not valid UDF,
  `Ok(Some(state))` = valid UDF.
- **`parse_udf_state() -> Option<UdfState>`** — a documented lenient wrapper
  (`checked(...).ok().flatten()`) for callers that genuinely do not care why it
  failed.

`detect_udf()` likewise treats a read error as a break (not a false positive).

## Consequences

- A forensic caller can tell "corrupt/truncated image — investigate" from
  "legitimately not a UDF volume", the distinction that matters in an evidence
  chain.
- The safe, expressive path (`checked`) is available and documented; the lossy
  convenience path is explicitly labelled as such rather than being the only
  option.
- Downstream (the `vfs` adapter, consumed by `forensic-vfs-engine`) can propagate
  the I/O error instead of reporting an empty/absent filesystem for a disc that was
  merely unreadable.
