# 1. Extract the UDF reader into a standalone crate

Date: 2026-07-24

Status: Accepted

## Context

The UDF (ECMA-167 / OSTA) reader began life inside `iso9660-forensic`, because
optical *bridge discs* carry both ISO 9660 and UDF structures on the same
sectors and the ISO reader needed to recognise the UDF mark. As the UDF support
grew past volume recognition into partition-map classification, File Entry and
directory traversal, and file-data reading, it stopped being an ISO detail and
became a filesystem in its own right.

The founding commit records the move: `629da9c` — *"feat: extract UDF
(ECMA-167/OSTA) reader into a standalone crate … extracted from iso9660-forensic
as a sibling to the other filesystem crates."* The fleet constitution
(`ronin-issen/CLAUDE.md`) places filesystem readers in the FILESYSTEM layer as
standalone, self-contained experts in one artifact family, and its Dependency
Preference rule ("prefer our own crates", DRY-via-search-first) says a capability
that more than one consumer could need belongs in a shared crate rather than
duplicated. UDF fits: extracting it lets the `forensic-vfs-engine` compose it for
any optical evidence image (via the `vfs` feature, ADR 0008) without embedding a
second copy. (`iso9660-forensic` took the complementary path — it later dropped
UDF entirely, `ff0b179`, keeping only a native `has_udf()` recognition boolean
rather than depending on this crate.)

## Decision

Ship UDF as its own repository and crate, `udf-forensic`, a FILESYSTEM-layer
reader over any `Read + Seek` source. It depends down only on the KNOWLEDGE leaf
(`forensicnomicon`) plus the shared `safe-read` primitive, and is consumed —
through the optional `vfs` feature — by the `forensic-vfs-engine` (see ADR 0008),
its sole fleet dependent today.

## Consequences

- One canonical, independently versioned UDF implementation. `iso9660-forensic`
  subsequently removed UDF handling entirely (`ff0b179`) rather than depending on
  this crate — a bridge disc's UDF/ISO co-residence is a composition fact for the
  mounter, not an ISO9660 fact — so the current dependent is `forensic-vfs-engine`,
  not the ISO reader.
- The crate is medium-agnostic (`Read + Seek`), so it works over a live file, a
  container-decoded sector stream, or a carved region without knowing the source.
- A new repo carries the full fleet publish surface (README, docs site, CI,
  fuzzing, supply-chain config) — accepted as the cost of a reusable, independently
  versioned library.
