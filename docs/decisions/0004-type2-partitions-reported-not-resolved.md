# 4. Detect and report Type-2 partitions; never silently resolve them

Date: 2026-07-24

Status: Accepted

## Context

UDF logical volumes reference partitions through partition maps (ECMA-167 §10.7,
OSTA UDF §2.2.8). A **Type 1** physical partition resolves trivially: a physical
block address is `partition_start + logical_block_num`. **Type 2** maps —
`*UDF Virtual Partition` (VAT-mapped packet-written media), `*UDF Sparable
Partition` (defect management), and `*UDF Metadata Partition` (UDF 2.50+,
Blu-ray) — do **not**: block resolution requires following additional structures
(a Virtual Allocation Table, a sparing table, a metadata file) that this reader
does not yet implement.

A reader that ignored the map type and applied the Type-1 formula to a Type-2
partition would silently produce wrong block addresses — reading the wrong
sectors and presenting them as file data. The fleet's Fail-loud / Secure-by-Design
disciplines forbid exactly this: an error turned into silent wrong output is the
most expensive bug class, and "unknown/unsupported" must surface the offending
value, not be swallowed.

## Decision

Classify the partition map and carry the result as a first-class part of the
parsed state, rather than assuming Type 1. `src/lib.rs` defines
`UdfPartitionKind { Physical, Virtual, Sparable, Metadata, Unknown }`;
`classify_type2()` scans a Type-2 map for the OSTA entity strings
(`*UDF Metadata Partition` / `*UDF Virtual Partition` / `*UDF Sparable
Partition`), falling to `Unknown` on an unrecognised identifier;
`parse_partition_maps()` distinguishes map type 1 (with its partition number)
from type 2. `UdfState.partition_kind` and `partition_map_count` are surfaced to
the caller so a forensic tool can refuse or flag a Type-2 volume rather than
mis-read it (README: "detected and reported rather than silently mis-read").

## Consequences

- A consumer sees exactly which partition mechanism a volume uses and can decide
  whether the physical-mapping traversal is valid for it.
- File traversal over a Type-2 volume is knowingly out of scope today, not a
  silent wrong answer — an honest capability gap the caller can act on.
- Adding real VAT/Sparable/Metadata resolution later is additive: the kind is
  already classified, so the block-mapping code gains a per-kind branch without
  changing the public contract.
- `Unknown` preserves the raw fact that a Type-2 map was present but its
  identifier was not one of the three known strings — the evidence is reported,
  not discarded.
