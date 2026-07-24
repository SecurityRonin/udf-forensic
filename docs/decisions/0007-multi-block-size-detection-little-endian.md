# 7. Auto-detect the logical block size; read little-endian ECMA-167 fields

Date: 2026-07-24

Status: Accepted

## Context

UDF is not exclusively an optical, 2048-byte-sector format. The logical block
size varies by medium: optical media (CD/DVD/BD) use 2048, hard-disk and USB UDF
use 512, and Advanced-Format media use 4096. The physical location of every
descriptor (the anchor at LBA 256, the VDS, the FSD) is expressed in *logical
blocks*, so a reader that hardcoded 2048 would seek to the wrong byte offsets on
a 512- or 4096-byte-block volume and fail to find the structure at all. The
recognition sequence at sector 16, by contrast, is always addressed in 2048-byte
units (the Volume Structure Descriptor size), independent of the logical block
size.

ECMA-167 stores its multi-byte integer fields **little-endian** (unlike, e.g.,
ISO 9660's both-endian fields or big-endian formats).

## Decision

Detect the logical block size at bootstrap rather than assuming one.
`BLOCK_SIZE_CANDIDATES = [2048, 512, 1024, 4096]` (most-common first);
`detect_block_size()` validates the AVDP tag at LBA 256 for each candidate and
picks the one that yields a coherent anchor, capped by `MAX_BLOCK_SIZE = 4096`
for the stack sector buffer. The detected size flows through `UdfState.block_size`
into every subsequent seek (`phys_lba = partition_start + logical_block_num`,
scaled by the block size). Commit `f610782` (*"GREEN — detect logical block size
from the AVDP"*) with its RED test `c2af436` added this; `udf_plain` is a
validated 512-block oracle case (`def09f6`).

All fixed-width fields are read little-endian through `safe-read`'s `le_u32` /
`le_u64` (and `u16::from_le_bytes` for the 2-byte partition number), matching
ECMA-167.

## Consequences

- The reader works across optical, USB/HDD, and Advanced-Format UDF without the
  caller specifying the geometry — the zero-config path is correct for the common
  media (Design-for-the-human / Secure-by-Default).
- Detection derives the block size from the *structure* (a valid AVDP tag), not
  from a filename or a guess, so it generalizes to any conformant volume rather
  than special-casing known fixtures.
- The recognition-sequence scan stays in fixed 2048-byte units by spec, so
  detection order (block size) and recognition (sector 16) are decoupled.
