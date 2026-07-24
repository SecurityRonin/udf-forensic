# 8. Expose the forensic-vfs adapter behind an optional `vfs` feature

Date: 2026-07-24

Status: Accepted

## Context

The fleet's universal container/filesystem abstraction (`ronin-issen/CLAUDE.md`,
"VFS & Universal Container Abstraction") lets a consumer read any evidence image
without knowing one filesystem from another: a reader implements the
`forensic-vfs` `FileSystem` trait and composes as `Arc<dyn FileSystem>` in the
`forensic-vfs-engine`. For a whole stack (`E01 → GPT → NTFS`, or an optical
`UDF` volume) to read as one shared source, UDF needs that adapter.

But `forensic-vfs` is a non-trivial dependency, and a bare `Read + Seek` caller
wants only the plain UDF reader without it. The Batteries-Included discipline
bans `default-features = false` as a
*fleet-slimming* tactic, but explicitly permits **one** exception: a genuinely
optional, rarely-wanted heavy subsystem may be a named non-default feature, with
the bare library staying dependency-light for third-party reuse.

## Decision

Implement `impl FileSystem for UdfVfs` in `src/vfs.rs`, gated behind a
non-default **`vfs`** Cargo feature that turns on an optional `forensic-vfs`
dependency (`Cargo.toml`: `vfs = ["dep:forensic-vfs"]`,
`forensic-vfs = { version = "0.7", optional = true }`). A bare reader stays
dependency-light; the `vfs` feature turns on the composition adapter. History:
the adapter landed RED/GREEN (`9dc8b97`/`d003c80`) and tracked the contract
through `forensic-vfs` 0.1 → 0.4 → 0.5 → 0.7 (`94c7453`, `acbe54f`, `4c1d6fd`).

Because `forensic-vfs`'s `FileId` is `#[non_exhaustive]` and this crate must not
add a variant, a node is addressed by `FileId::Opaque(fe_lba)` — the File Entry's
physical LBA, UDF's node-identity primitive — the closest honest mapping.

## Consequences

- UDF volumes compose in the `forensic-vfs` engine when wanted, without forcing
  the dependency on every reader consumer.
- The adapter's current limits are surfaced honestly in the module doc rather
  than faked: `FsMeta::times` is all-`None` (the reader's traversal API does not
  yet surface per-FE times), `extents` yields a single logical run, and
  deleted/unallocated/symlink streams are empty — future work, not fabricated
  data (fail-loud over guessing).
- Node classification (file vs dir) relies on a per-FE cache seeded from the
  parent's File Identifier Descriptor (UDF stores `is_dir` in the parent FID, not
  the child FE); an untraversed file FE returns a loud `VfsError::Decode` rather
  than a guess.
